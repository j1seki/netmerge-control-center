package dashboard

// The HTTP API. Every handler is short: the work lives in the packages the command wires in,
// and anything slow is handed to a background job (jobs.go).
//
// Two habits are deliberate throughout:
//
//   - Missing data is reported as missing. A nil TTL manager answers "the TTL manager is not
//     available here" instead of an empty settings list that would look like a host with
//     nothing to show.
//   - A real system change is only reachable with confirm=true, and the outcome that comes back
//     is the manager's own, with its per-change verification, not a summary this layer invents.

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"net-merge/internal/appcfg"
	"net-merge/internal/diag"
	"net-merge/internal/engine"
	"net-merge/internal/errcodes"
	"net-merge/internal/inventory"
	"net-merge/internal/logx"
	"net-merge/internal/monitor"
	"net-merge/internal/platform"
	"net-merge/internal/state"
	"net-merge/internal/ttlmgr"
)

// --- state ------------------------------------------------------------------------------------

type appView struct {
	Version      string `json:"version"`
	Platform     string `json:"platform"`
	Arch         string `json:"arch"`
	Elevated     bool   `json:"elevated"`
	Dashboard    string `json:"dashboard"`
	SettingsFile string `json:"settingsFile"`
	StateDir     string `json:"stateDir"`
}

type stateView struct {
	Now           time.Time           `json:"now"`
	App           appView             `json:"app"`
	Collecting    bool                `json:"collecting"`
	CollectError  string              `json:"collectError,omitempty"`
	CollectedAt   time.Time           `json:"collectedAt,omitempty"`
	Snapshot      *inventory.Snapshot `json:"snapshot,omitempty"`
	Engine        *engineStatus       `json:"engine,omitempty"`
	EngineOn      bool                `json:"engineOn"`
	Monitor       *monitorView        `json:"monitor,omitempty"`
	Settings      *appcfg.Config      `json:"settings,omitempty"`
	SettingsError string              `json:"settingsError,omitempty"`
}

// monitorView is the link-health probe's state for the page. Enabled false is a fact the page
// states out loud ("the reachability probe is off") rather than leaving a table that looks
// like every link is unknown.
type monitorView struct {
	Enabled     bool                 `json:"enabled"`
	IntervalMs  int64                `json:"intervalMs,omitempty"`
	Endpoint    string               `json:"endpoint,omitempty"`
	Links       []monitor.LinkView   `json:"links,omitempty"`
	Transitions []monitor.Transition `json:"transitions,omitempty"`
}

// healthView builds the monitor section. It returns nil when no monitor is attached at all,
// so the field is absent rather than claiming to be off.
func (s *Server) healthView() *monitorView {
	if s.deps.Health == nil {
		return nil
	}
	v := &monitorView{
		Enabled:    s.cfg.Health.Enabled,
		IntervalMs: s.cfg.Health.Interval.Milliseconds(),
		Endpoint:   s.cfg.Health.Endpoint,
	}
	if !s.cfg.Health.Enabled {
		return v
	}
	v.Links = s.deps.Health.View()
	v.Transitions = s.deps.Health.Transitions(20)
	return v
}

func (s *Server) buildState() stateView {
	snap, at, snapErr := s.cached()
	view := stateView{
		Now:          s.now(),
		Collecting:   snap == nil,
		CollectError: snapErr,
		CollectedAt:  at,
		Snapshot:     snap,
		Monitor:      s.healthView(),
		App: appView{
			Version:      s.cfg.Version,
			Platform:     runtime.GOOS,
			Arch:         runtime.GOARCH,
			Elevated:     platform.IsAdmin(),
			Dashboard:    s.addr,
			SettingsFile: appcfg.Path(s.cfg.SettingsDir),
			StateDir:     s.cfg.StateDir,
		},
	}
	if st, on := s.engine(); on {
		view.Engine, view.EngineOn = viewEngineStatus(st), true
	}
	if cfg, _, err := s.loadSettings(); err != nil {
		view.SettingsError = err.Error()
	} else {
		view.Settings = &cfg
	}
	return view
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.buildState())
}

// handleRefresh takes a fresh snapshot on demand. The UI's refresh button uses it; the monitor
// loop keeps the cache current regardless.
func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	s.refresh(ctx)
	writeJSON(w, http.StatusOK, s.buildState())
}

// --- engine -----------------------------------------------------------------------------------

// engineNIC is one line of the engine's per-adapter table, in the API's lowercase shape.
// engine.SlotStats carries no JSON tags on purpose - it is embedded in the engine's own status
// file, whose wire format is a contract with the engine binary - so the projection is built
// here. Without it the API served PascalCase field names that the page could not read.
type engineNIC struct {
	Name     string  `json:"name"`
	IP       string  `json:"ip,omitempty"`
	IP6      string  `json:"ip6,omitempty"`
	State    string  `json:"state,omitempty"`  // IPv4 probe state; "-" when the adapter has no IPv4
	State6   string  `json:"state6,omitempty"` // IPv6 probe state
	Weight   float64 `json:"weight"`
	Weight6  float64 `json:"weight6"`
	Present  bool    `json:"present"`
	Active   int64   `json:"active"`
	Total    int64   `json:"total"`
	Failed   int64   `json:"failed"`
	BytesIn  int64   `json:"bytesIn"`
	BytesOut int64   `json:"bytesOut"`
	RateIn   float64 `json:"rateIn"`
	RateOut  float64 `json:"rateOut"`
	LinkIn   float64 `json:"linkIn"`
	LinkOut  float64 `json:"linkOut"`
	Peak     float64 `json:"peak"`
	Peak6    float64 `json:"peak6"`
}

func viewSlotStats(s engine.SlotStats) engineNIC {
	return engineNIC{
		Name: s.Name, IP: s.IP, IP6: s.IP6, State: s.State, State6: s.State6,
		Weight: s.Weight, Weight6: s.Weight6, Present: s.Present,
		Active: s.Active, Total: s.Total, Failed: s.Failed,
		BytesIn: s.BytesIn, BytesOut: s.BytesOut,
		RateIn: s.RateIn, RateOut: s.RateOut, LinkIn: s.LinkIn, LinkOut: s.LinkOut,
		Peak: s.Peak, Peak6: s.Peak6,
	}
}

type engineStatus struct {
	PID     int         `json:"pid"`
	Mode    string      `json:"mode"`
	V6      string      `json:"v6"`
	Since   time.Time   `json:"since"`
	Updated time.Time   `json:"updated"`
	NICs    []engineNIC `json:"nics,omitempty"`
}

func viewEngineStatus(st *state.Status) *engineStatus {
	if st == nil {
		return nil
	}
	v := &engineStatus{PID: st.PID, Mode: st.Mode, V6: st.V6, Since: st.Since, Updated: st.Updated}
	for _, n := range st.NICs {
		v.NICs = append(v.NICs, viewSlotStats(n))
	}
	return v
}

type engineView struct {
	On     bool          `json:"on"`
	Status *engineStatus `json:"status,omitempty"`
}

func (s *Server) engineView() engineView {
	st, on := s.engine()
	return engineView{On: on, Status: viewEngineStatus(st)}
}

func (s *Server) handleEngineGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.engineView())
}

type engineRequest struct {
	Action string `json:"action"` // on|off|quit
}

// handleEnginePost turns the engine on or off through the same marker files the CLI uses.
// There is no second control path: `net-merge off` and the dashboard's OFF switch do the same
// one thing, and both are visible in the engine's own status file afterwards.
func (s *Server) handleEnginePost(w http.ResponseWriter, r *http.Request) {
	var req engineRequest
	if err := decodeBody(r, &req); err != nil {
		fail(w, http.StatusBadRequest, "dashboard_bad_request", "the request body is not valid JSON", err.Error())
		return
	}
	switch req.Action {
	case "on", "off", "quit":
	default:
		fail(w, http.StatusBadRequest, "dashboard_bad_action",
			fmt.Sprintf("action must be on, off or quit, got %q", req.Action), nil)
		return
	}
	if err := state.Prepare(s.cfg.StateDir); err != nil {
		fail(w, http.StatusInternalServerError, "dashboard_state_dir", "the state directory could not be prepared", err.Error())
		return
	}
	if err := state.SendMarker(s.cfg.StateDir, req.Action); err != nil {
		fail(w, http.StatusInternalServerError, "dashboard_marker_failed", "the marker file could not be written", err.Error())
		return
	}
	_, on := s.engine()
	logx.Eventf(logx.LevelInfo, "dashboard.engine", "requested engine action %q (engine was %s)", req.Action, onWord(on))
	writeJSON(w, http.StatusOK, s.engineView())
}

func onWord(on bool) string {
	if on {
		return "on"
	}
	return "off"
}

// --- TTL / hop limit --------------------------------------------------------------------------

type ttlView struct {
	Report    ttlmgr.Report `json:"report"`
	CanWrite  bool          `json:"canWrite"`
	Elevated  bool          `json:"elevated"`
	Interface []string      `json:"interfacesConsidered,omitempty"`
}

func (s *Server) handleTTLGet(w http.ResponseWriter, r *http.Request) {
	if s.deps.TTL == nil {
		fail(w, http.StatusServiceUnavailable, "dashboard_ttl_unavailable",
			"the TTL manager is not available in this context (it needs the platform backend)", nil)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	ifaces := s.ifaces()
	rep, err := s.deps.TTL.Inspect(ctx, ifaces)
	if err != nil {
		fail(w, http.StatusInternalServerError, "dashboard_ttl_inspect_failed", "the TTL/hop-limit settings could not be read", err.Error())
		return
	}
	names := make([]string, 0, len(ifaces))
	for _, i := range ifaces {
		names = append(names, i.Name)
	}
	writeJSON(w, http.StatusOK, ttlView{
		Report: rep, CanWrite: rep.Capabilities.Supported, Elevated: rep.Elevated, Interface: names,
	})
}

func (s *Server) handleTTLHistory(w http.ResponseWriter, r *http.Request) {
	if s.deps.TTL == nil {
		fail(w, http.StatusServiceUnavailable, "dashboard_ttl_unavailable", "the TTL manager is not available in this context", nil)
		return
	}
	limit := queryInt(r, "limit", 100, 1, 1000)
	evs, err := s.deps.TTL.History(limit)
	if err != nil {
		fail(w, http.StatusInternalServerError, "dashboard_ttl_history_failed", "the change history could not be read", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": evs})
}

// handleTTLConfig saves the opt-in configuration. It never applies anything: a saved config is
// a record of what the user chose, and every write still goes through preview and confirm.
func (s *Server) handleTTLConfig(w http.ResponseWriter, r *http.Request) {
	if s.deps.TTL == nil {
		fail(w, http.StatusServiceUnavailable, "dashboard_ttl_unavailable", "the TTL manager is not available in this context", nil)
		return
	}
	var cfg ttlmgr.Config
	if err := decodeBody(r, &cfg); err != nil {
		fail(w, http.StatusBadRequest, "dashboard_bad_request", "the request body is not a valid TTL configuration", err.Error())
		return
	}
	if err := cfg.Validate(); err != nil {
		fail(w, http.StatusBadRequest, "dashboard_ttl_config_invalid", "the TTL configuration was rejected", err.Error())
		return
	}
	if err := s.deps.TTL.SaveConfig(cfg); err != nil {
		fail(w, http.StatusInternalServerError, "dashboard_ttl_config_save_failed", "the TTL configuration could not be saved", err.Error())
		return
	}
	logx.Eventf(logx.LevelInfo, "dashboard.ttl.config", "TTL configuration saved (enabled=%v, ipv4=%d, ipv6=%d, policy=%s)",
		cfg.Enabled, cfg.BumpIPv4, cfg.BumpIPv6, cfg.Policy)
	writeJSON(w, http.StatusOK, map[string]any{"saved": true})
}

type ttlOpRequest struct {
	DryRun  bool     `json:"dryRun"`
	Confirm bool     `json:"confirm"`
	Reason  string   `json:"reason"`
	Only    []string `json:"only,omitempty"`
}

func (s *Server) handleTTLApply(w http.ResponseWriter, r *http.Request) {
	s.ttlOp(w, r, false)
}

func (s *Server) handleTTLRestore(w http.ResponseWriter, r *http.Request) {
	s.ttlOp(w, r, true)
}

func (s *Server) ttlOp(w http.ResponseWriter, r *http.Request, restore bool) {
	if s.deps.TTL == nil {
		fail(w, http.StatusServiceUnavailable, "dashboard_ttl_unavailable", "the TTL manager is not available in this context", nil)
		return
	}
	var req ttlOpRequest
	if err := decodeBody(r, &req); err != nil {
		fail(w, http.StatusBadRequest, "dashboard_bad_request", "the request body is not valid JSON", err.Error())
		return
	}
	if !req.DryRun && !req.Confirm {
		// The manager refuses this too; refusing here keeps the message about the UI's flow.
		fail(w, http.StatusBadRequest, "dashboard_confirm_required",
			"a real change needs confirm=true; preview with dryRun=true first", nil)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	reason := req.Reason
	if reason == "" {
		reason = "requested from the Control Center dashboard"
	}

	var (
		out ttlmgr.Outcome
		err error
	)
	if restore {
		var only []ttlmgr.SettingID
		for _, id := range req.Only {
			only = append(only, ttlmgr.SettingID(id))
		}
		out, err = s.deps.TTL.Restore(ctx, ttlmgr.RestoreRequest{
			Ifaces: s.ifaces(), DryRun: req.DryRun, Confirm: req.Confirm, Reason: reason, Only: only,
		})
	} else {
		out, err = s.deps.TTL.Apply(ctx, ttlmgr.ApplyRequest{
			Ifaces: s.ifaces(), DryRun: req.DryRun, Confirm: req.Confirm, Reason: reason,
		})
	}
	if err != nil {
		fail(w, http.StatusInternalServerError, "dashboard_ttl_op_failed", "the TTL operation did not complete", err.Error())
		return
	}
	verb := "apply"
	if restore {
		verb = "restore"
	}
	level := logx.LevelInfo
	if !req.DryRun {
		level = logx.LevelWarn
	}
	logx.Eventf(level, "dashboard.ttl."+verb,
		"TTL %s (dryRun=%v): %d applied, %d failed, rolledBack=%v, rollbackIncomplete=%v",
		verb, req.DryRun, out.Applied, out.Failed, out.RolledBack, out.RollbackIncomplete)
	writeJSON(w, http.StatusOK, out)
}

// --- diagnostics ------------------------------------------------------------------------------

func (s *Server) handleDiagChecks(w http.ResponseWriter, r *http.Request) {
	if s.deps.Diag == nil {
		fail(w, http.StatusServiceUnavailable, "dashboard_diag_unavailable", "the diagnostics registry is not available in this context", nil)
		return
	}
	cfg, _, _ := s.loadSettings()
	writeJSON(w, http.StatusOK, map[string]any{
		"checks":         s.deps.Diag.Metas(),
		"categories":     diag.Categories(),
		"disabledChecks": cfg.Diagnostics.DisabledChecks,
	})
}

type diagRunRequest struct {
	All        bool     `json:"all"`
	IDs        []string `json:"ids"`
	Categories []string `json:"categories"`
}

func (s *Server) handleDiagRun(w http.ResponseWriter, r *http.Request) {
	if s.deps.Diag == nil {
		fail(w, http.StatusServiceUnavailable, "dashboard_diag_unavailable", "the diagnostics registry is not available in this context", nil)
		return
	}
	var req diagRunRequest
	if err := decodeBody(r, &req); err != nil {
		fail(w, http.StatusBadRequest, "dashboard_bad_request", "the request body is not valid JSON", err.Error())
		return
	}
	if !req.All && len(req.IDs) == 0 && len(req.Categories) == 0 {
		fail(w, http.StatusBadRequest, "dashboard_bad_request",
			"ask for all=true, a list of check ids, or categories", nil)
		return
	}
	cfg, _, _ := s.loadSettings()
	cats := make([]diag.Category, 0, len(req.Categories))
	for _, c := range req.Categories {
		cats = append(cats, diag.Category(c))
	}
	opts := diag.Options{
		Categories:      cats,
		Disabled:        cfg.Diagnostics.DisabledChecks,
		Concurrency:     4,
		PerCheckTimeout: time.Duration(cfg.Diagnostics.TracerouteTimeoutMs+30_000) * time.Millisecond,
	}
	if !req.All {
		opts.Only = req.IDs
	}
	runner := s.deps.Diag
	j := s.startJob("diag", func(ctx context.Context) (any, error) {
		return runner.RunAll(ctx, opts), nil
	})
	logx.Eventf(logx.LevelInfo, "dashboard.diag", "diagnostics run %s started (all=%v, ids=%d, categories=%d)",
		j.id, req.All, len(req.IDs), len(req.Categories))
	writeJSON(w, http.StatusAccepted, j.view())
}

func (s *Server) handleDiagRuns(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"runs": s.jobs.list("diag", 20)})
}

func (s *Server) handleDiagRunGet(w http.ResponseWriter, r *http.Request) {
	s.jobGet(w, r, "diag")
}

func (s *Server) handleDiagCancel(w http.ResponseWriter, r *http.Request) {
	s.jobCancel(w, r, "diag")
}

// jobGet serves one job by id. The kind check keeps a diag id from being fetched through the
// export route, which would only confuse the caller.
func (s *Server) jobGet(w http.ResponseWriter, r *http.Request, kind string) {
	id := r.PathValue("id")
	j, ok := s.jobs.get(id)
	if !ok || (kind != "" && j.kind != kind) {
		fail(w, http.StatusNotFound, "dashboard_job_unknown", fmt.Sprintf("no %s job with id %q", kind, id), nil)
		return
	}
	writeJSON(w, http.StatusOK, j.view())
}

type cancelRequest struct {
	ID string `json:"id"`
}

func (s *Server) jobCancel(w http.ResponseWriter, r *http.Request, kind string) {
	var req cancelRequest
	if err := decodeBody(r, &req); err != nil {
		fail(w, http.StatusBadRequest, "dashboard_bad_request", "the request body is not valid JSON", err.Error())
		return
	}
	j, ok := s.jobs.get(req.ID)
	if !ok || (kind != "" && j.kind != kind) {
		fail(w, http.StatusNotFound, "dashboard_job_unknown", fmt.Sprintf("no %s job with id %q", kind, req.ID), nil)
		return
	}
	j.mu.Lock()
	running := j.status == JobRunning
	cancel := j.cancel
	j.mu.Unlock()
	if !running {
		writeJSON(w, http.StatusOK, j.view())
		return
	}
	if cancel != nil {
		cancel()
	}
	logx.Eventf(logx.LevelInfo, "dashboard.job", "job %s cancelled by the user", j.id)
	writeJSON(w, http.StatusOK, j.view())
}

// --- logs -------------------------------------------------------------------------------------

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	if s.deps.Logs == nil {
		fail(w, http.StatusServiceUnavailable, "dashboard_logs_unavailable", "the log reader is not available in this context", nil)
		return
	}
	limit := queryInt(r, "limit", 200, 1, 1000)
	min := logx.LevelDebug
	if lv := r.URL.Query().Get("level"); lv != "" {
		parsed, ok := logx.ParseLevel(lv)
		if !ok {
			fail(w, http.StatusBadRequest, "dashboard_bad_level", fmt.Sprintf("unknown log level %q", lv), nil)
			return
		}
		min = parsed
	}
	q := r.URL.Query().Get("q")
	since := queryUint(r, "since", 0)

	if q != "" {
		// A search replaces the incremental read; it is what the search box does.
		evs := s.deps.Logs.Search(logx.Filter{Query: q, Min: min}, limit)
		_, cursor := s.deps.Logs.Events(0, logx.LevelError, 1)
		writeJSON(w, http.StatusOK, map[string]any{"events": evs, "cursor": cursor, "search": true})
		return
	}
	evs, cursor := s.deps.Logs.Events(since, min, limit)
	writeJSON(w, http.StatusOK, map[string]any{"events": evs, "cursor": cursor})
}

// handleErrorCodes serves the application's code registry: for every code a person can meet,
// what it means and what to do about it. The UI shows these beside errors and in the
// diagnostics results, so a code is never left as a bare identifier.
func (s *Server) handleErrorCodes(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"codes": errcodes.All()})
}

// --- settings ---------------------------------------------------------------------------------

type settingsView struct {
	Config       appcfg.Config `json:"config"`
	Path         string        `json:"path"`
	LoadError    string        `json:"loadError,omitempty"`
	LoadExisted  bool          `json:"existed"`
	ProfileOrder []string      `json:"profileOrder"`
	Stale        bool          `json:"stale,omitempty"`
	StaleReason  string        `json:"staleReason,omitempty"`
}

func (s *Server) handleSettingsGet(w http.ResponseWriter, r *http.Request) {
	cfg, existed, err := appcfg.Load(s.cfg.SettingsDir)
	view := settingsView{Config: cfg, Path: appcfg.Path(s.cfg.SettingsDir), LoadExisted: existed}
	if err != nil {
		// A corrupted file is reported and stays on disk; the settings page still renders so the
		// user can see and fix what they wrote.
		view.LoadError = err.Error()
	}
	ids := make([]string, 0, len(cfg.Profiles))
	for _, p := range cfg.SortedProfiles() {
		ids = append(ids, string(p.ID))
	}
	view.ProfileOrder = ids
	// A file written by another build is usable, but the user is told: the settings page is the
	// only place where a silent format change would otherwise go unnoticed.
	if stale, why := cfg.Stale(); stale {
		view.Stale, view.StaleReason = true, why
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) handleSettingsPut(w http.ResponseWriter, r *http.Request) {
	var cfg appcfg.Config
	if err := decodeBody(r, &cfg); err != nil {
		fail(w, http.StatusBadRequest, "dashboard_bad_request", "the request body is not a valid settings file", err.Error())
		return
	}
	if err := cfg.Validate(); err != nil {
		fail(w, http.StatusBadRequest, "dashboard_settings_invalid", "the settings were rejected", err.Error())
		return
	}
	if err := appcfg.Save(s.cfg.SettingsDir, cfg); err != nil {
		fail(w, http.StatusInternalServerError, "dashboard_settings_save_failed", "the settings file could not be saved", err.Error())
		return
	}
	logx.Eventf(logx.LevelInfo, "dashboard.settings", "settings saved (active profile %q, log level %q)", cfg.ActiveProfile, cfg.Logging.Level)
	writeJSON(w, http.StatusOK, map[string]any{"saved": true, "path": appcfg.Path(s.cfg.SettingsDir)})
}

// --- small helpers ----------------------------------------------------------------------------

func queryInt(r *http.Request, name string, def, min, max int) int {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < min {
		return def
	}
	if n > max {
		return max
	}
	return n
}

func queryUint(r *http.Request, name string, def uint64) uint64 {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return def
	}
	return n
}

// exportDir is where saved reports land: the configured output directory, made if needed.
func (s *Server) exportDir() (string, error) {
	dir := s.cfg.OutputDir
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("creating %s: %w", filepath.Clean(dir), err)
	}
	return dir, nil
}
