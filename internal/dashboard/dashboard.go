// Package dashboard is the Control Center's single interface: one localhost-only web page over
// the shared adapter inventory, the bonding engine's own control files, the TTL manager, the
// diagnostics centre and the log ring.
//
// Three properties are structural, not conventions:
//
//   - It binds loopback only. New refuses a listen address that is not loopback, so the page can
//     never be reachable from the LAN, and the privacy story of the export does not depend on
//     the user remembering a flag.
//   - Every request carries a per-run token. The token is generated when the server starts, is
//     handed over once in the URL, and is then required as a cookie (reads) or a header
//     (writes). State-changing requests are only accepted with the header, which a cross-site
//     request cannot set.
//   - Nothing long runs inside a request. Diagnostics runs and report exports are background
//     jobs with their own ids; a request to start one returns immediately and the UI polls. The
//     adapter snapshot the page reads is a cached copy refreshed by one monitor loop, so however
//     many browser tabs are open, the machine is sampled at one rate.
//
// The engine is controlled only through the same marker files the CLI uses (`net-merge on|off`),
// so the dashboard cannot invent a second control path, and TTL writes remain behind the
// manager's own dry-run/confirm gate.
package dashboard

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"net-merge/internal/appcfg"
	"net-merge/internal/diag"
	"net-merge/internal/errcodes"
	"net-merge/internal/inventory"
	"net-merge/internal/logx"
	"net-merge/internal/monitor"
	"net-merge/internal/state"
	"net-merge/internal/ttlmgr"
)

//go:embed assets
var assetsFS embed.FS

const (
	// TokenHeader is the request header that authorizes a state-changing call. The page's own
	// JavaScript sends it; a request from another origin cannot, which is what stands in for a
	// CSRF token here.
	TokenHeader = "X-NetMerge-Token"

	cookieName = "nm_dashboard_token"

	// tokenPlaceholder in index.html is replaced with the session token when the page is
	// served, so the page can send the header without asking the user to copy anything.
	tokenPlaceholder = "{{TOKEN}}"

	// defaultInterval is how often the monitor refreshes the cached snapshot.
	defaultInterval = 2 * time.Second
	// defaultHealthInterval is how often link reachability is probed when the settings file
	// does not say. It is much slower than the snapshot loop on purpose: each round opens one
	// TCP connection per adapter, so the snapshot loop must never carry it.
	defaultHealthInterval = 30 * time.Second
	// defaultMaxJobs bounds retained background jobs; the oldest finished one is dropped.
	defaultMaxJobs = 24
)

// Snapshotter is the monitor feed. The dashboard calls it on its own schedule and never from a
// request path that must stay fast.
type Snapshotter interface {
	Snapshot(ctx context.Context) (*inventory.Snapshot, error)
}

// TTLManager is the subset of the TTL manager the dashboard uses. It is an interface so the
// HTTP layer can be tested without a Windows host, and so the dashboard cannot reach any method
// the manager does not expose deliberately.
type TTLManager interface {
	Inspect(ctx context.Context, ifaces []ttlmgr.IfaceInfo) (ttlmgr.Report, error)
	Apply(ctx context.Context, req ttlmgr.ApplyRequest) (ttlmgr.Outcome, error)
	Restore(ctx context.Context, req ttlmgr.RestoreRequest) (ttlmgr.Outcome, error)
	SaveConfig(c ttlmgr.Config) error
	History(limit int) ([]ttlmgr.Event, error)
}

// DiagRunner is the diagnostics registry as the dashboard uses it.
type DiagRunner interface {
	Metas() []diag.Meta
	RunAll(ctx context.Context, opts diag.Options) diag.RunResult
}

// LogsReader is the log ring as the dashboard reads it.
type LogsReader interface {
	Events(since uint64, min logx.Level, limit int) ([]logx.Event, uint64)
	Search(f logx.Filter, limit int) []logx.Event
}

// HealthChecker is the reachability monitor as the dashboard uses it. It is an interface so the
// HTTP layer is tested without a network, and the monitor itself has no idea a dashboard exists.
type HealthChecker interface {
	Check(ctx context.Context, targets []monitor.Target) monitor.Round
	Health() map[string]inventory.Health
	View() []monitor.LinkView
	Transitions(limit int) []monitor.Transition
}

// Deps are the collaborators. Snapshot is required; the rest may be nil, and the endpoints that
// need a missing one say so rather than serving an empty view that looks like real state.
type Deps struct {
	Snapshot Snapshotter
	TTL      TTLManager
	Diag     DiagRunner
	Logs     LogsReader
	Health   HealthChecker

	// Now is injectable for tests. Defaults to time.Now.
	Now func() time.Time
}

// HealthConfig is the link-health probe's schedule, assembled from the application settings.
// Enabled false means the user turned the probe off; the page then says so instead of showing
// an empty table that looks like "nothing is known".
type HealthConfig struct {
	Enabled  bool
	Interval time.Duration
	Endpoint string
	Timeout  time.Duration
	Window   int
}

// Config is the dashboard's own settings, assembled by the command from the application
// settings file.
type Config struct {
	Version     string
	Listen      string
	Interval    time.Duration
	OutputDir   string
	StateDir    string
	SettingsDir string
	MaxJobs     int
	Health      HealthConfig
}

// Server is the running dashboard.
type Server struct {
	cfg  Config
	deps Deps
	now  func() time.Time

	token string
	mux   http.Handler

	ln  net.Listener
	srv *http.Server
	// addr is the real listen address once Start has run (Listen may have port 0).
	addr string

	baseCtx    context.Context
	baseCancel context.CancelFunc

	mu        sync.Mutex
	snap      *inventory.Snapshot
	snapAt    time.Time
	snapErr   string
	snapFails int

	jobs *jobStore
}

// New builds the server. It refuses a non-loopback listen address: the dashboard is part of the
// privacy story of the application, and a flag cannot be the thing that keeps it private.
func New(cfg Config, deps Deps) (*Server, error) {
	if deps.Snapshot == nil {
		return nil, errors.New("dashboard: a snapshot source is required")
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:0"
	}
	if !listenIsLoopback(cfg.Listen) {
		return nil, fmt.Errorf("dashboard: %q is not a loopback address; the dashboard is local-only by design", cfg.Listen)
	}
	if cfg.Interval <= 0 {
		cfg.Interval = defaultInterval
	}
	if cfg.MaxJobs <= 0 {
		cfg.MaxJobs = defaultMaxJobs
	}
	if cfg.OutputDir == "" {
		cfg.OutputDir = "outputs"
	}
	if cfg.SettingsDir == "" {
		cfg.SettingsDir = cfg.StateDir
	}
	if cfg.SettingsDir == "" {
		cfg.SettingsDir = state.DefaultDir()
	}
	if cfg.StateDir == "" {
		cfg.StateDir = state.DefaultDir()
	}
	if cfg.Health.Interval <= 0 {
		cfg.Health.Interval = defaultHealthInterval
	}
	now := deps.Now
	if now == nil {
		now = time.Now
	}
	token, err := newToken()
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:   cfg,
		deps:  deps,
		now:   now,
		token: token,
		jobs:  newJobStore(cfg.MaxJobs),
	}
	s.baseCtx, s.baseCancel = context.WithCancel(context.Background())
	s.mux = s.routes()
	return s, nil
}

// Token is the per-run access token. The command prints it (or opens the browser with it); the
// page is not reachable without it.
func (s *Server) Token() string { return s.token }

// Addr is the real listen address, valid after Start.
func (s *Server) Addr() string { return s.addr }

// URL is the address a browser should open, including the one-time token.
func (s *Server) URL() string {
	if s.addr == "" {
		return ""
	}
	host := s.addr
	if h, port, err := net.SplitHostPort(s.addr); err == nil {
		if h == "0.0.0.0" || h == "::" || h == "" {
			h = "127.0.0.1"
		}
		host = net.JoinHostPort(h, port)
	}
	return "http://" + host + "/?token=" + s.token
}

// Handler exposes the HTTP routes; tests mount it in an httptest server.
func (s *Server) Handler() http.Handler { return s.mux }

// Start binds the address, begins serving and starts the monitor loop. It returns the real
// listen address, which matters when the configured port is 0.
func (s *Server) Start() (string, error) {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return "", fmt.Errorf("dashboard: listening on %s: %w", s.cfg.Listen, err)
	}
	s.ln = ln
	s.addr = ln.Addr().String()
	s.srv = &http.Server{Handler: s.mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := s.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logx.Eventf(logx.LevelError, "dashboard.serve", "dashboard server stopped: %v", err)
		}
	}()
	go s.monitor()
	if s.cfg.Health.Enabled && s.deps.Health != nil {
		go s.healthLoop()
	}
	logx.Eventf(logx.LevelInfo, "dashboard.start", "dashboard listening on %s", s.addr)
	return s.addr, nil
}

// Close stops the monitor, cancels background jobs and shuts the server down.
func (s *Server) Close(ctx context.Context) error {
	s.baseCancel()
	s.jobs.cancelAll()
	if s.srv == nil {
		return nil
	}
	return s.srv.Shutdown(ctx)
}

// monitor refreshes the cached snapshot on the configured interval until Close.
func (s *Server) monitor() {
	t := time.NewTicker(s.cfg.Interval)
	defer t.Stop()
	// Take one snapshot immediately so the first page load has data.
	s.refresh(s.baseCtx)
	for {
		select {
		case <-s.baseCtx.Done():
			return
		case <-t.C:
			s.refresh(s.baseCtx)
		}
	}
}

// refresh takes one snapshot into the cache. A failure keeps the previous snapshot and records
// the error: a stale view plus an explicit error beats an empty page that looks like a network
// with no adapters.
func (s *Server) refresh(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	snap, err := s.deps.Snapshot.Snapshot(ctx)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapAt = s.now()
	if err != nil {
		s.snapErr = err.Error()
		s.snapFails++
		// Log the first failure and then sparsely; a dead collector at a 2s interval must not
		// fill the event ring with its own noise.
		if s.snapFails == 1 || s.snapFails%15 == 0 {
			logx.Eventf(logx.LevelWarn, "dashboard.snapshot", "adapter snapshot failed (%d times): %v", s.snapFails, err)
		}
		return
	}
	s.snap = snap
	s.snapErr = ""
	s.snapFails = 0
	s.applyHealthLocked()
}

// healthLoop probes link reachability on its own, slower schedule until Close. It is a separate
// loop because this is the most expensive thing the dashboard does and the snapshot loop must
// stay cheap: the page always has data, even while a probe is in flight.
func (s *Server) healthLoop() {
	t := time.NewTicker(s.cfg.Health.Interval)
	defer t.Stop()
	s.healthOnce(s.baseCtx)
	for {
		select {
		case <-s.baseCtx.Done():
			return
		case <-t.C:
			s.healthOnce(s.baseCtx)
		}
	}
}

// healthOnce runs one round of checks and folds the results in. It returns how many adapters
// were actually tested, so a caller (or a test) can tell "all reachable" from "nothing probed".
func (s *Server) healthOnce(ctx context.Context) int {
	if s.deps.Health == nil || !s.cfg.Health.Enabled {
		return 0
	}
	targets := healthTargets(s.cachedSnap())
	if len(targets) == 0 {
		return 0
	}
	round := s.deps.Health.Check(ctx, targets)
	s.mu.Lock()
	s.applyHealthLocked()
	s.mu.Unlock()
	for _, tr := range round.Transitions {
		s.logTransition(tr)
	}
	return len(round.Results)
}

// cachedSnap is the snapshot without the error state, for callers that only need the adapters.
func (s *Server) cachedSnap() *inventory.Snapshot {
	snap, _, _ := s.cached()
	return snap
}

// healthTargets picks the adapters worth probing: the ones that can carry traffic now. An
// excluded, disconnected or unhealthy adapter is not probed - the collector already explained
// why it is out, and a probe would only produce a failure that says "the cable is unplugged"
// in a worse way. An adapter the engine uses is probed like any other: the monitor observes,
// it does not need to be told what the engine decided.
func healthTargets(snap *inventory.Snapshot) []monitor.Target {
	if snap == nil {
		return nil
	}
	var out []monitor.Target
	for _, a := range snap.Adapters {
		if a.Status != inventory.StateActive && a.Status != inventory.StateEligible {
			continue
		}
		if a.Index == 0 {
			continue
		}
		t := monitor.Target{Name: a.Name, Index: a.Index, IP: firstUsable(a.IPv4), IP6: firstUsable(a.IPv6)}
		if t.IP == nil && t.IP6 == nil {
			continue
		}
		out = append(out, t)
	}
	return out
}

// firstUsable returns the first address that can actually reach a public endpoint: a link-local
// address cannot, and a tentative or duplicate one must not be used.
func firstUsable(addrs []inventory.Address) net.IP {
	for _, a := range addrs {
		if a.LinkLocal || a.Virtual {
			continue
		}
		switch a.Status {
		case "tentative", "duplicate", "deprecated":
			continue
		}
		if ip := net.ParseIP(a.Address); ip != nil {
			return ip
		}
	}
	return nil
}

// applyHealthLocked merges the monitor's most recent result per adapter into the cached
// snapshot. It is called both after a snapshot (so a fresh snapshot never loses the health it
// just had) and after a probe round (so a result shows up without waiting for the next
// snapshot). Callers hold s.mu.
func (s *Server) applyHealthLocked() {
	if s.deps.Health == nil || s.snap == nil {
		return
	}
	health := s.deps.Health.Health()
	for i := range s.snap.Adapters {
		a := &s.snap.Adapters[i]
		if h, ok := health[a.Name]; ok {
			hh := h
			a.Health = &hh
		} else {
			// No reading means no reading. Leaving a previous value would present an
			// observation from an unknown moment as the current state.
			a.Health = nil
		}
	}
}

// logTransition writes a state change to the event log. The first sighting of a reachable
// adapter is not logged: on every dashboard start that would be one line per adapter saying
// nothing happened. A first sighting that is a failure is logged, because that is a link that
// never came up.
func (s *Server) logTransition(tr monitor.Transition) {
	switch {
	case tr.To == monitor.StateReachable && tr.From == monitor.StateUnknown:
		return
	case tr.To == monitor.StateReachable:
		logx.Eventf(logx.LevelInfo, "link.reachability", "%s is reachable again (was %s): %s", tr.Name, tr.From, tr.Reason)
	default:
		logx.Eventf(logx.LevelWarn, "link.reachability", "%s is %s now (was %s): %s", tr.Name, tr.To, tr.From, tr.Reason)
	}
}

// cached returns the last snapshot and the error state around it.
func (s *Server) cached() (*inventory.Snapshot, time.Time, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snap, s.snapAt, s.snapErr
}

// ifaces lists the adapters the TTL manager should consider, from the cached snapshot. The
// snapshot's adapter indices are the same ones the manager writes against.
func (s *Server) ifaces() []ttlmgr.IfaceInfo {
	snap, _, _ := s.cached()
	if snap == nil {
		return nil
	}
	out := make([]ttlmgr.IfaceInfo, 0, len(snap.Adapters))
	for _, a := range snap.Adapters {
		if a.Index == 0 {
			continue
		}
		out = append(out, ttlmgr.IfaceInfo{Index: a.Index, Name: a.Name})
	}
	return out
}

// loadSettings reads the application settings, falling back to the defaults so every endpoint
// works on a first run before the file exists.
func (s *Server) loadSettings() (appcfg.Config, string, error) {
	cfg, _, err := appcfg.Load(s.cfg.SettingsDir)
	return cfg, appcfg.Path(s.cfg.SettingsDir), err
}

// engine reads the engine's status file, which is the same source `net-merge status` uses. It is
// deliberately not "is a process alive": the file is what the running engine publishes.
func (s *Server) engine() (*state.Status, bool) {
	st, on := state.Read(s.cfg.StateDir)
	if !on {
		return nil, false
	}
	return st, true
}

func newToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("dashboard: generating an access token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// listenIsLoopback reports whether a listen address is a loopback one (or a bare port, which
// Go's net.Listen interprets as all interfaces, so a bare ":1234" is rejected too).
func listenIsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// isLoopbackHost reports whether a Host header value names this machine's loopback interface.
// net.SplitHostPort handles the bracketed IPv6 form.
func isLoopbackHost(host string) bool {
	if host == "localhost" || host == "localhost." {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isLoopbackRemote(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	return isLoopbackHost(host)
}

// routes builds the mux and wraps it in the security middleware. Order matters: the Host and
// remote checks run before anything data-bearing is served, and the token before any handler.
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	page, err := fs.ReadFile(assetsFS, "assets/index.html")
	if err != nil {
		// A missing embedded asset is a build error, caught by TestEmbeddedAssetsAreComplete.
		panic("dashboard: embedded assets are incomplete: " + err.Error())
	}
	pageStr := string(page)

	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		html := strings.ReplaceAll(pageStr, tokenPlaceholder, s.token)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(html))
	})

	// Static assets are embedded; the same no-store policy applies to everything so a stale
	// page can never talk to a newer server.
	sub, err := fs.Sub(assetsFS, "assets")
	if err != nil {
		panic("dashboard: embedded assets are incomplete: " + err.Error())
	}
	static := http.FileServer(http.FS(sub))
	mux.Handle("GET /assets/", http.StripPrefix("/assets/", static))

	mux.HandleFunc("GET /api/state", s.handleState)
	mux.HandleFunc("POST /api/refresh", s.handleRefresh)
	mux.HandleFunc("GET /api/engine", s.handleEngineGet)
	mux.HandleFunc("POST /api/engine", s.handleEnginePost)
	mux.HandleFunc("GET /api/ttl", s.handleTTLGet)
	mux.HandleFunc("GET /api/ttl/history", s.handleTTLHistory)
	mux.HandleFunc("POST /api/ttl/config", s.handleTTLConfig)
	mux.HandleFunc("POST /api/ttl/apply", s.handleTTLApply)
	mux.HandleFunc("POST /api/ttl/restore", s.handleTTLRestore)
	mux.HandleFunc("GET /api/diag/checks", s.handleDiagChecks)
	mux.HandleFunc("POST /api/diag/run", s.handleDiagRun)
	mux.HandleFunc("GET /api/diag/runs", s.handleDiagRuns)
	mux.HandleFunc("GET /api/diag/runs/{id}", s.handleDiagRunGet)
	mux.HandleFunc("POST /api/diag/cancel", s.handleDiagCancel)
	mux.HandleFunc("POST /api/export", s.handleExportStart)
	mux.HandleFunc("GET /api/export/{id}", s.handleExportGet)
	mux.HandleFunc("POST /api/export/save", s.handleExportSave)
	mux.HandleFunc("GET /api/logs", s.handleLogs)
	mux.HandleFunc("GET /api/errcodes", s.handleErrorCodes)
	mux.HandleFunc("GET /api/settings", s.handleSettingsGet)
	mux.HandleFunc("PUT /api/settings", s.handleSettingsPut)

	return s.protect(mux)
}

// protect enforces the loopback Host, the loopback remote, and the token. Writes additionally
// require the header form of the token, which no cross-site request can set.
func (s *Server) protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")

		host := r.Host
		if h, _, err := net.SplitHostPort(r.Host); err == nil {
			host = h
		}
		if !isLoopbackHost(host) {
			fail(w, http.StatusForbidden, "dashboard_host_rejected",
				fmt.Sprintf("request Host %q is not a loopback name; the dashboard is reachable only as localhost", r.Host), nil)
			return
		}
		if !isLoopbackRemote(r.RemoteAddr) {
			fail(w, http.StatusForbidden, "dashboard_remote_rejected",
				"the dashboard only accepts connections from this machine", nil)
			return
		}

		// The one-time URL token: validated, converted into a cookie, and removed from the
		// address bar so it does not sit in browser history or get copied by accident.
		if tok := r.URL.Query().Get("token"); tok != "" {
			if !s.tokenMatches(tok) {
				fail(w, http.StatusUnauthorized, "dashboard_bad_token", "the dashboard token is not valid", nil)
				return
			}
			http.SetCookie(w, &http.Cookie{
				Name: cookieName, Value: s.token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode,
			})
			if r.Method == http.MethodGet {
				clean := *r.URL
				q := clean.Query()
				q.Del("token")
				clean.RawQuery = q.Encode()
				http.Redirect(w, r, clean.String(), http.StatusFound)
				return
			}
		}

		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			if !s.authorized(r, false) {
				fail(w, http.StatusUnauthorized, "dashboard_unauthorized",
					"open the dashboard with the link printed by `net-merge dashboard`, which carries the access token", nil)
				return
			}
		} else {
			// Mutations need the header: a browser will send the cookie cross-site under some
			// conditions, but it will not let another origin set this header.
			if !s.tokenMatches(r.Header.Get(TokenHeader)) {
				fail(w, http.StatusForbidden, "dashboard_unauthorized_write",
					"state-changing requests must carry the "+TokenHeader+" header", nil)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// authorized checks the read path: header or cookie.
func (s *Server) authorized(r *http.Request, _ bool) bool {
	if s.tokenMatches(r.Header.Get(TokenHeader)) {
		return true
	}
	c, err := r.Cookie(cookieName)
	return err == nil && s.tokenMatches(c.Value)
}

func (s *Server) tokenMatches(v string) bool {
	return v != "" && subtle.ConstantTimeCompare([]byte(v), []byte(s.token)) == 1
}

// --- response helpers -------------------------------------------------------------------------

// apiError is the error half of every response, shaped so the UI can show a code, a sentence,
// the details underneath, and - from the shared registry - what the code means and what to do
// about it. A code with no registered explanation is still shown; it is never invented.
type apiError struct {
	Code        string `json:"code"`
	Message     string `json:"message"`
	Details     any    `json:"details,omitempty"`
	Explanation string `json:"explanation,omitempty"`
	Fix         string `json:"fix,omitempty"`
}

type apiResponse struct {
	OK    bool      `json:"ok"`
	Data  any       `json:"data,omitempty"`
	Error *apiError `json:"error,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	writeJSONBody(w, apiResponse{OK: true, Data: data})
}

func fail(w http.ResponseWriter, status int, code, msg string, details any) {
	e := &apiError{Code: code, Message: msg, Details: details}
	if entry, ok := errcodes.Lookup(code); ok {
		e.Explanation = entry.Meaning
		e.Fix = entry.Fix
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	writeJSONBody(w, apiResponse{OK: false, Error: e})
}

func writeJSONBody(w http.ResponseWriter, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		// Never happens for the types used here; if it somehow does, a plain body is still better
		// than a truncated one.
		_, _ = w.Write([]byte(`{"ok":false,"error":{"code":"dashboard_encode_failed","message":"the response could not be encoded"}}`))
		return
	}
	_, _ = w.Write(b)
}

// decodeBody reads a JSON request body with a bound, so a runaway client cannot make the
// dashboard allocate without limit.
func decodeBody(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 4<<20))
	return dec.Decode(v)
}
