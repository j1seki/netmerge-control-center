package dashboard

// Tests for the dashboard's HTTP layer.
//
// Everything here is a simulation: a fake snapshot source, a fake TTL manager and a fake
// diagnostics registry are wired into the real server, and the real HTTP stack is exercised with
// httptest. No test touches a real adapter, a real TTL setting or a real command, and no result
// may be read as a measurement of a live network.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"net-merge/internal/appcfg"
	"net-merge/internal/diag"
	"net-merge/internal/diagreport"
	"net-merge/internal/errcodes"
	"net-merge/internal/inventory"
	"net-merge/internal/logx"
	"net-merge/internal/state"
	"net-merge/internal/ttlmgr"
)

// --- fakes ------------------------------------------------------------------------------------

type fakeSnap struct {
	mu    sync.Mutex
	snap  *inventory.Snapshot
	err   error
	delay time.Duration
	calls int
}

func (f *fakeSnap) Snapshot(ctx context.Context) (*inventory.Snapshot, error) {
	f.mu.Lock()
	f.calls++
	s, err, d := f.snap, f.err, f.delay
	f.mu.Unlock()
	if d > 0 {
		select {
		case <-time.After(d):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return s, err
}

func (f *fakeSnap) set(s *inventory.Snapshot, err error) {
	f.mu.Lock()
	f.snap, f.err = s, err
	f.mu.Unlock()
}

func snapshotWith() *inventory.Snapshot {
	return &inventory.Snapshot{
		Taken:  time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC),
		Source: "test-simulation",
		Adapters: []inventory.Adapter{{
			Name: "Ethernet", Index: 12, Kind: "ethernet", Status: "active", Link: "up",
			IPv4: []inventory.Address{{Address: "192.0.2.10", Prefix: 24, Origin: "dhcp"}},
			DNS4: []string{"8.8.8.8"}, Gateways4: []string{"192.0.2.1"},
			Counters: &inventory.Counters{In: 1000, Out: 2000},
			Rates:    &inventory.Rates{InPerSec: 125000, OutPerSec: 64000, Span: 2, At: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)},
		}},
		InPerSecTotal: 125000, OutPerSecTotal: 64000,
	}
}

type fakeTTL struct {
	mu       sync.Mutex
	report   ttlmgr.Report
	applyReq []ttlmgr.ApplyRequest
	resReq   []ttlmgr.RestoreRequest
	saved    []ttlmgr.Config
	history  []ttlmgr.Event
	err      error
}

func (f *fakeTTL) Inspect(context.Context, []ttlmgr.IfaceInfo) (ttlmgr.Report, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.report, f.err
}
func (f *fakeTTL) Apply(_ context.Context, req ttlmgr.ApplyRequest) (ttlmgr.Outcome, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return ttlmgr.Outcome{}, f.err
	}
	f.applyReq = append(f.applyReq, req)
	return ttlmgr.Outcome{Schema: "x", DryRun: req.DryRun, Applied: 1, Changes: []ttlmgr.Change{{
		Setting: ttlmgr.SettingRef{ID: ttlmgr.IDv4Default, Kind: ttlmgr.KindPacketTTL, Family: ttlmgr.FamilyIPv4, Scope: ttlmgr.ScopeSystemGlobal},
		To:      65, Outcome: "applied", Verified: !req.DryRun,
	}}}, nil
}
func (f *fakeTTL) Restore(_ context.Context, req ttlmgr.RestoreRequest) (ttlmgr.Outcome, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resReq = append(f.resReq, req)
	return ttlmgr.Outcome{Schema: "x", DryRun: req.DryRun, Applied: 0}, nil
}
func (f *fakeTTL) SaveConfig(c ttlmgr.Config) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.saved = append(f.saved, c)
	return nil
}
func (f *fakeTTL) History(int) ([]ttlmgr.Event, error) { return f.history, f.err }

func (f *fakeTTL) applied() []ttlmgr.ApplyRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]ttlmgr.ApplyRequest{}, f.applyReq...)
}

type fakeDiag struct {
	metas   []diag.Meta
	release chan struct{}
	result  diag.RunResult
	mu      sync.Mutex
	opts    []diag.Options
	calls   int
}

func (f *fakeDiag) Metas() []diag.Meta { return f.metas }
func (f *fakeDiag) RunAll(ctx context.Context, opts diag.Options) diag.RunResult {
	f.mu.Lock()
	f.calls++
	f.opts = append(f.opts, opts)
	f.mu.Unlock()
	if f.release != nil {
		select {
		case <-f.release:
		case <-ctx.Done():
			// A cancelled run returns the checks that had already finished, which is what the
			// real registry does: cancellation stops the run, it does not erase its evidence.
			return diag.RunResult{
				Summary: "cancelled after 1 of 2 checks",
				Results: []diag.Result{{
					ID: "platform.info", Title: "Platform", Category: "platform", Status: "info",
					Summary: "the check that finished before the cancel",
				}},
			}
		}
	}
	return f.result
}

type fakeLogs struct {
	events []logx.Event
}

func (f *fakeLogs) Events(since uint64, min logx.Level, limit int) ([]logx.Event, uint64) {
	out := []logx.Event{}
	var cursor uint64
	for _, e := range f.events {
		if e.Seq > cursor {
			cursor = e.Seq
		}
		if e.Seq <= since || e.Level < min {
			continue
		}
		out = append(out, e)
	}
	// Newest first, like the real ring.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, cursor
}

func (f *fakeLogs) Search(fl logx.Filter, limit int) []logx.Event {
	out := []logx.Event{}
	for _, e := range f.events {
		if e.Level < fl.Min {
			continue
		}
		if fl.Code != "" && !strings.Contains(e.Code, fl.Code) {
			continue
		}
		if fl.Query != "" && !strings.Contains(strings.ToLower(e.Message+" "+e.Detail), strings.ToLower(fl.Query)) {
			continue
		}
		out = append(out, e)
	}
	// newest first
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// --- test scaffolding -------------------------------------------------------------------------

type harness struct {
	t       *testing.T
	srv     *Server
	http    *httptest.Server
	token   string
	snap    *fakeSnap
	ttl     *fakeTTL
	diag    *fakeDiag
	logs    *fakeLogs
	health  *fakeHealth
	dir     string
	outDir  string
	stateIn string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	snap := &fakeSnap{snap: snapshotWith()}
	ttl := &fakeTTL{report: ttlmgr.Report{
		Schema:       "netmerge.ttlmgr.report/1",
		At:           time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC),
		Capabilities: ttlmgr.Capabilities{Platform: "linux", Supported: false, Notes: []string{"no mechanism on this test host"}},
		Config:       ttlmgr.Config{Schema: "netmerge-ttl/1", Version: 1},
		Elevated:     false, Elevation: "not elevated",
	}}
	dl := &fakeDiag{
		metas: []diag.Meta{{
			ID: "tcp.connect", Title: "TCP reachability", Category: "connectivity",
			Purpose:          "Check whether a TCP connection to the endpoint succeeds.",
			Establishes:      []string{"whether a TCP handshake to the endpoint completed"},
			DoesNotEstablish: []string{"that the route used the adapter you expected"},
		}},
		result: diag.RunResult{
			Started: time.Now(), Duration: 1200 * time.Millisecond,
			Summary: "1 checks: 1 fail",
			Results: []diag.Result{{
				ID: "tcp.connect", Title: "TCP reachability", Category: "connectivity", Status: "fail",
				Summary:     "the endpoint did not answer",
				Established: []string{"connecting to 203.0.113.9:443 timed out"},
				ErrorCodes:  []string{"diag_tcp_timeout"},
				Evidence: []diag.Evidence{{
					Label: "tcp dial", Started: true, Duration: 200 * time.Millisecond,
					Output: []string{"dial tcp 203.0.113.9:443: i/o timeout", "started from C:\\Users\\alex\\AppData\\Local\\net-merge"},
				}},
			}},
		},
	}
	lg := &fakeLogs{events: []logx.Event{
		{Seq: 1, At: time.Now(), Level: logx.LevelInfo, LevelID: "info", Code: "engine.start", Message: "engine started"},
		{Seq: 2, At: time.Now(), Level: logx.LevelWarn, LevelID: "warn", Code: "ttl.apply", Message: "TTL change requested"},
		{Seq: 3, At: time.Now(), Level: logx.LevelError, LevelID: "error", Code: "ttl.apply", Message: "write failed", Detail: "access denied"},
	}}
	hl := newFakeHealth()
	s, err := New(Config{
		Version: "test-version", Listen: "127.0.0.1:0", Interval: time.Hour,
		OutputDir: filepath.Join(dir, "outputs"), StateDir: filepath.Join(dir, "state"), SettingsDir: filepath.Join(dir, "cfg"),
		Health: HealthConfig{Enabled: true, Interval: 30 * time.Second, Endpoint: "203.0.113.9:443", Timeout: time.Second, Window: 4},
	}, Deps{Snapshot: snap, TTL: ttl, Diag: dl, Logs: lg, Health: hl})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h := &harness{t: t, srv: s, token: s.Token(), snap: snap, ttl: ttl, diag: dl, logs: lg, health: hl, dir: dir}
	h.outDir = filepath.Join(dir, "outputs")
	h.stateIn = filepath.Join(dir, "state")
	s.refresh(context.Background()) // one snapshot so the state endpoint has data
	h.http = httptest.NewServer(s.Handler())
	t.Cleanup(h.http.Close)
	return h
}

// call sends a request with the token as both cookie and header unless overridden.
func (h *harness) call(method, path string, body any, mutate ...func(*http.Request)) (*http.Response, []byte) {
	h.t.Helper()
	var rdr io.Reader
	if body != nil {
		switch b := body.(type) {
		case string:
			rdr = strings.NewReader(b)
		default:
			enc, err := json.Marshal(body)
			if err != nil {
				h.t.Fatal(err)
			}
			rdr = strings.NewReader(string(enc))
		}
	}
	req, err := http.NewRequest(method, h.http.URL+path, rdr)
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set(TokenHeader, h.token)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: h.token})
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, m := range mutate {
		m(req)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		h.t.Fatal(err)
	}
	return res, b
}

// data runs a request and unwraps the envelope's data field.
func (h *harness) data(method, path string, body any, mutate ...func(*http.Request)) (int, map[string]any) {
	h.t.Helper()
	res, b := h.call(method, path, body, mutate...)
	var env struct {
		OK    bool           `json:"ok"`
		Data  map[string]any `json:"data"`
		Error *apiError      `json:"error"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		h.t.Fatalf("%s %s: response is not JSON (%d): %.200s", method, path, res.StatusCode, b)
	}
	if res.StatusCode < 300 && !env.OK {
		h.t.Fatalf("%s %s: 2xx with ok=false: %s", method, path, b)
	}
	return res.StatusCode, env.Data
}

func (h *harness) errCode(method, path string, body any, mutate ...func(*http.Request)) (int, string) {
	h.t.Helper()
	res, b := h.call(method, path, body, mutate...)
	var env struct {
		OK    bool `json:"ok"`
		Error *apiError
	}
	if err := json.Unmarshal(b, &env); err != nil {
		h.t.Fatalf("%s %s: response is not JSON (%d): %.200s", method, path, res.StatusCode, b)
	}
	if env.Error == nil {
		h.t.Fatalf("%s %s: expected an error envelope, got: %.300s", method, path, b)
	}
	return res.StatusCode, env.Error.Code
}

// --- tests ------------------------------------------------------------------------------------

func TestNewRefusesNonLoopbackListen(t *testing.T) {
	cases := []string{"0.0.0.0:8765", ":8765", "192.168.1.5:8765", "[::]:8765", "not-an-address"}
	for _, addr := range cases {
		snap := &fakeSnap{}
		if _, err := New(Config{Listen: addr}, Deps{Snapshot: snap}); err == nil {
			t.Errorf("New accepted listen address %q; the dashboard must be loopback-only", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:0", "localhost:1234", "[::1]:1234", "127.5.6.7:99"} {
		snap := &fakeSnap{}
		if _, err := New(Config{Listen: addr}, Deps{Snapshot: snap}); err != nil {
			t.Errorf("New refused loopback address %q: %v", addr, err)
		}
	}
}

func TestSnapshotSourceIsRequired(t *testing.T) {
	if _, err := New(Config{Listen: "127.0.0.1:0"}, Deps{}); err == nil {
		t.Fatal("New accepted a nil snapshot source; every view would look like an empty network")
	}
}

func TestTokenGatesEverything(t *testing.T) {
	h := newHarness(t)

	// No token at all.
	if code, errCode := h.errCode("GET", "/", nil, func(r *http.Request) {
		r.Header.Del(TokenHeader)
		r.Header.Del("Cookie")
	}); code != http.StatusUnauthorized || errCode != "dashboard_unauthorized" {
		t.Errorf("unauthenticated GET / = %d/%s", code, errCode)
	}

	// Wrong token in the URL.
	if code, errCode := h.errCode("GET", "/?token=deadbeef", nil, func(r *http.Request) {
		r.Header.Del(TokenHeader)
		r.Header.Del("Cookie")
	}); code != http.StatusUnauthorized || errCode != "dashboard_bad_token" {
		t.Errorf("wrong URL token = %d/%s", code, errCode)
	}

	// The right token in the URL sets a cookie and redirects away from the token. A client that
	// does not follow redirects is used so the Set-Cookie on the redirect itself is visible.
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequest("GET", h.http.URL+"/?token="+h.token, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("GET /?token=... = %d, want a redirect", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); loc != "/" {
		t.Errorf("redirect Location = %q, want /", loc)
	}
	found := false
	for _, c := range res.Cookies() {
		if c.Name == cookieName && c.Value == h.token {
			found = true
			if !c.HttpOnly {
				t.Error("the session cookie must be HttpOnly")
			}
		}
	}
	if !found {
		t.Error("the URL token did not set the session cookie")
	}

	// The page itself is served, carries the seven sections and knows its token.
	_, body := h.call("GET", "/", nil)
	page := string(body)
	for _, section := range []string{"Overview", "Connections", "Routing", "TTL / Hop limit", "Diagnostics", "Logs", "Settings"} {
		if !strings.Contains(page, section) {
			t.Errorf("the dashboard page is missing the %q section", section)
		}
	}
	if !strings.Contains(page, "window.NETMERGE_TOKEN = \""+h.token+"\"") {
		t.Error("the page does not carry the session token for its own API calls")
	}
	if strings.Contains(page, tokenPlaceholder) {
		t.Error("the token placeholder was not substituted")
	}

	// Static assets are served too.
	res, _ = h.call("GET", "/assets/app.js", nil)
	if res.StatusCode != 200 {
		t.Errorf("GET /assets/app.js = %d", res.StatusCode)
	}
	// But an API read without the token is refused even though the page loads.
	if code, errCode := h.errCode("GET", "/api/state", nil, func(r *http.Request) {
		r.Header.Del(TokenHeader)
		r.Header.Del("Cookie")
	}); code != http.StatusUnauthorized || errCode != "dashboard_unauthorized" {
		t.Errorf("unauthenticated GET /api/state = %d/%s", code, errCode)
	}
}

func TestHostAndRemoteAreChecked(t *testing.T) {
	h := newHarness(t)
	// A Host header that is not a loopback name is the DNS-rebinding shape.
	code, errCode := h.errCode("GET", "/api/state", nil, func(r *http.Request) { r.Host = "evil.example.com" })
	if code != http.StatusForbidden || errCode != "dashboard_host_rejected" {
		t.Errorf("foreign Host = %d/%s", code, errCode)
	}
	if code, errCode := h.errCode("GET", "/api/state", nil, func(r *http.Request) { r.Host = "127.0.0.1.nip.io" }); code != http.StatusForbidden || errCode != "dashboard_host_rejected" {
		t.Errorf("rebinding host = %d/%s", code, errCode)
	}
}

func TestWritesRequireTheHeaderNotJustTheCookie(t *testing.T) {
	h := newHarness(t)
	code, errCode := h.errCode("POST", "/api/engine", map[string]any{"action": "off"}, func(r *http.Request) {
		r.Header.Del(TokenHeader) // cookie still present
	})
	if code != http.StatusForbidden || errCode != "dashboard_unauthorized_write" {
		t.Errorf("cookie-only write = %d/%s, want a refusal", code, errCode)
	}
}

func TestStateServesTheCachedSnapshotAndSurvivesAFailedRefresh(t *testing.T) {
	h := newHarness(t)
	code, data := h.data("GET", "/api/state", nil)
	if code != 200 {
		t.Fatalf("GET /api/state = %d", code)
	}
	if data["collecting"] == true {
		t.Error("the state endpoint reports collecting despite a successful snapshot")
	}
	snap, _ := data["snapshot"].(map[string]any)
	if snap == nil {
		t.Fatal("no snapshot in the state response")
	}
	adapters, _ := snap["adapters"].([]any)
	if len(adapters) != 1 {
		t.Fatalf("adapters = %v", snap["adapters"])
	}
	if snap["inPerSecTotal"].(float64) != 125000 {
		t.Errorf("aggregate rate = %v", snap["inPerSecTotal"])
	}

	// A failing collector keeps the previous view and says so.
	h.snap.set(nil, errors.New("adapter read exploded"))
	h.srv.refresh(context.Background())
	_, data = h.data("GET", "/api/state", nil)
	if data["collectError"] != "adapter read exploded" {
		t.Errorf("collectError = %v", data["collectError"])
	}
	if data["snapshot"] == nil {
		t.Error("a failed refresh discarded the last good snapshot")
	}
	if data["collecting"] == true {
		t.Error("collecting = true even though a snapshot is being served")
	}

	// Engine state comes from the engine's own status file.
	if data["engineOn"] != false {
		t.Error("engineOn = true with no status file")
	}
	if err := os.MkdirAll(h.stateIn, 0o755); err != nil {
		t.Fatal(err)
	}
	state.Write(h.stateIn, state.Status{PID: 4242, Mode: "system-wide", V6: "auto", Since: time.Now().Add(-time.Minute), Updated: time.Now()})
	_, data = h.data("GET", "/api/state", nil)
	if data["engineOn"] != true {
		t.Error("engineOn = false with a status file present")
	}
	eng, _ := data["engine"].(map[string]any)
	if eng == nil || eng["mode"] != "system-wide" {
		t.Errorf("engine view = %v", data["engine"])
	}
}

func TestRefreshEndpointTakesANewSnapshot(t *testing.T) {
	h := newHarness(t)
	h.snap.set(&inventory.Snapshot{Taken: time.Now(), Source: "test-simulation", Adapters: nil}, nil)
	code, data := h.data("POST", "/api/refresh", map[string]any{})
	if code != 200 {
		t.Fatalf("POST /api/refresh = %d", code)
	}
	if data["collecting"] == true {
		t.Error("refresh did not update the cache")
	}
}

func TestEngineControlUsesTheMarkerFiles(t *testing.T) {
	h := newHarness(t)
	if code, errCode := h.errCode("POST", "/api/engine", map[string]any{"action": "sideways"}); code != http.StatusBadRequest || errCode != "dashboard_bad_action" {
		t.Errorf("bad action = %d/%s", code, errCode)
	}
	code, _ := h.data("POST", "/api/engine", map[string]any{"action": "off"})
	if code != 200 {
		t.Fatalf("engine off = %d", code)
	}
	if _, err := os.Stat(filepath.Join(h.stateIn, "ctl", "off")); err != nil {
		t.Errorf("the off marker was not written where the engine looks for it: %v", err)
	}
	code, data := h.data("GET", "/api/engine", nil)
	if code != 200 || data["on"] != false {
		t.Errorf("engine view after off = %v", data)
	}
}

func TestDiagRunIsAsyncAndPollable(t *testing.T) {
	h := newHarness(t)
	h.diag.release = make(chan struct{})

	start := time.Now()
	code, data := h.data("POST", "/api/diag/run", map[string]any{"all": true})
	if code != http.StatusAccepted {
		t.Fatalf("run = %d", code)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("starting a run blocked for %s; it must return at once", elapsed)
	}
	id, _ := data["id"].(string)
	if id == "" || data["status"] != "running" {
		t.Fatalf("job view = %v", data)
	}

	// It is visibly running while it runs.
	_, data = h.data("GET", "/api/diag/runs/"+id, nil)
	if data["status"] != "running" {
		t.Fatalf("status while blocked = %v", data["status"])
	}

	close(h.diag.release)
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, data = h.data("GET", "/api/diag/runs/"+id, nil)
		if data["status"] != "running" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the diagnostics job did not finish")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if data["status"] != "done" {
		t.Fatalf("final status = %v (error %v)", data["status"], data["error"])
	}
	d, _ := data["diag"].(map[string]any)
	if d == nil {
		t.Fatalf("no diag payload: %v", data)
	}
	run, _ := d["result"].(map[string]any)
	if run == nil || run["summary"] != "1 checks: 1 fail" {
		t.Errorf("result = %v", d["result"])
	}
	results, _ := run["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("results = %v", run["results"])
	}
	first, _ := results[0].(map[string]any)
	if first["status"] != "fail" || first["summary"] != "the endpoint did not answer" {
		t.Errorf("result[0] = %v", first)
	}
	if est, _ := first["established"].([]any); len(est) != 1 {
		t.Errorf("established = %v", first["established"])
	}

	// The run is also in the list, and unknown ids are a clean 404.
	_, data = h.data("GET", "/api/diag/runs", nil)
	if runs, _ := data["runs"].([]any); len(runs) == 0 {
		t.Error("the finished run is not listed")
	}
	if code, errCode := h.errCode("GET", "/api/diag/runs/diag-999", nil); code != http.StatusNotFound || errCode != "dashboard_job_unknown" {
		t.Errorf("unknown job = %d/%s", code, errCode)
	}
}

func TestDiagRunRequiresASelection(t *testing.T) {
	h := newHarness(t)
	if code, errCode := h.errCode("POST", "/api/diag/run", map[string]any{}); code != http.StatusBadRequest || errCode != "dashboard_bad_request" {
		t.Errorf("empty selection = %d/%s", code, errCode)
	}
	_, data := h.data("POST", "/api/diag/run", map[string]any{"ids": []string{"tcp.connect"}})
	if data["status"] != "running" && data["status"] != "done" {
		t.Errorf("selected run = %v", data)
	}
	h.diag.mu.Lock()
	defer h.diag.mu.Unlock()
	if len(h.diag.opts) == 0 || len(h.diag.opts[0].Only) != 1 || h.diag.opts[0].Only[0] != "tcp.connect" {
		t.Errorf("the selection did not reach the registry: %+v", h.diag.opts)
	}
}

func TestDiagChecksListCarriesWhatEachCheckEstablishes(t *testing.T) {
	h := newHarness(t)
	code, data := h.data("GET", "/api/diag/checks", nil)
	if code != 200 {
		t.Fatalf("checks = %d", code)
	}
	checks, _ := data["checks"].([]any)
	if len(checks) != 1 {
		t.Fatalf("checks = %v", data["checks"])
	}
	m, _ := checks[0].(map[string]any)
	if m["id"] != "tcp.connect" {
		t.Errorf("check = %v", m)
	}
	if est, _ := m["establishes"].([]any); len(est) == 0 {
		t.Error("the check list must carry what each check establishes")
	}
	if dns, _ := m["doesNotEstablish"].([]any); len(dns) == 0 {
		t.Error("the check list must carry what each check does not establish")
	}
}

func TestTTLApplyNeedsAnExplicitConfirmAndDryRunDoesNot(t *testing.T) {
	h := newHarness(t)

	// A dry run needs no confirm.
	code, data := h.data("POST", "/api/ttl/apply", map[string]any{"dryRun": true})
	if code != 200 {
		t.Fatalf("dry run = %d (%v)", code, data)
	}
	if data["dryRun"] != true {
		t.Errorf("dry run outcome = %v", data)
	}
	reqs := h.ttl.applied()
	if len(reqs) != 1 || !reqs[0].DryRun || reqs[0].Confirm {
		t.Fatalf("manager saw %+v", reqs)
	}
	if ch := reqs[0].Ifaces; len(ch) != 1 || ch[0].Name != "Ethernet" {
		t.Errorf("the manager was given the wrong interfaces: %+v", ch)
	}

	// A real change without confirm is refused before the manager is reached.
	before := len(reqs)
	if code, errCode := h.errCode("POST", "/api/ttl/apply", map[string]any{}); code != http.StatusBadRequest || errCode != "dashboard_confirm_required" {
		t.Fatalf("unconfirmed apply = %d/%s", code, errCode)
	}
	if len(h.ttl.applied()) != before {
		t.Fatal("an unconfirmed apply reached the TTL manager")
	}

	// With confirm it goes through, and the manager's own per-change verification is what is
	// reported back.
	code, data = h.data("POST", "/api/ttl/apply", map[string]any{"confirm": true, "reason": "test"})
	if code != 200 || data["applied"].(float64) != 1 {
		t.Fatalf("confirmed apply = %d %v", code, data)
	}
	changes, _ := data["changes"].([]any)
	if len(changes) != 1 {
		t.Fatalf("changes = %v", data["changes"])
	}
	ch0, _ := changes[0].(map[string]any)
	if ch0["verified"] != true {
		t.Errorf("a verified write must come back verified: %v", ch0)
	}
}

func TestTTLInspectAndConfig(t *testing.T) {
	h := newHarness(t)
	code, data := h.data("GET", "/api/ttl", nil)
	if code != 200 {
		t.Fatalf("GET /api/ttl = %d", code)
	}
	if data["canWrite"] != false {
		t.Errorf("canWrite = %v for an unsupported host", data["canWrite"])
	}
	if _, ok := data["report"].(map[string]any); !ok {
		t.Fatalf("report = %v", data["report"])
	}

	// An invalid configuration is refused with the manager's own validator.
	bad := map[string]any{"schema": "netmerge-ttl/1", "version": 1, "enabled": true, "bumpIPv4": 999999, "bumpIPv6": 65, "interfacePolicy": "none"}
	if code, errCode := h.errCode("POST", "/api/ttl/config", bad); code != http.StatusBadRequest || errCode != "dashboard_ttl_config_invalid" {
		t.Errorf("invalid TTL config = %d/%s", code, errCode)
	}

	good := map[string]any{"schema": "netmerge-ttl/1", "version": 1, "enabled": true, "bumpIPv4": 65, "bumpIPv6": 65, "interfacePolicy": "none"}
	if code, _ := h.data("POST", "/api/ttl/config", good); code != 200 {
		t.Fatalf("valid TTL config = %d", code)
	}
	h.ttl.mu.Lock()
	defer h.ttl.mu.Unlock()
	if len(h.ttl.saved) != 1 || h.ttl.saved[0].BumpIPv4 != 65 || !h.ttl.saved[0].Enabled {
		t.Errorf("saved config = %+v", h.ttl.saved)
	}
}

func TestTTLRestoreCarriesTheSelectedSettings(t *testing.T) {
	h := newHarness(t)
	code, _ := h.data("POST", "/api/ttl/restore", map[string]any{"dryRun": true, "only": []string{string(ttlmgr.IDv4Default)}})
	if code != 200 {
		t.Fatalf("restore dry run = %d", code)
	}
	h.ttl.mu.Lock()
	defer h.ttl.mu.Unlock()
	if len(h.ttl.resReq) != 1 || len(h.ttl.resReq[0].Only) != 1 || h.ttl.resReq[0].Only[0] != ttlmgr.IDv4Default {
		t.Fatalf("restore request = %+v", h.ttl.resReq)
	}
}

func TestExportRendersRedactedArtifacts(t *testing.T) {
	h := newHarness(t)
	// Produce a diagnostics result first: the export includes the last completed run.
	_, runData := h.data("POST", "/api/diag/run", map[string]any{"all": true})
	runID, _ := runData["id"].(string)
	waitJob(t, h, "/api/diag/runs/"+runID)

	code, data := h.data("POST", "/api/export", map[string]any{})
	if code != http.StatusAccepted {
		t.Fatalf("export = %d", code)
	}
	id, _ := data["id"].(string)
	final := waitJob(t, h, "/api/export/"+id)
	if final["status"] != "done" {
		t.Fatalf("export status = %v (%v)", final["status"], final["error"])
	}
	e, _ := final["export"].(map[string]any)
	if e == nil {
		t.Fatalf("no export payload: %v", final)
	}
	text, _ := e["text"].(string)
	jsonText, _ := e["json"].(string)
	if text == "" || jsonText == "" {
		t.Fatal("the export produced empty artifacts")
	}

	// The public address and the account name from the simulated evidence must be gone from
	// both artifacts.
	for _, secret := range []string{"203.0.113.9", "alex", `C:\Users\alex`} {
		if strings.Contains(text, secret) {
			t.Errorf("the text report still contains %q", secret)
		}
		if strings.Contains(jsonText, secret) {
			t.Errorf("the JSON report still contains %q", secret)
		}
	}
	if !strings.Contains(text, "[ip#") {
		t.Error("the text report has no address placeholder; the redaction did not run")
	}
	if !json.Valid([]byte(jsonText)) {
		t.Error("the redacted JSON report is not valid JSON")
	}

	// The visibility mapping is returned to the UI and names the real value.
	entries, _ := e["redactionEntries"].([]any)
	if len(entries) == 0 {
		t.Fatal("no redaction entries were returned")
	}
	sawIP := false
	for _, raw := range entries {
		en, _ := raw.(map[string]any)
		if v, _ := en["value"].(string); strings.Contains(v, "203.0.113.9") {
			sawIP = true
			if p, _ := en["placeholder"].(string); p == "" {
				t.Error("an entry has no placeholder")
			}
		}
	}
	if !sawIP {
		t.Errorf("the mapping does not explain the replaced address: %v", entries)
	}
	counts, _ := e["redactionCounts"].(map[string]any)
	if counts == nil || counts["total"].(float64) == 0 {
		t.Errorf("redaction counts = %v", e["redactionCounts"])
	}

	// Saving writes the redacted bytes only.
	code, saved := h.data("POST", "/api/export/save", map[string]any{"id": id})
	if code != 200 {
		t.Fatalf("save = %d", code)
	}
	paths, _ := saved["saved"].([]any)
	if len(paths) != 2 {
		t.Fatalf("saved = %v", saved["saved"])
	}
	for _, p := range paths {
		b, err := os.ReadFile(p.(string))
		if err != nil {
			t.Fatalf("reading %s: %v", p, err)
		}
		if strings.Contains(string(b), "203.0.113.9") || strings.Contains(string(b), "alex") {
			t.Errorf("the saved file %s contains an unredacted value", p)
		}
		if strings.Contains(string(b), "redactionEntries") {
			t.Errorf("the saved file %s contains the visibility mapping", p)
		}
	}
	// And the job now reports where they went.
	after := waitJob(t, h, "/api/export/"+id)
	e2, _ := after["export"].(map[string]any)
	if got, _ := e2["saved"].([]any); len(got) != 2 {
		t.Errorf("the job does not report the saved paths: %v", e2["saved"])
	}
}

func TestExportWithoutADiagnosticsRunSaysSo(t *testing.T) {
	h := newHarness(t)
	_, data := h.data("POST", "/api/export", map[string]any{})
	id, _ := data["id"].(string)
	final := waitJob(t, h, "/api/export/"+id)
	e, _ := final["export"].(map[string]any)
	text, _ := e["text"].(string)
	if !strings.Contains(text, "no diagnostics run has been completed yet") {
		t.Errorf("an export with no run must say so; got:\n%.600s", text)
	}
}

func TestLogsCursorAndSearch(t *testing.T) {
	h := newHarness(t)
	_, data := h.data("GET", "/api/logs?since=0", nil)
	evs, _ := data["events"].([]any)
	if len(evs) != 3 {
		t.Fatalf("logs = %v", data["events"])
	}
	cursor := data["cursor"].(float64)
	if cursor != 3 {
		t.Errorf("cursor = %v", cursor)
	}
	_, data = h.data("GET", "/api/logs?since=2", nil)
	evs, _ = data["events"].([]any)
	if len(evs) != 1 {
		t.Fatalf("incremental logs = %v", data["events"])
	}
	first, _ := evs[0].(map[string]any)
	if first["message"] != "write failed" {
		t.Errorf("incremental read = %v", first)
	}
	// Search by text, and by level.
	_, data = h.data("GET", "/api/logs?q=access+denied", nil)
	if evs, _ := data["events"].([]any); len(evs) != 1 {
		t.Errorf("search = %v", data["events"])
	}
	_, data = h.data("GET", "/api/logs?level=error", nil)
	if evs, _ := data["events"].([]any); len(evs) != 1 {
		t.Errorf("level filter = %v", data["events"])
	}
	if code, errCode := h.errCode("GET", "/api/logs?level=loud", nil); code != http.StatusBadRequest || errCode != "dashboard_bad_level" {
		t.Errorf("bad level = %d/%s", code, errCode)
	}
}

func TestSettingsRoundTripAndValidation(t *testing.T) {
	h := newHarness(t)
	code, data := h.data("GET", "/api/settings", nil)
	if code != 200 {
		t.Fatalf("GET settings = %d", code)
	}
	cfg, _ := data["config"].(map[string]any)
	if cfg == nil {
		t.Fatal("no config in the settings response")
	}
	if data["existed"] != false {
		t.Error("existed = true before the first save")
	}

	// An invalid edit is refused with every problem listed.
	cfg["logging"].(map[string]any)["level"] = "loud"
	code, errCode := h.errCode("PUT", "/api/settings", cfg)
	if code != http.StatusBadRequest || errCode != "dashboard_settings_invalid" {
		t.Fatalf("invalid settings = %d/%s", code, errCode)
	}
	if _, err := os.Stat(appcfg.Path(filepath.Join(h.dir, "cfg"))); err == nil {
		t.Error("an invalid settings file was written")
	}

	// A valid edit round-trips.
	cfg["logging"].(map[string]any)["level"] = "debug"
	cfg["activeProfile"] = string(appcfg.ProfileGaming)
	if code, _ := h.data("PUT", "/api/settings", cfg); code != 200 {
		t.Fatalf("PUT settings = %d", code)
	}
	_, data = h.data("GET", "/api/settings", nil)
	cfg2, _ := data["config"].(map[string]any)
	if cfg2["activeProfile"] != string(appcfg.ProfileGaming) {
		t.Errorf("active profile = %v", cfg2["activeProfile"])
	}
	if cfg2["logging"].(map[string]any)["level"] != "debug" {
		t.Errorf("log level = %v", cfg2["logging"])
	}
	if data["existed"] != true {
		t.Error("existed = false after a save")
	}
}

func TestCancelAJob(t *testing.T) {
	h := newHarness(t)
	h.diag.release = make(chan struct{})
	_, data := h.data("POST", "/api/diag/run", map[string]any{"all": true})
	id, _ := data["id"].(string)
	code, data := h.data("POST", "/api/diag/cancel", map[string]any{"id": id})
	if code != 200 {
		t.Fatalf("cancel = %d", code)
	}
	if s, _ := data["status"].(string); s != "running" {
		// The job goroutine notices the cancelled context; either running or cancelled is
		// acceptable here, and the wait below pins the terminal state.
		t.Logf("status right after cancel: %s", s)
	}
	final := waitJob(t, h, "/api/diag/runs/"+id)
	if final["status"] != "cancelled" {
		t.Errorf("a cancelled job ended as %v", final["status"])
	}
	// The finished checks survive the cancellation: a stopped run must not look like a run that
	// found nothing, and the UI labels what it shows as the partial set.
	d, _ := final["diag"].(map[string]any)
	if d == nil {
		t.Fatalf("a cancelled run discarded its partial result: %v", final)
	}
	run, _ := d["result"].(map[string]any)
	results, _ := run["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("partial results = %v, want the one check that had finished", run["results"])
	}
	if first, _ := results[0].(map[string]any); first["id"] != "platform.info" {
		t.Errorf("partial result[0] = %v", results[0])
	}
}

func TestStartServesOnAnEphemeralPortWithATokenURL(t *testing.T) {
	snap := &fakeSnap{snap: snapshotWith()}
	s, err := New(Config{Listen: "127.0.0.1:0", Interval: 5 * time.Millisecond, OutputDir: filepath.Join(t.TempDir(), "o")},
		Deps{Snapshot: snap})
	if err != nil {
		t.Fatal(err)
	}
	addr, err := s.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close(context.Background())
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Fatalf("started on %q", addr)
	}
	url := s.URL()
	if !strings.HasPrefix(url, "http://127.0.0.1:") || !strings.Contains(url, "?token="+s.Token()) {
		t.Fatalf("URL = %q", url)
	}

	// A browser follows the token URL, keeps the cookie and then reads the page. A cookie jar
	// reproduces exactly that.
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar}
	deadline := time.Now().Add(2 * time.Second)
	for {
		res, err := client.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode == http.StatusUnauthorized {
			t.Fatal("the token URL was rejected")
		}
		if res.StatusCode == http.StatusOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("dashboard did not answer: %d", res.StatusCode)
		}
		time.Sleep(20 * time.Millisecond)
	}
	s.mu.Lock()
	got := s.snap
	s.mu.Unlock()
	if got == nil {
		t.Error("the monitor loop never stored a snapshot")
	}
}

func TestEmbeddedAssetsAndSectionIDs(t *testing.T) {
	for _, name := range []string{"assets/index.html", "assets/app.js", "assets/style.css"} {
		if _, err := assetsFS.ReadFile(name); err != nil {
			t.Errorf("embedded asset %s is missing: %v", name, err)
		}
	}
	page, _ := assetsFS.ReadFile("assets/index.html")
	for _, id := range []string{
		`id="view-overview"`, `id="view-connections"`, `id="view-routing"`, `id="view-ttl"`,
		`id="view-diag"`, `id="view-logs"`, `id="view-settings"`,
	} {
		if !strings.Contains(string(page), id) {
			t.Errorf("index.html has no %s section", id)
		}
	}
	js, _ := assetsFS.ReadFile("assets/app.js")
	if strings.Contains(string(js), ".innerHTML") {
		t.Error("app.js assigns innerHTML; the dashboard interpolates untrusted command output and must build nodes instead")
	}
}

func TestTTLUnavailableIsReportedNotFaked(t *testing.T) {
	dir := t.TempDir()
	s, err := New(Config{Listen: "127.0.0.1:0", OutputDir: dir, StateDir: dir, SettingsDir: dir}, Deps{Snapshot: &fakeSnap{snap: snapshotWith()}})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	req, _ := http.NewRequest("GET", ts.URL+"/api/ttl", nil)
	req.Header.Set(TokenHeader, s.Token())
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("GET /api/ttl without a manager = %d", res.StatusCode)
	}
	b, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(b), "dashboard_ttl_unavailable") {
		t.Errorf("body = %s", b)
	}
}

// waitJob polls a job endpoint until it leaves the running state.
func waitJob(t *testing.T, h *harness, path string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, data := h.data("GET", path, nil)
		if s, _ := data["status"].(string); s != "running" {
			return data
		}
		if time.Now().After(deadline) {
			t.Fatalf("job at %s did not finish", path)
		}
		time.Sleep(15 * time.Millisecond)
	}
}

var _ = diagreport.DefaultLimits // keep the import honest if the export test changes

// --- error-code explanations and stale settings ------------------------------------------------

// TestEveryFailCodeIsRegistered scans this package's own sources for every fail(...) call and
// checks the code it passes is in internal/errcodes. The scan is the test: a new error path that
// forgets its explanation fails here instead of reaching a user as a bare identifier.
func TestEveryFailCodeIsRegistered(t *testing.T) {
	re := regexp.MustCompile(`(?s)fail\(w,[^,]*?,\s*"([a-z0-9_]+)"`)
	found := map[string]bool{}
	for _, name := range []string{"api.go", "dashboard.go", "export.go", "jobs.go"} {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, m := range re.FindAllStringSubmatch(string(b), -1) {
			code := m[1]
			found[code] = true
			if entry, ok := errcodes.Lookup(code); !ok {
				t.Errorf("%s returns %q, which is not registered in internal/errcodes; add it there with a meaning and a next step", name, code)
			} else if entry.Meaning == "" {
				t.Errorf("%s returns %q, registered with no meaning", name, code)
			}
		}
	}
	// A floor, so a change to the call shape cannot silently turn the scan into a no-op.
	if len(found) < 15 {
		t.Errorf("the scan found only %d codes; it is probably no longer matching the fail(...) calls", len(found))
	}
}

func TestErrorCodesEndpointExplains(t *testing.T) {
	h := newHarness(t)
	code, data := h.data("GET", "/api/errcodes", nil)
	if code != 200 {
		t.Fatalf("GET /api/errcodes = %d", code)
	}
	rows, _ := data["codes"].([]any)
	if len(rows) < 50 {
		t.Fatalf("codes = %d rows, want the full registry", len(rows))
	}
	byCode := map[string]map[string]any{}
	for _, r := range rows {
		m, _ := r.(map[string]any)
		if m == nil {
			t.Fatalf("a registry row is not an object: %v", r)
		}
		byCode[m["code"].(string)] = m
	}
	// The codes the dashboard itself returns must be present with prose, and refusals must say
	// what to do next.
	for _, want := range []string{"dashboard_confirm_required", "dashboard_unauthorized", "dashboard_ttl_op_failed"} {
		m, ok := byCode[want]
		if !ok {
			t.Errorf("%s is missing from /api/errcodes", want)
			continue
		}
		if m["meaning"].(string) == "" {
			t.Errorf("%s has no meaning", want)
		}
		if m["fix"].(string) == "" {
			t.Errorf("%s has no suggested next step", want)
		}
	}
	if m, ok := byCode["dashboard_confirm_required"]; ok && m["kind"] != string(errcodes.KindSafety) {
		t.Errorf("dashboard_confirm_required kind = %v, want safety (it is a deliberate refusal, not a defect)", m["kind"])
	}
}

func TestAPIErrorsCarryTheirExplanation(t *testing.T) {
	h := newHarness(t)
	// The confirm gate is a real refusal the UI meets: apply without confirm.
	status, errCode := h.errCode("POST", "/api/ttl/apply", map[string]any{"dryRun": false, "confirm": false})
	if status != http.StatusBadRequest || errCode != "dashboard_confirm_required" {
		t.Fatalf("apply without confirm = %d %s", status, errCode)
	}
	_, b := h.call("POST", "/api/ttl/apply", map[string]any{"dryRun": false, "confirm": false})
	var env struct {
		Error *apiError
	}
	if err := json.Unmarshal(b, &env); err != nil || env.Error == nil {
		t.Fatalf("response is not an error envelope: %.200s", b)
	}
	if env.Error.Explanation == "" || env.Error.Fix == "" {
		t.Errorf("the refusal came back without its explanation: %+v", env.Error)
	}
	if !strings.Contains(env.Error.Explanation, "confirm") {
		t.Errorf("explanation does not read like prose about the refusal: %q", env.Error.Explanation)
	}
}

func TestStaleSettingsAreSurfaced(t *testing.T) {
	h := newHarness(t)
	// A file written by a newer build: schema and version valid, version above this build's.
	cfg := appcfg.Default()
	cfg.Version = appcfg.ConfigVersion + 1
	dir := filepath.Join(h.dir, "cfg")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(appcfg.Path(dir), b, 0o600); err != nil {
		t.Fatal(err)
	}

	code, data := h.data("GET", "/api/settings", nil)
	if code != 200 {
		t.Fatalf("GET /api/settings = %d", code)
	}
	if data["stale"] != true {
		t.Fatalf("a version-%d file was not reported as stale: %v", cfg.Version, data["stale"])
	}
	why, _ := data["staleReason"].(string)
	if !strings.Contains(why, "newer build") {
		t.Errorf("staleReason = %q, want it to explain a newer-build file", why)
	}
	if data["loadError"] != nil && data["loadError"] != "" {
		t.Errorf("a version-%d file is usable, not a load error: %v", cfg.Version, data["loadError"])
	}

	// A current file is not stale.
	cfg.Version = appcfg.ConfigVersion
	b, _ = json.Marshal(cfg)
	if err := os.WriteFile(appcfg.Path(dir), b, 0o600); err != nil {
		t.Fatal(err)
	}
	_, data = h.data("GET", "/api/settings", nil)
	if data["stale"] == true {
		t.Errorf("a current settings file was reported stale: %v", data["staleReason"])
	}
}

// TestAppJSSyntax parses the UI's JavaScript with a real runtime when one is on PATH. It skips
// (loudly) when there is none: the project must build on a machine without Node, but when Node
// is present a typo in the UI is caught here instead of surfacing as a blank page in a browser.
func TestAppJSSyntax(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed; skipping the optional JavaScript syntax check")
	}
	if out, err := exec.Command(node, "--check", "assets/app.js").CombinedOutput(); err != nil {
		t.Fatalf("node --check assets/app.js failed (%v):\n%s", err, out)
	}
}
