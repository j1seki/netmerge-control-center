package dashboard

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"net-merge/internal/inventory"
)

// fakePublicIP records what it was asked and returns scripted answers per interface index. It is
// a PublicIPProbe so the handler is exercised without opening a socket or contacting a network.
type fakePublicIP struct {
	mu        sync.Mutex
	endpoints []string
	answers   map[int]string
	errs      map[int]error
	calls     int
}

func (f *fakePublicIP) ResolvePublicIP(_ context.Context, endpoint string, index int, _ string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.endpoints = append(f.endpoints, endpoint)
	if err := f.errs[index]; err != nil {
		return "", err
	}
	if ip, ok := f.answers[index]; ok {
		return ip, nil
	}
	return "", context.Canceled
}

func (f *fakePublicIP) askedEndpoints() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.endpoints...)
}

// pubIPServer builds a server whose snapshot has the given adapters and whose probe is fake.
func pubIPServer(t *testing.T, adapters []inventory.Adapter, probe PublicIPProbe) *Server {
	t.Helper()
	dir := t.TempDir()
	snap := &inventory.Snapshot{Source: "test-simulation", Adapters: adapters}
	s, err := New(Config{
		Listen: "127.0.0.1:0", OutputDir: filepath.Join(dir, "o"),
		StateDir: filepath.Join(dir, "s"), SettingsDir: filepath.Join(dir, "c"),
	}, Deps{Snapshot: &fakeSnap{snap: snap}, PublicIP: probe})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.refresh(context.Background()) // one snapshot so the handler has adapters to offer
	return s
}

// eligibleAdapters is a two-uplink inventory: one active, one eligible, plus a down adapter and a
// virtual one that must both be skipped rather than asked.
func eligibleAdapters() []inventory.Adapter {
	return []inventory.Adapter{
		{Name: "eth0", Index: 2, Status: inventory.StateActive, Kind: inventory.KindEthernet},
		{Name: "wlan0", Index: 7, Status: inventory.StateEligible, Kind: inventory.KindWiFi},
		{Name: "down0", Index: 9, Status: inventory.StateDisconnected, Kind: inventory.KindEthernet},
		{Name: "veth0", Index: 0, Status: inventory.StateEligible, Kind: inventory.KindVirtual},
	}
}

func postPublicIP(t *testing.T, s *Server) (int, publicIPCheckResponse) {
	t.Helper()
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/uplinks/publicip", nil)
	req.Header.Set(TokenHeader, s.Token())
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	var out publicIPCheckResponse
	if res.StatusCode == http.StatusOK {
		var env struct {
			OK   bool                  `json:"ok"`
			Data publicIPCheckResponse `json:"data"`
		}
		if err := json.Unmarshal(body, &env); err != nil {
			t.Fatalf("decode %s: %v", body, err)
		}
		out = env.Data
	}
	return res.StatusCode, out
}

// TestPublicIPCheckResolvesEachUplink pins that every eligible uplink is asked, one result is
// returned per uplink with its public IP, and the endpoint is disclosed in the response.
func TestPublicIPCheckResolvesEachUplink(t *testing.T) {
	probe := &fakePublicIP{answers: map[int]string{2: "203.0.113.10", 7: "198.51.100.20"}}
	s := pubIPServer(t, eligibleAdapters(), probe)

	status, out := postPublicIP(t, s)
	if status != http.StatusOK {
		t.Fatalf("POST /api/uplinks/publicip = %d", status)
	}
	if out.Endpoint != DefaultPublicIPEcho {
		t.Errorf("endpoint = %q, want the disclosed default %q", out.Endpoint, DefaultPublicIPEcho)
	}
	if len(out.Results) != 2 {
		t.Fatalf("results = %d, want 2 (only the active and eligible uplinks)", len(out.Results))
	}
	byName := map[string]PublicIPResult{}
	for _, r := range out.Results {
		byName[r.Name] = r
	}
	if got := byName["eth0"].IP; got != "203.0.113.10" {
		t.Errorf("eth0 IP = %q, want 203.0.113.10", got)
	}
	if got := byName["wlan0"].IP; got != "198.51.100.20" {
		t.Errorf("wlan0 IP = %q, want 198.51.100.20", got)
	}
	// The down and virtual adapters are skipped, not silently dropped.
	if len(out.Skipped) != 2 {
		t.Errorf("skipped = %v, want down0 and veth0", out.Skipped)
	}
	// Every eligible uplink was asked exactly once, over the disclosed endpoint.
	eps := probe.askedEndpoints()
	if len(eps) != 2 {
		t.Errorf("probe calls = %d, want 2", len(eps))
	}
	for _, e := range eps {
		if e != DefaultPublicIPEcho {
			t.Errorf("probe was asked over %q, want the disclosed default", e)
		}
	}
}

// TestPublicIPCheckReportsPerUplinkFailure pins that a dead uplink yields an honest error for that
// row while the other uplink's value still arrives — one failure never hides the rest.
func TestPublicIPCheckReportsPerUplinkFailure(t *testing.T) {
	probe := &fakePublicIP{
		answers: map[int]string{2: "203.0.113.10"},
		errs:    map[int]error{7: errFake("no route to host over wlan0")},
	}
	s := pubIPServer(t, eligibleAdapters(), probe)

	status, out := postPublicIP(t, s)
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	byName := map[string]PublicIPResult{}
	for _, r := range out.Results {
		byName[r.Name] = r
	}
	if byName["eth0"].IP != "203.0.113.10" || byName["eth0"].Error != "" {
		t.Errorf("eth0 = %+v, want a clean IP and no error", byName["eth0"])
	}
	if byName["wlan0"].Error == "" || byName["wlan0"].IP != "" {
		t.Errorf("wlan0 = %+v, want an honest error and no IP", byName["wlan0"])
	}
}

// TestPublicIPCheckWithoutProbeIsUnavailable pins that a context without the resolver reports its
// absence rather than an empty list that would read as "no public IPs exist".
func TestPublicIPCheckWithoutProbeIsUnavailable(t *testing.T) {
	dir := t.TempDir()
	snap := &inventory.Snapshot{Source: "test-simulation", Adapters: eligibleAdapters()}
	s, err := New(Config{
		Listen: "127.0.0.1:0", OutputDir: filepath.Join(dir, "o"),
		StateDir: filepath.Join(dir, "s"), SettingsDir: filepath.Join(dir, "c"),
	}, Deps{Snapshot: &fakeSnap{snap: snap}}) // no PublicIP probe
	if err != nil {
		t.Fatal(err)
	}
	s.refresh(context.Background())
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/uplinks/publicip", nil)
	req.Header.Set(TokenHeader, s.Token())
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", res.StatusCode)
	}
	body, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(body), "dashboard_publicip_unavailable") {
		t.Errorf("body = %s", body)
	}
}

// errFake is a minimal error type for scripting a probe failure.
type errFake string

func (e errFake) Error() string { return string(e) }
