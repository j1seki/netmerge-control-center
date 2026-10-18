package dashboard

// Tests for the link-health wiring: that probe results reach the page, that state changes are
// logged with their reason, and that the engine's own per-adapter table is served in the shape
// the page reads. The monitor is faked throughout - no socket is opened and no adapter is read.

import (
	"context"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"net-merge/internal/engine"
	"net-merge/internal/inventory"
	"net-merge/internal/logx"
	"net-merge/internal/monitor"
	"net-merge/internal/state"
)

type fakeHealth struct {
	mu      sync.Mutex
	round   monitor.Round
	health  map[string]inventory.Health
	links   []monitor.LinkView
	trans   []monitor.Transition
	targets []monitor.Target
	calls   int
}

func newFakeHealth() *fakeHealth {
	return &fakeHealth{health: map[string]inventory.Health{}}
}

func (f *fakeHealth) Check(_ context.Context, targets []monitor.Target) monitor.Round {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.targets = append([]monitor.Target(nil), targets...)
	round := f.round
	for name, h := range round.Results {
		f.health[name] = h
	}
	f.trans = append(f.trans, round.Transitions...)
	for _, tr := range round.Transitions {
		f.links = upsertLink(f.links, tr)
	}
	return round
}

// upsertLink mirrors the real monitor's view maintenance for the faked one.
func upsertLink(links []monitor.LinkView, tr monitor.Transition) []monitor.LinkView {
	for i := range links {
		if links[i].Name == tr.Name {
			links[i].State = tr.To
			links[i].Changes++
			links[i].Since = tr.At
			return links
		}
	}
	return append(links, monitor.LinkView{Name: tr.Name, State: tr.To, Changes: 1, Since: tr.At})
}

func (f *fakeHealth) Health() map[string]inventory.Health {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]inventory.Health, len(f.health))
	for k, v := range f.health {
		out[k] = v
	}
	return out
}

func (f *fakeHealth) View() []monitor.LinkView {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]monitor.LinkView(nil), f.links...)
}

func (f *fakeHealth) Transitions(limit int) []monitor.Transition {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := len(f.trans)
	if limit > 0 && n > limit {
		n = limit
	}
	return append([]monitor.Transition(nil), f.trans[len(f.trans)-n:]...)
}

func (f *fakeHealth) setRound(r monitor.Round) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.round = r
}

func (f *fakeHealth) targetNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	names := make([]string, 0, len(f.targets))
	for _, t := range f.targets {
		names = append(names, t.Name)
	}
	return names
}

// A probe round must (a) test the adapters that can carry traffic, (b) land its result on the
// adapter in the state the page reads, and (c) describe itself, including when it is off.
func TestProbeResultsReachTheStateView(t *testing.T) {
	h := newHarness(t)
	at := time.Date(2026, 10, 18, 12, 30, 0, 0, time.UTC)
	h.health.setRound(monitor.Round{
		At: at,
		Results: map[string]inventory.Health{
			"Ethernet": {Checked: true, OK: true, RTTms: 12.5, Endpoint: "203.0.113.9:443", At: at},
		},
		Transitions: []monitor.Transition{{At: at, Name: "Ethernet", From: monitor.StateUnknown, To: monitor.StateReachable, Reason: "the probe succeeded"}},
	})

	if n := h.srv.healthOnce(context.Background()); n != 1 {
		t.Fatalf("healthOnce tested %d adapters, want 1", n)
	}
	if names := h.health.targetNames(); len(names) != 1 || names[0] != "Ethernet" {
		t.Fatalf("probe targets = %v, want the one active adapter", names)
	}

	_, data := h.data("GET", "/api/state", nil)
	snap, _ := data["snapshot"].(map[string]any)
	if snap == nil {
		t.Fatal("no snapshot in the state view")
	}
	adapters, _ := snap["adapters"].([]any)
	if len(adapters) == 0 {
		t.Fatal("no adapters in the snapshot")
	}
	adapter, _ := adapters[0].(map[string]any)
	health, _ := adapter["health"].(map[string]any)
	if health == nil {
		t.Fatalf("adapter carries no health: %v", adapter)
	}
	if health["ok"] != true || health["rttMs"] != 12.5 || health["endpoint"] != "203.0.113.9:443" {
		t.Errorf("health = %v, want the probe's result", health)
	}

	mon, _ := data["monitor"].(map[string]any)
	if mon == nil {
		t.Fatal("the state view has no monitor section")
	}
	if mon["enabled"] != true || mon["endpoint"] != "203.0.113.9:443" {
		t.Errorf("monitor = %v", mon)
	}
	links, _ := mon["links"].([]any)
	if len(links) != 1 {
		t.Fatalf("monitor links = %v", mon["links"])
	}
	link, _ := links[0].(map[string]any)
	if link["name"] != "Ethernet" || link["state"] != monitor.StateReachable {
		t.Errorf("link = %v", link)
	}
}

// A failure that follows a success is logged with the reason; a first sighting that is fine is
// not, because on every dashboard start that would be one line per adapter saying nothing
// happened. A first sighting that is broken IS logged.
func TestReachabilityTransitionsAreLogged(t *testing.T) {
	h := newHarness(t)
	at := time.Date(2026, 10, 18, 12, 31, 0, 0, time.UTC)
	h.health.setRound(monitor.Round{
		At: at,
		Results: map[string]inventory.Health{
			"Ethernet": {Checked: true, OK: false, Endpoint: "203.0.113.9:443", At: at, Detail: "no answer within 1s"},
		},
		Transitions: []monitor.Transition{
			{At: at, Name: "Ethernet", From: monitor.StateReachable, To: monitor.StateUnreachable, Reason: "the probe failed: no answer within 1s"},
			{At: at, Name: "Wi-Fi", From: monitor.StateUnknown, To: monitor.StateReachable, Reason: "the probe succeeded"},
		},
	})

	h.srv.healthOnce(context.Background())

	events := logx.Search(logx.Filter{Code: "link.reachability"}, 50)
	var sawDown, sawFirstSighting bool
	for _, e := range events {
		if !strings.Contains(e.Message, "Ethernet") {
			continue
		}
		if e.Level != logx.LevelWarn {
			t.Errorf("a link going down was logged at %v, want warn: %v", e.LevelID, e.Message)
		}
		if !strings.Contains(e.Message, "no answer within 1s") {
			t.Errorf("the event does not carry the reason: %q", e.Message)
		}
		sawDown = true
	}
	for _, e := range events {
		if strings.Contains(e.Message, "Wi-Fi") {
			sawFirstSighting = true
		}
	}
	if !sawDown {
		t.Error("no event was logged when a link stopped answering")
	}
	if sawFirstSighting {
		t.Error("a first sighting that is reachable was logged; that is noise on every start")
	}
}

// With the probe switched off the page must say so, and nothing may be probed.
func TestProbeOffIsStatedRatherThanEmpty(t *testing.T) {
	h := newHarness(t)
	h.srv.cfg.Health.Enabled = false
	if n := h.srv.healthOnce(context.Background()); n != 0 {
		t.Fatalf("healthOnce tested %d adapters with the probe off", n)
	}
	if h.health.calls != 0 {
		t.Fatalf("the probe was called %d times with it switched off", h.health.calls)
	}
	_, data := h.data("GET", "/api/state", nil)
	mon, _ := data["monitor"].(map[string]any)
	if mon == nil || mon["enabled"] != false {
		t.Fatalf("monitor = %v, want enabled=false", data["monitor"])
	}
	if _, ok := mon["links"]; ok {
		t.Errorf("a disabled probe still reported links: %v", mon)
	}
}

// The engine's status file has no JSON tags (it is a wire contract with the engine binary), so
// the API must project it into the lowercase shape the page reads. Without this the engine's
// per-adapter table rendered as "unknown" everywhere while the data was right there.
func TestEngineNICTableIsLowercase(t *testing.T) {
	h := newHarness(t)
	if err := os.MkdirAll(h.stateIn, 0o755); err != nil {
		t.Fatal(err)
	}
	state.Write(h.stateIn, state.Status{
		PID: 4242, Mode: "system-wide", V6: "auto", Since: time.Now().Add(-time.Minute), Updated: time.Now(),
		NICs: []engine.SlotStats{{
			Name: "Ethernet", IP: "192.0.2.10", State: "up", State6: "-",
			Weight: 3, Active: 5, Total: 5, Present: true,
			BytesIn: 1234, BytesOut: 5678, RateIn: 42.5, RateOut: 8.25, LinkIn: 1000, LinkOut: 1000,
		}},
	})

	_, data := h.data("GET", "/api/state", nil)
	eng, _ := data["engine"].(map[string]any)
	if eng == nil {
		t.Fatal("no engine section")
	}
	nics, _ := eng["nics"].([]any)
	if len(nics) != 1 {
		t.Fatalf("nics = %v", eng["nics"])
	}
	nic, _ := nics[0].(map[string]any)
	for _, key := range []string{"name", "state", "state6", "weight", "active", "total", "bytesIn", "rateIn"} {
		if _, ok := nic[key]; !ok {
			t.Errorf("engine NIC is missing %q: %v", key, nic)
		}
	}
	if _, ok := nic["Name"]; ok {
		t.Errorf("engine NIC leaked the Go field name: %v", nic)
	}
	if nic["state"] != "up" || nic["bytesIn"] != float64(1234) || nic["rateIn"] != 42.5 {
		t.Errorf("engine NIC values = %v", nic)
	}
}
