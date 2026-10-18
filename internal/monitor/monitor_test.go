package monitor

// Tests for the reachability monitor. The network is entirely faked: a scripted dialer and
// resolver produce every outcome, so nothing here touches a real adapter, a real endpoint or a
// real clock. No assertion in this file is a measurement of a live network.

import (
	"context"
	"fmt"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"net-merge/internal/inventory"
)

type dialStep struct {
	rtt time.Duration
	err error
}

type fakeNet struct {
	mu         sync.Mutex
	script     map[int][]dialStep // per interface index, consumed in order; the last step repeats
	dialed     []int
	addrs      []net.IP
	resolveErr error
}

func (f *fakeNet) dial(_ context.Context, network, address string, _ net.IP, ifIndex int, _ bool) (time.Duration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dialed = append(f.dialed, ifIndex)
	steps := f.script[ifIndex]
	if len(steps) == 0 {
		return 10 * time.Millisecond, nil
	}
	s := steps[0]
	if len(steps) > 1 {
		f.script[ifIndex] = steps[1:]
	}
	return s.rtt, s.err
}

func (f *fakeNet) resolve(_ context.Context, _ string) ([]net.IP, error) {
	return f.addrs, f.resolveErr
}

func testClock(start time.Time) (func() time.Time, func(time.Duration)) {
	mu := sync.Mutex{}
	now := start
	return func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			return now
		}, func(d time.Duration) {
			mu.Lock()
			defer mu.Unlock()
			now = now.Add(d)
		}
}

func v4(s string) net.IP { return net.ParseIP(s).To4() }

func newFakeMonitor(t *testing.T, script map[int][]dialStep) (*Monitor, *fakeNet, func(time.Duration)) {
	t.Helper()
	now, advance := testClock(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	fake := &fakeNet{script: script, addrs: []net.IP{v4("203.0.113.7")}}
	m := New(Config{Endpoint: "203.0.113.7:443", Timeout: 3 * time.Second, Window: 4}, Deps{
		Now: now, Dial: fake.dial, Resolve: fake.resolve,
	})
	return m, fake, advance
}

func targets(names ...string) []Target {
	out := make([]Target, 0, len(names))
	for i, n := range names {
		out = append(out, Target{Name: n, Index: i + 1, IP: v4(fmt.Sprintf("192.0.2.%d", i+1))})
	}
	return out
}

// The three outcomes a real attempt can produce, classified honestly: success, silence, and a
// refusal (which is an answer - the packets reached a host).
func TestCheckClassifiesOutcomes(t *testing.T) {
	m, _, _ := newFakeMonitor(t, map[int][]dialStep{
		1: {{rtt: 12 * time.Millisecond}},
		2: {{rtt: 3 * time.Second, err: context.DeadlineExceeded}},
		3: {{rtt: 1 * time.Millisecond, err: syscall.ECONNREFUSED}},
	})
	round := m.Check(context.Background(), targets("ok", "silent", "refused"))

	ok := round.Results["ok"]
	if !ok.OK || ok.RTTms != 12 || ok.Detail != "" {
		t.Errorf("ok = %+v", ok)
	}
	if !ok.Checked || ok.Endpoint != "203.0.113.7:443" {
		t.Errorf("ok = %+v, want a checked result naming the endpoint", ok)
	}
	silent := round.Results["silent"]
	if silent.OK || silent.Detail == "" {
		t.Errorf("silent = %+v, want an unreachable result with a reason", silent)
	}
	refused := round.Results["refused"]
	if !refused.OK {
		t.Errorf("refused = %+v; a refusal proves the path answered", refused)
	}
	if refused.Detail == "" {
		t.Error("a refusal must carry its explanation, not look like a clean success")
	}
}

func TestLossAndJitterFromTheWindow(t *testing.T) {
	m, _, _ := newFakeMonitor(t, map[int][]dialStep{
		1: {{rtt: 10 * time.Millisecond}, {rtt: 20 * time.Millisecond}, {rtt: time.Second, err: context.DeadlineExceeded}},
	})
	tgt := targets("eth")
	m.Check(context.Background(), tgt)
	m.Check(context.Background(), tgt)
	round := m.Check(context.Background(), tgt)

	h := round.Results["eth"]
	if h.OK {
		t.Errorf("h = %+v, want the latest attempt to be a failure", h)
	}
	if got := h.Loss; got < 33 || got > 34 {
		t.Errorf("loss = %v, want ~33%% (1 of 3)", got)
	}
	if got := h.Jitter; got != 10 {
		t.Errorf("jitter = %v, want 10 ms (|20-10|)", got)
	}
	if h.RTTms != 0 {
		t.Errorf("rttMs = %v, want 0 on a failed latest attempt", h.RTTms)
	}
	// One sample is not a rate: before the second attempt there was no loss percentage.
	m2, _, _ := newFakeMonitor(t, map[int][]dialStep{1: {{rtt: 5 * time.Millisecond}}})
	if h2 := m2.Check(context.Background(), targets("e")).Results["e"]; h2.Loss != 0 {
		t.Errorf("loss with a single sample = %v, want 0", h2.Loss)
	}
}

// A failure is recorded as a transition, recovery is recorded as one, and the view reports the
// current state with the time it last changed.
func TestTransitionsAndRecovery(t *testing.T) {
	m, _, advance := newFakeMonitor(t, map[int][]dialStep{
		1: {{rtt: 10 * time.Millisecond}, {err: context.DeadlineExceeded}, {err: context.DeadlineExceeded}, {rtt: 11 * time.Millisecond}},
	})
	tgt := targets("eth")

	m.Check(context.Background(), tgt)
	advance(time.Second)
	m.Check(context.Background(), tgt)
	advance(time.Second)
	m.Check(context.Background(), tgt)
	advance(time.Second)
	m.Check(context.Background(), tgt)

	tr := m.Transitions(0)
	want := []struct{ from, to string }{
		{StateUnknown, StateReachable},
		{StateReachable, StateUnreachable},
		{StateUnreachable, StateReachable},
	}
	if len(tr) != len(want) {
		t.Fatalf("transitions = %+v, want %d", tr, len(want))
	}
	for i, w := range want {
		if tr[i].From != w.from || tr[i].To != w.to {
			t.Errorf("transition %d = %s -> %s, want %s -> %s", i, tr[i].From, tr[i].To, w.from, w.to)
		}
		if tr[i].Name != "eth" {
			t.Errorf("transition %d names %q", i, tr[i].Name)
		}
	}
	if tr[2].Reason == "" {
		t.Error("a recovery transition must say how it was established")
	}

	v := m.View()
	if len(v) != 1 || v[0].State != StateReachable || v[0].Changes != 3 {
		t.Fatalf("view = %+v, want reachable after 3 changes", v)
	}
}

// An adapter that disappears is reported absent with its stale reading dropped; when it comes
// back it starts from a fresh observation, not from the state it had before it was unplugged.
func TestAbsentAndReappearingAdapter(t *testing.T) {
	m, _, advance := newFakeMonitor(t, map[int][]dialStep{
		1: {{rtt: 10 * time.Millisecond}},
		2: {{err: context.DeadlineExceeded}, {rtt: 5 * time.Millisecond}},
	})
	both := append(targets("eth"), Target{Name: "phone", Index: 2, IP: v4("192.0.2.9")})
	ethOnly := targets("eth")

	m.Check(context.Background(), both) // the phone fails its first probe
	if h, ok := m.Health()["phone"]; !ok || h.OK {
		t.Fatalf("phone health = %+v, want a failed first reading", h)
	}

	advance(time.Second)
	round := m.Check(context.Background(), ethOnly)
	if len(round.Transitions) != 1 || round.Transitions[0].To != StateAbsent {
		t.Fatalf("transitions on disappearance = %+v", round.Transitions)
	}
	if _, ok := m.Health()["phone"]; ok {
		t.Error("health for a gone adapter must be dropped, not left as yesterday's reading")
	}
	views := map[string]LinkView{}
	for _, v := range m.View() {
		views[v.Name] = v
	}
	if views["phone"].State != StateAbsent {
		t.Errorf("phone state = %q, want absent", views["phone"].State)
	}

	advance(time.Second)
	round = m.Check(context.Background(), both) // the phone is back and answers
	last := round.Transitions[len(round.Transitions)-1]
	if last.Name != "phone" || last.From != StateAbsent || last.To != StateReachable {
		t.Fatalf("reappearance transition = %+v", last)
	}
	if h, ok := m.Health()["phone"]; !ok || !h.OK {
		t.Errorf("phone health after reappearance = %+v", h)
	}
}

// A round that verified nothing (endpoint not resolvable) reports every target as skipped and
// keeps the previous readings: losing DNS must not look like losing the links.
func TestUnresolvableEndpointKeepsPreviousReadings(t *testing.T) {
	now, _ := testClock(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	fake := &fakeNet{addrs: []net.IP{v4("203.0.113.7")}}
	m := New(Config{Endpoint: "probe.invalid:443", Timeout: time.Second, Window: 4}, Deps{
		Now: now, Dial: fake.dial, Resolve: fake.resolve,
	})
	tgt := targets("eth")
	m.Check(context.Background(), tgt)
	before := m.Health()["eth"]
	if !before.OK {
		t.Fatalf("first reading = %+v, want it to have succeeded", before)
	}

	fake.resolveErr = &net.DNSError{Err: "temporary failure", Name: "probe.invalid", IsTemporary: true}
	round := m.Check(context.Background(), tgt)
	if len(round.Results) != 0 {
		t.Errorf("results = %+v, want nothing when resolution failed", round.Results)
	}
	if len(round.Skipped) != 1 || round.Skipped[0].Reason == "" {
		t.Fatalf("skipped = %+v, want the adapter with the reason", round.Skipped)
	}
	if after := m.Health()["eth"]; after != before {
		t.Errorf("previous reading was replaced by %+v", after)
	}
}

// A target whose family the endpoint does not offer is skipped with a reason, not reported as a
// failure: nothing was tested, and the two must not look alike.
func TestNoCommonAddressFamilyIsSkipped(t *testing.T) {
	m, _, _ := newFakeMonitor(t, nil)
	v6only := []Target{{Name: "phone6", Index: 9, IP6: net.ParseIP("2001:db8::2")}}
	round := m.Check(context.Background(), v6only)
	if len(round.Skipped) != 1 || round.Skipped[0].Name != "phone6" {
		t.Fatalf("round = %+v, want a skip", round)
	}
	if len(round.Results) != 0 {
		t.Errorf("results = %+v, want none", round.Results)
	}
}

// The IPv6 path is used when that is all the adapter has, and the chosen address is the
// endpoint's IPv6 address.
func TestIPv6OnlyAdapterUsesV6(t *testing.T) {
	now, _ := testClock(time.Now())
	fake := &fakeNet{addrs: []net.IP{net.ParseIP("2001:db8::99")}}
	var gotNetwork, gotAddress string
	m := New(Config{Endpoint: "probe.invalid:443"}, Deps{
		Now: now, Resolve: fake.resolve,
		Dial: func(_ context.Context, network, address string, _ net.IP, _ int, v6 bool) (time.Duration, error) {
			gotNetwork, gotAddress = network, address
			if !v6 {
				t.Error("an IPv6-only adapter dialled with v6=false")
			}
			return time.Millisecond, nil
		},
	})
	round := m.Check(context.Background(), []Target{{Name: "p", Index: 3, IP6: net.ParseIP("2001:db8::2")}})
	if gotNetwork != "tcp6" {
		t.Fatalf("network = %q, want tcp6", gotNetwork)
	}
	if gotAddress != "[2001:db8::99]:443" {
		t.Errorf("address = %q", gotAddress)
	}
	if h := round.Results["p"]; !h.OK {
		t.Errorf("result = %+v", h)
	}
}

// Health() hands out a copy: a caller mutating it cannot change the monitor's state.
func TestHealthIsACopy(t *testing.T) {
	m, _, _ := newFakeMonitor(t, nil)
	m.Check(context.Background(), targets("eth"))
	h := m.Health()
	h["eth"] = inventory.Health{OK: false}
	h["injected"] = inventory.Health{}
	if got := m.Health()["eth"]; !got.OK {
		t.Error("Health() exposed the monitor's own map")
	}
	if _, ok := m.Health()["injected"]; ok {
		t.Error("Health() exposed the monitor's own map")
	}
}
