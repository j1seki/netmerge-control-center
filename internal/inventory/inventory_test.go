package inventory

// Tests for the inventory model, the eligibility rules and the collector.
//
// Everything in these tests is a SIMULATION: the adapters are handed to the collector through a
// fake Source, no operating-system interface is touched, and no traffic is generated. The
// simulations exist because the interesting cases - a phone that is plugged in but not sharing,
// an adapter with no gateway, two adapters with different DNS - are the ones a real machine
// cannot be asked to reproduce on demand.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeSource is a scripted Source. Its zero value is a machine with no adapters at all.
type fakeSource struct {
	name      string
	adapters  []Adapter
	routes    []Route
	counters  map[int]Counters
	gaps      []string
	routeGaps []string
	err       error
	routesErr error
}

func (f *fakeSource) Name() string {
	if f.name == "" {
		return "fake"
	}
	return f.name
}

func (f *fakeSource) Adapters(context.Context) ([]Adapter, []string, error) {
	return f.adapters, f.gaps, f.err
}

func (f *fakeSource) Routes(context.Context) ([]Route, []string, error) {
	return f.routes, f.routeGaps, f.routesErr
}

func (f *fakeSource) Counters(_ context.Context, index int) (Counters, bool) {
	c, ok := f.counters[index]
	return c, ok
}

// ethernet builds an eligible-looking wired adapter for tests to vary.
func ethernet(name string, index int) Adapter {
	return Adapter{
		Name:          name,
		Description:   "Intel(R) Ethernet Connection I219-V",
		Index:         index,
		Kind:          KindEthernet,
		Hardware:      true,
		Link:          LinkUp,
		Media:         "connected",
		Admin:         "up",
		SpeedBps:      1_000_000_000,
		MTU:           1500,
		MAC:           "aa:bb:cc:dd:ee:ff",
		IPv4:          []Address{{Address: "192.168.1.10", Prefix: 24, Origin: "dhcp"}},
		Gateways4:     []string{"192.168.1.1"},
		DefaultRoute4: true,
		DNS4:          []string{"192.168.1.1"},
		DHCP4:         TriYes,
		DHCP6:         TriNo,
		Metric4:       intPtrOf(25),
		MTU4:          intPtrOf(1500),
		IPv6:          []Address{{Address: "2001:db8::10", Prefix: 64, Origin: "router-advertisement"}},
		DefaultRoute6: true,
		Gateways6:     []string{"fe80::1"},
	}
}

// snapshotOf runs the collector over a scripted source.
func snapshotOf(t *testing.T, src Source, opts Options) *Snapshot {
	t.Helper()
	c := NewCollector(src)
	snap, err := c.Snapshot(context.Background(), opts)
	if err != nil {
		t.Fatalf("Snapshot returned an error: %v", err)
	}
	return snap
}

func findAdapter(t *testing.T, snap *Snapshot, name string) Adapter {
	t.Helper()
	a, ok := snap.ByName(name)
	if !ok {
		t.Fatalf("adapter %q not present in the snapshot (%d adapters)", name, len(snap.Adapters))
	}
	return a
}

// --- the discovery matrix the specification requires -------------------------------

func TestNoAdaptersAtAll(t *testing.T) {
	snap := snapshotOf(t, &fakeSource{}, Options{})
	if len(snap.Adapters) != 0 {
		t.Fatalf("got %d adapters, want none", len(snap.Adapters))
	}
	if got := snap.Summary(); !strings.Contains(got, "no network adapters") {
		t.Errorf("Summary() = %q, want it to say nothing was found", got)
	}
	if len(snap.Warnings) == 0 {
		t.Error("a machine with no adapters at all must warn that the list itself may have failed to read")
	}
	if len(snap.Usable()) != 0 || len(snap.Unusable()) != 0 {
		t.Error("with no adapters there is nothing usable or unusable")
	}
}

func TestOneAdapterIsEligible(t *testing.T) {
	src := &fakeSource{adapters: []Adapter{ethernet("Ethernet", 7)}}
	snap := snapshotOf(t, src, Options{})

	a := findAdapter(t, snap, "Ethernet")
	if a.Status != StateEligible {
		t.Errorf("status = %q, want %q (exclusion: %s)", a.Status, StateEligible, a.Exclusion)
	}
	if a.ExclusionCode != "" || a.Exclusion != "" {
		t.Errorf("an eligible adapter carries an exclusion: %q %q", a.ExclusionCode, a.Exclusion)
	}
	if got := snap.Summary(); !strings.Contains(got, "1 usable") {
		t.Errorf("Summary() = %q, want it to report one usable link", got)
	}
	if len(snap.Warnings) != 0 {
		t.Errorf("a single clean adapter produced warnings: %v", snap.Warnings)
	}
}

func TestMultipleAdaptersAreAllEligibleAndTheOverlapIsWarnedAbout(t *testing.T) {
	a, b := ethernet("Ethernet", 7), ethernet("Wi-Fi", 12)
	b.Kind, b.Description = KindWiFi, "Intel(R) Wi-Fi 6E AX211"
	b.SpeedBps = 600_000_000
	src := &fakeSource{adapters: []Adapter{a, b}}
	snap := snapshotOf(t, src, Options{})

	if len(snap.Usable()) != 2 {
		t.Fatalf("usable adapters = %d, want both", len(snap.Usable()))
	}
	joined := strings.Join(snap.Warnings, " | ")
	if !strings.Contains(joined, "default route") {
		t.Errorf("warnings = %v, want one about several default routes", snap.Warnings)
	}
	if snap.LinkSpeedTotalBps != 1_600_000_000 {
		t.Errorf("link speed total = %d, want the sum of the two adapters", snap.LinkSpeedTotalBps)
	}
}

func TestDisconnectedPhoneTetherIsReportedAsDisconnected(t *testing.T) {
	phone := Adapter{
		Name:        "Ethernet 3",
		Description: "Remote NDIS based Internet Sharing Device",
		Index:       21,
		Kind:        KindUSBTether,
		Hardware:    true,
		Link:        LinkDown,
		Media:       "disconnected",
		Admin:       "up",
		DHCP4:       TriUnknown,
		DHCP6:       TriUnknown,
	}
	snap := snapshotOf(t, &fakeSource{adapters: []Adapter{phone}}, Options{})

	a := findAdapter(t, snap, "Ethernet 3")
	if a.Status != StateDisconnected {
		t.Errorf("status = %q, want %q", a.Status, StateDisconnected)
	}
	if a.ExclusionCode != ExclLinkDown {
		t.Errorf("exclusion code = %q, want %q", a.ExclusionCode, ExclLinkDown)
	}
	if !strings.Contains(a.Exclusion, "disconnected") {
		t.Errorf("exclusion = %q, want it to explain the link is down", a.Exclusion)
	}
	if a.Kind != KindUSBTether {
		t.Errorf("kind = %q, want the tether classification so the UI can say 'phone'", a.Kind)
	}
	if len(snap.Unusable()) != 1 {
		t.Error("a disconnected adapter must show up in the unusable list")
	}
}

func TestAdapterWithoutDefaultGatewayIsExcludedWithThatReason(t *testing.T) {
	lan := ethernet("Ethernet 2", 9)
	lan.Gateways4, lan.DefaultRoute4 = nil, false
	lan.Gateways6, lan.DefaultRoute6 = nil, false
	snap := snapshotOf(t, &fakeSource{adapters: []Adapter{lan}}, Options{})

	a := findAdapter(t, snap, "Ethernet 2")
	if a.Status != StateExcluded || a.ExclusionCode != ExclNoGateway {
		t.Errorf("status = %q / code = %q, want excluded with %q", a.Status, a.ExclusionCode, ExclNoGateway)
	}
	if !strings.Contains(a.Exclusion, "default gateway") {
		t.Errorf("exclusion = %q, want it to name the missing gateway", a.Exclusion)
	}
}

func TestSeveralDefaultRoutesOnOneAdapterIsAWarningNotAnError(t *testing.T) {
	a := ethernet("Ethernet", 7)
	a.DefaultRoutes = []Route{
		{Family: "v4", Destination: "0.0.0.0/0", NextHop: "192.168.1.1", Default: true},
		{Family: "v4", Destination: "0.0.0.0/0", NextHop: "192.168.1.254", Default: true},
	}
	snap := snapshotOf(t, &fakeSource{adapters: []Adapter{a}}, Options{})

	got := findAdapter(t, snap, "Ethernet")
	if got.Status != StateEligible {
		t.Fatalf("status = %q, want still eligible", got.Status)
	}
	if !strings.Contains(strings.Join(got.Warnings, " | "), "2 default routes") {
		t.Errorf("warnings = %v, want one naming both default routes", got.Warnings)
	}
}

func TestMissingIPv4OrIPv6Configuration(t *testing.T) {
	v6only := ethernet("Ethernet 4", 11)
	v6only.IPv4 = nil
	v6only.Gateways4, v6only.DefaultRoute4, v6only.DNS4 = nil, false, nil
	v6only.MTU4 = nil
	v6only.Gaps = []string{"no IPv4 configuration on this adapter"}

	v4only := ethernet("Ethernet 5", 12)
	v4only.IPv6, v4only.Gateways6, v4only.DefaultRoute6 = nil, nil, false

	snap := snapshotOf(t, &fakeSource{adapters: []Adapter{v6only, v4only}}, Options{})

	for _, name := range []string{"Ethernet 4", "Ethernet 5"} {
		a := findAdapter(t, snap, name)
		if a.Status != StateEligible {
			t.Errorf("%s: status = %q, want eligible (one working family is enough)", name, a.Status)
		}
	}
	if a := findAdapter(t, snap, "Ethernet 4"); len(a.Gaps) == 0 {
		t.Error("an adapter with no IPv4 configuration must say so in its gaps")
	}
	if !strings.Contains(strings.Join(snap.Warnings, " | "), "split families") {
		t.Errorf("warnings = %v, want the split IPv4/IPv6 observation", snap.Warnings)
	}
}

func TestDifferingDNSServersAcrossAdaptersIsWarnedAbout(t *testing.T) {
	a, b := ethernet("Ethernet", 7), ethernet("Wi-Fi", 12)
	b.DNS4 = []string{"1.1.1.1", "8.8.8.8"}
	snap := snapshotOf(t, &fakeSource{adapters: []Adapter{a, b}}, Options{})

	if !strings.Contains(strings.Join(snap.Warnings, " | "), "different DNS servers") {
		t.Errorf("warnings = %v, want the differing-DNS observation", snap.Warnings)
	}
}

func TestIdenticalDNSAcrossAdaptersIsNotWarnedAbout(t *testing.T) {
	a, b := ethernet("Ethernet", 7), ethernet("Wi-Fi", 12)
	b.DNS4 = []string{"192.168.1.1"}
	snap := snapshotOf(t, &fakeSource{adapters: []Adapter{a, b}}, Options{})

	if strings.Contains(strings.Join(snap.Warnings, " | "), "different DNS servers") {
		t.Errorf("warnings = %v, want no DNS warning when every adapter agrees", snap.Warnings)
	}
}

func TestConnectedAdapterThatCannotReachTheInternetIsUnhealthy(t *testing.T) {
	dead := ethernet("Ethernet 6", 13)
	health := Health{
		Checked: true, OK: false, Endpoint: "1.1.1.1:443", Loss: 100,
		At: time.Now(), Detail: "no TCP handshake completed in 3 attempts",
	}
	snap := snapshotOf(t, &fakeSource{adapters: []Adapter{dead}}, Options{Health: map[string]Health{"Ethernet 6": health}})

	a := findAdapter(t, snap, "Ethernet 6")
	if a.Status != StateUnhealthy {
		t.Errorf("status = %q, want %q", a.Status, StateUnhealthy)
	}
	if a.ExclusionCode != ExclNoInternet {
		t.Errorf("exclusion code = %q, want %q", a.ExclusionCode, ExclNoInternet)
	}
	if !strings.Contains(a.Exclusion, "1.1.1.1:443") {
		t.Errorf("exclusion = %q, want it to name what could not be reached", a.Exclusion)
	}
	if a.Health == nil || a.Health.Detail == "" {
		t.Error("the health evidence must be kept on the adapter, not boiled down to a verdict")
	}
}

// --- the rest of the eligibility rules --------------------------------------------

func TestVirtualAdaptersAreExcludedWithTheReasonThatFired(t *testing.T) {
	cases := []struct{ name, desc string }{
		{"vEthernet (Default Switch)", "Hyper-V Virtual Ethernet Adapter"},
		{"net-merge", "Wintun Userspace Tunnel"},
		{"Ethernet 8", "TAP-Windows Adapter V9"},
	}
	for _, c := range cases {
		a := ethernet(c.name, 15)
		a.Description = c.desc
		a.Hardware = false
		a.VirtualReason = "virtual/VPN adapter (" + c.desc + ")"
		snap := snapshotOf(t, &fakeSource{adapters: []Adapter{a}}, Options{})
		got := findAdapter(t, snap, c.name)
		if got.Status != StateExcluded || got.ExclusionCode != ExclVirtual {
			t.Errorf("%s: status = %q code = %q, want excluded/%s", c.name, got.Status, got.ExclusionCode, ExclVirtual)
		}
		if !strings.Contains(got.Exclusion, "virtual") {
			t.Errorf("%s: exclusion = %q, want it to say the adapter is virtual", c.name, got.Exclusion)
		}
	}
}

func TestExplicitlyIncludedVirtualAdapterIsUsedWithAWarning(t *testing.T) {
	a := ethernet("net-merge", 16)
	a.Hardware = false
	a.VirtualReason = "looks like a virtual/VPN adapter (name)"
	snap := snapshotOf(t, &fakeSource{adapters: []Adapter{a}}, Options{Include: []string{"net-merge"}})

	got := findAdapter(t, snap, "net-merge")
	if got.Status != StateEligible {
		t.Fatalf("status = %q, want eligible: an explicit include list is the user's decision", got.Status)
	}
	if !strings.Contains(strings.Join(got.Warnings, " | "), "not real network hardware") {
		t.Errorf("warnings = %v, want the caveat that it is not real hardware", got.Warnings)
	}
}

func TestIncludeListExcludesEverythingNotNamed(t *testing.T) {
	snap := snapshotOf(t, &fakeSource{adapters: []Adapter{ethernet("Ethernet", 7), ethernet("Wi-Fi", 12)}},
		Options{Include: []string{"Ethernet"}})

	if got := findAdapter(t, snap, "Ethernet"); got.Status != StateEligible {
		t.Errorf("Ethernet status = %q, want eligible", got.Status)
	}
	if got := findAdapter(t, snap, "Wi-Fi"); got.Status != StateExcluded || got.ExclusionCode != ExclNotSelected {
		t.Errorf("Wi-Fi status = %q code = %q, want excluded by the include list", got.Status, got.ExclusionCode)
	}
}

func TestUserExclusionWinsOverEverythingElse(t *testing.T) {
	a := ethernet("Wi-Fi", 12)
	// Even a healthy adapter that the engine is using can be excluded by the profile; the
	// dashboard must show that conflict rather than hide it.
	snap := snapshotOf(t, &fakeSource{adapters: []Adapter{a}},
		Options{Exclude: []string{"Wi-Fi"}, EngineUsed: map[string]bool{"Wi-Fi": true}})

	got := findAdapter(t, snap, "Wi-Fi")
	if got.Status != StateExcluded || got.ExclusionCode != ExclUserExcluded {
		t.Errorf("status = %q code = %q, want excluded by the user", got.Status, got.ExclusionCode)
	}
	if !got.Engine {
		t.Error("the engine-usage flag must still be reported on an excluded adapter")
	}
}

func TestLinkLocalOnlyAddressIsItsOwnReason(t *testing.T) {
	a := ethernet("Ethernet 7", 17)
	a.IPv4 = []Address{{Address: "169.254.13.7", Prefix: 16, Origin: "wellknown", LinkLocal: true}}
	a.IPv6 = nil
	a.Gateways4, a.DefaultRoute4 = nil, false
	snap := snapshotOf(t, &fakeSource{adapters: []Adapter{a}}, Options{})

	got := findAdapter(t, snap, "Ethernet 7")
	if got.Status != StateExcluded || got.ExclusionCode != ExclLinkLocal {
		t.Errorf("status = %q code = %q, want %s", got.Status, got.ExclusionCode, ExclLinkLocal)
	}
	if !strings.Contains(got.Exclusion, "169.254") {
		t.Errorf("exclusion = %q, want it to name the link-local address", got.Exclusion)
	}
}

func TestDisabledAdapterIsExcludedAsDisabled(t *testing.T) {
	a := ethernet("Ethernet 8", 18)
	a.Link = LinkDisabled
	a.Admin = "down"
	snap := snapshotOf(t, &fakeSource{adapters: []Adapter{a}}, Options{})

	got := findAdapter(t, snap, "Ethernet 8")
	if got.Status != StateExcluded || got.ExclusionCode != ExclDisabled {
		t.Errorf("status = %q code = %q, want %s", got.Status, got.ExclusionCode, ExclDisabled)
	}
}

func TestTentativeAddressIsNotAUsablePath(t *testing.T) {
	a := ethernet("Ethernet 9", 19)
	a.IPv4 = nil
	a.Gateways4, a.DefaultRoute4 = nil, false
	a.IPv6 = []Address{{Address: "2001:db8::19", Prefix: 64, Status: "tentative", Origin: "router-advertisement"}}
	snap := snapshotOf(t, &fakeSource{adapters: []Adapter{a}}, Options{})

	got := findAdapter(t, snap, "Ethernet 9")
	if got.Status != StateExcluded {
		t.Fatalf("status = %q, want excluded while the address is still tentative", got.Status)
	}
	if got.ExclusionCode != ExclNoAddress && got.ExclusionCode != ExclLinkLocal {
		t.Errorf("exclusion code = %q, want a no-usable-address reason", got.ExclusionCode)
	}
}

func TestEngineUsageMakesAnEligibleAdapterActive(t *testing.T) {
	snap := snapshotOf(t, &fakeSource{adapters: []Adapter{ethernet("Ethernet", 7), ethernet("Wi-Fi", 12)}},
		Options{
			EngineUsed:     map[string]bool{"Ethernet": true},
			EngineAssigned: map[string]int{"Ethernet": 42},
		})

	active := findAdapter(t, snap, "Ethernet")
	if active.Status != StateActive {
		t.Errorf("status = %q, want %q for an adapter the engine uses", active.Status, StateActive)
	}
	if active.EngineAssigned == nil || *active.EngineAssigned != 42 {
		t.Errorf("assigned connections = %v, want 42", active.EngineAssigned)
	}
	idle := findAdapter(t, snap, "Wi-Fi")
	if idle.EngineAssigned != nil {
		t.Error("an adapter the engine does not report on must leave the count unknown, not zero")
	}
	if got := snap.Summary(); !strings.Contains(got, "1 carrying engine traffic") {
		t.Errorf("Summary() = %q, want it to report the carrying adapter", got)
	}
}

// --- collection behaviour ---------------------------------------------------------

func TestRoutesAreAttributedToTheirAdapter(t *testing.T) {
	a, b := ethernet("Ethernet", 7), ethernet("Wi-Fi", 12)
	src := &fakeSource{
		adapters: []Adapter{a, b},
		routes: []Route{
			{Family: "v4", Destination: "0.0.0.0/0", NextHop: "192.168.1.1", Index: 7, Metric: 25},
			{Family: "v4", Destination: "192.168.1.0/24", Index: 7},
			{Family: "v4", Destination: "0.0.0.0/0", NextHop: "10.0.0.1", Index: 12, Metric: 50},
			{Family: "v4", Destination: "10.9.9.0/24", Index: 99, Name: "VPN"},
		},
	}
	snap := snapshotOf(t, src, Options{})

	if got := findAdapter(t, snap, "Ethernet"); got.RouteCount != 2 || len(got.DefaultRoutes) != 1 {
		t.Errorf("Ethernet routes = %d (defaults %d), want 2 with one default", got.RouteCount, len(got.DefaultRoutes))
	}
	if got := findAdapter(t, snap, "Wi-Fi"); got.RouteCount != 1 {
		t.Errorf("Wi-Fi routes = %d, want 1", got.RouteCount)
	}
	// A route for an adapter that is no longer present stays in the snapshot's table: it is
	// evidence of a stale route, which is one of the things the diagnostics look for.
	if len(snap.Routes) != 4 {
		t.Errorf("snapshot routes = %d, want all 4 kept", len(snap.Routes))
	}
}

func TestCounterFailuresBecomeGapsNotZeroes(t *testing.T) {
	src := &fakeSource{
		adapters: []Adapter{ethernet("Ethernet", 7)},
		counters: map[int]Counters{},
	}
	snap := snapshotOf(t, src, Options{})
	got := findAdapter(t, snap, "Ethernet")
	if got.Counters != nil {
		t.Errorf("counters = %+v, want nil when they could not be read", got.Counters)
	}
	if !strings.Contains(strings.Join(got.Gaps, " | "), "byte counters unavailable") {
		t.Errorf("gaps = %v, want the counter gap recorded", got.Gaps)
	}
}

func TestAdapterListFailureIsAnErrorButRouteFailureIsNot(t *testing.T) {
	c := NewCollector(&fakeSource{err: errors.New("no interfaces")})
	if _, err := c.Snapshot(context.Background(), Options{}); err == nil {
		t.Error("a failure to list adapters must be reported as an error")
	}

	snap := snapshotOf(t, &fakeSource{
		adapters:  []Adapter{ethernet("Ethernet", 7)},
		routesErr: errors.New("routing table unreadable"),
	}, Options{})
	if len(snap.Errors) == 0 {
		t.Error("a routing-table failure must be recorded in the snapshot")
	}
	if len(snap.Adapters) != 1 {
		t.Error("a routing-table failure must not lose the adapters")
	}
}

func TestSnapshotIsSortedWithTheEngineCarryingAdapterFirst(t *testing.T) {
	// Listed worst-first on purpose: the snapshot must reorder them.
	a := ethernet("Wi-Fi", 12)
	b := ethernet("Ethernet", 7)
	c := ethernet("Ethernet 2", 9)
	c.Gateways4, c.DefaultRoute4 = nil, false
	src := &fakeSource{adapters: []Adapter{a, b, c}}
	snap := snapshotOf(t, src, Options{EngineUsed: map[string]bool{"Wi-Fi": true}})

	if snap.Adapters[0].Name != "Wi-Fi" {
		t.Errorf("first adapter = %q, want the engine's active link", snap.Adapters[0].Name)
	}
	if last := snap.Adapters[len(snap.Adapters)-1]; last.Name != "Ethernet 2" {
		t.Errorf("last adapter = %q, want the excluded one", last.Name)
	}
}

func TestSourceGapsFlowIntoTheSnapshot(t *testing.T) {
	src := &fakeSource{
		adapters: []Adapter{ethernet("Ethernet", 7)},
		gaps:     []string{"DHCP state is not exposed by the kernel on Linux"},
	}
	snap := snapshotOf(t, src, Options{})
	if !strings.Contains(strings.Join(snap.Gaps, " | "), "DHCP state") {
		t.Errorf("gaps = %v, want the source's own limitation", snap.Gaps)
	}
	if snap.Source != "fake" {
		t.Errorf("source = %q, want the source's name carried through", snap.Source)
	}
}
