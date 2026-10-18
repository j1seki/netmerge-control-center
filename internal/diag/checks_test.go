package diag

// Behaviour tests for individual checks. Every one of these runs the real check logic against
// simulated inputs: a fake command runner replaying recorded output, and a fake prober
// answering from a table. Nothing here contacts a network or a Windows host, and no test
// result may be read as a measurement of a real link.

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"net-merge/internal/engine"
	"net-merge/internal/inventory"
	"net-merge/internal/state"
)

// runOne is the shorthand these tests use: build a registry around the prepared env and run a
// single check by id.
func runOne(t *testing.T, env *Env, id string) Result {
	t.Helper()
	reg := NewRegistry(env)
	res, ok := reg.RunOne(context.Background(), id)
	if !ok {
		t.Fatalf("check %q is not registered", id)
	}
	return res
}

// TestConnectOutcomes pins the classification that makes the TCP check useful: a refusal and a
// timeout mean different things, and a local unreachable is reported before any packet leaves.
func TestConnectOutcomes(t *testing.T) {
	cases := []struct {
		name       string
		connErr    error
		wantStatus Status
		wantCode   string
	}{
		{"success", nil, StatusPass, ""},
		{"timeout", timeoutError{}, StatusFail, "diag_tcp_timeout"},
		{"refused", refusedError("93.184.216.34:443"), StatusWarn, "diag_tcp_refused"},
		{"no route", unroutableError{}, StatusFail, "diag_no_route"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env, _, p := testEnv("linux")
			p.lookupFn = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("93.184.216.34")}, nil }
			p.connectFn = func(string, net.IP) (time.Duration, error) { return 12 * time.Millisecond, c.connErr }
			res := runOne(t, env, "ipv4.connect")
			if res.Status != c.wantStatus {
				t.Fatalf("status = %s, want %s (summary: %s)", res.Status, c.wantStatus, res.Summary)
			}
			if c.wantCode != "" && !hasCode(res, c.wantCode) {
				t.Errorf("codes %v do not include %s", res.ErrorCodes, c.wantCode)
			}
			if len(res.Evidence) == 0 || !res.Evidence[0].Started {
				t.Error("the probe left no evidence")
			}
			if c.name == "success" && res.Measure == nil {
				t.Error("a successful probe recorded no measurement")
			}
			if c.name == "timeout" {
				// The over-reading this must prevent: a timeout says nothing about the far
				// end, only that nothing answered.
				if len(res.Inconclusive) == 0 {
					t.Error("a timeout result does not state what it failed to establish")
				}
			}
		})
	}
}

// TestConnectSkipsWhenTheFamilyIsAbsent checks the split-family case: asking for IPv6 against a
// v4-only name is a skip with an explanation, not a failure.
func TestConnectSkipsWhenTheFamilyIsAbsent(t *testing.T) {
	env, _, p := testEnv("linux")
	env.Config.Endpoint = "v4only.example.test:443"
	p.lookupFn = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("93.184.216.34")}, nil }
	res := runOne(t, env, "ipv6.connect")
	if res.Status != StatusSkipped {
		t.Fatalf("status = %s, want skipped (summary: %s)", res.Status, res.Summary)
	}
	if len(res.Established) == 0 || !strings.Contains(res.Established[0], "without a ipv6") {
		t.Errorf("the skip does not explain itself: %v", res.Established)
	}
}

// TestConnectReportsUnresolvedEndpoint covers a mistyped endpoint in settings: the check fails
// with the resolver's own words rather than a generic connect error.
func TestConnectReportsUnresolvedEndpoint(t *testing.T) {
	env, _, _ := testEnv("linux")
	env.Config.Endpoint = "no-such-host.example.test:443"
	res := runOne(t, env, "ipv4.connect")
	if res.Status != StatusFail || !hasCode(res, "diag_endpoint_unresolved") {
		t.Fatalf("status = %s, codes = %v", res.Status, res.ErrorCodes)
	}
	if !strings.Contains(res.Summary, "no-such-host.example.test") {
		t.Errorf("the summary does not name the endpoint: %s", res.Summary)
	}
}

// TestAdapterConnectBindsEveryEligibleAddress is the load-bearing test for per-adapter
// verification: each eligible adapter must be probed from its own address, and the check must
// report per-adapter outcomes rather than one aggregate.
func TestAdapterConnectBindsEveryEligibleAddress(t *testing.T) {
	env, _, p := testEnv("linux")
	p.lookupFn = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("93.184.216.34")}, nil }
	p.connectFn = func(addr string, local net.IP) (time.Duration, error) {
		if local.String() == "10.0.0.9" {
			return 30 * time.Millisecond, timeoutError{}
		}
		return 8 * time.Millisecond, nil
	}
	env.SnapshotValue = snap([]inventory.Adapter{
		adapter("eth0", 2, "10.0.0.5"),
		adapter("wlan0", 3, "10.0.0.9"),
		adapter("docker0", 4, "172.17.0.1", withState(inventory.StateExcluded, inventory.ExclVirtual)),
	})
	res := runOne(t, env, "adapters.connect")

	if len(p.connects) != 2 {
		t.Fatalf("probed %d adapter(s): %+v", len(p.connects), p.connects)
	}
	locals := []string{p.connects[0].Local, p.connects[1].Local}
	for _, want := range []string{"10.0.0.5", "10.0.0.9"} {
		if !containsString(locals, want) {
			t.Errorf("no probe was bound to %s (probes: %+v)", want, locals)
		}
	}
	if res.Status != StatusWarn {
		t.Fatalf("status = %s, want warn (one of two links failed)", res.Status)
	}
	if !strings.Contains(strings.Join(res.Established, "\n"), "wlan0") {
		t.Errorf("the failing adapter is not named: %v", res.Established)
	}
	if strings.Contains(strings.Join(res.Established, "\n"), "docker0") {
		t.Errorf("an excluded adapter was probed: %v", res.Established)
	}
}

// TestDNSResolveDistinguishesOutcomes checks that NXDOMAIN, a timeout and a reserved-range
// answer are reported as three different findings.
func TestDNSResolveDistinguishesOutcomes(t *testing.T) {
	t.Run("nxdomain", func(t *testing.T) {
		env, _, p := testEnv("linux")
		p.lookupFn = func(name string) ([]net.IP, error) {
			return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
		}
		res := runOne(t, env, "dns.resolve")
		if res.Status != StatusFail {
			t.Fatalf("status = %s, want fail", res.Status)
		}
		if !strings.Contains(strings.Join(res.Established, "\n"), "NXDOMAIN") {
			t.Errorf("the result does not say the server answered: %v", res.Established)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		env, _, p := testEnv("linux")
		p.lookupFn = func(name string) ([]net.IP, error) {
			return nil, &net.DNSError{Err: "i/o timeout", Name: name, IsTimeout: true}
		}
		res := runOne(t, env, "dns.resolve")
		if !hasCode(res, "diag_dns_timeout") {
			t.Errorf("a DNS timeout was not given its own code: %v", res.ErrorCodes)
		}
	})
	t.Run("reserved answer", func(t *testing.T) {
		env, _, p := testEnv("linux")
		p.lookupFn = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("192.0.2.7")}, nil }
		res := runOne(t, env, "dns.resolve")
		if res.Status != StatusWarn || !hasCode(res, "diag_dns_reserved_answer") {
			t.Fatalf("status = %s, codes = %v", res.Status, res.ErrorCodes)
		}
		if !strings.Contains(res.Summary, "reserved") {
			t.Errorf("summary does not flag the address range: %s", res.Summary)
		}
	})
	t.Run("public answer", func(t *testing.T) {
		env, _, p := testEnv("linux")
		p.lookupFn = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("93.184.216.34")}, nil }
		res := runOne(t, env, "dns.resolve")
		if res.Status != StatusPass {
			t.Fatalf("status = %s, want pass (%s)", res.Status, res.Summary)
		}
	})
}

// TestDNSAtServerChecksOneServerSpecifically covers the configured-server path and its fallback
// to the first adapter's server, including the second probe being named in the evidence.
func TestDNSAtServerChecksOneServerSpecifically(t *testing.T) {
	env, _, p := testEnv("linux")
	env.Config.DNSServer = "9.9.9.9"
	p.lookupAtFn = func(name, server string) ([]net.IP, error) {
		if server != "9.9.9.9" {
			t.Errorf("queried %q, want the configured server", server)
		}
		return []net.IP{net.ParseIP("1.1.1.1")}, nil
	}
	res := runOne(t, env, "dns.server")
	if res.Status != StatusPass {
		t.Fatalf("status = %s (%s)", res.Status, res.Summary)
	}
	if !res.Evidence[0].Started || !strings.Contains(res.Evidence[0].Label, "9.9.9.9") {
		t.Errorf("the evidence does not name the server queried: %+v", res.Evidence[0])
	}
	if len(res.Inconclusive) == 0 {
		t.Error("the result does not say which adapters were NOT proven")
	}

	t.Run("falls back to an adapter's server", func(t *testing.T) {
		env, _, p := testEnv("linux")
		env.Config.DNSServer = ""
		env.SnapshotValue = snap([]inventory.Adapter{adapter("eth0", 2, "10.0.0.5", withDNS("192.168.1.1"))})
		var asked string
		p.lookupAtFn = func(name, server string) ([]net.IP, error) {
			asked = server
			return []net.IP{net.ParseIP("1.1.1.1")}, nil
		}
		res := runOne(t, env, "dns.server")
		if asked != "192.168.1.1" {
			t.Errorf("fallback queried %q, want the adapter's server", asked)
		}
		if res.Status != StatusPass {
			t.Errorf("status = %s (%s)", res.Status, res.Summary)
		}
	})

	t.Run("no server at all", func(t *testing.T) {
		env, _, _ := testEnv("linux")
		env.Config.DNSServer = ""
		env.SnapshotValue = snap([]inventory.Adapter{adapter("eth0", 2, "10.0.0.5")})
		res := runOne(t, env, "dns.server")
		if res.Status != StatusWarn {
			t.Fatalf("status = %s, want warn", res.Status)
		}
		if len(res.NextSteps) == 0 {
			t.Error("no next step was offered for a missing DNS server")
		}
	})

	t.Run("unresponsive", func(t *testing.T) {
		env, _, p := testEnv("linux")
		env.Config.DNSServer = "9.9.9.9"
		p.lookupAtFn = func(string, string) ([]net.IP, error) { return nil, timeoutError{} }
		res := runOne(t, env, "dns.server")
		if res.Status != StatusFail || !hasCode(res, "diag_dns_server_unresponsive") {
			t.Fatalf("status = %s, codes = %v", res.Status, res.ErrorCodes)
		}
	})
}

// TestUDProbeValidatesTheReply checks that UDP is proven with a response that parses, and that
// a non-NTP datagram is reported as suspicious rather than as success.
func TestUDProbeValidatesTheReply(t *testing.T) {
	valid := make([]byte, 48)
	valid[0] = 0x24
	valid[1] = 3
	valid[40] = 0xE5

	t.Run("valid", func(t *testing.T) {
		env, _, p := testEnv("linux")
		p.udpFn = func(string, []byte) ([]byte, time.Duration, error) {
			return valid, 21 * time.Millisecond, nil
		}
		res := runOne(t, env, "udp.probe")
		if res.Status != StatusPass {
			t.Fatalf("status = %s (%s)", res.Status, res.Summary)
		}
		if res.Measure == nil || res.Measure.Kind != "latency" {
			t.Errorf("the round trip was not recorded as a measurement: %+v", res.Measure)
		}
	})
	t.Run("unexpected payload", func(t *testing.T) {
		env, _, p := testEnv("linux")
		p.udpFn = func(string, []byte) ([]byte, time.Duration, error) {
			return []byte("not ntp at all"), 5 * time.Millisecond, nil
		}
		res := runOne(t, env, "udp.probe")
		if res.Status != StatusWarn || !hasCode(res, "diag_udp_unexpected_reply") {
			t.Fatalf("status = %s, codes = %v", res.Status, res.ErrorCodes)
		}
	})
	t.Run("no reply", func(t *testing.T) {
		env, _, p := testEnv("linux")
		p.udpFn = func(string, []byte) ([]byte, time.Duration, error) { return nil, 0, timeoutError{} }
		res := runOne(t, env, "udp.probe")
		if !hasCode(res, "diag_udp_no_reply") {
			t.Fatalf("codes = %v", res.ErrorCodes)
		}
		if len(res.Inconclusive) == 0 || !strings.Contains(res.Inconclusive[0], "rate-limit") {
			t.Errorf("the ambiguous case is not stated: %v", res.Inconclusive)
		}
	})
	t.Run("bad target", func(t *testing.T) {
		env, _, _ := testEnv("linux")
		env.Config.UDPTarget = "no-port-here"
		res := runOne(t, env, "udp.probe")
		if res.Status != StatusSkipped || !hasCode(res, "diag_endpoint_invalid") {
			t.Fatalf("status = %s, codes = %v", res.Status, res.ErrorCodes)
		}
	})
}

// TestGatewayReachUsesParsedLoss covers the Windows ping-on-a-real-host shape: exit 0 with a
// "Destination host unreachable" body must not be reported as a reachable gateway.
func TestGatewayReachUsesParsedLoss(t *testing.T) {
	env, r, _ := testEnv("windows")
	c := windowsCmds()["ping"]
	r.on("Reply from 10.0.0.1: Destination host unreachable.\r\n\r\nPing statistics for 10.0.1.1:\r\n    Packets: Sent = 2, Received = 2, Lost = 0 (0% loss),\r\n", c.Name, append(c.Args, "10.0.0.1")...)
	r.on("Reply from 10.0.0.1: bytes=32 time=1ms TTL=64\r\n\r\nPing statistics for 10.0.0.1:\r\n    Packets: Sent = 2, Received = 2, Lost = 0 (0% loss),\r\n    Minimum = 1ms, Maximum = 2ms, Average = 1ms\r\n", c.Name, append(c.Args, "10.0.0.2")...)

	env.SnapshotValue = snap([]inventory.Adapter{
		adapter("Ethernet", 4, "10.0.0.10", withGateway("10.0.0.1")),
		adapter("Wi-Fi", 5, "10.0.1.10", withGateway("10.0.0.2")),
	})
	res := runOne(t, env, "gateway.reach")
	joined := strings.Join(res.Established, "\n")
	if !strings.Contains(joined, "10.0.0.1 on Ethernet did not answer") {
		t.Errorf("the unreachable gateway was not reported as silent: %v", res.Established)
	}
	if !strings.Contains(joined, "answered") {
		t.Errorf("the reachable gateway was not reported: %v", res.Established)
	}
	if res.Status != StatusWarn {
		t.Fatalf("status = %s, want warn", res.Status)
	}
	if len(res.Inconclusive) == 0 || !strings.Contains(strings.Join(res.Inconclusive, " "), "ICMP") {
		t.Error("the result does not say that a silent gateway may simply drop ICMP")
	}
}

// TestMTULadderDescends checks the ladder logic: a size that must fragment is passed over, the
// next size that works is reported, and the result is explicit that the true MTU lies between.
func TestMTULadderDescends(t *testing.T) {
	env, r, _ := testEnv("linux")
	c := linuxCmds()["pingPath"]
	r.on("ping: local error: message too long, mtu=1500\n", c.Name, append(c.Args, "1472", "example.test")...)
	r.on("PING example.test: 1 packets transmitted, 1 received, 0% packet loss\n", c.Name, append(c.Args, "1452", "example.test")...)

	res := runOne(t, env, "mtu.path")
	if res.Status != StatusWarn {
		t.Fatalf("status = %s, want warn (%s)", res.Status, res.Summary)
	}
	if !strings.Contains(res.Summary, "1480") {
		t.Errorf("the largest working packet size (1452+28) is not in the summary: %s", res.Summary)
	}
	if len(res.Inconclusive) > 0 {
		t.Errorf("a resolved ladder should not be inconclusive: %v", res.Inconclusive)
	}
	// Only the two registered sizes should have been tried: the ladder must stop after success.
	if len(r.calls) != 2 {
		t.Errorf("the ladder ran %d probes, want 2: %v", len(r.calls), r.calls)
	}
}

// TestMTULadderNoProbeWorks reports the honest inconclusive case.
func TestMTULadderNoProbeWorks(t *testing.T) {
	env, r, _ := testEnv("linux")
	c := linuxCmds()["pingPath"]
	for _, size := range mtuLadder {
		r.on("ping: local error: message too long, mtu=1500\n", c.Name, append(c.Args, fmt.Sprint(size), "example.test")...)
	}
	res := runOne(t, env, "mtu.path")
	if res.Status != StatusWarn {
		t.Fatalf("status = %s", res.Status)
	}
	if len(res.Inconclusive) == 0 {
		t.Error("a path that could not be measured is not stated as such")
	}
}

// TestCountersMovementDetectsReset is the counter-reset case: an adapter re-plugged mid-window
// reports a smaller total, and that window must be discarded rather than turned into a spike.
func TestCountersMovementDetectsReset(t *testing.T) {
	env, _, _ := testEnv("linux")
	env.Snapshot = sequenceSnapshots(
		snap([]inventory.Adapter{adapter("eth0", 2, "10.0.0.5", withCounters(5_000_000, 4_000_000))}),
		snap([]inventory.Adapter{adapter("eth0", 2, "10.0.0.5", withCounters(10, 20))}),
	)
	res := runOne(t, env, "counters.movement")
	if !strings.Contains(strings.Join(res.Inconclusive, "\n"), "went backwards") {
		t.Fatalf("a counter reset was not reported: %v / %v", res.Established, res.Inconclusive)
	}
	if strings.Contains(strings.Join(res.Established, "\n"), "in,") {
		t.Errorf("a reset window produced a byte figure: %v", res.Established)
	}
}

// TestCountersMovementReportsBytes covers the ordinary case.
func TestCountersMovementReportsBytes(t *testing.T) {
	env, _, _ := testEnv("linux")
	env.Snapshot = sequenceSnapshots(
		snap([]inventory.Adapter{
			adapter("eth0", 2, "10.0.0.5", withCounters(1_000, 1_000)),
			adapter("wlan0", 3, "10.0.0.6", withCounters(2_000, 2_000)),
		}),
		snap([]inventory.Adapter{
			adapter("eth0", 2, "10.0.0.5", withCounters(601_000, 401_000)),
			adapter("wlan0", 3, "10.0.0.6", withCounters(2_000, 2_000)),
		}),
	)
	res := runOne(t, env, "counters.movement")
	joined := strings.Join(res.Established, "\n")
	if !strings.Contains(joined, "eth0: 585.9 kB in") {
		t.Errorf("the byte delta is not reported in readable units: %v", res.Established)
	}
	if !strings.Contains(joined, "wlan0: no bytes") {
		t.Errorf("the idle adapter is not reported as idle: %v", res.Established)
	}
	if res.Status != StatusPass {
		t.Errorf("status = %s, want pass", res.Status)
	}
}

// TestEngineStatusReadsTheStateFile exercises the engine view end to end from a written status
// file, including the disagreement case between the file and the CLI.
func TestEngineStatusReadsTheStateFile(t *testing.T) {
	dir := t.TempDir()
	env, r, _ := testEnv("linux")
	env.StateDir = dir
	env.Self = "net-merge"
	state.Write(dir, state.Status{
		PID: 4321, Mode: "tun", V6: "on", Since: time.Now().Add(-90 * time.Second), Updated: time.Now(),
		NICs: []engine.SlotStats{engineSlot("enp130s0", 12345)},
	})
	r.on("net-merge is ON (tun mode).\n", "net-merge", "status", "-state-dir", dir)

	res := runOne(t, env, "engine.status")
	if res.Status != StatusPass {
		t.Fatalf("status = %s (%s)", res.Status, res.Summary)
	}
	joined := strings.Join(res.Established, "\n")
	if !strings.Contains(joined, "tun mode") || !strings.Contains(joined, "enp130s0") {
		t.Errorf("the engine state was not reported: %v", res.Established)
	}
	if !strings.Contains(joined, "active connection") {
		t.Errorf("per-adapter connection counts were not reported: %v", res.Established)
	}
}

func TestEngineStatusReportsNotRunning(t *testing.T) {
	env, _, _ := testEnv("linux")
	env.StateDir = t.TempDir()
	env.Self = "net-merge"
	res := runOne(t, env, "engine.status")
	if res.Status != StatusInfo {
		t.Fatalf("status = %s", res.Status)
	}
	if len(res.NextSteps) == 0 {
		t.Error("no next step was offered for a stopped engine")
	}
}

// TestEngineStatusFlagsDisagreement is the honesty guard on the status file: a stale file the
// freshness window has not yet covered, when the CLI says the engine is off, is reported.
func TestEngineStatusFlagsDisagreement(t *testing.T) {
	dir := t.TempDir()
	env, r, _ := testEnv("linux")
	env.StateDir = dir
	env.Self = "net-merge"
	state.Write(dir, state.Status{PID: 1, Mode: "tun", Since: time.Now(), Updated: time.Now()})
	r.on("net-merge is OFF.\n", "net-merge", "status", "-state-dir", dir)
	res := runOne(t, env, "engine.status")
	if res.Status != StatusWarn {
		t.Fatalf("status = %s, want warn", res.Status)
	}
	if !strings.Contains(strings.Join(res.Inconclusive, " "), "disagree") {
		t.Errorf("the disagreement is not stated: %v", res.Inconclusive)
	}
}

// TestEngineEligibilityCrossChecksTheInventory is the 'interface is there but carries no
// traffic' explanation: the engine's own list is compared with the shared inventory.
func TestEngineEligibilityCrossChecksTheInventory(t *testing.T) {
	env, r, _ := testEnv("linux")
	env.StateDir = "/tmp/state-for-test"
	env.Self = "net-merge"
	env.SnapshotValue = snap([]inventory.Adapter{
		adapter("enp130s0", 4, "192.168.1.20"),
		adapter("wlan0", 5, "10.0.0.20"),
	})
	r.on("net-merge interfaces:\nUSE   enp130s0  (index 4)  192.168.1.20\nskip  docker0: virtual bridge\n",
		"net-merge", "list", "-state-dir", "/tmp/state-for-test")

	res := runOne(t, env, "engine.eligibility")
	if !strings.Contains(strings.Join(res.Established, "\n"), "engine will use enp130s0") {
		t.Errorf("the engine's usable list was not reported: %v", res.Established)
	}
	if !strings.Contains(strings.Join(res.Inconclusive, " "), "wlan0") {
		t.Errorf("a usable-but-unlisted adapter was not flagged: %v", res.Inconclusive)
	}
	if res.Status != StatusWarn {
		t.Errorf("status = %s, want warn", res.Status)
	}
}

// TestEngineStaleFindsLeftoverAdapter covers crash recovery: a net-merge adapter with no engine
// running is reported with the supported cleanup as the next step, never with an instruction to
// delete things by hand.
func TestEngineStaleFindsLeftoverAdapter(t *testing.T) {
	env, _, _ := testEnv("linux")
	env.StateDir = t.TempDir()
	tun := adapter("net-merge", 9, "198.18.0.1", withGateway("0.0.0.0"))
	tun.Description = "net-merge virtual adapter"
	env.SnapshotValue = snap([]inventory.Adapter{adapter("eth0", 2, "10.0.0.5"), tun})
	res := runOne(t, env, "engine.stale")
	if res.Status != StatusWarn || !hasCode(res, "engine_stale_adapter") {
		t.Fatalf("status = %s, codes = %v", res.Status, res.ErrorCodes)
	}
	if !strings.Contains(strings.Join(res.NextSteps, " "), "net-merge cleanup") {
		t.Errorf("the supported repair is not named: %v", res.NextSteps)
	}
}

func TestEngineStaleCleanHostIsAPass(t *testing.T) {
	env, _, _ := testEnv("linux")
	env.StateDir = t.TempDir()
	env.SnapshotValue = snap([]inventory.Adapter{adapter("eth0", 2, "10.0.0.5")})
	res := runOne(t, env, "engine.stale")
	if res.Status != StatusPass {
		t.Fatalf("status = %s (%s)", res.Status, res.Summary)
	}
}

// TestFirewallAndAVParsing runs the Windows firewall and security-product checks against
// replayed Get-NetFirewallProfile / AntiVirusProduct JSON.
func TestFirewallAndAVParsing(t *testing.T) {
	env, r, _ := testEnv("windows")
	fw := windowsCmds()["firewall"]
	r.on(`[{"Name":"Domain","Enabled":true,"DefaultInboundAction":"Block","DefaultOutboundAction":"Allow"},`+
		`{"Name":"Public","Enabled":true,"DefaultInboundAction":"Block","DefaultOutboundAction":"Allow"}]`,
		fw.Name, fw.Args...)
	res := runOne(t, env, "security.firewall")
	if res.Status != StatusInfo {
		t.Fatalf("status = %s", res.Status)
	}
	joined := strings.Join(res.Established, "\n")
	if !strings.Contains(joined, "Domain profile: enabled") || !strings.Contains(joined, "inbound Block") {
		t.Errorf("profile state not reported: %v", res.Established)
	}
	if len(res.Inconclusive) == 0 {
		t.Error("the firewall result does not say it is configuration rather than a verdict")
	}

	av := windowsCmds()["av"]
	r.on(`[{"displayName":"Windows Defender","productState":397568}]`, av.Name, av.Args...)
	res = runOne(t, env, "security.av")
	if res.Status != StatusInfo || !strings.Contains(strings.Join(res.Established, "\n"), "Windows Defender") {
		t.Fatalf("security product not reported: %s / %v", res.Summary, res.Established)
	}
}

// TestDriverIdentityParse covers Get-NetAdapter's driver fields.
func TestDriverIdentityParse(t *testing.T) {
	env, r, _ := testEnv("windows")
	ad := windowsCmds()["adapters"]
	r.on(`[{"Name":"Ethernet","DriverProvider":"Intel","DriverVersion":"12.19.2.50","Status":"Up"},`+
		`{"Name":"Wi-Fi","DriverProvider":"Realtek","DriverVersion":"2024.10.1","Status":"Up"}]`,
		ad.Name, ad.Args...)
	res := runOne(t, env, "adapters.driver")
	if res.Status != StatusPass {
		t.Fatalf("status = %s (%s)", res.Status, res.Summary)
	}
	joined := strings.Join(res.Established, "\n")
	if !strings.Contains(joined, "Intel 12.19.2.50") || !strings.Contains(joined, "Realtek 2024.10.1") {
		t.Errorf("driver identities not reported: %v", res.Established)
	}
}

// TestDriverIdentityReportsParseFailure keeps the failure honest: unparseable output is a
// warning with the raw evidence kept, not a crash and not a silent pass.
func TestDriverIdentityReportsParseFailure(t *testing.T) {
	env, r, _ := testEnv("windows")
	ad := windowsCmds()["adapters"]
	r.on("Get-NetAdapter : The term is not recognized\r\n", ad.Name, ad.Args...)
	res := runOne(t, env, "adapters.driver")
	if res.Status != StatusWarn || !hasCode(res, "diag_parse_failed") {
		t.Fatalf("status = %s, codes = %v", res.Status, res.ErrorCodes)
	}
	if len(res.Evidence) == 0 || len(res.Evidence[0].Output) == 0 {
		t.Error("the raw command output was not kept as evidence")
	}
}

// TestPortsConflict covers both the free and the busy case, plus the second-instance answer.
func TestPortsConflict(t *testing.T) {
	t.Run("free", func(t *testing.T) {
		env, _, p := testEnv("linux")
		p.portFree = true
		res := runOne(t, env, "ports.conflict")
		if res.Status != StatusPass {
			t.Fatalf("status = %s (%s)", res.Status, res.Summary)
		}
	})
	t.Run("busy", func(t *testing.T) {
		env, _, p := testEnv("linux")
		p.portFree = false
		env.instanceRunning = func() bool { return true }
		res := runOne(t, env, "ports.conflict")
		if res.Status != StatusWarn || !hasCode(res, "port_in_use") {
			t.Fatalf("status = %s, codes = %v", res.Status, res.ErrorCodes)
		}
		if !strings.Contains(strings.Join(res.Established, "\n"), "another net-merge process is alive") {
			t.Errorf("the instance answer was not reported: %v", res.Established)
		}
		if got := strings.Join(res.NextSteps, " "); !strings.Contains(got, "findstr") && !strings.Contains(got, "ss -ltnp") {
			t.Errorf("no way to find the port owner was offered: %v", res.NextSteps)
		}
	})
	t.Run("no instance answer", func(t *testing.T) {
		env, _, p := testEnv("linux")
		p.portFree = true
		res := runOne(t, env, "ports.conflict")
		if !strings.Contains(strings.Join(res.Inconclusive, " "), "another instance") {
			t.Errorf("the missing instance answer was not stated: %v", res.Inconclusive)
		}
	})
}

// TestSplitFamiliesDetectsIPv4Only covers the family view.
func TestSplitFamiliesDetectsIPv4Only(t *testing.T) {
	env, _, _ := testEnv("linux")
	env.SnapshotValue = snap([]inventory.Adapter{
		adapter("eth0", 2, "10.0.0.5"),
		adapter("wlan0", 3, "10.0.1.5", withIPv6("2606:4700:4700::1")),
	})
	res := runOne(t, env, "families.split")
	joined := strings.Join(res.Established, "\n")
	if !strings.Contains(joined, "IPv4 only: "+"eth0") && !strings.Contains(joined, "IPv4 only: eth0") {
		t.Errorf("the v4-only adapter was not listed: %v", res.Established)
	}
	if !strings.Contains(joined, "dual-stack: wlan0") {
		t.Errorf("the dual-stack adapter was not listed: %v", res.Established)
	}
}

// TestRoutingDefaultFlagsTies covers the ambiguous default-route case: two defaults with the
// same metric must not be presented as a resolved preference.
func TestRoutingDefaultFlagsTies(t *testing.T) {
	env, _, _ := testEnv("linux")
	env.SnapshotValue = snap(
		[]inventory.Adapter{adapter("eth0", 2, "10.0.0.5"), adapter("wlan0", 3, "10.0.1.5")},
		inventory.Route{Family: "ipv4", Destination: "0.0.0.0/0", NextHop: "10.0.0.1", Index: 2, Name: "eth0", Metric: 100, Default: true},
		inventory.Route{Family: "ipv4", Destination: "0.0.0.0/0", NextHop: "10.0.1.1", Index: 3, Name: "wlan0", Metric: 100, Default: true},
	)
	res := runOne(t, env, "routing.default")
	if res.Status != StatusWarn {
		t.Fatalf("status = %s (%s)", res.Status, res.Summary)
	}
	if len(res.Established) != 2 {
		t.Errorf("both defaults should be listed, got %v", res.Established)
	}
	if len(res.Inconclusive) == 0 {
		t.Error("the tied-metric ambiguity was not stated")
	}
}

func TestRoutingDefaultNoRouteIsAFailure(t *testing.T) {
	env, _, _ := testEnv("linux")
	env.SnapshotValue = snap([]inventory.Adapter{adapter("eth0", 2, "10.0.0.5")})
	res := runOne(t, env, "routing.default")
	if res.Status != StatusFail {
		t.Fatalf("status = %s (%s)", res.Status, res.Summary)
	}
}

// TestAdaptersInventoryReportsGaps checks that a platform gap is surfaced as inconclusive
// rather than as a zero.
func TestAdaptersInventoryReportsGaps(t *testing.T) {
	env, _, _ := testEnv("linux")
	s := snap([]inventory.Adapter{
		adapter("eth0", 2, "10.0.0.5"),
		adapter("vpn0", 3, "10.9.0.2", withState(inventory.StateExcluded, inventory.ExclVirtual)),
	})
	s.Gaps = []string{"this platform exposes no DHCP state"}
	env.SnapshotValue = s
	res := runOne(t, env, "adapters.inventory")
	joined := strings.Join(res.Inconclusive, "\n")
	if !strings.Contains(joined, "DHCP state") {
		t.Errorf("the platform gap was not surfaced: %v", res.Inconclusive)
	}
	if !strings.Contains(strings.Join(res.Established, "\n"), "excluded") {
		t.Errorf("no exclusion reason was reported: %v", res.Established)
	}
}

// helpers -------------------------------------------------------------------------------------

// sequenceSnapshots returns a Snapshot provider that yields the given snapshots in order and
// then repeats the last one, so a check taking two samples gets two different views.
func sequenceSnapshots(snaps ...*inventory.Snapshot) func(context.Context) (*inventory.Snapshot, error) {
	i := 0
	return func(context.Context) (*inventory.Snapshot, error) {
		s := snaps[i]
		if i < len(snaps)-1 {
			i++
		}
		return s, nil
	}
}

func hasCode(r Result, code string) bool {
	for _, c := range r.ErrorCodes {
		if c == code {
			return true
		}
	}
	return false
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// engineSlot builds a state.SlotStats for a test, keeping the literal small.
func engineSlot(name string, active int64) engine.SlotStats {
	return engine.SlotStats{Name: name, State: "ok", Weight: 1, Present: true, Active: active, Total: active * 2, RateIn: 1500, RateOut: 300}
}
