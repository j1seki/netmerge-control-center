package diag

// This file holds the test doubles used by the diagnostics tests. They are simulations of a
// host, not measurements of one: the fake runner replays recorded command output, and the fake
// prober answers network probes from a table. Every test that relies on them says so in its
// name or its comment, so a passing suite is never mistaken for a passing network.

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"net-merge/internal/execx"
	"net-merge/internal/inventory"
)

// fakeRunner replays command results. It is the simulation of a Windows (or Linux) host's
// command surface: a test registers the exact argv it expects, and anything unregistered
// returns an empty success - which is itself a case the checks must handle gracefully.
type fakeRunner struct {
	results map[string]execx.Result
	paths   map[string]string // command name -> path; missing means "not installed"
	calls   []string
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{results: map[string]execx.Result{}, paths: map[string]string{}}
}

func key(name string, args ...string) string {
	return strings.Join(append([]string{name}, args...), " ")
}

// on registers a successful command with the given output.
func (f *fakeRunner) on(out string, name string, args ...string) *fakeRunner {
	f.results[key(name, args...)] = execx.Result{
		Command: key(name, args...), Started: true, ExitCode: 0,
		Stdout: out, Duration: 5 * time.Millisecond,
	}
	return f
}

// fail registers a command that started and exited non-zero.
func (f *fakeRunner) fail(code int, out string, name string, args ...string) *fakeRunner {
	f.results[key(name, args...)] = execx.Result{
		Command: key(name, args...), Started: true, ExitCode: code,
		Stderr: out, Duration: 5 * time.Millisecond,
	}
	return f
}

// timeout registers a command that was killed by its timeout.
func (f *fakeRunner) timeout(name string, args ...string) *fakeRunner {
	f.results[key(name, args...)] = execx.Result{
		Command: key(name, args...), Started: true, TimedOut: true,
		Err: "timed out", Duration: time.Second,
	}
	return f
}

// installed marks a command as resolvable by LookPath.
func (f *fakeRunner) installed(name string) *fakeRunner {
	f.paths[name] = "/usr/bin/" + name
	return f
}

func (f *fakeRunner) Run(ctx context.Context, name string, args ...string) execx.Result {
	k := key(name, args...)
	f.calls = append(f.calls, k)
	if r, ok := f.results[k]; ok {
		return r
	}
	// An unregistered command resolves, runs, and prints nothing: the shape of a real command
	// whose output this check does not parse.
	return execx.Result{Command: k, Started: true, ExitCode: 0}
}

func (f *fakeRunner) LookPath(name string) (string, error) {
	if p, ok := f.paths[name]; ok {
		return p, nil
	}
	return "", &notFoundError{name: name}
}

type notFoundError struct{ name string }

func (e *notFoundError) Error() string { return "executable file not found: " + e.name }

// fakeProber answers network probes from a table. Nothing here touches a socket.
type fakeProber struct {
	connectFn  func(addr string, local net.IP) (time.Duration, error)
	lookupFn   func(name string) ([]net.IP, error)
	lookupAtFn func(name, server string) ([]net.IP, error)
	udpFn      func(addr string, payload []byte) ([]byte, time.Duration, error)
	portFree   bool
	portErr    error

	connects []connectCall
	udps     []string
}

type connectCall struct {
	Addr  string
	Local string
}

func (p *fakeProber) TCPConnect(ctx context.Context, addr string, local net.IP) (time.Duration, error) {
	l := ""
	if local != nil {
		l = local.String()
	}
	p.connects = append(p.connects, connectCall{Addr: addr, Local: l})
	if p.connectFn != nil {
		return p.connectFn(addr, local)
	}
	return 10 * time.Millisecond, nil
}

func (p *fakeProber) UDPExchange(ctx context.Context, addr string, payload []byte, want int) ([]byte, time.Duration, error) {
	p.udps = append(p.udps, addr)
	if p.udpFn != nil {
		return p.udpFn(addr, payload)
	}
	return nil, 0, &timeoutError{}
}

func (p *fakeProber) LookupIP(ctx context.Context, name string) ([]net.IP, error) {
	if p.lookupFn != nil {
		return p.lookupFn(name)
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (p *fakeProber) LookupAtServer(ctx context.Context, name, server string) ([]net.IP, error) {
	if p.lookupAtFn != nil {
		return p.lookupAtFn(name, server)
	}
	return nil, &timeoutError{}
}

func (p *fakeProber) PortFree(ctx context.Context, addr string) (bool, error) {
	return p.portFree, p.portErr
}

// timeoutError is a net.Error that reports a timeout, so the classification under test is the
// real one rather than a string match on a made-up message.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// refusedError is the shape net.Dialer produces for a TCP reset.
func refusedError(addr string) error {
	return &net.OpError{Op: "dial", Net: "tcp", Addr: fakeAddr(addr), Err: errRefused{}}
}

type errRefused struct{}

func (errRefused) Error() string { return "connect: connection refused" }

// unroutableError is what the local stack reports when no route matches.
type unroutableError struct{}

func (unroutableError) Error() string { return "connect: network is unreachable" }

type fakeAddr string

func (a fakeAddr) Network() string { return "tcp" }
func (a fakeAddr) String() string  { return string(a) }

// parseIP parses an address in a test, failing rather than returning a nil that would silently
// change what is being tested.
func parseIP(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("%q is not an address", s)
	}
	return ip
}

// testEnv returns an Env wired to the fakes with a no-op sleep, so no test waits on a clock.
func testEnv(platform string) (*Env, *fakeRunner, *fakeProber) {
	r, p := newFakeRunner(), &fakeProber{}
	env := &Env{
		Runner:     r,
		Probes:     p,
		Platform:   platform,
		StateDir:   "/nonexistent-state-dir-for-tests",
		IsAdmin:    false,
		Now:        time.Now,
		Sleep:      func(context.Context, time.Duration) error { return nil },
		AppVersion: "test",
	}
	env.Config.DNSName = "example.test"
	env.Config.Endpoint = "example.test:443"
	env.Config.DNSServer = ""
	env.Config.MTUHost = "example.test"
	env.Config.TracerouteTarget = "example.test"
	env.Config.UDPTarget = "time.example.test:123"
	return env, r, p
}

// snap builds a snapshot from adapters, with routes appended.
func snap(adapters []inventory.Adapter, routes ...inventory.Route) *inventory.Snapshot {
	s := &inventory.Snapshot{Taken: time.Now(), Source: "simulated", Adapters: adapters, Routes: routes}
	s.Sort()
	return s
}

// adapter is a compact builder for a usable adapter in a simulated snapshot.
func adapter(name string, index int, ipv4 string, opts ...func(*inventory.Adapter)) inventory.Adapter {
	a := inventory.Adapter{
		Name: name, Index: index, Status: inventory.StateEligible,
		Kind: inventory.KindEthernet, Hardware: true,
		Link: inventory.LinkUp, SpeedBps: 1_000_000_000,
		IPv4: []inventory.Address{{Address: ipv4, Prefix: 24}},
	}
	for _, o := range opts {
		o(&a)
	}
	return a
}

func withGateway(gw string) func(*inventory.Adapter) {
	return func(a *inventory.Adapter) { a.Gateways4 = []string{gw} }
}

func withDNS(servers ...string) func(*inventory.Adapter) {
	return func(a *inventory.Adapter) { a.DNS4 = servers }
}

func withIPv6(addr string) func(*inventory.Adapter) {
	return func(a *inventory.Adapter) {
		a.IPv6 = append(a.IPv6, inventory.Address{Address: addr, Prefix: 64})
	}
}

func withCounters(in, out uint64) func(*inventory.Adapter) {
	return func(a *inventory.Adapter) { a.Counters = &inventory.Counters{In: in, Out: out} }
}

func withMetric(m int) func(*inventory.Adapter) {
	return func(a *inventory.Adapter) { a.Metric4 = &m }
}

func withState(st inventory.State, excl string) func(*inventory.Adapter) {
	return func(a *inventory.Adapter) {
		a.Status = st
		if excl != "" {
			a.ExclusionCode = excl
			a.Exclusion = "excluded for the test: " + excl
		}
	}
}
