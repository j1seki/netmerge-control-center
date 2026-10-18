// Package monitor performs the bounded, low-volume reachability checks that fill the
// inventory's Health slot and the dashboard's link-health view.
//
// It exists because nothing else answers "does this link reach the internet right now" cheaply:
// the bonding engine probes only while it runs, and only reports up/down without latency, and
// the diagnostics registry runs on demand. The monitor is deliberately small and never a
// control path - it opens one TCP connection per adapter per round, sends no payload, runs no
// ICMP (which needs privileges), and changes no setting. It never decides which link the engine
// uses; that is the engine's scheduler, and this package only observes.
//
// Every dep is injected, so the classification and history logic (what counts as unreachable,
// when a transition is recorded, how loss and jitter are derived) is tested without a network.
package monitor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"syscall"
	"time"

	"net-merge/internal/inventory"
	"net-merge/internal/nics"
)

// Link states. "unknown" is the honest state before anything has been observed; it is not a
// softer way of saying "reachable".
const (
	StateUnknown     = "unknown"
	StateReachable   = "reachable"
	StateUnreachable = "unreachable"
	StateAbsent      = "absent"
)

// Config is what a monitor instance is told once.
type Config struct {
	// Endpoint is host:port to connect to. A bare host gets :443.
	Endpoint string
	// Timeout bounds each attempt.
	Timeout time.Duration
	// Window is how many recent attempts per adapter feed the loss and jitter numbers.
	Window int
}

// Target is one adapter to test: the name shown to the user, the interface index the socket is
// bound to, and the source addresses that can be used.
type Target struct {
	Name  string
	Index int
	IP    net.IP // may be nil
	IP6   net.IP // may be nil
}

// Deps are the collaborators, injectable for tests. Nil fields get the real implementations.
type Deps struct {
	Now     func() time.Time
	Dial    func(ctx context.Context, network, address string, local net.IP, ifIndex int, v6 bool) (time.Duration, error)
	Resolve func(ctx context.Context, host string) ([]net.IP, error)
}

// Transition is one observed change of an adapter's reachability state.
type Transition struct {
	At     time.Time `json:"at"`
	Name   string    `json:"name"`
	From   string    `json:"from"`
	To     string    `json:"to"`
	Reason string    `json:"reason,omitempty"`
}

// Round is the result of one Check: the health of every adapter tested, the state changes it
// observed, and the adapters it could not test with the reason.
type Round struct {
	At          time.Time                   `json:"at"`
	Results     map[string]inventory.Health `json:"results,omitempty"`
	Transitions []Transition                `json:"transitions,omitempty"`
	Skipped     []Skip                      `json:"skipped,omitempty"`
}

// Skip is an adapter this round did not test, and why. It is reported rather than silently
// dropped: "not tested" and "tested and fine" must never look alike.
type Skip struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

// LinkView is one adapter's current health state for the UI.
type LinkView struct {
	Name     string    `json:"name"`
	State    string    `json:"state"`
	Since    time.Time `json:"since,omitempty"`
	Changes  int       `json:"changes"`
	RTTms    float64   `json:"rttMs,omitempty"`
	LossPct  float64   `json:"lossPct,omitempty"`
	JitterMs float64   `json:"jitterMs,omitempty"`
	Endpoint string    `json:"endpoint,omitempty"`
	Detail   string    `json:"detail,omitempty"`
	At       time.Time `json:"at,omitempty"`
}

type sample struct {
	ok  bool
	rtt time.Duration
	at  time.Time
}

type record struct {
	state    string
	since    time.Time
	changes  int
	samples  []sample
	health   *inventory.Health
	lastSeen time.Time
}

// maxTransitions bounds the history the UI can read. The log has the durable record; this list
// is for the page, and an unbounded one in a long-running window would be a leak.
const maxTransitions = 200

// Monitor holds the state between rounds.
type Monitor struct {
	cfg  Config
	deps Deps

	mu    sync.Mutex
	recs  map[string]*record
	trans []Transition
	last  map[string]inventory.Health
}

// New builds a monitor. An empty endpoint defaults to a well-known anycast address that
// answers on 443 from anywhere; the browser and DNS do not use it.
func New(cfg Config, deps Deps) *Monitor {
	if cfg.Endpoint == "" {
		cfg.Endpoint = "1.1.1.1:443"
	}
	if _, _, err := net.SplitHostPort(cfg.Endpoint); err != nil {
		cfg.Endpoint = net.JoinHostPort(cfg.Endpoint, "443")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}
	if cfg.Window <= 0 {
		cfg.Window = 8
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.Dial == nil {
		deps.Dial = defaultDial
	}
	if deps.Resolve == nil {
		deps.Resolve = defaultResolve
	}
	return &Monitor{cfg: cfg, deps: deps, recs: map[string]*record{}, last: map[string]inventory.Health{}}
}

// Endpoint is the address being tested, for display.
func (m *Monitor) Endpoint() string { return m.cfg.Endpoint }

// Check tests every target once and folds the outcomes into the monitor's state. It is safe to
// call concurrently with View and Health.
func (m *Monitor) Check(ctx context.Context, targets []Target) Round {
	now := m.deps.Now()
	round := Round{At: now, Results: map[string]inventory.Health{}}

	port := "443"
	if _, p, err := net.SplitHostPort(m.cfg.Endpoint); err == nil {
		port = p
	}
	addrs, resolveErr := m.resolve(ctx)

	type outcome struct {
		target Target
		fam    string
		dur    time.Duration
		err    error
		skip   string
	}
	outcomes := make([]outcome, len(targets))
	var wg sync.WaitGroup
	for i, tgt := range targets {
		network, host, why := chooseFamily(tgt, addrs, resolveErr)
		if why != "" {
			outcomes[i] = outcome{target: tgt, skip: why}
			continue
		}
		wg.Add(1)
		go func(i int, tgt Target, network, host string) {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, m.cfg.Timeout)
			defer cancel()
			v6 := network == "tcp6"
			local := tgt.IP
			if v6 {
				local = tgt.IP6
			}
			dur, err := m.deps.Dial(cctx, network, net.JoinHostPort(host, port), local, tgt.Index, v6)
			outcomes[i] = outcome{target: tgt, fam: network, dur: dur, err: err}
		}(i, tgt, network, host)
	}
	wg.Wait()

	m.mu.Lock()
	defer m.mu.Unlock()

	tested := map[string]bool{}
	for _, o := range outcomes {
		if o.skip != "" {
			round.Skipped = append(round.Skipped, Skip{Name: o.target.Name, Reason: o.skip})
			continue
		}
		tested[o.target.Name] = true
		h, tr := m.record(o.target.Name, o.dur, o.err, now)
		if tr != nil {
			round.Transitions = append(round.Transitions, *tr)
		}
		round.Results[o.target.Name] = h
		m.last[o.target.Name] = h
	}
	// An adapter that was watched and is not in this round's list is gone (unplugged, or no
	// longer a candidate): its state becomes "absent" and its stale health is dropped, so a
	// phone that comes back later starts from a current reading, not yesterday's.
	if len(tested) > 0 {
		for name, rec := range m.recs {
			if tested[name] || rec.state == StateAbsent {
				continue
			}
			round.Transitions = append(round.Transitions, m.transition(name, StateAbsent,
				"the adapter is no longer present, so nothing tests it", now))
			rec.health = nil
			rec.samples = nil
			delete(m.last, name)
		}
	} else {
		// Nothing was tested at all (no candidates, or resolution failed): keep the previous
		// readings rather than erasing them. The skipped list says nothing was verified.
		round.Results = nil
	}
	return round
}

// record folds one attempt into the adapter's record and returns the health to report, plus the
// transition it produced (nil when the state did not change).
func (m *Monitor) record(name string, dur time.Duration, err error, now time.Time) (inventory.Health, *Transition) {
	rec := m.recs[name]
	if rec == nil {
		rec = &record{state: StateUnknown, since: now}
		m.recs[name] = rec
	}
	rec.lastSeen = now

	ok := err == nil
	detail := ""
	switch {
	case err == nil:
	case isRefused(err):
		// A refusal is an answer: the packets reached a host, so the path works. Saying
		// "unreachable" here would be wrong in a way that sends people to the wrong problem.
		ok = true
		detail = "the endpoint refused the connection; the path itself answered"
	default:
		detail = dialDetail(err, m.cfg.Timeout)
	}

	rec.samples = append(rec.samples, sample{ok: ok, rtt: dur, at: now})
	if len(rec.samples) > m.cfg.Window {
		rec.samples = rec.samples[len(rec.samples)-m.cfg.Window:]
	}

	var changed *Transition
	if want := stateFor(ok); rec.state != want {
		reason := "the probe to " + m.cfg.Endpoint + " succeeded"
		if !ok {
			reason = "the probe to " + m.cfg.Endpoint + " failed: " + detail
		} else if rec.state == StateUnreachable {
			reason = "the probe to " + m.cfg.Endpoint + " succeeded again"
		}
		t := m.transitionLocked(rec, name, want, reason, now)
		changed = &t
	}

	h := inventory.Health{Checked: true, OK: ok, Endpoint: m.cfg.Endpoint, At: now, Detail: detail}
	if ok {
		h.RTTms = ms(dur)
	}
	h.Loss, h.Jitter = windowStats(rec.samples)
	rec.health = &h
	return h, changed
}

// stateFor maps an attempt's outcome to a state name.
func stateFor(ok bool) string {
	if ok {
		return StateReachable
	}
	return StateUnreachable
}

// transitionLocked moves a record's state and appends to the history. Callers hold m.mu.
func (m *Monitor) transitionLocked(rec *record, name, to, reason string, now time.Time) Transition {
	from := rec.state
	rec.state = to
	rec.since = now
	rec.changes++
	t := Transition{At: now, Name: name, From: from, To: to, Reason: reason}
	m.pushTransition(t)
	return t
}

// transition changes a record that may not exist yet, for the "adapter disappeared" path.
func (m *Monitor) transition(name, to, reason string, now time.Time) Transition {
	rec := m.recs[name]
	if rec == nil {
		rec = &record{state: StateUnknown, since: now}
		m.recs[name] = rec
	}
	return m.transitionLocked(rec, name, to, reason, now)
}

func (m *Monitor) pushTransition(t Transition) {
	m.trans = append(m.trans, t)
	if len(m.trans) > maxTransitions {
		m.trans = m.trans[len(m.trans)-maxTransitions:]
	}
}

// resolve resolves the endpoint once for a round. An address literal needs no resolver.
func (m *Monitor) resolve(ctx context.Context) ([]net.IP, error) {
	host, _, err := net.SplitHostPort(m.cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("the endpoint %q is not host:port", m.cfg.Endpoint)
	}
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	addrs, err := m.deps.Resolve(ctx, host)
	if err != nil {
		// A resolver that failed is a resolver whose partial answers are not trustworthy: a
		// round that resolved nothing verified nothing.
		return nil, err
	}
	return addrs, nil
}

// chooseFamily picks the address family for one target: IPv4 when the adapter has one and the
// endpoint does, IPv6 otherwise. The reason string is shown to the user verbatim.
func chooseFamily(t Target, addrs []net.IP, resolveErr error) (network, host, why string) {
	var v4, v6 net.IP
	for _, ip := range addrs {
		if ip.To4() != nil && v4 == nil {
			v4 = ip
		} else if ip.To4() == nil && v6 == nil {
			v6 = ip
		}
	}
	switch {
	case t.IP != nil && v4 != nil:
		return "tcp4", v4.String(), ""
	case t.IP6 != nil && v6 != nil:
		return "tcp6", v6.String(), ""
	case resolveErr != nil:
		return "", "", "the test endpoint could not be resolved: " + resolveErr.Error()
	case t.IP == nil && t.IP6 == nil:
		return "", "", "the adapter has no address to test from"
	case v4 == nil && v6 == nil:
		return "", "", "the test endpoint has no usable address"
	default:
		return "", "", "the adapter and the test endpoint have no address family in common"
	}
}

// Health returns the most recent result per adapter, for merging into a snapshot.
func (m *Monitor) Health() map[string]inventory.Health {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]inventory.Health, len(m.last))
	for k, v := range m.last {
		out[k] = v
	}
	return out
}

// View returns the current state of every adapter the monitor has seen, ordered by name.
func (m *Monitor) View() []LinkView {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]LinkView, 0, len(m.recs))
	for name, rec := range m.recs {
		v := LinkView{Name: name, State: rec.state, Since: rec.since, Changes: rec.changes}
		if h := rec.health; h != nil {
			v.RTTms, v.LossPct, v.JitterMs = h.RTTms, h.Loss, h.Jitter
			v.Endpoint, v.Detail, v.At = h.Endpoint, h.Detail, h.At
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Transitions returns the most recent state changes, oldest first, at most limit of them.
func (m *Monitor) Transitions(limit int) []Transition {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := len(m.trans)
	if limit > 0 && n > limit {
		n = limit
	}
	return append([]Transition(nil), m.trans[len(m.trans)-n:]...)
}

// windowStats derives loss and jitter from the recent attempts. Loss is a percentage of the
// window and is only reported once there are at least two attempts: one sample is not a rate.
// Jitter is the mean absolute difference between consecutive successful RTTs.
func windowStats(samples []sample) (lossPct, jitterMs float64) {
	if len(samples) < 2 {
		return 0, 0
	}
	var fails int
	var lastRTT time.Duration
	var haveLast bool
	var sum float64
	var pairs int
	for _, s := range samples {
		if !s.ok {
			fails++
			haveLast = false
			continue
		}
		if haveLast {
			d := s.rtt - lastRTT
			if d < 0 {
				d = -d
			}
			sum += float64(d) / float64(time.Millisecond)
			pairs++
		}
		lastRTT, haveLast = s.rtt, true
	}
	lossPct = 100 * float64(fails) / float64(len(samples))
	if pairs > 0 {
		jitterMs = sum / float64(pairs)
	}
	return lossPct, jitterMs
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

// isRefused reports whether the attempt was refused. A refusal is an answer - the packets
// reached a host - so it counts as reachable. On Windows the same condition arrives as
// WSAECONNREFUSED, which Go maps to the same value.
func isRefused(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }

// dialDetail turns an attempt's error into a sentence that says what happened, not what to
// fix (the troubleshooting guide does that, keyed by the symptom).
func dialDetail(err error, timeout time.Duration) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Sprintf("no answer within %s", timeout)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return fmt.Sprintf("no answer within %s", timeout)
	}
	// Strip the operation prefix net puts in front; the address is already on screen.
	msg := err.Error()
	return msg
}

// defaultDial is the real attempt: bind to the adapter (so the test uses the link it claims
// to), connect, and close without sending a byte.
func defaultDial(ctx context.Context, network, address string, local net.IP, ifIndex int, v6 bool) (time.Duration, error) {
	d := net.Dialer{Control: nics.ForceEgress(ifIndex, v6)}
	if local != nil {
		d.LocalAddr = &net.TCPAddr{IP: local}
	}
	start := time.Now()
	conn, err := d.DialContext(ctx, network, address)
	elapsed := time.Since(start)
	if err != nil {
		return elapsed, err
	}
	_ = conn.Close()
	return elapsed, nil
}

func defaultResolve(ctx context.Context, host string) ([]net.IP, error) {
	rctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(rctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.IP)
	}
	return out, nil
}
