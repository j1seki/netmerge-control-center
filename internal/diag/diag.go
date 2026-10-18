// Package diag is the diagnostic centre: a registry of individually runnable checks plus a
// combined procedure, each one reporting what its own result actually establishes.
//
// Two rules shape every check in here, and they are the reason this package exists instead of
// a list of shell commands:
//
//   - A command exiting 0 is not a result. Each check reads the *content* of what came back
//     (a parsed reply, a resolved address, a routing table entry) and states the fact that
//     content establishes. "Resolve-DnsName succeeded" is reported as "the name resolved to
//     these addresses on this host", never as "the adapter under test used its configured DNS".
//
//   - What a check cannot establish is part of its result. Every check declares, up front,
//     what a pass means and what it does not mean, so a reader of the report cannot over-read
//     a green tick. This is carried on the check's Meta and surfaced in the UI next to the run.
//
// The package performs no writes to system state: it reads, it probes, and it reports. The
// one action it can offer is the *name* of the supported fix (for example "run net-merge
// cleanup"), which the UI runs as a separate, confirmed operation.
package diag

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"net-merge/internal/appcfg"
	"net-merge/internal/execx"
	"net-merge/internal/inventory"
	"net-merge/internal/logx"
	"net-merge/internal/ttlmgr"
)

// Status is the verdict of one check. The set matches what a reader needs to distinguish:
// succeeded, succeeded with a caveat, failed, could not be decided, not applicable here.
type Status string

const (
	StatusPass    Status = "pass"
	StatusWarn    Status = "warn"
	StatusFail    Status = "fail"
	StatusSkipped Status = "skipped"
	StatusError   Status = "error"
	StatusInfo    Status = "info"
)

// Rank orders statuses by severity, for the summary line and for a report that must lead with
// the worst thing found.
func (s Status) Rank() int {
	switch s {
	case StatusError:
		return 5
	case StatusFail:
		return 4
	case StatusWarn:
		return 3
	case StatusSkipped:
		return 2
	case StatusInfo:
		return 1
	default:
		return 0
	}
}

// Worse returns the more severe of two statuses. A skipped check never outranks a real result.
func Worse(a, b Status) Status {
	if b.Rank() > a.Rank() {
		return b
	}
	return a
}

// Category groups checks in the UI and the report.
type Category string

const (
	CatPlatform Category = "platform"
	CatAdapters Category = "adapters"
	CatRouting  Category = "routing"
	CatDNS      Category = "dns"
	CatGateway  Category = "gateway"
	CatPath     Category = "path"
	CatTunnel   Category = "tun"
	CatEngine   Category = "engine"
	CatSecurity Category = "security"
)

// Categories lists every category in display order.
func Categories() []Category {
	return []Category{CatPlatform, CatAdapters, CatRouting, CatDNS, CatGateway, CatPath, CatTunnel, CatEngine, CatSecurity}
}

// Valid reports whether the category is one this build knows about. A result whose category is
// unknown would be misplaced in the UI's grouping, so it is checked rather than assumed.
func (c Category) Valid() bool {
	for _, known := range Categories() {
		if c == known {
			return true
		}
	}
	return false
}

// Meta is a check's static description. It is what the UI shows before a run, so a user can
// see what a check is for and what it will not prove.
type Meta struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Category Category `json:"category"`
	// Purpose is one sentence: why a user would run this.
	Purpose string `json:"purpose"`
	// Establishes lists what a passing result proves, in plain language.
	Establishes []string `json:"establishes"`
	// DoesNotEstablish lists the tempting over-readings. It is required to be non-empty for
	// any check whose result is easy to misread, and the UI shows it under the result.
	DoesNotEstablish []string `json:"doesNotEstablish,omitempty"`
	// Platforms limits the check; empty means every platform.
	Platforms []string `json:"platforms,omitempty"`
	// NeedsAdmin marks a check that needs elevation. It is still listed when not elevated:
	// it runs, and reports that it was skipped for that reason, which is more useful than an
	// absent check.
	NeedsAdmin bool `json:"needsAdmin,omitempty"`
	// Slow marks a check that takes seconds (traceroute, MTU ladder). The UI runs those
	// with a visible pending state instead of blocking on them.
	Slow bool `json:"slow,omitempty"`
}

// Evidence is one command run or one in-process probe, kept verbatim enough to re-run.
type Evidence struct {
	Label    string        `json:"label"`
	Command  []string      `json:"command,omitempty"` // exact argv, when a command was run
	ExitCode *int          `json:"exitCode,omitempty"`
	Started  bool          `json:"started"`
	TimedOut bool          `json:"timedOut,omitempty"`
	Duration time.Duration `json:"duration"`
	// Output is the command's own output, already trimmed to the report's line budget.
	Output    []string `json:"output,omitempty"`
	Truncated bool     `json:"truncated,omitempty"`
	// Note records an interpretation of this evidence, e.g. "exit 1 with 100% loss parsed as
	// unreachable" - so the reader does not have to know tool exit conventions.
	Note string `json:"note,omitempty"`
	// Err is a transport-level failure (could not start, cancelled).
	Err string `json:"err,omitempty"`
}

// Measurement is one number a check measured, so the dashboard can plot it without parsing
// prose. It is deliberately narrow: probes measure latency, and the path-MTU check measures a
// size. Anything a check did not measure is absent rather than zero.
type Measurement struct {
	Kind    string    `json:"kind"` // latency | mtu | loss
	Ms      float64   `json:"ms,omitempty"`
	LossPct float64   `json:"lossPct,omitempty"`
	Bytes   int       `json:"bytes,omitempty"`
	Target  string    `json:"target,omitempty"`
	At      time.Time `json:"at"`
}

// Result is one check's output.
type Result struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Category Category `json:"category"`

	Status Status `json:"status"`
	// Summary is one line a person reads first.
	Summary string `json:"summary"`
	// Established lists the facts this run proved, as opposed to what the check could prove
	// in principle. A run that found nothing new has an empty list.
	Established []string `json:"established"`
	// Inconclusive lists things this run could not decide, with the reason.
	Inconclusive []string `json:"inconclusive,omitempty"`
	// NextSteps are concrete, supported actions a user can take next. They never include a
	// system change this application performs silently.
	NextSteps []string `json:"nextSteps,omitempty"`
	// ErrorCodes are stable codes for errors this run hit, so the troubleshooting guide can
	// be searched by code.
	ErrorCodes []string `json:"errorCodes,omitempty"`

	Evidence []Evidence `json:"evidence,omitempty"`

	// Measure, when set, is the numeric result a UI can chart or compare across runs.
	Measure *Measurement `json:"measure,omitempty"`

	Started  time.Time     `json:"started"`
	Duration time.Duration `json:"duration"`
	// Generated describes anything about this run that affects how it should be read: a
	// simulation in a test, a partial run, a platform limit.
	Notes []string `json:"notes,omitempty"`
}

// Check is one diagnostic.
type Check interface {
	Meta() Meta
	Run(ctx context.Context, env *Env) Result
}

// Env is everything a check is allowed to touch. Everything is a field or a function so a test
// can substitute a fake and exercise the real check logic: on a Linux development host the
// Windows checks can still be tested against recorded command output.
type Env struct {
	// Runner runs external commands. Never nil (NewEnv fills it in).
	Runner execx.Runner
	// Probes are the in-process network probes. Never nil.
	Probes Prober

	// Snapshot returns the current inventory, or an error. The dashboard passes its cached
	// monitor snapshot so a diagnostic run does not re-read the whole system.
	Snapshot func(ctx context.Context) (*inventory.Snapshot, error)
	// SnapshotValue is a snapshot the caller already has. When set, Snapshot is not called.
	SnapshotValue *inventory.Snapshot

	// TTL is the TTL manager's report, when the caller has one. Checks that need it say so.
	TTL *ttlmgr.Report

	// StateDir is where status/marker files live; the engine checks read it.
	StateDir string
	// AppVersion is the net-merge version string.
	AppVersion string
	// Self is the path to this executable, used to run the engine's own CLI commands.
	Self string

	// Config is the diagnostics section of the Control Center settings.
	Config appcfg.Diagnostics
	// LocalIP is the host's primary local address, when the caller knows it.
	LocalIP string

	// IsAdmin reports whether this process can make system changes.
	IsAdmin bool
	// Platform is runtime.GOOS, injectable so the Windows checks can be exercised on Linux.
	Platform string

	// instanceRunning reports whether another net-merge instance is alive, when the platform
	// exposes a cheap way to ask. Nil means "no answer available", which the ports check
	// reports as inconclusive rather than guessing.
	instanceRunning func() bool

	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error

	// maxLines and maxBytes bound each evidence block.
	maxLines int
	maxBytes int
}

// NewEnv returns an Env with the real implementations filled in.
func NewEnv() *Env {
	return &Env{
		Runner:   execx.NewExecRunner(),
		Probes:   SystemProber{},
		IsAdmin:  false,
		Platform: runtime.GOOS,
		Now:      time.Now,
		Sleep:    sleepCtx,
		maxLines: DefaultEvidenceLines,
		maxBytes: DefaultEvidenceBytes,
	}
}

// DefaultEvidenceLines and DefaultEvidenceBytes bound how much command output one evidence
// block carries. A report that includes every line of a routing table is unreadable; one that
// includes none is useless. These are the middle.
const (
	DefaultEvidenceLines = 40
	DefaultEvidenceBytes = 8 << 10
)

// snapshot returns the snapshot to judge, calling the provider only when the caller did not
// hand one over. A failure is returned so a check can report it instead of pretending the
// system has no adapters.
func (e *Env) snapshot(ctx context.Context) (*inventory.Snapshot, error) {
	if e.SnapshotValue != nil {
		return e.SnapshotValue, nil
	}
	if e.Snapshot == nil {
		return nil, errors.New("no inventory source is configured")
	}
	return e.Snapshot(ctx)
}

// fixup fills in every field a check may assume, so a caller that builds an Env by hand (a
// test, or a future embedding) cannot trip a nil pointer.
func (e *Env) fixup() {
	if e.Runner == nil {
		e.Runner = execx.NewExecRunner()
	}
	if e.Probes == nil {
		e.Probes = SystemProber{}
	}
	if e.Now == nil {
		e.Now = time.Now
	}
	if e.Sleep == nil {
		e.Sleep = sleepCtx
	}
	if e.Platform == "" {
		e.Platform = runtime.GOOS
	}
	if e.maxLines <= 0 {
		e.maxLines = DefaultEvidenceLines
	}
	if e.maxBytes <= 0 {
		e.maxBytes = DefaultEvidenceBytes
	}
	if e.Config.TimeoutMs <= 0 {
		e.Config.TimeoutMs = 4000
	}
	if e.Config.TracerouteTimeoutMs <= 0 {
		e.Config.TracerouteTimeoutMs = 15000
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Registry is the set of checks. It is a value, so the dashboard can hold one and a test can
// build another without touching global state.
type Registry struct {
	env    *Env
	checks []Check
	byID   map[string]Check
}

// NewRegistry builds the standard check set for env.
func NewRegistry(env *Env) *Registry {
	if env == nil {
		env = NewEnv()
	}
	env.fixup()
	r := &Registry{env: env, byID: map[string]Check{}}
	r.add(allChecks()...)
	return r
}

func (r *Registry) add(checks ...Check) {
	for _, c := range checks {
		id := c.Meta().ID
		if _, dup := r.byID[id]; dup {
			// A duplicate id would make the CLI's -only flag ambiguous; skip loudly in the
			// log rather than silently shadowing.
			logx.Eventf(logx.LevelWarn, "diag.registry", "duplicate check id %q ignored", id)
			continue
		}
		r.byID[id] = c
		r.checks = append(r.checks, c)
	}
}

// Metas returns every check's description, in registry order.
func (r *Registry) Metas() []Meta {
	out := make([]Meta, 0, len(r.checks))
	for _, c := range r.checks {
		out = append(out, c.Meta())
	}
	return out
}

// Env exposes the environment a caller can adjust before running.
func (r *Registry) Env() *Env { return r.env }

// Options selects which checks run.
type Options struct {
	// Only limits the run to these check ids. Empty means every check the platform supports.
	Only []string
	// Categories limits the run to these categories (applied together with Only).
	Categories []Category
	// SkipAdminOnly leaves out checks that cannot work unelevated. By default they run and
	// report the skip, which is more informative.
	SkipAdminOnly bool
	// Disabled lists check ids the user turned off in settings.
	Disabled []string
	// Concurrency bounds simultaneous checks. Probe-heavy checks are mostly waiting; a small
	// number keeps the run quick without flooding a slow link.
	Concurrency int
	// PerCheckTimeout bounds one check on top of its own command timeouts.
	PerCheckTimeout time.Duration
}

// RunResult is the outcome of a combined run.
type RunResult struct {
	Started  time.Time     `json:"started"`
	Duration time.Duration `json:"duration"`
	Results  []Result      `json:"results"`
	// Summary is one line: counts by status and the worst status found.
	Summary string `json:"summary"`
	// Skipped lists checks that did not run, with the reason, so a partial run is visible.
	Skipped    map[string]string `json:"skipped,omitempty"`
	Platform   string            `json:"platform"`
	AppVersion string            `json:"appVersion"`
}

// Worst returns the most severe status in the run.
func (r RunResult) Worst() Status {
	w := StatusPass
	for _, res := range r.Results {
		w = Worse(w, res.Status)
	}
	return w
}

// Counts returns how many results have each status.
func (r RunResult) Counts() map[Status]int {
	m := map[Status]int{}
	for _, res := range r.Results {
		m[res.Status]++
	}
	return m
}

// RunAll runs the selected checks and returns every result in registry order, so two runs of
// the same registry diff cleanly. A check that panics is contained: the panic becomes an
// error result, because a diagnostic tool that crashes on a malformed command output is
// worse than one that reports it.
func (r *Registry) RunAll(ctx context.Context, opts Options) RunResult {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 4
	}
	res := RunResult{Started: r.env.Now(), Skipped: map[string]string{}, Platform: r.env.Platform, AppVersion: r.env.AppVersion}
	disabled := map[string]bool{}
	for _, id := range opts.Disabled {
		disabled[id] = true
	}
	only := map[string]bool{}
	for _, id := range opts.Only {
		only[id] = true
	}
	cat := map[Category]bool{}
	for _, c := range opts.Categories {
		cat[c] = true
	}

	type slot struct {
		idx    int
		result Result
	}
	var toRun []Check
	order := map[string]int{}
	for _, c := range r.checks {
		m := c.Meta()
		order[m.ID] = len(order)
		switch {
		case len(only) > 0 && !only[m.ID]:
			res.Skipped[m.ID] = "not selected for this run"
			continue
		case len(cat) > 0 && !cat[m.Category]:
			res.Skipped[m.ID] = "category not selected for this run"
			continue
		case disabled[m.ID]:
			res.Skipped[m.ID] = "turned off in Settings"
			continue
		case len(m.Platforms) > 0 && !platformAllowed(m.Platforms, r.env.Platform):
			res.Skipped[m.ID] = "not applicable on " + r.env.Platform
			continue
		case opts.SkipAdminOnly && m.NeedsAdmin && !r.env.IsAdmin:
			res.Skipped[m.ID] = "needs an elevated process and this run is not elevated"
			continue
		}
		toRun = append(toRun, c)
	}

	results := make([]slot, len(toRun))
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup
	start := time.Now()
	for i, c := range toRun {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, c Check) {
			defer wg.Done()
			defer func() { <-sem }()
			cctx := ctx
			var cancel context.CancelFunc
			if opts.PerCheckTimeout > 0 {
				cctx, cancel = context.WithTimeout(ctx, opts.PerCheckTimeout)
				defer cancel()
			}
			results[i] = slot{idx: i, result: safeRun(cctx, c, r.env)}
		}(i, c)
	}
	wg.Wait()
	res.Duration = time.Since(start)
	// Report in registry order, not completion order.
	sort.SliceStable(results, func(a, b int) bool { return results[a].idx < results[b].idx })
	for _, s := range results {
		res.Results = append(res.Results, s.result)
	}
	res.Summary = summarize(res)
	return res
}

// RunOne runs a single check by id. It reports ok=false when the id is unknown, so the caller
// can answer "no such check" instead of an empty success.
func (r *Registry) RunOne(ctx context.Context, id string) (Result, bool) {
	c, ok := r.byID[id]
	if !ok {
		return Result{}, false
	}
	m := c.Meta()
	if len(m.Platforms) > 0 && !platformAllowed(m.Platforms, r.env.Platform) {
		return Result{
			ID: m.ID, Title: m.Title, Category: m.Category, Status: StatusSkipped,
			Summary:  "not applicable on " + r.env.Platform,
			Started:  r.env.Now(),
			Evidence: nil,
		}, true
	}
	return safeRun(ctx, c, r.env), true
}

func safeRun(ctx context.Context, c Check, env *Env) (res Result) {
	m := c.Meta()
	defer func() {
		if p := recover(); p != nil {
			res = Result{
				ID: m.ID, Title: m.Title, Category: m.Category,
				Status:      StatusError,
				Summary:     fmt.Sprintf("the check hit an unexpected problem and was stopped: %v", p),
				Established: []string{},
				ErrorCodes:  []string{"diag_check_panic"},
				Started:     env.Now(),
			}
		}
	}()
	start := env.Now()
	res = c.Run(ctx, env)
	res.ID, res.Title, res.Category = m.ID, m.Title, m.Category
	res.Started = start
	if res.Duration == 0 {
		res.Duration = env.Now().Sub(start)
	}
	if res.Established == nil {
		res.Established = []string{}
	}
	return res
}

func platformAllowed(list []string, p string) bool {
	for _, s := range list {
		if strings.EqualFold(s, p) {
			return true
		}
	}
	return false
}

func summarize(r RunResult) string {
	c := r.Counts()
	parts := []string{}
	for _, s := range []Status{StatusError, StatusFail, StatusWarn, StatusPass, StatusInfo, StatusSkipped} {
		if c[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", c[s], s))
		}
	}
	if len(r.Skipped) > 0 {
		parts = append(parts, fmt.Sprintf("%d not run", len(r.Skipped)))
	}
	if len(parts) == 0 {
		return "no checks ran"
	}
	return strings.Join(parts, ", ")
}

// truncateOutput applies the evidence budget, reporting whether it cut anything. It keeps the
// head and the tail of the output: the first lines say what command it was and the last lines
// usually carry the error.
func (e *Env) truncateOutput(s string) ([]string, bool) {
	if int64(len(s)) > int64(e.maxBytes) {
		half := e.maxBytes / 2
		s = s[:half] + "\n... (output truncated at " + fmt.Sprint(e.maxBytes) + " bytes) ...\n" + s[len(s)-half:]
	}
	lines := execx.Detail(s, e.maxLines)
	truncated := false
	for _, l := range lines {
		if strings.Contains(l, "truncated") {
			truncated = true
		}
	}
	return lines, truncated
}

// evidenceFrom turns one execx.Result into an Evidence block with the exact command preserved.
func (e *Env) evidenceFrom(label string, argv []string, r execx.Result) Evidence {
	out, truncated := e.truncateOutput(r.Output())
	ev := Evidence{
		Label:     label,
		Command:   argv,
		Started:   r.Started,
		TimedOut:  r.TimedOut,
		Duration:  r.Duration,
		Output:    out,
		Truncated: truncated,
		Err:       r.Err,
	}
	if r.Started {
		code := r.ExitCode
		ev.ExitCode = &code
	}
	return ev
}

// noteEvidence records an in-process probe (no command) so a result is never a bare assertion.
func (e *Env) noteEvidence(label, note string, d time.Duration) Evidence {
	return Evidence{Label: label, Note: note, Duration: d, Started: true}
}

// run executes one command with a per-command timeout taken from settings, and returns both
// the raw result and the evidence block. Every command a check runs goes through here, so
// timeouts and output budgets cannot diverge between checks.
func (e *Env) run(ctx context.Context, label string, timeout time.Duration, name string, args ...string) (execx.Result, Evidence) {
	if timeout <= 0 {
		timeout = time.Duration(e.Config.TimeoutMs) * time.Millisecond
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	r := e.Runner.Run(cctx, name, args...)
	if cctx.Err() == context.DeadlineExceeded && !r.TimedOut {
		// A runner that ignores the context (a fake in a test) still reports the timeout.
		r.TimedOut = true
		r.Err = "timed out after " + timeout.String()
	}
	return r, e.evidenceFrom(label, append([]string{name}, args...), r)
}

// hasCommand reports whether an external command exists on this host, and records the reason
// when it does not, so a check can say "tracert is not installed" instead of failing.
func (e *Env) hasCommand(name string) (string, bool) {
	p, err := e.Runner.LookPath(name)
	if err != nil || p == "" {
		return "", false
	}
	return p, true
}

// missingCommandResult is the honest result for a check whose tool is not on this host.
func missingCommandResult(env *Env, meta Meta, tool string) Result {
	return Result{
		Status:       StatusSkipped,
		Summary:      tool + " is not available on this host, so this check could not run.",
		Established:  []string{},
		Inconclusive: []string{"whether the thing this check looks for is present: the tool that reads it is missing"},
		NextSteps:    []string{"Install " + tool + ", or use the other checks in this category."},
		ErrorCodes:   []string{"diag_tool_missing"},
	}
}

// localIPFor picks the address bound to a snapshot adapter, preferring IPv4. This is the
// best-effort source binding that per-adapter probes use.
func localIPFor(a inventory.Adapter) net.IP {
	if ip, ok := a.RoutableIPv4(); ok {
		return ip
	}
	if ip, ok := a.RoutableIPv6(); ok {
		return ip
	}
	return nil
}

// eligibleAdapters returns the adapters a per-link probe should test.
func eligibleAdapters(snap *inventory.Snapshot) []inventory.Adapter {
	if snap == nil {
		return nil
	}
	var out []inventory.Adapter
	for _, a := range snap.Usable() {
		if localIPFor(a) != nil {
			out = append(out, a)
		}
	}
	return out
}

// nonEmpty returns the first non-empty string, used so a message never renders as a bare
// colon when a platform leaves a field out.
func nonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
