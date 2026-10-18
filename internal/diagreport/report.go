package diagreport

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"net-merge/internal/diag"
	"net-merge/internal/engine"
	"net-merge/internal/inventory"
	"net-merge/internal/logx"
	"net-merge/internal/ttlmgr"
)

// Schema identifies the JSON document's shape, versioned so a consumer can tell one revision
// from another.
const Schema = "netmerge.diagreport/1"

// AppInfo is what the report says about itself: version, platform, and whether it could make
// system changes at all.
type AppInfo struct {
	Version   string    `json:"version"`
	Platform  string    `json:"platform"`
	Arch      string    `json:"arch"`
	Elevated  bool      `json:"elevated"`
	StateDir  string    `json:"stateDir,omitempty"`
	Generated time.Time `json:"generated"`
}

// Summary is the one-screen digest.
type Summary struct {
	WorstStatus  string         `json:"worstStatus"`
	Counts       map[string]int `json:"counts"`
	ChecksRan    int            `json:"checksRan"`
	ChecksNotRun int            `json:"checksNotRun"`
}

// Fact is one observation a check actually established, attributed to the check.
type Fact struct {
	Check     string `json:"check"`
	Statement string `json:"statement"`
}

// Hypothesis is a candidate explanation. It is deliberately a different type from Fact: a
// hypothesis is something to test, and the report never presents one as an observation.
type Hypothesis struct {
	Rank       int      `json:"rank"`
	Kind       string   `json:"kind"` // verified | hypothesis
	Confidence string   `json:"confidence,omitempty"`
	Statement  string   `json:"statement"`
	Supports   []string `json:"supports,omitempty"`
	NextSteps  []string `json:"nextSteps,omitempty"`
}

// EngineView is the bonding engine's own view, as read from its status file and CLI.
type EngineView struct {
	Running bool               `json:"running"`
	Mode    string             `json:"mode,omitempty"`
	V6      string             `json:"v6,omitempty"`
	Since   time.Time          `json:"since,omitempty"`
	PID     int                `json:"pid,omitempty"`
	NICs    []engine.SlotStats `json:"nics,omitempty"`
	Problem string             `json:"problem,omitempty"` // e.g. the CLI and the file disagreed
}

// Document is the whole report. It is the unit that is rendered, redacted and handed back to the
// caller; this package never writes or sends it anywhere itself.
type Document struct {
	Schema    string    `json:"schema"`
	Generated time.Time `json:"generated"`
	App       AppInfo   `json:"app"`

	Summary    Summary      `json:"summary"`
	Facts      []Fact       `json:"verifiedObservations"`
	Hypotheses []Hypothesis `json:"hypotheses"`

	Inventory    *inventory.Snapshot `json:"inventory,omitempty"`
	Engine       *EngineView         `json:"engine,omitempty"`
	TTL          *ttlmgr.Report      `json:"ttlAndHopLimit,omitempty"`
	Diagnostics  []diag.Result       `json:"diagnostics"`
	ChecksNotRun map[string]string   `json:"checksNotRun,omitempty"`
	Logs         []logx.Event        `json:"recentEvents,omitempty"`

	Caveats   []string        `json:"caveats"`
	Reading   []string        `json:"howToRead"`
	Redaction RedactionCounts `json:"redaction"`
}

// Limits bounds the export so a report stays readable. The live UI is not bounded by these; they
// apply to what leaves the application.
type Limits struct {
	EvidenceLines int // per evidence block
	Routes        int // route table entries kept
	Logs          int // recent events kept
	Adapters      int // adapters kept; 0 means all
}

// DefaultLimits are the export defaults.
func DefaultLimits() Limits {
	return Limits{EvidenceLines: 12, Routes: 60, Logs: 200, Adapters: 0}
}

// Options is everything Build needs. Every field is optional except Run: a report with only
// diagnostics is still a valid report.
type Options struct {
	Now      time.Time
	Version  string
	Platform string
	Arch     string
	Elevated bool
	StateDir string

	Snapshot *inventory.Snapshot
	Run      diag.RunResult
	Engine   *EngineView
	TTL      *ttlmgr.Report
	Logs     []logx.Event

	Limits Limits
}

// Build assembles the document. It performs no I/O and no redaction: those are separate so a
// caller can inspect the unredacted document in memory if it is the thing the user is looking
// at, and only redact what gets exported.
func Build(o Options) *Document {
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	if o.Limits == (Limits{}) {
		o.Limits = DefaultLimits()
	}
	run := trimRun(o.Run, o.Limits.EvidenceLines)
	doc := &Document{
		Schema:    Schema,
		Generated: o.Now,
		App: AppInfo{
			Version: o.Version, Platform: o.Platform, Arch: o.Arch,
			Elevated: o.Elevated, StateDir: o.StateDir, Generated: o.Now,
		},
		Inventory:    trimSnapshot(o.Snapshot, o.Limits),
		Engine:       o.Engine,
		TTL:          o.TTL,
		Diagnostics:  run.Results,
		ChecksNotRun: run.Skipped,
		Logs:         trimLogs(o.Logs, o.Limits.Logs),
	}
	doc.Summary = summarize(run)
	doc.Facts = factsFrom(run)
	doc.Hypotheses = Analyze(doc)
	doc.Reading = reading()
	doc.Caveats = caveats(o, run)
	return doc
}

// trimRun copies a run with evidence shortened to the export budget.
func trimRun(run diag.RunResult, maxLines int) diag.RunResult {
	if maxLines <= 0 {
		return run
	}
	out := run
	out.Results = make([]diag.Result, 0, len(run.Results))
	for _, res := range run.Results {
		r := res
		r.Established = append([]string{}, res.Established...)
		r.Inconclusive = append([]string{}, res.Inconclusive...)
		r.NextSteps = append([]string{}, res.NextSteps...)
		r.ErrorCodes = append([]string{}, res.ErrorCodes...)
		r.Items = append([]diag.Item{}, res.Items...)
		r.Evidence = make([]diag.Evidence, 0, len(res.Evidence))
		for _, ev := range res.Evidence {
			e := ev
			e.Command = append([]string{}, ev.Command...)
			if len(ev.Output) > maxLines {
				e.Output = append([]string{}, ev.Output[:maxLines]...)
				e.Output = append(e.Output, fmt.Sprintf("... (%d more line(s) in the application log)", len(ev.Output)-maxLines))
				e.Truncated = true
			} else {
				e.Output = append([]string{}, ev.Output...)
			}
			r.Evidence = append(r.Evidence, e)
		}
		out.Results = append(out.Results, r)
	}
	return out
}

func trimSnapshot(s *inventory.Snapshot, l Limits) *inventory.Snapshot {
	if s == nil {
		return nil
	}
	out := *s
	out.Adapters = append([]inventory.Adapter{}, s.Adapters...)
	if l.Adapters > 0 && len(out.Adapters) > l.Adapters {
		out.Adapters = out.Adapters[:l.Adapters]
	}
	out.Routes = append([]inventory.Route{}, s.Routes...)
	if l.Routes > 0 && len(out.Routes) > l.Routes {
		out.Routes = out.Routes[:l.Routes]
	}
	out.Gaps = append([]string{}, s.Gaps...)
	out.Errors = append([]string{}, s.Errors...)
	out.Warnings = append([]string{}, s.Warnings...)
	return &out
}

func trimLogs(events []logx.Event, max int) []logx.Event {
	if len(events) == 0 {
		return nil
	}
	if max > 0 && len(events) > max {
		events = events[len(events)-max:]
	}
	return append([]logx.Event{}, events...)
}

func summarize(run diag.RunResult) Summary {
	counts := map[string]int{}
	for _, r := range run.Results {
		counts[string(r.Status)]++
	}
	return Summary{
		WorstStatus:  string(run.Worst()),
		Counts:       counts,
		ChecksRan:    len(run.Results),
		ChecksNotRun: len(run.Skipped),
	}
}

// factsFrom collects what the checks actually established. Skipped and errored checks establish
// nothing, so they contribute nothing: an absent check must not read as a clean result.
func factsFrom(run diag.RunResult) []Fact {
	var out []Fact
	for _, r := range run.Results {
		switch r.Status {
		case diag.StatusSkipped, diag.StatusError, diag.StatusInfo:
			// Info results are descriptive (platform, firewall configuration); their lines are
			// already carried in the diagnostics section and are not evidence about a fault.
			if r.Status != diag.StatusInfo {
				continue
			}
			// Firewall and AV results are observations worth carrying; platform info is not.
			if r.ID == "platform.info" || r.ID == "dns.cache" || r.ID == "adapters.link" {
				continue
			}
		}
		for _, s := range r.Established {
			out = append(out, Fact{Check: r.ID, Statement: s})
		}
	}
	return out
}

// reading is the fixed explanation of how to read the report. It is written for a reader with no
// context - human or machine - and is deliberately blunt about the limits.
func reading() []string {
	return []string{
		`"verified observations" are things the listed checks actually established on this host at the listed time. A check that did not run, or was skipped, establishes nothing - absence of a finding is not a clean bill of health.`,
		`"hypotheses" are candidate explanations inferred from those observations, each labelled with a confidence. They are things to test, not conclusions; a hypothesis that contradicts a later observation is wrong, not the observation.`,
		`"inconclusive" entries inside a check state what that check could not decide and why. They are part of the result, not noise: they are where a false "everything is fine" would otherwise come from.`,
		`a link-speed figure is a negotiated rate, never a measured throughput; per-adapter counters are the OS's totals for the whole adapter and include traffic from every application, not only this one.`,
		`"via net-merge" rates exist only while the bonding engine is running, and only cover traffic the engine relayed; ordinary traffic that bypasses it does not appear.`,
		`IPv4 TTL and IPv6 hop limit are packet header values, and are unrelated to DNS record TTLs or traceroute hop counts even though all are called "TTL" somewhere.`,
	}
}

// caveats states the limits of this particular report, so nobody has to infer them.
func caveats(o Options, run diag.RunResult) []string {
	var out []string
	out = append(out,
		"this report contains only what the checks listed here observed; nothing was inferred from a model of how Windows usually behaves.")
	if !o.Elevated {
		out = append(out,
			"the report was produced without administrator/root rights, so checks that need elevation were skipped or reported as not applicable, and no system change was attempted.")
	}
	if n := len(run.Skipped); n > 0 {
		out = append(out, fmt.Sprintf("%d check(s) did not run; the reason for each is listed under \"checks not run\".", n))
	}
	var errored []string
	for _, r := range run.Results {
		if r.Status == diag.StatusError {
			errored = append(errored, r.ID)
		}
	}
	if len(errored) > 0 {
		out = append(out, "these checks failed to run to completion and establish nothing: "+strings.Join(errored, ", ")+".")
	}
	if o.Snapshot == nil {
		out = append(out, "no adapter inventory was attached, so per-adapter observations are limited to what the diagnostic commands reported.")
	}
	if o.TTL == nil {
		out = append(out, "no TTL/hop-limit inspection was attached; this report says nothing about packet header values.")
	}
	out = append(out,
		"redaction removes values by pattern and by label; a secret with neither a recognisable shape nor a label cannot be detected, so inspect the file before sharing it.")
	return out
}

// Bundle is the pair of rendered artifacts plus what was redacted while producing them.
type Bundle struct {
	// BaseName is the suggested file name without an extension.
	BaseName string
	// JSON and Text are the renderings, redacted.
	JSON []byte
	Text []byte
	// Counts describes what was removed from the exported bytes.
	Counts RedactionCounts
	// Entries is the mapping shown to the user on their own terminal. It is deliberately not
	// part of either artifact.
	Entries []Entry
}

// Bundle renders the report twice - once as JSON for a machine, once as text for a reader - with
// one redactor, so both files use the same placeholders for the same values.
//
// The counts that appear inside the JSON are measured by a first pass over the document before
// they are written into it, and then the file is rendered again with the same redactor. The
// redaction is idempotent, so the second render replaces nothing new; TestRenderingIsIdempotent
// holds that property.
func (d *Document) Bundle(p Policy) (Bundle, error) {
	d.Redaction = RedactionCounts{}
	probeJSON, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return Bundle{}, fmt.Errorf("rendering the report: %w", err)
	}
	r := NewRedactor(p)
	_ = r.String(string(probeJSON)) // first pass: learn what needs removing
	d.Redaction = r.Counts()

	finalJSON, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return Bundle{}, fmt.Errorf("rendering the report: %w", err)
	}
	b := Bundle{
		BaseName: "net-merge-diagnostics-" + d.Generated.Format("20060102-150405"),
		JSON:     []byte(r.String(string(finalJSON))),
		Text:     []byte(r.String(d.Text())),
		Entries:  r.Entries(),
	}
	b.Counts = r.Counts()
	return b, nil
}

// WriteName returns the two file names a bundle should be written under.
func (b Bundle) WriteName(dir string) (txt, js string) {
	return filepath.Join(dir, b.BaseName+".txt"), filepath.Join(dir, b.BaseName+".json")
}

// Text renders the human- and model-readable form. It is built to be read top to bottom by
// someone who was not present when it was produced.
func (d *Document) Text() string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }

	w("net-merge diagnostic report\n")
	w("schema: %s\n", d.Schema)
	w("generated: %s\n", d.Generated.Format(time.RFC3339))
	w("app: net-merge %s (%s/%s), elevated: %s\n", d.App.Version, d.App.Platform, d.App.Arch, yesno(d.App.Elevated))
	if d.App.StateDir != "" {
		w("state directory: %s\n", d.App.StateDir)
	}

	w("\n== Summary ==\n")
	w("worst finding: %s\n", d.Summary.WorstStatus)
	w("checks run: %d; not run: %d\n", d.Summary.ChecksRan, d.Summary.ChecksNotRun)
	var statuses []string
	for s, n := range d.Summary.Counts {
		statuses = append(statuses, fmt.Sprintf("%s=%d", s, n))
	}
	sort.Strings(statuses)
	w("status counts: %s\n", strings.Join(statuses, " "))

	w("\n== How to read this report ==\n")
	for _, line := range d.Reading {
		w("- %s\n", line)
	}

	w("\n== Caveats for this report ==\n")
	for _, c := range d.Caveats {
		w("- %s\n", c)
	}

	if d.Redaction.Total > 0 {
		w("\n== Redaction ==\n")
		w("%s were replaced with placeholders before this file was written: %s.\n", plural(d.Redaction.Total, "item", "items"), d.Redaction.Describe())
		w("the values themselves were shown on the generating machine's own screen and are not in this file.\n")
	} else {
		w("\n== Redaction ==\n")
		w("nothing matched the redaction rules. That is not a guarantee that the file is free of identifying detail; it means the patterns found none.\n")
	}

	if len(d.Facts) > 0 {
		w("\n== Verified observations ==\n")
		byCheck := map[string][]string{}
		var order []string
		for _, f := range d.Facts {
			if _, ok := byCheck[f.Check]; !ok {
				order = append(order, f.Check)
			}
			byCheck[f.Check] = append(byCheck[f.Check], f.Statement)
		}
		sort.Strings(order)
		for _, check := range order {
			w("\n[%s]\n", check)
			for _, s := range byCheck[check] {
				w("  - %s\n", s)
			}
		}
	}

	if len(d.Hypotheses) > 0 {
		w("\n== Hypotheses (candidates to test, not conclusions) ==\n")
		for _, h := range d.Hypotheses {
			tag := h.Kind
			if h.Confidence != "" {
				tag += ", " + h.Confidence + " confidence"
			}
			w("\n%d. (%s) %s\n", h.Rank, tag, h.Statement)
			if len(h.Supports) > 0 {
				w("   supported by: %s\n", strings.Join(h.Supports, ", "))
			}
			for _, n := range h.NextSteps {
				w("   next: %s\n", n)
			}
		}
	}

	if d.Inventory != nil {
		w("\n== Interfaces ==\n")
		w("source: %s; taken: %s\n", d.Inventory.Source, d.Inventory.Taken.Format(time.RFC3339))
		w("total negotiated link speed: %s (a rate, not a measurement)\n", humanRate(d.Inventory.LinkSpeedTotalBps))
		for _, a := range d.Inventory.Adapters {
			w("\n- %s (index %d): %s, link %s", a.Name, a.Index, a.Kind, a.Link)
			if a.SpeedBps > 0 {
				w(", negotiated %s", humanRate(a.SpeedBps))
			}
			if a.MTU > 0 {
				w(", MTU %d", a.MTU)
			}
			w("\n")
			if a.Description != "" {
				w("  description: %s\n", a.Description)
			}
			w("  state: %s", a.Status)
			if a.Exclusion != "" {
				w(" - %s (%s)", a.Exclusion, a.ExclusionCode)
			}
			w("\n")
			if len(a.IPv4) > 0 || len(a.IPv6) > 0 {
				w("  addresses: %s\n", strings.Join(addressLines(a), ", "))
			}
			if len(a.Gateways4) > 0 || len(a.Gateways6) > 0 {
				w("  gateways: %s\n", strings.Join(append(append([]string{}, a.Gateways4...), a.Gateways6...), ", "))
			}
			if len(a.DNS4) > 0 || len(a.DNS6) > 0 {
				w("  dns: %s\n", strings.Join(append(append([]string{}, a.DNS4...), a.DNS6...), ", "))
			}
			if a.Metric4 != nil || a.Metric6 != nil {
				w("  interface metric: %s/%s\n", metric(a.Metric4), metric(a.Metric6))
			}
			if a.DriverProvider != "" || a.DriverVersion != "" {
				w("  driver: %s %s\n", nonEmpty(a.DriverProvider, "unknown provider"), nonEmpty(a.DriverVersion, "unknown version"))
			}
			if a.Counters != nil {
				w("  counters: %s in / %s out since the adapter's counters last reset\n", humanBytes(a.Counters.In), humanBytes(a.Counters.Out))
			}
			if a.Rates != nil {
				w("  rate over the last %.1fs: %s/s in / %s/s out\n", a.Rates.Span, humanBytes(uint64(a.Rates.InPerSec)), humanBytes(uint64(a.Rates.OutPerSec)))
			}
			if a.Health != nil && a.Health.Checked {
				if a.Health.OK {
					w("  reachability: ok, %.1f ms, %s\n", a.Health.RTTms, a.Health.Endpoint)
				} else {
					w("  reachability: failed, %s\n", nonEmpty(a.Health.Detail, a.Health.Endpoint))
				}
			}
			if a.Engine {
				w("  bonding engine: in use")
				if a.EngineAssigned != nil {
					w(" (%d connection(s) assigned)", *a.EngineAssigned)
				}
				w("\n")
			}
			for _, g := range a.Gaps {
				w("  not reported by this platform: %s\n", g)
			}
			for _, wl := range a.Warnings {
				w("  warning: %s\n", wl)
			}
		}
		if len(d.Inventory.Routes) > 0 {
			w("\n== Routes (first %d) ==\n", len(d.Inventory.Routes))
			for _, r := range d.Inventory.Routes {
				def := ""
				if r.Default {
					def = " [default]"
				}
				w("- %s via %s dev %s metric %d%s", nonEmpty(r.Destination, "default"), nonEmpty(r.NextHop, "on-link"), nonEmpty(r.Name, fmt.Sprint(r.Index)), r.Metric, def)
				if r.Protocol != "" {
					w(" (%s)", r.Protocol)
				}
				w("\n")
			}
		}
		for _, g := range d.Inventory.Gaps {
			w("\nplatform gap: %s\n", g)
		}
		for _, wl := range d.Inventory.Warnings {
			w("\nwarning: %s\n", wl)
		}
		for _, e := range d.Inventory.Errors {
			w("\ncollection problem: %s\n", e)
		}
	}

	if d.Engine != nil {
		w("\n== Bonding engine ==\n")
		if d.Engine.Running {
			w("running: yes, mode %s", d.Engine.Mode)
			if d.Engine.PID != 0 {
				w(", pid %d", d.Engine.PID)
			}
			if !d.Engine.Since.IsZero() {
				w(", up %s", time.Since(d.Engine.Since).Truncate(time.Second))
			}
			w("\n")
			if d.Engine.V6 != "" {
				w("IPv6 handling: %s\n", d.Engine.V6)
			}
			for _, n := range d.Engine.NICs {
				w("- %s: state %s, weight %.2f, %d active / %d total connection(s)", n.Name, nonEmpty(n.State, "unknown"), n.Weight, n.Active, n.Total)
				if n.RateIn > 0 || n.RateOut > 0 {
					w(", relaying %.0f B/s in / %.0f B/s out", n.RateIn, n.RateOut)
				}
				w("\n")
			}
		} else {
			w("running: no\n")
		}
		if d.Engine.Problem != "" {
			w("note: %s\n", d.Engine.Problem)
		}
	}

	if d.TTL != nil {
		w("\n== IPv4 TTL and IPv6 hop limit ==\n")
		w("scope: packet header values only. DNS record TTLs and traceroute hop counts are different things and are reported separately below.\n")
		w("elevated: %s (%s)\n", yesno(d.TTL.Elevated), d.TTL.Elevation)
		w("configuration enabled (a stored choice, not an action this report took): %s\n", yesno(d.TTL.Config.Enabled))
		for _, s := range d.TTL.Settings {
			w("- %s: %s", s.ID, ttlValue(s))
			if s.ValueOrigin != "" {
				w(" (read from %s)", s.ValueOrigin)
			}
			if !s.Writable {
				w(" [not changeable: %s]", nonEmpty(s.WritableReason, "reason not reported"))
			}
			if o, ok := d.TTL.Captured[s.ID]; ok {
				w(" [original captured before the first change: %s]", ttlOriginal(o))
			}
			w("\n")
		}
		for _, s := range d.TTL.NotSettings {
			w("- not a settable value here: %s: %s\n", s.ID, ttlValue(s))
		}
		for _, r := range d.TTL.ReadErrors {
			w("- could not be read: %s: %s (code %s)\n", r.Setting.ID, r.Message, nonEmpty(r.Code, "unspecified"))
			for _, det := range r.Details {
				w("    %s\n", det)
			}
		}
		for _, wl := range d.TTL.Warnings {
			w("- warning: %s\n", wl)
		}
	}

	w("\n== Diagnostics ==\n")
	byCat := map[diag.Category][]diag.Result{}
	var cats []diag.Category
	for _, r := range d.Diagnostics {
		if _, ok := byCat[r.Category]; !ok {
			cats = append(cats, r.Category)
		}
		byCat[r.Category] = append(byCat[r.Category], r)
	}
	for _, c := range diag.Categories() {
		res, ok := byCat[c]
		if !ok {
			continue
		}
		w("\n--- %s ---\n", c)
		for _, r := range res {
			w("\n[%s] %s\n", r.Status, r.ID)
			w("  %s\n", r.Summary)
			for _, s := range r.Established {
				w("  established: %s\n", s)
			}
			for _, s := range r.Inconclusive {
				w("  not established: %s\n", s)
			}
			for _, s := range r.NextSteps {
				w("  next: %s\n", s)
			}
			if len(r.ErrorCodes) > 0 {
				w("  codes: %s\n", strings.Join(r.ErrorCodes, ", "))
			}
			for _, e := range r.Evidence {
				w("  evidence: %s\n", e.Label)
				if len(e.Command) > 0 {
					w("    $ %s\n", shellJoin(e.Command))
				}
				meta := fmt.Sprintf("    started=%t", e.Started)
				if e.ExitCode != nil {
					meta += fmt.Sprintf(" exit=%d", *e.ExitCode)
				}
				if e.TimedOut {
					meta += " timed out"
				}
				if e.Duration > 0 {
					meta += fmt.Sprintf(" in %s", e.Duration.Truncate(time.Millisecond))
				}
				if e.Err != "" {
					meta += " err=" + e.Err
				}
				w("%s\n", meta)
				if e.Note != "" {
					w("    note: %s\n", e.Note)
				}
				for _, line := range e.Output {
					w("    | %s\n", line)
				}
				if e.Truncated {
					w("    | (output trimmed for the report)\n")
				}
			}
		}
	}

	if len(d.ChecksNotRun) > 0 {
		w("\n== Checks not run ==\n")
		var ids []string
		for id := range d.ChecksNotRun {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			w("- %s: %s\n", id, d.ChecksNotRun[id])
		}
	}

	if len(d.Logs) > 0 {
		w("\n== Recent events ==\n")
		for _, e := range d.Logs {
			line := fmt.Sprintf("%s %-5s %s", e.At.Format("15:04:05"), e.LevelID, e.Message)
			if e.Code != "" {
				line += " [" + e.Code + "]"
			}
			if e.Detail != "" {
				line += " - " + e.Detail
			}
			w("- %s\n", line)
		}
	}

	w("\nend of report\n")
	return b.String()
}

// helpers ---------------------------------------------------------------------------------------

func yesno(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

func metric(p *int) string {
	if p == nil {
		return "unknown"
	}
	return fmt.Sprint(*p)
}

// ttlValue renders a setting's effective value. Absent is a real state on Windows - the registry
// value is often not written, which means the operating system's built-in default is in effect -
// so it is never rendered as a zero.
func ttlValue(s ttlmgr.Setting) string {
	if s.Value == nil {
		return "not configured (the system's own default is in effect)"
	}
	return fmt.Sprint(*s.Value)
}

func ttlOriginal(o ttlmgr.Original) string {
	v := "not read"
	if o.Value != nil {
		v = fmt.Sprint(*o.Value)
	}
	if o.Explicit {
		return v + ", explicitly set on the platform"
	}
	return v + ", the platform's own default was in effect"
}

func nonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func addressLines(a inventory.Adapter) []string {
	var out []string
	for _, addr := range a.IPv4 {
		out = append(out, fmt.Sprintf("%s/%d", addr.Address, addr.Prefix))
	}
	for _, addr := range a.IPv6 {
		out = append(out, fmt.Sprintf("%s/%d", addr.Address, addr.Prefix))
	}
	return out
}

// shellJoin renders an argv readably without pretending to quote it for a shell, since the
// evidence is for reading, not for re-running blindly.
func shellJoin(argv []string) string {
	parts := make([]string, 0, len(argv))
	for _, a := range argv {
		if strings.ContainsAny(a, " \t\"'") {
			parts = append(parts, "\""+strings.ReplaceAll(a, "\"", "\\\"")+"\"")
		} else {
			parts = append(parts, a)
		}
	}
	return strings.Join(parts, " ")
}

func humanRate(bps uint64) string {
	switch {
	case bps >= 1_000_000_000:
		return fmt.Sprintf("%.1f Gbps", float64(bps)/1e9)
	case bps >= 1_000_000:
		return fmt.Sprintf("%.1f Mbps", float64(bps)/1e6)
	case bps >= 1_000:
		return fmt.Sprintf("%.1f kbps", float64(bps)/1e3)
	default:
		return fmt.Sprintf("%d bps", bps)
	}
}

func humanBytes(n uint64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.2f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
