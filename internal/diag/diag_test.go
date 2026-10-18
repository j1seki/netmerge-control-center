package diag

// Tests for the framework itself: the registry, selection, containment, evidence budgets and
// the promise that a result never overstates what ran.

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"net-merge/internal/inventory"
)

// TestEveryCheckIsWellFormed enforces the contract the UI and the exported report rely on: a
// unique id, a title, a purpose, and at least one explicit statement of what a pass proves.
func TestEveryCheckIsWellFormed(t *testing.T) {
	env, _, _ := testEnv("linux")
	reg := NewRegistry(env)
	metas := reg.Metas()
	if len(metas) < 30 {
		t.Fatalf("the registry has %d checks; this report is meant to cover the platform broadly", len(metas))
	}
	seen := map[string]bool{}
	for _, m := range metas {
		if m.ID == "" || strings.ContainsAny(m.ID, " \t") {
			t.Errorf("check %q has an unusable id: %q", m.Title, m.ID)
		}
		if seen[m.ID] {
			t.Errorf("duplicate check id %q", m.ID)
		}
		seen[m.ID] = true
		if m.Title == "" {
			t.Errorf("check %q has no title", m.ID)
		}
		if m.Purpose == "" {
			t.Errorf("check %q has no purpose", m.ID)
		}
		if len(m.Establishes) == 0 {
			t.Errorf("check %q does not state what a pass establishes", m.ID)
		}
		if !m.Category.Valid() {
			t.Errorf("check %q has an unknown category %q", m.ID, m.Category)
		}
	}
}

func TestCategoryValid(t *testing.T) {
	for _, c := range Categories() {
		if !c.Valid() {
			t.Errorf("category %q is listed but reports itself invalid", c)
		}
	}
	if Category("nonsense").Valid() {
		t.Error("an unknown category reported itself as valid")
	}
}

// TestSelectionRules checks that Only, Categories, Disabled and platform filters are each
// applied, and that an excluded check is reported as skipped with a reason rather than
// vanishing.
func TestSelectionRules(t *testing.T) {
	env, _, _ := testEnv("linux")
	env.SnapshotValue = snap([]inventory.Adapter{adapter("eth0", 2, "10.0.0.5")})
	reg := NewRegistry(env)
	ctx := context.Background()

	t.Run("only", func(t *testing.T) {
		res := reg.RunAll(ctx, Options{Only: []string{"platform.info"}, Concurrency: 2})
		if len(res.Results) != 1 || res.Results[0].ID != "platform.info" {
			t.Fatalf("Only selected %d result(s)", len(res.Results))
		}
		if res.Skipped["dns.resolve"] == "" {
			t.Error("a check left out by Only was not reported as skipped")
		}
	})

	t.Run("category", func(t *testing.T) {
		res := reg.RunAll(ctx, Options{Categories: []Category{CatPlatform}, Concurrency: 2})
		for _, r := range res.Results {
			if r.Category != CatPlatform {
				t.Errorf("category filter let %q (%s) through", r.ID, r.Category)
			}
		}
	})

	t.Run("disabled", func(t *testing.T) {
		res := reg.RunAll(ctx, Options{Disabled: []string{"platform.info"}, Concurrency: 2})
		for _, r := range res.Results {
			if r.ID == "platform.info" {
				t.Error("a disabled check ran anyway")
			}
		}
		if !strings.Contains(res.Skipped["platform.info"], "Settings") {
			t.Errorf("the skip reason should point at Settings, got %q", res.Skipped["platform.info"])
		}
	})

	t.Run("platform", func(t *testing.T) {
		res := reg.RunAll(ctx, Options{Only: []string{"security.firewall"}, Concurrency: 1})
		if res.Skipped["security.firewall"] == "" {
			t.Error("a Windows-only check was not skipped on linux")
		}
	})
}

// TestPanicIsContained proves a check that panics becomes an error result rather than taking the
// run down: a diagnostic tool that crashes on malformed input is worse than one that reports it.
func TestPanicIsContained(t *testing.T) {
	env, _, _ := testEnv("linux")
	reg := NewRegistry(env)
	reg.add(funcCheck{
		meta: Meta{
			ID: "test.panic", Title: "Panicking check", Category: CatPlatform,
			Purpose: "test", Establishes: []string{"nothing; it panics"},
		},
		run: func(context.Context, *Env) Result { panic("simulated malformed command output") },
	})
	res, ok := reg.RunOne(context.Background(), "test.panic")
	if !ok {
		t.Fatal("the check was not registered")
	}
	if res.Status != StatusError {
		t.Fatalf("a panicking check reported %q, want error", res.Status)
	}
	if len(res.ErrorCodes) == 0 || res.ErrorCodes[0] != "diag_check_panic" {
		t.Errorf("the panic result carries codes %v", res.ErrorCodes)
	}
}

// TestUnknownCheckIDIsReported makes sure asking for a check that does not exist fails loudly
// instead of running an empty success.
func TestUnknownCheckIDIsReported(t *testing.T) {
	env, _, _ := testEnv("linux")
	reg := NewRegistry(env)
	if _, ok := reg.RunOne(context.Background(), "no.such.check"); ok {
		t.Fatal("an unknown check id was accepted")
	}
}

// TestEvidenceBudget checks that a command producing a wall of output is trimmed, and that the
// trim is flagged so a reader knows the report is not complete.
func TestEvidenceBudget(t *testing.T) {
	env, _, _ := testEnv("linux")
	env.maxLines = 10
	env.maxBytes = 2048
	var b strings.Builder
	for i := 0; i < 500; i++ {
		b.WriteString("route entry line with some content\n")
	}
	out, truncated := env.truncateOutput(b.String())
	if !truncated {
		t.Error("a 500-line output was not reported as truncated")
	}
	if len(out) > 12 {
		t.Errorf("the line budget was not applied: %d lines kept", len(out))
	}
}

// TestResultsAreDeterministicOrder checks that two runs of the same registry return results in
// the same order even though the checks themselves run concurrently.
func TestResultsAreDeterministicOrder(t *testing.T) {
	env, _, _ := testEnv("linux")
	env.SnapshotValue = snap([]inventory.Adapter{adapter("eth0", 2, "10.0.0.5")})
	reg := NewRegistry(env)
	opts := Options{Categories: []Category{CatPlatform, CatAdapters, CatDNS, CatPath}, Concurrency: 8}
	first := reg.RunAll(context.Background(), opts)
	second := reg.RunAll(context.Background(), opts)
	if len(first.Results) != len(second.Results) {
		t.Fatalf("run sizes differ: %d vs %d", len(first.Results), len(second.Results))
	}
	for i := range first.Results {
		if first.Results[i].ID != second.Results[i].ID {
			t.Fatalf("result %d differs between runs: %s vs %s", i, first.Results[i].ID, second.Results[i].ID)
		}
	}
}

// TestEveryResultCarriesASummary is the cheapest possible guard against a check that returns a
// bare status: every result must say something in words.
func TestEveryResultCarriesASummary(t *testing.T) {
	env, _, _ := testEnv("linux")
	env.SnapshotValue = snap(
		[]inventory.Adapter{
			adapter("eth0", 2, "10.0.0.5", withGateway("10.0.0.1"), withDNS("10.0.0.1")),
			adapter("vpn0", 7, "10.8.0.2", withState(inventory.StateExcluded, inventory.ExclVirtual)),
		},
		inventory.Route{Family: "ipv4", Destination: "0.0.0.0/0", NextHop: "10.0.0.1", Index: 2, Name: "eth0", Metric: 100, Default: true},
	)
	reg := NewRegistry(env)
	res := reg.RunAll(context.Background(), Options{
		Concurrency:     4,
		PerCheckTimeout: 5 * time.Second,
	})
	for _, r := range res.Results {
		if strings.TrimSpace(r.Summary) == "" {
			t.Errorf("check %q returned no summary (status %s)", r.ID, r.Status)
		}
		if r.Established == nil {
			t.Errorf("check %q returned a nil Established list, which renders as a claim of none", r.ID)
		}
	}
	if res.Summary == "" {
		t.Error("the run has no summary line")
	}
}

// TestResultsMarshalHonestly checks the JSON contract the export relies on: a result that
// establishes nothing still says so, and a measurement is absent rather than zero when nothing
// was measured.
func TestResultsMarshalHonestly(t *testing.T) {
	res := Result{
		ID: "x", Title: "X", Category: CatPath, Status: StatusWarn, Summary: "s",
		Established: []string{}, Evidence: []Evidence{{Label: "l", Started: true}},
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, `"established":[]`) {
		t.Errorf("an empty established list should serialize as [], got %s", s)
	}
	if strings.Contains(s, `"measure"`) {
		t.Errorf("an unmeasured result should not carry a measure field, got %s", s)
	}
}

// TestRunOneHonoursPlatform makes sure a platform-limited check asked for by id on the wrong
// platform reports the skip rather than running commands that do not exist there.
func TestRunOneHonoursPlatform(t *testing.T) {
	env, _, _ := testEnv("linux")
	reg := NewRegistry(env)
	res, ok := reg.RunOne(context.Background(), "security.firewall")
	if !ok {
		t.Fatal("the check is not registered")
	}
	if res.Status != StatusSkipped {
		t.Fatalf("a Windows-only check on linux reported %q, want skipped", res.Status)
	}
}

// TestEnvFixupKeepsRunner ensures a hand-built Env cannot end up with nil dependencies.
func TestEnvFixupKeepsRunner(t *testing.T) {
	env := &Env{}
	env.fixup()
	if env.Runner == nil || env.Probes == nil || env.Now == nil || env.Sleep == nil {
		t.Fatal("fixup left a nil dependency")
	}
	if env.Platform == "" {
		t.Fatal("fixup left the platform empty")
	}
	if err := env.Sleep(context.Background(), time.Microsecond); err != nil {
		t.Fatalf("the default sleep returned %v", err)
	}
}

// TestSummaryCountsWorstStatus checks the line a user reads first.
func TestSummaryCountsWorstStatus(t *testing.T) {
	r := RunResult{Results: []Result{
		{Status: StatusPass}, {Status: StatusWarn}, {Status: StatusPass},
	}}
	if got := r.Worst(); got != StatusWarn {
		t.Errorf("Worst = %q, want warn", got)
	}
	if s := summarize(r); !strings.Contains(s, "2 pass") || !strings.Contains(s, "1 warn") {
		t.Errorf("summary %q does not count both statuses", s)
	}
}

// TestStatusRanking pins the severity order used everywhere a report leads with the worst
// finding.
func TestStatusRanking(t *testing.T) {
	order := []Status{StatusPass, StatusInfo, StatusSkipped, StatusWarn, StatusFail, StatusError}
	for i := 1; i < len(order); i++ {
		if order[i].Rank() <= order[i-1].Rank() {
			t.Errorf("%s does not outrank %s", order[i], order[i-1])
		}
	}
	if Worse(StatusSkipped, StatusWarn) != StatusWarn {
		t.Error("a skipped check outranked a warning")
	}
}

// TestAsDNSUnwraps checks the helper that finds a *net.DNSError inside a wrapped error, because
// the difference between NXDOMAIN and a timeout is the whole diagnosis.
func TestAsDNSUnwraps(t *testing.T) {
	inner := &net.DNSError{Err: "no such host", IsNotFound: true}
	wrapped := wrappedErr{inner}
	var got *net.DNSError
	if !asDNS(wrapped, &got) {
		t.Fatal("the wrapper hid the DNS error")
	}
	if !got.IsNotFound {
		t.Error("the unwrapped error lost IsNotFound")
	}
	if asDNS(errors.New("plain"), &got) {
		t.Error("a plain error was reported as a DNS error")
	}
}

type wrappedErr struct{ e error }

func (w wrappedErr) Error() string { return "wrapped: " + w.e.Error() }
func (w wrappedErr) Unwrap() error { return w.e }
