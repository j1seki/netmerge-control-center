package ttlmgr

// The tests in this file drive the TTL manager against a fake backend and a real on-disk
// store under t.TempDir(). The fake backend is a SIMULATION of a platform: it models readable
// values, explicit configuration, writes that fail, and writes that report success while
// silently doing nothing. Nothing here touches a real network setting, and nothing here is a
// physical-network test.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- fake backend ----------------------------------------------------------------------

type fakeWrite struct {
	Ref   SettingRef
	Value int
}

type fakeBackend struct {
	mu sync.Mutex

	values map[SettingID]int
	writes []fakeWrite

	readErrs     map[SettingID]error
	writeErrFn   func(ref SettingRef, value int) error
	ignoreWrites map[SettingID]bool

	caps Capabilities
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{
		values: map[SettingID]int{
			IDv4Default: 128, // the Windows built-in default for both families
			IDv6Default: 128,
		},
		caps: Capabilities{
			Platform:  "test-simulation",
			Supported: true,
			Readable:  true,
			Commands: []CommandCapability{
				{Command: "Set-NetIPInterface", Parameter: "CurrentHopLimit", Present: true, HasParam: true},
			},
			Notes: []string{"simulated backend used by the automated test suite; no real setting is touched"},
		},
	}
}

func (f *fakeBackend) Name() string { return "fake-simulation" }

func (f *fakeBackend) Capabilities(context.Context) Capabilities { return f.caps }

func (f *fakeBackend) Read(_ context.Context, ref SettingRef) (Observed, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.readErrs[ref.ID]; err != nil {
		return Observed{}, err
	}
	v, ok := f.values[ref.ID]
	if !ok {
		return Observed{Origin: "fake:not-configured"}, nil
	}
	return Observed{Value: intPtr(v), Explicit: true, Origin: "fake:configured"}, nil
}

func (f *fakeBackend) Write(_ context.Context, ref SettingRef, value int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes = append(f.writes, fakeWrite{Ref: ref, Value: value})
	if f.writeErrFn != nil {
		if err := f.writeErrFn(ref, value); err != nil {
			return err
		}
	}
	if f.ignoreWrites[ref.ID] {
		return nil // reports success, has no effect: the verification step must catch this
	}
	f.values[ref.ID] = value
	return nil
}

func (f *fakeBackend) Unset(_ context.Context, ref SettingRef) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.values, ref.ID)
	return nil
}

func (f *fakeBackend) value(id SettingID) (int, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.values[id]
	return v, ok
}

func (f *fakeBackend) writeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.writes)
}

func (f *fakeBackend) snapshotWrites() []fakeWrite {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeWrite(nil), f.writes...)
}

func (f *fakeBackend) lastWrite() (fakeWrite, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.writes) == 0 {
		return fakeWrite{}, false
	}
	return f.writes[len(f.writes)-1], true
}

// --- helpers ---------------------------------------------------------------------------

func newTestManager(t *testing.T, backend Backend) (*Manager, *Store) {
	t.Helper()
	store := NewStore(filepath.Join(t.TempDir(), "state"))
	m := NewManager(store, backend)
	m.lockWait = 400 * time.Millisecond
	return m, store
}

func settingByID(rep Report, id SettingID) (Setting, bool) {
	for _, s := range rep.Settings {
		if s.ID == id {
			return s, true
		}
	}
	return Setting{}, false
}

func mustValue(t *testing.T, s Setting, want int) {
	t.Helper()
	if s.Value == nil {
		t.Fatalf("%s has no value, want %d", s.ID, want)
	}
	if *s.Value != want {
		t.Fatalf("%s = %d, want %d", s.ID, *s.Value, want)
	}
}

// --- inspection ------------------------------------------------------------------------

func TestInspectReportsRealValuesAndScopes(t *testing.T) {
	fb := newFakeBackend()
	iface := IfaceInfo{Index: 7, Name: "Wi-Fi"}
	fb.values[InterfaceSettingID(FamilyIPv4, 7, "Wi-Fi")] = 64
	m, _ := newTestManager(t, fb)

	rep, err := m.Inspect(context.Background(), []IfaceInfo{iface})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if !rep.Capabilities.Supported {
		t.Fatal("capabilities should be supported with the fake backend")
	}
	if len(rep.ReadErrors) != 0 {
		t.Fatalf("unexpected read errors: %+v", rep.ReadErrors)
	}

	sys4, ok := settingByID(rep, IDv4Default)
	if !ok {
		t.Fatalf("report is missing %s", IDv4Default)
	}
	mustValue(t, sys4, 128)
	if !sys4.Writable || sys4.Scope != ScopeSystemGlobal || sys4.Kind != KindPacketTTL {
		t.Errorf("system v4 setting = %+v, want writable system-global packet-ttl", sys4.SettingRef)
	}

	if4, ok := settingByID(rep, InterfaceSettingID(FamilyIPv4, 7, "Wi-Fi"))
	if !ok {
		t.Fatal("report is missing the per-interface v4 setting")
	}
	mustValue(t, if4, 64)
	if if4.Scope != ScopePerInterface || if4.Interface != "Wi-Fi" || if4.InterfaceIdx != 7 {
		t.Errorf("per-interface v4 setting = %+v, want scope per-interface on Wi-Fi (7)", if4.SettingRef)
	}

	if6, ok := settingByID(rep, InterfaceSettingID(FamilyIPv6, 7, "Wi-Fi"))
	if !ok {
		t.Fatal("report is missing the per-interface v6 setting")
	}
	if if6.Value != nil {
		t.Errorf("unconfigured per-interface v6 = %v, want no value", *if6.Value)
	}
	if got := if6.Display(); got != "not configured" {
		t.Errorf("Display() = %q, want %q", got, "not configured")
	}

	// The look-alike kinds are reported as non-settings, never as configurable values.
	kinds := map[Kind]bool{}
	for _, ns := range rep.NotSettings {
		if ns.Kind.IsConfigurable() {
			t.Errorf("%s is presented as configurable; it is not a host setting", ns.Kind)
		}
		kinds[ns.Kind] = true
	}
	if !kinds[KindDNSRecordTTL] || !kinds[KindTracerouteHops] {
		t.Errorf("NotSettings kinds = %v, want both DNS record TTL and traceroute hops", kinds)
	}

	// A system-global change must announce its blast radius wherever it is explained.
	if !strings.Contains(ScopeSystemGlobal.Explain(), "every adapter") {
		t.Error("system-global scope explanation does not warn about all adapters")
	}
}

func TestInspectUnsupportedHostReportsHonestly(t *testing.T) {
	m, _ := newTestManager(t, NewUnsupportedBackend("this host has no supported mechanism for these settings"))
	rep, err := m.Inspect(context.Background(), []IfaceInfo{{Index: 3, Name: "eth0"}})
	if err != nil {
		t.Fatalf("Inspect on an unsupported host must still succeed: %v", err)
	}
	if rep.Capabilities.Supported {
		t.Fatal("an unsupported backend must not report support")
	}
	if len(rep.Capabilities.Notes) == 0 {
		t.Error("unsupported capabilities carry no explanation")
	}
	for _, s := range rep.Settings {
		if s.Writable {
			t.Errorf("%s reported writable on an unsupported host", s.ID)
		}
		if s.WritableReason == "" {
			t.Errorf("%s is not writable but gives no reason", s.ID)
		}
	}
}

func TestInspectPartialFailureStaysVisible(t *testing.T) {
	fb := newFakeBackend()
	fb.readErrs = map[SettingID]error{
		IDv6Default: newError(CodeReadFailed, "the v6 read exploded", "retry on the Windows PC"),
	}
	m, _ := newTestManager(t, fb)

	rep, err := m.Inspect(context.Background(), nil)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(rep.ReadErrors) != 1 || rep.ReadErrors[0].Setting.ID != IDv6Default {
		t.Fatalf("read errors = %+v, want exactly the v6 failure", rep.ReadErrors)
	}
	if rep.ReadErrors[0].Code != CodeReadFailed {
		t.Errorf("read error code = %q, want %q", rep.ReadErrors[0].Code, CodeReadFailed)
	}

	// The family that could be read still reports its value.
	sys4, _ := settingByID(rep, IDv4Default)
	mustValue(t, sys4, 128)

	// The failed one is present, marked unwritable, with a reason - not silently missing.
	sys6, ok := settingByID(rep, IDv6Default)
	if !ok {
		t.Fatal("the unreadable setting was omitted from the report instead of shown as failed")
	}
	if sys6.Writable || sys6.WritableReason == "" {
		t.Errorf("unreadable setting = writable %t, reason %q; want unwritable with a reason", sys6.Writable, sys6.WritableReason)
	}
}

// --- apply -----------------------------------------------------------------------------

func TestApplyDryRunPlansWithoutWriting(t *testing.T) {
	fb := newFakeBackend()
	m, store := newTestManager(t, fb)

	out, err := m.Apply(context.Background(), ApplyRequest{DryRun: true})
	if err != nil {
		t.Fatalf("Apply(dry-run): %v", err)
	}
	if !out.DryRun {
		t.Error("outcome is not marked as a dry run")
	}
	if len(out.Changes) != 2 {
		t.Fatalf("planned %d changes, want 2 (both families)", len(out.Changes))
	}
	for _, c := range out.Changes {
		if c.Outcome != OutcomeDryRun || c.Verified {
			t.Errorf("%s: outcome %q verified %t, want dry-run and unverified", c.Setting.ID, c.Outcome, c.Verified)
		}
		if c.From == nil || *c.From != 128 || c.To != DefaultBump {
			t.Errorf("%s: from %s to %d, want from 128 to %d", c.Setting.ID, FormatIntPtr(c.From), c.To, DefaultBump)
		}
	}
	if fb.writeCount() != 0 {
		t.Fatalf("a preview wrote %d value(s)", fb.writeCount())
	}
	if orig, _ := store.LoadOriginals(); len(orig.Entries) != 0 {
		t.Error("a preview captured originals; a preview must not change stored state")
	}
	joined := strings.Join(out.Notes, " ")
	if !strings.Contains(joined, "Preview") || !strings.Contains(joined, "system-wide") {
		t.Errorf("preview notes = %q, want a preview statement and a system-wide warning", joined)
	}
}

func TestApplyConfirmedWritesVerifiesAndCaptures(t *testing.T) {
	fb := newFakeBackend()
	m, store := newTestManager(t, fb)

	out, err := m.Apply(context.Background(), ApplyRequest{Confirm: true, Reason: "automated test run"})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if out.Applied != 2 || len(out.Changes) != 2 || out.Failed != 0 {
		t.Fatalf("applied=%d changes=%d failed=%d, want 2/2/0", out.Applied, len(out.Changes), out.Failed)
	}
	for _, c := range out.Changes {
		if c.Outcome != OutcomeApplied || !c.Verified {
			t.Errorf("%s: outcome %q verified %t, want applied and verified by read-back", c.Setting.ID, c.Outcome, c.Verified)
		}
	}

	if v, ok := fb.value(IDv4Default); !ok || v != DefaultBump {
		t.Errorf("v4 system value = %d (present %t), want %d", v, ok, DefaultBump)
	}
	if v, ok := fb.value(IDv6Default); !ok || v != DefaultBump {
		t.Errorf("v6 system value = %d (present %t), want %d", v, ok, DefaultBump)
	}

	writes := fb.snapshotWrites()
	if len(writes) != 2 || writes[0].Ref.ID != IDv4Default || writes[1].Ref.ID != IDv6Default {
		t.Fatalf("writes = %+v, want exactly the two planned system settings", writes)
	}

	// Originals were captured before the first write and hold the pre-change values.
	orig, err := store.LoadOriginals()
	if err != nil {
		t.Fatalf("LoadOriginals: %v", err)
	}
	byID := orig.ByID()
	for _, id := range []SettingID{IDv4Default, IDv6Default} {
		e, ok := byID[id]
		if !ok {
			t.Fatalf("no capture for %s", id)
		}
		if e.Value == nil || *e.Value != 128 {
			t.Errorf("captured %s = %s, want the pre-change value 128", id, FormatIntPtr(e.Value))
		}
		if e.Origin == "" || e.CapturedAt.IsZero() {
			t.Errorf("capture for %s is missing provenance: %+v", id, e)
		}
	}

	// The history records both sides of each change and the stated reason.
	hist, err := store.History(0)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(hist) != 2 {
		t.Fatalf("history has %d events, want 2", len(hist))
	}
	for _, ev := range hist {
		if ev.Reason != "automated test run" {
			t.Errorf("history reason = %q, want the caller's reason", ev.Reason)
		}
		if ev.Outcome != OutcomeApplied || ev.Old == nil || *ev.Old != 128 || ev.New == nil || *ev.New != DefaultBump {
			t.Errorf("history event = %+v, want applied 128 -> %d", ev, DefaultBump)
		}
	}

	joined := strings.Join(out.Notes, " ")
	if !strings.Contains(joined, "system-wide") || !strings.Contains(joined, "DNS caching") {
		t.Errorf("apply notes = %q, want the blast-radius and DNS-caching notes", joined)
	}
}

func TestApplyWithoutConfirmationIsRefused(t *testing.T) {
	fb := newFakeBackend()
	m, store := newTestManager(t, fb)

	_, err := m.Apply(context.Background(), ApplyRequest{})
	if !IsCode(err, CodePermission) {
		t.Fatalf("error = %v, want %s", err, CodePermission)
	}
	if fb.writeCount() != 0 {
		t.Fatal("an unconfirmed request wrote a value")
	}
	if orig, _ := store.LoadOriginals(); len(orig.Entries) != 0 {
		t.Fatal("an unconfirmed request captured originals")
	}
}

func TestApplyNoOpWhenAlreadyAtTarget(t *testing.T) {
	fb := newFakeBackend()
	fb.values[IDv4Default] = DefaultBump
	fb.values[IDv6Default] = DefaultBump
	m, _ := newTestManager(t, fb)

	out, err := m.Apply(context.Background(), ApplyRequest{Confirm: true})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(out.Changes) != 0 || out.Applied != 0 {
		t.Fatalf("changes=%d applied=%d, want none", len(out.Changes), out.Applied)
	}
	if fb.writeCount() != 0 {
		t.Fatal("a no-op apply still wrote")
	}
	if joined := strings.Join(out.Notes, " "); !strings.Contains(joined, "No setting needed changing") {
		t.Errorf("notes = %q, want the explicit no-op statement", joined)
	}
}

func TestCaptureKeepsFirstOriginalAcrossRepeatedApplies(t *testing.T) {
	fb := newFakeBackend()
	m, store := newTestManager(t, fb)

	if _, err := m.Apply(context.Background(), ApplyRequest{Confirm: true}); err != nil {
		t.Fatalf("first apply: %v", err)
	}

	cfg := DefaultConfig()
	cfg.BumpIPv4, cfg.BumpIPv6 = 70, 70
	if _, err := m.Apply(context.Background(), ApplyRequest{Confirm: true, Override: &cfg}); err != nil {
		t.Fatalf("second apply: %v", err)
	}

	orig, err := store.LoadOriginals()
	if err != nil {
		t.Fatalf("LoadOriginals: %v", err)
	}
	byID := orig.ByID()
	if len(orig.Entries) != 2 {
		t.Fatalf("capture entries = %d, want 2 (one per setting, no duplicates)", len(orig.Entries))
	}
	for id, e := range byID {
		if e.Value == nil || *e.Value != 128 {
			t.Errorf("capture for %s = %s; the first capture must win, so a second apply cannot "+
				"overwrite the true original", id, FormatIntPtr(e.Value))
		}
	}
}

func TestApplyFailedWriteChangesNothing(t *testing.T) {
	fb := newFakeBackend()
	fb.writeErrFn = func(ref SettingRef, value int) error {
		if ref.ID == IDv4Default {
			return errors.New("refused by policy")
		}
		return nil
	}
	m, store := newTestManager(t, fb)

	_, err := m.Apply(context.Background(), ApplyRequest{Confirm: true})
	if err == nil || !strings.Contains(err.Error(), "refused by policy") {
		t.Fatalf("error = %v, want the backend refusal propagated", err)
	}

	// Nothing changed: the refused setting kept its value and the later setting was never reached.
	if v, _ := fb.value(IDv4Default); v != 128 {
		t.Errorf("v4 = %d, want the original 128", v)
	}
	if v, _ := fb.value(IDv6Default); v != 128 {
		t.Errorf("v6 = %d, want the untouched 128", v)
	}

	hist, _ := store.History(0)
	if len(hist) != 1 || hist[0].Outcome != OutcomeFailed || !strings.Contains(hist[0].Error, "refused by policy") {
		t.Fatalf("history = %+v, want one failed event carrying the cause", hist)
	}
}

func TestApplyPartialFailureRollsBackEverythingApplied(t *testing.T) {
	fb := newFakeBackend()
	fb.writeErrFn = func(ref SettingRef, value int) error {
		if ref.ID == IDv6Default {
			return errors.New("second setting refused")
		}
		return nil
	}
	m, store := newTestManager(t, fb)

	out, err := m.Apply(context.Background(), ApplyRequest{Confirm: true})
	if err == nil {
		t.Fatal("expected the second write to fail")
	}
	if !out.RolledBack || out.RollbackIncomplete {
		t.Fatalf("rolledBack=%t incomplete=%t, want a complete rollback", out.RolledBack, out.RollbackIncomplete)
	}

	// Both settings are back at their pre-change values: the first one was put back.
	if v, _ := fb.value(IDv4Default); v != 128 {
		t.Errorf("v4 = %d after rollback, want 128", v)
	}
	if v, _ := fb.value(IDv6Default); v != 128 {
		t.Errorf("v6 = %d, want the untouched 128", v)
	}

	joined := strings.Join(out.RollbackDetail, " | ")
	if !strings.Contains(joined, "failed") || !strings.Contains(joined, "put back to 128") {
		t.Errorf("rollback detail = %q, want the failure and the put-back both described", joined)
	}

	hist, _ := store.History(0)
	var sawRollback, sawFailed bool
	for _, ev := range hist {
		switch ev.Outcome {
		case OutcomeRolledBack:
			sawRollback = true
		case OutcomeFailed:
			sawFailed = true
		}
	}
	if !sawRollback || !sawFailed {
		t.Errorf("history outcomes = %+v, want a rolled-back event and a failed event", hist)
	}
}

func TestApplyVerifyFailureIsNotReportedAsSuccess(t *testing.T) {
	fb := newFakeBackend()
	fb.ignoreWrites = map[SettingID]bool{IDv4Default: true} // exit 0, no effect
	m, _ := newTestManager(t, fb)

	_, err := m.Apply(context.Background(), ApplyRequest{Confirm: true})
	if !IsCode(err, CodeVerifyFailed) {
		t.Fatalf("error = %v, want %s: a setter that exits 0 is not proof of success", err, CodeVerifyFailed)
	}
	if !strings.Contains(err.Error(), "read back: 128") {
		t.Errorf("error = %q, want the value actually read back reported", err)
	}
	if v, _ := fb.value(IDv4Default); v != 128 {
		t.Errorf("v4 = %d, want 128 (the write never took effect)", v)
	}
}

func TestApplyUnrecoverableRollbackIsReported(t *testing.T) {
	fb := newFakeBackend()
	fb.writeErrFn = func(ref SettingRef, value int) error {
		if ref.ID == IDv6Default {
			return errors.New("second write refused")
		}
		if ref.ID == IDv4Default && value == 128 {
			return errors.New("rollback write refused")
		}
		return nil
	}
	m, _ := newTestManager(t, fb)

	out, err := m.Apply(context.Background(), ApplyRequest{Confirm: true})
	if !IsCode(err, CodeRollbackIncomplete) {
		t.Fatalf("error = %v, want %s", err, CodeRollbackIncomplete)
	}
	if !out.RollbackIncomplete || out.RolledBack {
		t.Fatalf("rolledBack=%t incomplete=%t, want an incomplete rollback", out.RolledBack, out.RollbackIncomplete)
	}
	joined := strings.Join(out.RollbackDetail, " | ")
	if !strings.Contains(joined, "could NOT be put back") {
		t.Errorf("rollback detail = %q, want a plain statement of what remains", joined)
	}
	// The reported state is the truth: v4 is still at the value this operation wrote.
	if v, _ := fb.value(IDv4Default); v != DefaultBump {
		t.Errorf("v4 = %d, but the report says it is still at %d", v, DefaultBump)
	}
}

func TestApplyRefusesWhenOriginalCannotBeCaptured(t *testing.T) {
	fb := newFakeBackend()
	fb.readErrs = map[SettingID]error{
		IDv4Default: newError(CodeReadFailed, "cannot read v4", "check permissions"),
	}
	m, _ := newTestManager(t, fb)

	_, err := m.Apply(context.Background(), ApplyRequest{Confirm: true})
	if !IsCode(err, CodeReadFailed) {
		t.Fatalf("error = %v, want %s: writing without a captured original would make a "+
			"restore impossible", err, CodeReadFailed)
	}
	if fb.writeCount() != 0 {
		t.Fatal("a setting whose original could not be captured was written anyway")
	}
}

func TestApplyTouchesOnlyConfiguredAdapters(t *testing.T) {
	cases := map[string]struct {
		policy  InterfacePolicy
		include []string
		exclude []string
		want    map[string]bool
	}{
		"none":       {PolicyInterfaceNone, nil, nil, map[string]bool{}},
		"list":       {PolicyInterfaceList, []string{"Wi-Fi"}, nil, map[string]bool{"Wi-Fi": true}},
		"all-except": {PolicyInterfaceAllExcept, nil, []string{"Ethernet"}, map[string]bool{"Wi-Fi": true}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			fb := newFakeBackend()
			ifaces := []IfaceInfo{{Index: 5, Name: "Ethernet"}, {Index: 7, Name: "Wi-Fi"}}
			for _, i := range ifaces {
				fb.values[InterfaceSettingID(FamilyIPv4, i.Index, i.Name)] = 128
				fb.values[InterfaceSettingID(FamilyIPv6, i.Index, i.Name)] = 128
			}
			m, _ := newTestManager(t, fb)

			cfg := DefaultConfig()
			cfg.Policy, cfg.IncludeIfaces, cfg.ExcludeIfaces = tc.policy, tc.include, tc.exclude
			if _, err := m.Apply(context.Background(), ApplyRequest{Confirm: true, Ifaces: ifaces, Override: &cfg}); err != nil {
				t.Fatalf("Apply: %v", err)
			}

			touched := map[string]bool{}
			for _, w := range fb.snapshotWrites() {
				if w.Ref.Scope == ScopePerInterface {
					touched[w.Ref.Interface] = true
					if !tc.want[w.Ref.Interface] {
						t.Errorf("wrote to %s, which the %q policy did not select", w.Ref.Interface, tc.policy)
					}
				}
			}
			for want := range tc.want {
				if !touched[want] {
					t.Errorf("expected a per-interface write on %s under policy %q", want, tc.policy)
				}
			}
		})
	}
}

func TestApplyCancelledBeforeFirstWrite(t *testing.T) {
	fb := newFakeBackend()
	m, _ := newTestManager(t, fb)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := m.Apply(ctx, ApplyRequest{Confirm: true})
	if !IsCode(err, CodeCancelled) {
		t.Fatalf("error = %v, want %s", err, CodeCancelled)
	}
	if fb.writeCount() != 0 {
		t.Fatal("a cancelled operation wrote a value")
	}
}

// --- restore ---------------------------------------------------------------------------

func TestRestoreWithoutCaptureIsRefused(t *testing.T) {
	fb := newFakeBackend()
	m, _ := newTestManager(t, fb)

	_, err := m.Restore(context.Background(), RestoreRequest{Confirm: true})
	if !IsCode(err, CodeNoCapture) {
		t.Fatalf("error = %v, want %s", err, CodeNoCapture)
	}
	if fb.writeCount() != 0 {
		t.Fatal("a restore with nothing captured wrote a value")
	}
}

func TestRestorePutsBackCapturedValues(t *testing.T) {
	fb := newFakeBackend()
	m, store := newTestManager(t, fb)

	if _, err := m.Apply(context.Background(), ApplyRequest{Confirm: true}); err != nil {
		t.Fatalf("apply: %v", err)
	}

	out, err := m.Restore(context.Background(), RestoreRequest{Confirm: true})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if out.Applied != 2 {
		t.Fatalf("restored %d settings, want 2", out.Applied)
	}
	for _, id := range []SettingID{IDv4Default, IDv6Default} {
		if v, ok := fb.value(id); !ok || v != 128 {
			t.Errorf("%s = %d (present %t) after restore, want the captured 128", id, v, ok)
		}
	}
	for _, c := range out.Changes {
		if !c.Verified {
			t.Errorf("%s restored but not verified", c.Setting.ID)
		}
	}

	joined := strings.Join(out.Notes, " ")
	if !strings.Contains(joined, "recorded before") || !strings.Contains(joined, "platform default") {
		t.Errorf("restore notes = %q, want the honest source-of-values statement", joined)
	}

	// The capture set is kept, so a later re-apply can still be undone.
	if orig, _ := store.LoadOriginals(); len(orig.Entries) != 2 {
		t.Errorf("captures = %d after restore, want them kept", len(orig.Entries))
	}

	hist, _ := store.History(0)
	sawRestore := false
	for _, ev := range hist {
		if ev.Reason == "restored the captured original values" {
			sawRestore = true
		}
	}
	if !sawRestore {
		t.Error("the restore is not recorded in the change history")
	}
}

func TestRestoreOnlySelectedSetting(t *testing.T) {
	fb := newFakeBackend()
	m, _ := newTestManager(t, fb)

	if _, err := m.Apply(context.Background(), ApplyRequest{Confirm: true}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	out, err := m.Restore(context.Background(), RestoreRequest{Confirm: true, Only: []SettingID{IDv4Default}})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if out.Applied != 1 {
		t.Fatalf("restored %d settings, want only the requested 1", out.Applied)
	}
	if v, _ := fb.value(IDv4Default); v != 128 {
		t.Errorf("v4 = %d, want restored to 128", v)
	}
	if v, _ := fb.value(IDv6Default); v != DefaultBump {
		t.Errorf("v6 = %d, want left at %d because it was not selected", v, DefaultBump)
	}
}

func TestRestoreDryRunDoesNotWrite(t *testing.T) {
	fb := newFakeBackend()
	m, _ := newTestManager(t, fb)

	if _, err := m.Apply(context.Background(), ApplyRequest{Confirm: true}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	before := fb.writeCount()

	out, err := m.Restore(context.Background(), RestoreRequest{DryRun: true})
	if err != nil {
		t.Fatalf("Restore(dry-run): %v", err)
	}
	if fb.writeCount() != before {
		t.Fatal("a restore preview wrote a value")
	}
	if len(out.Changes) != 2 {
		t.Fatalf("planned %d restores, want 2", len(out.Changes))
	}
	for _, c := range out.Changes {
		if c.Outcome != OutcomeDryRun || c.To != 128 {
			t.Errorf("%s: outcome %q to %d, want dry-run restoring 128", c.Setting.ID, c.Outcome, c.To)
		}
	}
}

func TestRestoreWithoutConfirmationIsRefused(t *testing.T) {
	fb := newFakeBackend()
	m, _ := newTestManager(t, fb)

	if _, err := m.Apply(context.Background(), ApplyRequest{Confirm: true}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	before := fb.writeCount()

	_, err := m.Restore(context.Background(), RestoreRequest{})
	if !IsCode(err, CodePermission) {
		t.Fatalf("error = %v, want %s", err, CodePermission)
	}
	if fb.writeCount() != before {
		t.Fatal("an unconfirmed restore wrote a value")
	}
}

func TestRestoreUsesCurrentInterfaceIndex(t *testing.T) {
	fb := newFakeBackend()
	ifaceID := InterfaceSettingID(FamilyIPv4, 7, "Wi-Fi")
	fb.values[ifaceID] = 129
	fb.values[InterfaceSettingID(FamilyIPv6, 7, "Wi-Fi")] = 129
	m, _ := newTestManager(t, fb)

	cfg := DefaultConfig()
	cfg.Policy = PolicyInterfaceList
	cfg.IncludeIfaces = []string{"Wi-Fi"}
	oldIfaces := []IfaceInfo{{Index: 7, Name: "Wi-Fi"}}
	if _, err := m.Apply(context.Background(), ApplyRequest{Confirm: true, Ifaces: oldIfaces, Override: &cfg}); err != nil {
		t.Fatalf("apply: %v", err)
	}

	// The adapter reconnects and comes back with a different interface index.
	newIfaces := []IfaceInfo{{Index: 21, Name: "Wi-Fi"}}
	out, err := m.Restore(context.Background(), RestoreRequest{Confirm: true, Ifaces: newIfaces, Only: []SettingID{ifaceID}})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if out.Applied != 1 {
		t.Fatalf("restored %d settings, want 1", out.Applied)
	}
	w, ok := fb.lastWrite()
	if !ok {
		t.Fatal("no write was recorded")
	}
	if w.Ref.Interface != "Wi-Fi" || w.Ref.InterfaceIdx != 21 {
		t.Errorf("restore wrote to %q index %d, want the adapter's current index 21", w.Ref.Interface, w.Ref.InterfaceIdx)
	}
	if v, _ := fb.value(InterfaceSettingID(FamilyIPv4, 21, "Wi-Fi")); v != 129 {
		t.Errorf("adapter value under the new index = %d, want the captured 129", v)
	}
}

// --- lifecycle invariants ---------------------------------------------------------------

func TestEnabledConfigIsNotActedOnByItself(t *testing.T) {
	// A stored Enabled=true records a user preference. It must never cause a write on its own,
	// which is what keeps net-merge starting, stopping or crashing from changing a setting.
	fb := newFakeBackend()
	store := NewStore(filepath.Join(t.TempDir(), "state"))
	cfg := DefaultConfig()
	cfg.Enabled = true
	if err := store.SaveConfig(cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	for i := 0; i < 2; i++ { // two "sessions" over the same store
		m := NewManager(store, fb)
		rep, err := m.Inspect(context.Background(), nil)
		if err != nil {
			t.Fatalf("Inspect: %v", err)
		}
		if !rep.Config.Enabled {
			t.Fatal("the stored preference is not reported")
		}
	}
	if fb.writeCount() != 0 {
		t.Fatalf("constructing and inspecting wrote %d value(s); nothing may act on the "+
			"preference by itself", fb.writeCount())
	}
}

// --- corrupted and interrupted state ----------------------------------------------------

func TestCorruptConfigIsQuarantinedNotDeleted(t *testing.T) {
	fb := newFakeBackend()
	m, store := newTestManager(t, fb)
	if err := store.ensureDir(); err != nil {
		t.Fatalf("ensureDir: %v", err)
	}
	bad := []byte("{ this is not json")
	cfgPath := filepath.Join(store.Dir(), "ttl-config.json")
	if err := os.WriteFile(cfgPath, bad, 0o600); err != nil {
		t.Fatalf("write corrupt config: %v", err)
	}

	rep, err := m.Inspect(context.Background(), nil)
	if err != nil {
		t.Fatalf("Inspect must survive a corrupt config: %v", err)
	}
	if len(rep.Warnings) == 0 || !strings.Contains(strings.Join(rep.Warnings, " "), "could not be used") {
		t.Errorf("warnings = %v, want the corrupt config reported", rep.Warnings)
	}
	if !reflect.DeepEqual(rep.Config, DefaultConfig()) {
		t.Errorf("config = %+v, want the conservative default after a corrupt file", rep.Config)
	}

	// The bad file is preserved for inspection, under a name that says what it is.
	matches, _ := filepath.Glob(cfgPath + ".corrupt-*")
	if len(matches) != 1 {
		t.Fatalf("quarantine files = %v, want exactly one", matches)
	}
	raw, err := os.ReadFile(matches[0])
	if err != nil || string(raw) != string(bad) {
		t.Errorf("quarantined content = %q (err %v), want the bad file preserved verbatim", raw, err)
	}

	// A later load starts from defaults instead of being wedged by the bad file.
	cfg, err := store.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig after quarantine: %v", err)
	}
	if !reflect.DeepEqual(cfg, DefaultConfig()) {
		t.Errorf("config = %+v, want defaults", cfg)
	}
}

func TestUnreadableCaptureFileBlocksChanges(t *testing.T) {
	fb := newFakeBackend()
	m, store := newTestManager(t, fb)
	if err := store.ensureDir(); err != nil {
		t.Fatalf("ensureDir: %v", err)
	}
	origPath := filepath.Join(store.Dir(), "ttl-originals.json")
	bad := "definitely not json"
	if err := os.WriteFile(origPath, []byte(bad), 0o600); err != nil {
		t.Fatalf("write corrupt captures: %v", err)
	}

	_, err := m.Apply(context.Background(), ApplyRequest{Confirm: true})
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("error = %v, want a refusal to overwrite the unreadable capture file", err)
	}
	if fb.writeCount() != 0 {
		t.Fatal("a change was written even though no honest restore would be possible")
	}
	raw, _ := os.ReadFile(origPath)
	if string(raw) != bad {
		t.Error("the unreadable capture file was replaced instead of preserved")
	}
}

func TestStaleLockFromOldOperationIsReclaimed(t *testing.T) {
	fb := newFakeBackend()
	m, store := newTestManager(t, fb)
	if err := store.ensureDir(); err != nil {
		t.Fatalf("ensureDir: %v", err)
	}
	lock := filepath.Join(store.Dir(), "ttl-operation.lock")
	if err := os.WriteFile(lock, []byte("999999\n2000-01-01T00:00:00Z\n"), 0o600); err != nil {
		t.Fatalf("write lock: %v", err)
	}
	old := time.Now().Add(-10 * time.Minute)
	if err := os.Chtimes(lock, old, old); err != nil {
		t.Fatalf("age lock: %v", err)
	}

	if _, err := m.Apply(context.Background(), ApplyRequest{DryRun: true}); err != nil {
		t.Fatalf("a stale lock was not reclaimed: %v", err)
	}
	if _, err := os.Stat(lock); !errors.Is(err, os.ErrNotExist) {
		t.Error("the lock file was left behind after the operation")
	}
}

func TestLockHeldByLiveProcessIsHonoured(t *testing.T) {
	fb := newFakeBackend()
	m, store := newTestManager(t, fb)
	if err := store.ensureDir(); err != nil {
		t.Fatalf("ensureDir: %v", err)
	}
	lock := filepath.Join(store.Dir(), "ttl-operation.lock")
	content := fmt.Sprintf("%d\n%s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339Nano))
	if err := os.WriteFile(lock, []byte(content), 0o600); err != nil {
		t.Fatalf("write lock: %v", err)
	}

	_, err := m.Apply(context.Background(), ApplyRequest{DryRun: true})
	if !IsCode(err, CodeBusy) {
		t.Fatalf("error = %v, want %s while another operation holds the lock", err, CodeBusy)
	}
	if fb.writeCount() != 0 {
		t.Fatal("a value was written while the lock was held elsewhere")
	}
	if _, statErr := os.Stat(lock); statErr != nil {
		t.Error("the lock held by a live process was removed")
	}
}

func TestLockFromDeadProcessIsReclaimed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX helper process to produce a provably dead pid")
	}
	fb := newFakeBackend()
	m, store := newTestManager(t, fb)
	if err := store.ensureDir(); err != nil {
		t.Fatalf("ensureDir: %v", err)
	}

	cmd := exec.Command("sh", "-c", "exit 0")
	if err := cmd.Run(); err != nil {
		t.Skipf("cannot spawn a helper process: %v", err)
	}
	dead := cmd.Process.Pid

	lock := filepath.Join(store.Dir(), "ttl-operation.lock")
	content := fmt.Sprintf("%d\n%s\n", dead, time.Now().UTC().Format(time.RFC3339Nano))
	if err := os.WriteFile(lock, []byte(content), 0o600); err != nil {
		t.Fatalf("write lock: %v", err)
	}

	if _, err := m.Apply(context.Background(), ApplyRequest{DryRun: true}); err != nil {
		t.Fatalf("a lock left by a dead process (pid %d) was not reclaimed: %v", dead, err)
	}
}
