package ttlmgr

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"net-merge/internal/platform"
)

// Manager coordinates inspection and change of the host's packet-header settings. It owns
// three responsibilities that must not be split apart:
//
//   - serialisation: one operation at a time, across processes as well as inside this one, so
//     two callers can never interleave writes to the same setting;
//   - capture before change: the original value is recorded the first time a setting is
//     touched, which is what makes an honest restore possible at all;
//   - transactional change: every write is read back, and a failure part-way through undoes
//     what already landed or reports plainly that it could not.
//
// Nothing here acts on a stored preference by itself. Apply and Restore run only when called,
// which is why the TTL manager cannot change a setting merely because net-merge started,
// stopped, crashed or reconnected.
type Manager struct {
	store   *Store
	backend Backend

	// mu serialises operations inside this process. The file lock serialises them across
	// processes, because the Control Center, a CLI call and the tray can all be running.
	mu sync.Mutex

	// now is injectable so tests can produce deterministic history timestamps.
	now func() time.Time

	// lockWait bounds how long one operation waits for another. It is a field rather than a
	// constant so the test suite can exercise the busy and stale-lock paths without sleeping
	// for the production timeout.
	lockWait time.Duration
}

// NewManager returns a Manager over the given store and backend.
func NewManager(store *Store, backend Backend) *Manager {
	return &Manager{store: store, backend: backend, now: time.Now, lockWait: defaultLockTimeout}
}

// Backend exposes the backend for callers that only need its capabilities.
func (m *Manager) Backend() Backend { return m.backend }

// Store exposes the store for callers that only need configuration or history.
func (m *Manager) Store() *Store { return m.store }

// Report is the complete, self-describing state of these settings on this host. It is what the
// TTL page renders and what the diagnostic export serialises, so it carries the explanation
// alongside every value rather than leaving the reader to know it.
type Report struct {
	Schema  string    `json:"schema"`
	At      time.Time `json:"at"`
	Version string    `json:"appVersion,omitempty"`

	Capabilities Capabilities `json:"capabilities"`

	// Settings are the configurable packet-header values, one per family and per adapter.
	Settings []Setting `json:"settings"`

	// NotSettings records the look-alike concepts that are deliberately NOT configurable here
	// (DNS record TTL, traceroute hop count). They are reported so a reader can tell them
	// apart from the packet header values instead of assuming they are the same thing.
	NotSettings []Setting `json:"notSettings"`

	// Captured is what a restore would put back, keyed by setting id.
	Captured map[SettingID]Original `json:"captured"`

	Config Config `json:"config"`

	// Elevated is whether this process can make system changes, with the reason stated.
	Elevated  bool   `json:"elevated"`
	Elevation string `json:"elevationNote"`

	// ReadErrors keeps the settings that could not be read, so a partial inspection is
	// visible as partial instead of looking like an empty system.
	ReadErrors []ReadFailure `json:"readErrors,omitempty"`

	Warnings []string `json:"warnings,omitempty"`
}

// ReadFailure records one setting that could not be read, with the error intact.
type ReadFailure struct {
	Setting SettingRef `json:"setting"`
	Code    string     `json:"code"`
	Message string     `json:"message"`
	Details []string   `json:"details,omitempty"`
}

// Inspect reads every relevant setting, the captured originals and the configuration, and
// reports what it could not read rather than omitting it.
func (m *Manager) Inspect(ctx context.Context, ifaces []IfaceInfo) (Report, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	rep := Report{
		Schema:       "netmerge-ttl-report/1",
		At:           m.now().UTC(),
		Capabilities: m.backend.Capabilities(ctx),
		NotSettings:  NonConfigurableKinds(),
		Elevated:     platform.IsAdmin(),
	}
	rep.Elevation = elevationNote(rep.Elevated)

	cfg, cfgErr := m.store.LoadConfig()
	if cfgErr != nil {
		rep.Warnings = append(rep.Warnings,
			"the stored configuration could not be used, so defaults are shown: "+cfgErr.Error())
	}
	rep.Config = cfg

	orig, origErr := m.store.LoadOriginals()
	if origErr != nil {
		rep.Warnings = append(rep.Warnings,
			"the captured original values could not be read: "+origErr.Error())
	}
	rep.Captured = orig.ByID()

	refs := SettingRefs(ifaces)
	for _, ref := range refs {
		setting := Setting{
			SettingRef:     ref,
			Writable:       false,
			WritableReason: "",
		}
		if !rep.Capabilities.Supported {
			setting.WritableReason = "This host has no supported mechanism for this setting."
			rep.Settings = append(rep.Settings, setting)
			continue
		}
		if ref.Scope == ScopePerInterface && !capabilitiesAllowPerInterface(rep.Capabilities) {
			setting.WritableReason = "Set-NetIPInterface -CurrentHopLimit is not available on this Windows build, " +
				"so a per-interface value cannot be set through a supported mechanism."
			rep.Settings = append(rep.Settings, setting)
			continue
		}
		obs, err := m.backend.Read(ctx, ref)
		if err != nil {
			rep.ReadErrors = append(rep.ReadErrors, failure(ref, err))
			setting.WritableReason = "The current value could not be read, so it is not shown."
			rep.Settings = append(rep.Settings, setting)
			continue
		}
		setting.Value = obs.Value
		setting.ValueOrigin = obs.Origin
		setting.Writable = true
		rep.Settings = append(rep.Settings, setting)
	}
	return rep, nil
}

// capabilitiesAllowPerInterface reports whether the probed build supports the per-interface
// setter. It reads the probe result rather than assuming, which is the whole reason the probe
// exists.
func capabilitiesAllowPerInterface(c Capabilities) bool {
	for _, cc := range c.Commands {
		if cc.Command == "Set-NetIPInterface" && cc.HasParam {
			return true
		}
	}
	return false
}

// elevationNote states whether a change is possible right now and why, so the UI never has to
// explain a permission error that it could have predicted.
func elevationNote(elevated bool) string {
	if elevated {
		return "This process is elevated, so it can change system settings. Elevation is requested only " +
			"when a change is actually asked for."
	}
	return "This process is not elevated. Inspection works without it; changing a value needs it, and " +
		"the change will be refused with an explanation rather than a silent failure."
}

func failure(ref SettingRef, err error) ReadFailure {
	f := ReadFailure{Setting: ref, Code: ErrorCode(err), Message: err.Error()}
	var e *Error
	if errors.As(err, &e) {
		f.Message, f.Details = e.Message, e.Details
	}
	return f
}

// ApplyRequest describes one change operation.
type ApplyRequest struct {
	// Ifaces is the adapter list the per-interface policy is evaluated against.
	Ifaces []IfaceInfo

	// DryRun plans and reports without writing anything. It is the preview mode: a user can
	// see exactly which settings would change and from what to what before allowing it.
	DryRun bool

	// Confirm must be true for a real change. Without it a non-dry-run request is refused,
	// which is what makes an accidental call from another code path harmless.
	Confirm bool

	// Reason is stored in the change history verbatim. It defaults to a plain description.
	Reason string

	// Override, when non-nil, replaces the stored configuration for this one operation.
	Override *Config
}

// Change is one planned or performed write.
type Change struct {
	Setting SettingRef `json:"setting"`

	// From and To are the values either side of the change. From is nil when the value could
	// not be read, which makes the change visible as unverified rather than as zero-to-N.
	From *int `json:"from"`
	To   int  `json:"to"`

	Outcome EventOutcome `json:"outcome"`
	Detail  string       `json:"detail,omitempty"`

	// Verified is true only when the value was read back and matched. A write that ran but
	// could not be confirmed is reported as unverified, never as success.
	Verified bool `json:"verified"`
}

// Outcome is the result of one Apply.
type Outcome struct {
	Schema string    `json:"schema"`
	At     time.Time `json:"at"`

	DryRun  bool     `json:"dryRun"`
	Applied int      `json:"applied"`
	Failed  int      `json:"failed"`
	Changes []Change `json:"changes"`

	// RolledBack is true when a failure was fully undone; RollbackIncomplete is true when it
	// was not, and RollbackDetail then says exactly what is still in place. These are separate
	// from an error because a partial rollback is a state the user must be told about, not a
	// message that can be dropped.
	RolledBack         bool     `json:"rolledBack"`
	RollbackIncomplete bool     `json:"rollbackIncomplete"`
	RollbackDetail     []string `json:"rollbackDetail,omitempty"`

	// Notes explain consequences a user needs in order to judge the result.
	Notes []string `json:"notes,omitempty"`
}

// Apply writes the requested values, capturing originals first and verifying each write.
//
// The order is deliberate: every original is captured before the first write, so a failure at
// any point leaves enough information to undo the whole operation.
func (m *Manager) Apply(ctx context.Context, req ApplyRequest) (Outcome, error) {
	out := Outcome{Schema: "netmerge-ttl-outcome/1", At: m.now().UTC(), DryRun: req.DryRun}

	// Serialise against other operations in this process and in other processes.
	release, err := m.lock(ctx)
	if err != nil {
		return out, err
	}
	defer release()

	cfg := req.Override
	if cfg == nil {
		c, cfgErr := m.store.LoadConfig()
		if cfgErr != nil {
			return out, cfgErr
		}
		cfg = &c
	}
	if verr := cfg.Validate(); verr != nil {
		return out, verr
	}

	plan, err := m.plan(ctx, *cfg, req.Ifaces)
	if err != nil {
		return out, err
	}
	if len(plan) == 0 {
		out.Notes = append(out.Notes, "No setting needed changing; every target already held the requested value.")
		return out, nil
	}

	if req.DryRun {
		for i := range plan {
			plan[i].Outcome = OutcomeDryRun
			plan[i].Detail = "would be set; nothing was written"
			plan[i].Verified = false
		}
		out.Changes = plan
		out.Notes = append(out.Notes, dryRunNote(plan))
		return out, nil
	}

	if !req.Confirm {
		return out, newError(CodePermission,
			fmt.Sprintf("refusing to write %d setting(s) without confirmation", len(plan)),
			"Call with confirmation set, or use the preview action to see what would change first.",
			fmt.Sprintf("planned changes: %d", len(plan)))
	}

	reason := req.Reason
	if reason == "" {
		reason = "applied through the Control Center TTL manager"
	}

	// Capture before writing. A capture failure aborts the whole operation, because writing
	// without a recorded original would make an honest restore impossible.
	captures := make([]Original, 0, len(plan))
	for _, c := range plan {
		captures = append(captures, Original{
			ID:         c.Setting.ID,
			Family:     c.Setting.Family,
			Scope:      c.Setting.Scope,
			Interface:  c.Setting.Interface,
			Value:      c.From,
			Origin:     "captured before apply",
			CapturedAt: m.now().UTC(),
		})
	}
	if _, _, err := m.store.CaptureOriginals(captures, false); err != nil {
		return out, newError(CodeWriteFailed,
			"the original values could not be recorded, so nothing was changed",
			"Without a capture a later restore could not be trusted. Check the state directory and retry.",
			err.Error())
	}

	// A capture with no value is not a restore point. If any planned setting has no usable
	// original, nothing is written at all: writing would leave a value this tool cannot
	// honestly put back, and a partial transaction is worse than none.
	current, err := m.store.LoadOriginals()
	if err != nil {
		return out, newError(CodeWriteFailed,
			"the captured originals could not be re-read, so nothing was changed",
			"An honest restore needs a readable capture. Check the state directory and retry.",
			err.Error())
	}
	byID := current.ByID()
	var noOriginal []string
	for _, c := range plan {
		if e, ok := byID[c.Setting.ID]; !ok || e.Value == nil {
			noOriginal = append(noOriginal, c.Setting.Compact())
		}
	}
	if len(noOriginal) > 0 {
		return out, newError(CodeReadFailed,
			"the value in place before the change could not be read for: "+strings.Join(noOriginal, ", "),
			"Restoring the original is what makes a change safe, so nothing was written. Inspect "+
				"the setting, then retry.",
			fmt.Sprintf("planned changes were not attempted: %d", len(plan)))
	}

	var events []Event
	applied := make([]Change, 0, len(plan))

	rollback := func(failed Change, cause error) (Outcome, error) {
		out.Changes = append(applied, failed)
		out.Failed = 1
		out.RollbackDetail = append(out.RollbackDetail, fmt.Sprintf("%s failed: %v", failed.Setting.Compact(), cause))

		// Undo in reverse order so a dependency between two settings cannot be observed
		// half-undone.
		incomplete := false
		for i := len(applied) - 1; i >= 0; i-- {
			c := applied[i]
			rbErr := m.writeBack(ctx, c.Setting, c.From)
			ev := Event{
				At: m.now().UTC(), ID: c.Setting.ID, Family: c.Setting.Family,
				Scope: c.Setting.Scope, Iface: c.Setting.Interface,
				Old: intPtr(c.To), New: c.From, Reason: "automatic rollback after a failed change",
			}
			if rbErr != nil {
				incomplete = true
				ev.Outcome = OutcomeRollbackFailed
				ev.Error = rbErr.Error()
				out.RollbackDetail = append(out.RollbackDetail,
					fmt.Sprintf("%s could NOT be put back to %s: %v", c.Setting.Compact(), FormatIntPtr(c.From), rbErr))
			} else {
				ev.Outcome = OutcomeRolledBack
				out.RollbackDetail = append(out.RollbackDetail,
					fmt.Sprintf("%s put back to %s", c.Setting.Compact(), FormatIntPtr(c.From)))
			}
			events = append(events, ev)
		}
		out.RolledBack = !incomplete
		out.RollbackIncomplete = incomplete
		events = append(events, failureEvent(failed, cause, reason))
		_ = m.store.AppendHistory(events...)

		if incomplete {
			return out, newError(CodeRollbackIncomplete,
				"the change failed part-way through and the rollback could not complete",
				"Some settings are still at the values this operation wrote. The reported values below "+
					"are what remains; restore them explicitly, and reboot if a value does not take effect.",
				out.RollbackDetail...)
		}
		return out, cause
	}

	for _, c := range plan {
		if err := ctx.Err(); err != nil {
			return rollback(c, newError(CodeCancelled,
				"the operation was cancelled before it finished",
				"Everything already applied was put back.", err.Error()))
		}

		if err := m.backend.Write(ctx, c.Setting, c.To); err != nil {
			return rollback(c, err)
		}

		// Read the value back. A setter that reported success is not evidence that the value
		// changed, so the confirmation is what decides.
		obs, verr := m.backend.Read(ctx, c.Setting)
		switch {
		case verr != nil:
			c.Outcome = OutcomeApplied
			c.Detail = "written, but the value could not be read back to confirm it: " + verr.Error()
			c.Verified = false
			events = append(events, appliedEvent(c, reason, obs, verr))
		case obs.Value != nil && *obs.Value == c.To:
			c.Outcome = OutcomeApplied
			c.Verified = true
			c.Detail = "confirmed by reading the value back"
			events = append(events, appliedEvent(c, reason, obs, nil))
		default:
			c.Outcome = OutcomeApplied
			c.Verified = false
			c.Detail = fmt.Sprintf("written, but reading it back gave %s", FormatIntPtr(obs.Value))
			events = append(events, appliedEvent(c, reason, obs, nil))
			return rollback(c, newError(CodeVerifyFailed,
				fmt.Sprintf("%s did not take the value %d", c.Setting.Compact(), c.To),
				"The command reported success but the value read back differently. The change was undone.",
				fmt.Sprintf("requested: %d", c.To),
				fmt.Sprintf("read back: %s", FormatIntPtr(obs.Value)),
				"origin: "+obs.Origin))
		}
		applied = append(applied, c)
		out.Applied++
	}

	out.Changes = applied
	out.Notes = append(out.Notes, applyNotes(applied)...)
	_ = m.store.AppendHistory(events...)
	return out, nil
}

func appliedEvent(c Change, reason string, obs Observed, verifyErr error) Event {
	ev := Event{
		At: time.Now().UTC(), ID: c.Setting.ID, Family: c.Setting.Family, Scope: c.Setting.Scope,
		Iface: c.Setting.Interface, Old: c.From, New: intPtr(c.To),
		Outcome: c.Outcome, Reason: reason, Output: c.Detail,
	}
	if verifyErr != nil {
		ev.Error = verifyErr.Error()
	}
	_ = obs
	return ev
}

func failureEvent(c Change, cause error, reason string) Event {
	ev := Event{
		At: time.Now().UTC(), ID: c.Setting.ID, Family: c.Setting.Family, Scope: c.Setting.Scope,
		Iface: c.Setting.Interface, Old: c.From, New: intPtr(c.To),
		Outcome: OutcomeFailed, Reason: reason, Error: cause.Error(),
	}
	var e *Error
	if errors.As(cause, &e) {
		ev.Command = strings.Join(e.Details, "; ")
	}
	return ev
}

// writeBack restores one setting during a rollback. A nil target means the value was not
// readable when the change was planned; in that case the stored capture from an earlier
// operation is used, and only when there is none either is the caller told that the value
// cannot be put back rather than being given a fabricated one.
func (m *Manager) writeBack(ctx context.Context, ref SettingRef, target *int) error {
	if target == nil {
		if orig, err := m.store.LoadOriginals(); err == nil {
			if e, ok := orig.ByID()[ref.ID]; ok && e.Value != nil {
				target = e.Value
			}
		}
	}
	if target == nil {
		return newError(CodeRollbackIncomplete,
			"the value in place before the change was never read, so it cannot be put back",
			"Inspect the current value and set it by hand if it needs to change.")
	}
	return m.backend.Write(ctx, ref, *target)
}

// plan works out which settings differ from what is requested.
func (m *Manager) plan(ctx context.Context, cfg Config, ifaces []IfaceInfo) ([]Change, error) {
	var plan []Change
	add := func(ref SettingRef, want int) {
		obs, err := m.backend.Read(ctx, ref)
		var from *int
		if err == nil {
			from = obs.Value
		}
		if from != nil && *from == want {
			return // already correct; no write, and so no history noise
		}
		plan = append(plan, Change{Setting: ref, From: from, To: want})
	}

	add(SystemRef(FamilyIPv4), cfg.BumpIPv4)
	add(SystemRef(FamilyIPv6), cfg.BumpIPv6)

	switch cfg.Policy {
	case PolicyInterfaceList:
		for _, i := range ifaces {
			if !nameInList(cfg.IncludeIfaces, i.Name) {
				continue
			}
			add(IfaceRef(FamilyIPv4, i.Index, i.Name), cfg.BumpIPv4)
			add(IfaceRef(FamilyIPv6, i.Index, i.Name), cfg.BumpIPv6)
		}
	case PolicyInterfaceAllExcept:
		for _, i := range ifaces {
			if nameInList(cfg.ExcludeIfaces, i.Name) {
				continue
			}
			add(IfaceRef(FamilyIPv4, i.Index, i.Name), cfg.BumpIPv4)
			add(IfaceRef(FamilyIPv6, i.Index, i.Name), cfg.BumpIPv6)
		}
	}
	return plan, nil
}

// nameInList matches adapter names case-insensitively, which is how Windows treats them.
func nameInList(list []string, name string) bool {
	for _, x := range list {
		if strings.EqualFold(strings.TrimSpace(x), name) {
			return true
		}
	}
	return false
}

// RestoreRequest describes a one-click rollback.
type RestoreRequest struct {
	Ifaces []IfaceInfo

	// DryRun plans the restore without writing.
	DryRun bool
	// Confirm must be true for a real restore.
	Confirm bool
	// Reason is stored in the change history.
	Reason string

	// Only, when non-empty, limits the restore to these setting ids. Empty restores everything
	// that was ever captured.
	Only []SettingID
}

// Restore puts back the values captured before this application first changed them. It uses
// the capture, never an assumed platform default, which matters on Windows because the
// built-in default is 128 rather than the 64 a port from another platform might assume.
func (m *Manager) Restore(ctx context.Context, req RestoreRequest) (Outcome, error) {
	out := Outcome{Schema: "netmerge-ttl-outcome/1", At: m.now().UTC(), DryRun: req.DryRun}

	release, err := m.lock(ctx)
	if err != nil {
		return out, err
	}
	defer release()

	orig, err := m.store.LoadOriginals()
	if err != nil {
		return out, err
	}
	byID := orig.ByID()
	if len(byID) == 0 {
		return out, newError(CodeNoCapture,
			"there is nothing captured to restore",
			"Nothing has been changed by this application, so there is no original value to put back. "+
				"No setting was touched.")
	}

	want := make(map[SettingID]bool, len(req.Only))
	for _, id := range req.Only {
		want[id] = true
	}

	ids := make([]SettingID, 0, len(byID))
	for id := range byID {
		if len(want) > 0 && !want[id] {
			continue
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return out, newError(CodeNoCapture,
			"none of the requested settings has a captured original",
			"Restore everything, or check which settings were changed in the history.")
	}
	sortSettingIDs(ids)

	plan := make([]Change, 0, len(ids))
	for _, id := range ids {
		e := byID[id]
		ref, err := m.refFor(ctx, e, req.Ifaces)
		if err != nil {
			out.Changes = append(out.Changes, Change{Setting: SettingRef{ID: id}, Outcome: OutcomeFailed, Detail: err.Error()})
			out.Failed++
			continue
		}
		if e.Value == nil {
			out.Changes = append(out.Changes, Change{Setting: ref, Outcome: OutcomeFailed,
				Detail: "the captured original has no value, so this setting cannot be restored automatically"})
			out.Failed++
			continue
		}
		plan = append(plan, Change{Setting: ref, From: nil, To: *e.Value,
			Detail: fmt.Sprintf("captured %s (explicit=%t, from %s)", e.CapturedAt.Format(time.RFC3339), e.Explicit, e.Origin)})
	}

	if req.DryRun {
		for i := range plan {
			plan[i].Outcome = OutcomeDryRun
			plan[i].Verified = false
		}
		out.Changes = append(out.Changes, plan...)
		out.Notes = append(out.Notes,
			"The values above are what was recorded before this application first changed each setting; they are "+
				"read from this PC, not assumed from a platform default.")
		return out, nil
	}
	if !req.Confirm {
		return out, newError(CodePermission,
			fmt.Sprintf("refusing to restore %d setting(s) without confirmation", len(plan)),
			"Call with confirmation set, or preview the restore first.",
			fmt.Sprintf("planned restores: %d", len(plan)))
	}

	reason := req.Reason
	if reason == "" {
		reason = "restored the captured original values"
	}

	var events []Event
	var restored []Change
	failed := out.Failed

	rollbackRestore := func(c Change, cause error) (Outcome, error) {
		out.Changes = append(out.Changes, restored...)
		out.Changes = append(out.Changes, c)
		failed++
		out.Failed = failed
		out.RollbackDetail = append(out.RollbackDetail, fmt.Sprintf("%s failed to restore: %v", c.Setting.Compact(), cause))
		incomplete := false
		for i := len(restored) - 1; i >= 0; i-- {
			p := restored[i]
			rbErr := m.writeBack(ctx, p.Setting, p.From)
			ev := Event{At: m.now().UTC(), ID: p.Setting.ID, Family: p.Setting.Family, Scope: p.Setting.Scope,
				Iface: p.Setting.Interface, Old: intPtr(p.To), New: p.From,
				Reason: "automatic rollback of a partial restore"}
			if rbErr != nil {
				incomplete = true
				ev.Outcome = OutcomeRollbackFailed
				ev.Error = rbErr.Error()
				out.RollbackDetail = append(out.RollbackDetail, fmt.Sprintf("%s could not be put back: %v", p.Setting.Compact(), rbErr))
			} else {
				ev.Outcome = OutcomeRolledBack
			}
			events = append(events, ev)
		}
		out.RolledBack = !incomplete
		out.RollbackIncomplete = incomplete
		events = append(events, failureEvent(c, cause, reason))
		_ = m.store.AppendHistory(events...)
		if incomplete {
			return out, newError(CodeRollbackIncomplete,
				"the restore failed part-way through and the rollback could not complete",
				"Some settings are still at the values this restore wrote. The values below are what remains.",
				out.RollbackDetail...)
		}
		return out, cause
	}

	for _, c := range plan {
		if err := ctx.Err(); err != nil {
			return rollbackRestore(c, newError(CodeCancelled, "the restore was cancelled", "Everything already restored was put back.", err.Error()))
		}
		// The value being replaced is read now so a mid-restore failure can be undone.
		cur, _ := m.backend.Read(ctx, c.Setting)
		c.From = cur.Value

		if err := m.backend.Write(ctx, c.Setting, c.To); err != nil {
			return rollbackRestore(c, err)
		}
		obs, verr := m.backend.Read(ctx, c.Setting)
		if verr != nil {
			c.Outcome, c.Verified = OutcomeApplied, false
			c.Detail = "restored, but the value could not be read back to confirm it: " + verr.Error()
		} else if obs.Value != nil && *obs.Value == c.To {
			c.Outcome, c.Verified = OutcomeApplied, true
			c.Detail = "restored and confirmed"
		} else {
			return rollbackRestore(c, newError(CodeVerifyFailed,
				fmt.Sprintf("%s did not accept the restored value %d", c.Setting.Compact(), c.To),
				"The command reported success but the value read back differently. The change was undone.",
				fmt.Sprintf("requested: %d", c.To),
				fmt.Sprintf("read back: %s", FormatIntPtr(obs.Value))))
		}
		restored = append(restored, c)
		out.Applied++
		events = append(events, Event{At: m.now().UTC(), ID: c.Setting.ID, Family: c.Setting.Family,
			Scope: c.Setting.Scope, Iface: c.Setting.Interface, Old: c.From, New: intPtr(c.To),
			Outcome: OutcomeApplied, Reason: reason, Output: c.Detail})
	}

	out.Changes = append(out.Changes, restored...)
	out.Notes = append(out.Notes,
		"Restored from the values recorded before this application first changed each setting. "+
			"Nothing was assumed from a platform default.")
	_ = m.store.AppendHistory(events...)
	return out, nil
}

// refFor rebuilds a SettingRef from a capture. The adapter is matched by name against the
// current adapter list because interface indices can be reused after a reconnect; the
// captured index is used only when no name match is available, and the mismatch is reported.
func (m *Manager) refFor(ctx context.Context, e Original, ifaces []IfaceInfo) (SettingRef, error) {
	if e.Scope != ScopePerInterface {
		return SettingRef{ID: e.ID, Kind: kindFor(e.Family), Family: e.Family, Scope: e.Scope}, nil
	}
	if _, idx, name, ok := ParseInterfaceSettingID(e.ID); ok {
		for _, i := range ifaces {
			if strings.EqualFold(i.Name, name) {
				return IfaceRef(e.Family, i.Index, i.Name), nil
			}
		}
		return IfaceRef(e.Family, idx, name), nil
	}
	return SettingRef{}, fmt.Errorf("cannot interpret captured setting id %q", e.ID)
}

// kindFor returns the packet-header kind for a family.
func kindFor(f Family) Kind {
	if f == FamilyIPv6 {
		return KindPacketHopLimit
	}
	return KindPacketTTL
}

// sortSettingIDs orders ids deterministically so a plan and a report diff cleanly.
func sortSettingIDs(ids []SettingID) {
	for i := 1; i < len(ids); i++ {
		for j := i; j > 0 && ids[j] < ids[j-1]; j-- {
			ids[j], ids[j-1] = ids[j-1], ids[j]
		}
	}
}

// dryRunNote summarises a preview, including the blast radius of each change, because that is
// what a user needs to judge before allowing it.
func dryRunNote(changes []Change) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Preview only: %d setting(s) would change and nothing was written.", len(changes))
	for _, c := range changes {
		if c.Setting.Scope == ScopeSystemGlobal {
			sb.WriteString(" This includes a system-wide value, which affects traffic on every adapter.")
			break
		}
	}
	return sb.String()
}

// applyNotes collects the consequences a user should be told after a successful change.
func applyNotes(changes []Change) []string {
	var notes []string
	var global, perIface, unverified int
	for _, c := range changes {
		switch {
		case c.Setting.Scope == ScopeSystemGlobal:
			global++
		case c.Setting.Scope == ScopePerInterface:
			perIface++
		}
		if !c.Verified {
			unverified++
		}
	}
	if global > 0 {
		notes = append(notes, fmt.Sprintf(
			"%d system-wide value(s) changed. These affect traffic on every adapter, not only the one you were looking at.", global))
	}
	if perIface > 0 {
		notes = append(notes, fmt.Sprintf("%d per-interface value(s) changed. These affect only their own adapter.", perIface))
	}
	if unverified > 0 {
		notes = append(notes, fmt.Sprintf(
			"%d change(s) were written but could not be confirmed by reading the value back. Treat them as unverified.", unverified))
	}
	notes = append(notes,
		"A TTL or hop limit is stamped into packets as they leave this PC. Existing connections may keep the "+
			"value they started with; new ones use the new value. Changing it does not change DNS caching and "+
			"does not affect packets that merely pass through this PC.")
	return notes
}

// --- cross-process serialisation ------------------------------------------------------

// defaultLockTimeout bounds how long one operation waits for another to finish. Setting a hop
// limit is a sub-second operation, so a long wait means something is wrong rather than busy.
const defaultLockTimeout = 20 * time.Second

// lockTimeout is the configured wait, falling back to the default when unset.
func (m *Manager) lockTimeout() time.Duration {
	if m.lockWait <= 0 {
		return defaultLockTimeout
	}
	return m.lockWait
}

// lock takes the in-process mutex and then a cross-process lock file, in that order, and
// returns a function that releases both. Taking the in-process lock first means a single
// process cannot deadlock against itself on the file.
func (m *Manager) lock(ctx context.Context) (func(), error) {
	m.mu.Lock()

	release, err := m.acquireFileLock(ctx)
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	return func() {
		release()
		m.mu.Unlock()
	}, nil
}

// acquireFileLock implements a small advisory lock: an exclusive create of a file holding the
// owner's pid and the time. A lock left behind by a process that died is detected by age and
// reclaimed, so a crash cannot wedge the feature permanently.
func (m *Manager) acquireFileLock(ctx context.Context) (func(), error) {
	if err := m.store.ensureDir(); err != nil {
		return nil, err
	}
	path := filepath.Join(m.store.Dir(), "ttl-operation.lock")
	deadline := time.Now().Add(m.lockTimeout())

	for {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			fmt.Fprintf(f, "%d\n%s\n", os.Getpid(), m.now().UTC().Format(time.RFC3339Nano))
			f.Close()
			return func() { os.Remove(path) }, nil
		}
		if !os.IsExist(err) {
			return nil, newError(CodeWriteFailed,
				"the operation lock could not be created",
				"Check that the state directory is writable by this user.",
				path, err.Error())
		}

		// Reclaim a lock whose owner is gone.
		if stale, detail := m.lockIsStale(path); stale {
			if rmErr := os.Remove(path); rmErr == nil {
				continue
			} else {
				return nil, newError(CodeBusy,
					"another operation is in progress and its stale lock could not be cleared",
					"Close any other Control Center window, then retry.",
					detail, rmErr.Error())
			}
		}

		if time.Now().After(deadline) {
			return nil, newError(CodeBusy,
				"another TTL operation is still running",
				"Wait for it to finish and retry. Only one operation may change these settings at a time.",
				"lock file: "+path)
		}
		select {
		case <-ctx.Done():
			return nil, newError(CodeCancelled, "waiting for another operation was cancelled",
				"Nothing was changed.", ctx.Err().Error())
		case <-time.After(150 * time.Millisecond):
		}
	}
}

// lockIsStale reports whether a lock file's owner has gone away or the file is simply old.
func (m *Manager) lockIsStale(path string) (bool, string) {
	info, err := os.Stat(path)
	if err != nil {
		return false, ""
	}
	age := m.now().Sub(info.ModTime())
	if age > m.lockTimeout()*3 {
		return true, fmt.Sprintf("lock file is %s old", age.Truncate(time.Second))
	}
	// A lock whose recorded pid is no longer alive was left by a crash. Checking liveness is
	// best-effort: if the pid cannot be read the age test above is the fallback.
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, ""
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) == 0 {
		return false, ""
	}
	pid, err := strconv.Atoi(strings.TrimSpace(lines[0]))
	if err != nil || pid <= 0 || pid == os.Getpid() {
		return false, ""
	}
	if processAlive(pid) {
		return false, fmt.Sprintf("held by live pid %d", pid)
	}
	return true, fmt.Sprintf("lock file's owner pid %d is no longer running", pid)
}
