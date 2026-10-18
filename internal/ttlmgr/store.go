package ttlmgr

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Schema identifiers. They are versioned because the on-disk shape may change and a future
// build must be able to tell an old file from a new one instead of misreading it.
const (
	SchemaConfig    = "netmerge-ttl/1"
	SchemaOriginals = "netmerge-ttl-originals/1"
)

// DefaultBump is the value a hop-limit bump writes. It is a named constant rather than a
// literal because the UI, the docs and the tests all refer to the same number.
const DefaultBump = 65

// Config is the user's explicit, persisted intent. It is deliberately small: the minimum
// state needed to know what the user asked for, what the user's own values are, and how to
// put the machine back. Everything else is re-read from the operating system.
type Config struct {
	Schema  string `json:"schema"`
	Version int    `json:"version"`

	// Enabled records that the user opted in to management. Nothing acts on it by itself:
	// Apply is only reached through an explicit call, so a stale Enabled=true can never
	// silently change a setting on startup.
	Enabled bool `json:"enabled"`

	// BumpIPv4 / BumpIPv6 are the values the user chose to write while a managed condition
	// holds. They are validated on load; an out-of-range value is rejected rather than
	// clamped, so a corrupted file cannot turn into a surprising write.
	BumpIPv4 int `json:"bumpIPv4"`
	BumpIPv6 int `json:"bumpIPv6"`

	// Policy selects which adapters the per-interface bump targets.
	Policy InterfacePolicy `json:"interfacePolicy"`

	// IncludeIfaces and ExcludeIfaces are adapter names, matched case-insensitively.
	IncludeIfaces []string `json:"includeIfaces,omitempty"`
	ExcludeIfaces []string `json:"excludeIfaces,omitempty"`

	// Updated is when the user last changed the file.
	Updated time.Time `json:"updated"`
}

// InterfacePolicy decides which adapters a per-interface bump is applied to.
type InterfacePolicy string

const (
	// PolicyInterfaceNone writes only the system-global value. This is the default because it
	// is the closest match to the behaviour of the macOS original, and because writing per
	// interface on every adapter is a bigger change than many users expect.
	PolicyInterfaceNone InterfacePolicy = "none"
	// PolicyInterfaceList targets exactly the adapters named in IncludeIfaces.
	PolicyInterfaceList InterfacePolicy = "list"
	// PolicyInterfaceAllExcept targets every adapter except those in ExcludeIfaces.
	PolicyInterfaceAllExcept InterfacePolicy = "all-except"
)

// ValidInterfacePolicies lists the accepted policy values, for validation messages.
func ValidInterfacePolicies() []InterfacePolicy {
	return []InterfacePolicy{PolicyInterfaceNone, PolicyInterfaceList, PolicyInterfaceAllExcept}
}

// Valid reports whether the policy is one this build understands.
func (p InterfacePolicy) Valid() bool {
	for _, v := range ValidInterfacePolicies() {
		if p == v {
			return true
		}
	}
	return false
}

// DefaultConfig returns the configuration a first run starts from. It is conservative: not
// enabled, no per-interface writes, and a bump of DefaultBump.
func DefaultConfig() Config {
	return Config{
		Schema:   SchemaConfig,
		Version:  1,
		Enabled:  false,
		BumpIPv4: DefaultBump,
		BumpIPv6: DefaultBump,
		Policy:   PolicyInterfaceNone,
	}
}

// Validate rejects values this build must not act on. It never silently corrects: a caller
// that gets an error shows it, which is how a corrupted file stays visible instead of turning
// into an unexpected write.
func (c Config) Validate() error {
	var problems []string
	if c.Schema != SchemaConfig {
		problems = append(problems, fmt.Sprintf("schema is %q, want %q", c.Schema, SchemaConfig))
	}
	if c.Version < 1 {
		problems = append(problems, fmt.Sprintf("version is %d, want >= 1", c.Version))
	}
	// The 8-bit header field is the real limit; 1..255 is the whole representable range.
	if c.BumpIPv4 < 1 || c.BumpIPv4 > 255 {
		problems = append(problems, fmt.Sprintf("bumpIPv4 is %d, want 1..255", c.BumpIPv4))
	}
	if c.BumpIPv6 < 1 || c.BumpIPv6 > 255 {
		problems = append(problems, fmt.Sprintf("bumpIPv6 is %d, want 1..255", c.BumpIPv6))
	}
	if !c.Policy.Valid() {
		problems = append(problems, fmt.Sprintf("interfacePolicy is %q, want one of %v", c.Policy, ValidInterfacePolicies()))
	}
	if c.Policy == PolicyInterfaceList && len(c.IncludeIfaces) == 0 {
		problems = append(problems, "interfacePolicy is \"list\" but includeIfaces is empty")
	}
	if len(problems) > 0 {
		return &ConfigError{Code: CodeConfigInvalid, Problems: problems}
	}
	return nil
}

// Original records one setting's value as it was before this application first wrote it. It
// is stored per setting so a restore puts back exactly what was there - never an assumed
// platform default, which on Windows would be 128 rather than the 64 the macOS original used.
type Original struct {
	ID SettingID `json:"id"`

	// Family, Scope and Interface are copied from the reference so the capture log is
	// readable on its own, without the live system to interpret the id.
	Family    Family `json:"family"`
	Scope     Scope  `json:"scope"`
	Interface string `json:"interface,omitempty"`

	// Value is the value that was in effect when it was captured. It is a pointer only
	// because a read can genuinely fail; it is never used to mean zero.
	//
	// On Windows an absent registry value means "use the built-in default" (128 for both
	// families), and the built-in default is what was in effect. Capturing the effective
	// value therefore restores the behaviour the user had, and Explicit records whether the
	// platform had it written down or was falling back to its own default, so a restore can
	// say which of the two it re-created instead of implying it unset something.
	Value *int `json:"value"`

	// Explicit is true when the platform had this setting written down before the capture
	// (for example a present registry value), and false when the operating system's own
	// default was in effect. Restore uses it to choose between writing the value back and
	// asking the backend to unset it again.
	Explicit bool `json:"explicit"`

	// Origin is where the value was read from at capture time.
	Origin string `json:"origin"`

	// CapturedAt is when it was captured. Restore uses the newest capture per setting.
	CapturedAt time.Time `json:"capturedAt"`
}

// Originals is the persisted capture set.
type Originals struct {
	Schema  string     `json:"schema"`
	Version int        `json:"version"`
	Entries []Original `json:"entries"`
}

// ByID indexes the captures, keeping the newest per setting.
func (o Originals) ByID() map[SettingID]Original {
	out := make(map[SettingID]Original, len(o.Entries))
	for _, e := range o.Entries {
		if cur, ok := out[e.ID]; ok && cur.CapturedAt.After(e.CapturedAt) {
			continue
		}
		out[e.ID] = e
	}
	return out
}

// EventOutcome is how a change attempt ended.
type EventOutcome string

const (
	OutcomeApplied        EventOutcome = "applied"
	OutcomeUnchanged      EventOutcome = "unchanged"
	OutcomeFailed         EventOutcome = "failed"
	OutcomeRolledBack     EventOutcome = "rolled-back"
	OutcomeRollbackFailed EventOutcome = "rollback-incomplete"
	OutcomeDryRun         EventOutcome = "dry-run"
)

// Event is one line of the change history. Every field is recorded at the moment of the
// attempt, including failures, so the history is a record of what was tried and not only
// what worked.
type Event struct {
	At      time.Time    `json:"at"`
	ID      SettingID    `json:"id"`
	Family  Family       `json:"family"`
	Scope   Scope        `json:"scope"`
	Iface   string       `json:"interface,omitempty"`
	Old     *int         `json:"old"`
	New     *int         `json:"new"`
	Outcome EventOutcome `json:"outcome"`
	Reason  string       `json:"reason"`
	Error   string       `json:"error,omitempty"`

	// Command and Output record how the change was attempted, so a failed write can be
	// diagnosed from the history alone without re-running it.
	Command string `json:"command,omitempty"`
	Output  string `json:"output,omitempty"`
}

// Store persists the configuration, the captured originals and the change history. All
// writes are atomic (temp file plus rename) so an interrupted write cannot truncate a file,
// and every mutation is serialised by mu so two callers cannot interleave.
type Store struct {
	dir string
	mu  sync.Mutex

	// maxHistoryLines bounds the append-only history. Old lines are dropped from the front
	// when the file grows past this, which keeps a long-running install from filling a disk
	// while still keeping far more history than a person will read.
	maxHistoryLines int
}

// NewStore returns a Store rooted at dir. The directory is created on first write, hardened
// where the platform supports it, and its path is returned so callers can show it.
func NewStore(dir string) *Store {
	return &Store{dir: dir, maxHistoryLines: 5000}
}

// Dir returns the directory the store writes to.
func (s *Store) Dir() string { return s.dir }

func (s *Store) configPath() string    { return filepath.Join(s.dir, "ttl-config.json") }
func (s *Store) originalsPath() string { return filepath.Join(s.dir, "ttl-originals.json") }
func (s *Store) historyPath() string   { return filepath.Join(s.dir, "ttl-history.jsonl") }
func (s *Store) backupDir() string     { return filepath.Join(s.dir, "backups") }

// ensureDir creates the store directory and applies the strictest permissions the platform
// offers. On Windows the mode bits are advisory; HardenDir applies an ACL there.
func (s *Store) ensureDir() error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("create state directory %q: %w", s.dir, err)
	}
	return HardenDir(s.dir)
}

// writeFileAtomic writes data to path via a temporary file in the same directory and then
// renames it into place, so a reader either sees the old file or the new one and never a
// partly written one.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		// A successful rename has already consumed the name; removing again is a no-op that
		// also cleans up every failure path.
		tmp.Close()
		os.Remove(tmpName)
	}()
	if err := tmp.Chmod(perm); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// LoadConfig reads the configuration. A missing file is not an error: it yields the default
// configuration, which is how a first run behaves. A file that exists but cannot be parsed or
// fails validation is reported as CodeConfigInvalid and is moved aside rather than deleted,
// so the user can inspect what went wrong.
func (s *Store) LoadConfig() (Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadConfigLocked()
}

func (s *Store) loadConfigLocked() (Config, error) {
	raw, err := os.ReadFile(s.configPath())
	if errors.Is(err, os.ErrNotExist) {
		return DefaultConfig(), nil
	}
	if err != nil {
		return DefaultConfig(), fmt.Errorf("read %s: %w", s.configPath(), err)
	}
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		s.quarantineLocked("config", err)
		return DefaultConfig(), &ConfigError{Code: CodeConfigUnreadable, Problems: []string{err.Error()}}
	}
	if err := c.Validate(); err != nil {
		s.quarantineLocked("config", err)
		return DefaultConfig(), err
	}
	return c, nil
}

// SaveConfig validates and writes the configuration, first backing up any file it replaces.
func (s *Store) SaveConfig(c Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c.Schema == "" {
		c.Schema = SchemaConfig
	}
	if c.Version == 0 {
		c.Version = 1
	}
	c.Updated = time.Now().UTC()
	if err := c.Validate(); err != nil {
		return err
	}
	if err := s.ensureDir(); err != nil {
		return err
	}
	if _, err := os.Stat(s.configPath()); err == nil {
		if err := s.backupLocked("config"); err != nil {
			return fmt.Errorf("back up existing configuration: %w", err)
		}
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.configPath(), append(data, '\n'), 0o600)
}

// backupLocked copies the current configuration aside before it is overwritten. Backups are
// capped so repeated saves during one session cannot grow without bound.
func (s *Store) backupLocked(kind string) error {
	src := s.configPath()
	if kind == "originals" {
		src = s.originalsPath()
	}
	data, err := os.ReadFile(src)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if err := os.MkdirAll(s.backupDir(), 0o700); err != nil {
		return err
	}
	stamp := time.Now().UTC().Format("20060102T150405.000000000Z")
	name := fmt.Sprintf("%s-%s.json", kind, stamp)
	if err := writeFileAtomic(filepath.Join(s.backupDir(), name), data, 0o600); err != nil {
		return err
	}
	return pruneDir(s.backupDir(), 50)
}

// pruneDir keeps the newest keep files in dir and removes the rest. It is best-effort: a
// failure to prune never fails the operation that triggered it.
func pruneDir(dir string, keep int) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	if len(names) <= keep {
		return nil
	}
	sort.Strings(names) // timestamped names sort chronologically
	for _, n := range names[:len(names)-keep] {
		os.Remove(filepath.Join(dir, n))
	}
	return nil
}

// ListBackups returns the backup filenames, oldest first, so the UI can offer a restore point.
func (s *Store) ListBackups() ([]string, error) {
	entries, err := os.ReadDir(s.backupDir())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// quarantineLocked preserves a file that could not be used, under a .corrupt-<stamp> name, so
// the bad content is still available for inspection and the next start is not blocked by it.
func (s *Store) quarantineLocked(kind string, cause error) {
	path := s.configPath()
	if kind == "originals" {
		path = s.originalsPath()
	}
	if _, err := os.Stat(path); err != nil {
		return
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	dst := fmt.Sprintf("%s.corrupt-%s", path, stamp)
	if err := os.Rename(path, dst); err != nil {
		// Not being able to preserve it must not be silent, but it also must not stop the
		// caller: the value is reported through the returned error, which mentions the cause.
		_ = os.WriteFile(filepath.Join(s.dir, "quarantine-failed.log"),
			[]byte(fmt.Sprintf("%s: %v: quarantine of %s failed: %v\n", time.Now().UTC().Format(time.RFC3339), cause, path, err)), 0o600)
	}
}

// LoadOriginals reads the captured original values. A missing file yields an empty set, which
// is the correct state before anything has been changed.
func (s *Store) LoadOriginals() (Originals, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := os.ReadFile(s.originalsPath())
	if errors.Is(err, os.ErrNotExist) {
		return Originals{Schema: SchemaOriginals, Version: 1}, nil
	}
	if err != nil {
		return Originals{Schema: SchemaOriginals, Version: 1}, fmt.Errorf("read %s: %w", s.originalsPath(), err)
	}
	var o Originals
	if err := json.Unmarshal(raw, &o); err != nil {
		s.quarantineLocked("originals", err)
		return Originals{Schema: SchemaOriginals, Version: 1},
			&ConfigError{Code: CodeConfigUnreadable, Problems: []string{"captured originals: " + err.Error()}}
	}
	if o.Schema != SchemaOriginals {
		problems := []string{fmt.Sprintf("captured originals schema is %q, want %q", o.Schema, SchemaOriginals)}
		s.quarantineLocked("originals", errors.New(strings.Join(problems, "; ")))
		return Originals{Schema: SchemaOriginals, Version: 1},
			&ConfigError{Code: CodeConfigInvalid, Problems: problems}
	}
	return o, nil
}

// CaptureOriginals records a setting's current value, but only the first time it is seen for
// that setting. Re-capturing on every apply would overwrite the true original with this tool's
// own bump value and make a faithful restore impossible, so the existing entry always wins.
//
// force is used by tests and by the explicit "re-capture" action.
func (s *Store) CaptureOriginals(entries []Original, force bool) (Originals, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cur := Originals{Schema: SchemaOriginals, Version: 1}
	if raw, err := os.ReadFile(s.originalsPath()); err == nil {
		if err := json.Unmarshal(raw, &cur); err != nil {
			// A damaged capture file must not be silently replaced: without it a faithful
			// restore is impossible, so the caller is told.
			return Originals{}, 0, &ConfigError{Code: CodeConfigUnreadable,
				Problems: []string{"refusing to overwrite an unreadable capture file: " + err.Error()}}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return Originals{}, 0, err
	}

	have := cur.ByID()
	added := 0
	for _, e := range entries {
		if _, ok := have[e.ID]; ok && !force {
			continue
		}
		if e.CapturedAt.IsZero() {
			e.CapturedAt = time.Now().UTC()
		}
		var replaced bool
		for i := range cur.Entries {
			if cur.Entries[i].ID == e.ID {
				cur.Entries[i], replaced = e, true
				break
			}
		}
		if !replaced {
			cur.Entries = append(cur.Entries, e)
			added++
		}
	}
	if added == 0 && !force {
		return cur, 0, nil
	}
	if err := s.ensureDir(); err != nil {
		return Originals{}, 0, err
	}
	sort.Slice(cur.Entries, func(a, b int) bool { return cur.Entries[a].ID < cur.Entries[b].ID })
	data, err := json.MarshalIndent(cur, "", "  ")
	if err != nil {
		return Originals{}, 0, err
	}
	if err := writeFileAtomic(s.originalsPath(), append(data, '\n'), 0o600); err != nil {
		return Originals{}, 0, err
	}
	return cur, added, nil
}

// AppendHistory records change attempts. It is append-only by design: a resubmit or a retry
// adds a line rather than replacing the earlier one, so a failure stays in the record even
// after it is fixed. History is best-effort - it never fails the operation it describes - but
// a failure to append is returned so the caller can surface it.
func (s *Store) AppendHistory(evs ...Event) error {
	if len(evs) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureDir(); err != nil {
		return err
	}
	var sb strings.Builder
	for _, ev := range evs {
		if ev.At.IsZero() {
			ev.At = time.Now().UTC()
		}
		b, err := json.Marshal(ev)
		if err != nil {
			return err
		}
		sb.Write(b)
		sb.WriteByte('\n')
	}
	f, err := os.OpenFile(s.historyPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(sb.String()); err != nil {
		return err
	}
	return s.trimHistoryLocked()
}

// trimHistoryLocked keeps the history bounded. It rewrites the file only when it has grown
// past twice the cap, so the usual append path stays a plain append.
func (s *Store) trimHistoryLocked() error {
	st, err := os.Stat(s.historyPath())
	if err != nil || st.Size() < 1<<20 {
		return nil // under a megabyte, no need to look at line counts
	}
	raw, err := os.ReadFile(s.historyPath())
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) <= s.maxHistoryLines*2 {
		return nil
	}
	kept := lines[len(lines)-s.maxHistoryLines:]
	return writeFileAtomic(s.historyPath(), []byte(strings.Join(kept, "\n")+"\n"), 0o600)
}

// History returns the recorded events, newest last, capped at limit entries (0 = all).
func (s *Store) History(limit int) ([]Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := os.ReadFile(s.historyPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Event
	for _, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var ev Event
		// One malformed line must not hide the rest of the history: skip it and keep going.
		if json.Unmarshal([]byte(line), &ev) != nil {
			continue
		}
		out = append(out, ev)
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out, nil
}

// ClearOriginals removes the capture set. It is used by uninstall and by an explicit
// "forget captured originals" action, and it is deliberately not reachable from Apply.
func (s *Store) ClearOriginals() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := os.Remove(s.originalsPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// FormatIntPtr renders an optional value for human-facing text.
func FormatIntPtr(v *int) string {
	if v == nil {
		return "not configured"
	}
	return strconv.Itoa(*v)
}
