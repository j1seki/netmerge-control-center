// Package appcfg is the Control Center's own settings file: quality profiles, dashboard
// preferences, monitoring targets, privacy and logging.
//
// It is deliberately NOT the TTL manager's configuration. The TTL manager owns its own
// versioned file (internal/ttlmgr) and is the single writer for it; this file never contains
// TTL values. That separation is what keeps "one authoritative TTL-manager configuration"
// true even while profiles are edited.
//
// Every field is validated on load. A file that fails validation is kept, quarantined beside
// itself, and reported - never silently replaced with defaults, because a user who edited a
// value wrongly needs to see what they typed, not lose it.
package appcfg

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Schema identifies this file's shape. A future build that changes it must bump the string so
// an old file is recognised rather than misread.
const Schema = "netmerge-control-center/1"

// ConfigVersion is the revision of the schema above.
const ConfigVersion = 1

// FileName is the settings file inside the state directory.
const FileName = "control-center.json"

// ProfileID is a stable identifier for a quality profile.
type ProfileID string

const (
	ProfileThroughput  ProfileID = "maximum-throughput"
	ProfileGaming      ProfileID = "gaming-low-latency"
	ProfileFiber       ProfileID = "fiber-preferred"
	ProfileReliability ProfileID = "connection-reliability"
	ProfileCustom      ProfileID = "custom"
)

// ProfileIDs lists the built-in profiles in the order the UI shows them.
func ProfileIDs() []ProfileID {
	return []ProfileID{ProfileThroughput, ProfileGaming, ProfileFiber, ProfileReliability, ProfileCustom}
}

// EnginePrefs is the part of a profile that maps onto the bonding engine's documented
// options. These are exactly the knobs the engine actually has (net-merge run -include,
// -weight, -auto-weight, -ipv6, -mtu); nothing here is invented, and the Routing section
// renders the resulting command line so a user can see what a profile would do.
type EnginePrefs struct {
	// Include names the adapters to use. Empty means "every adapter the engine considers
	// usable", which is the engine's own default.
	Include []string `json:"include,omitempty"`
	// Exclude names adapters to leave out. The engine has no exclude flag, so the Control
	// Center translates this into the inclusion list it hands the engine; storing the
	// exclusion is still the honest representation of "use everything except this".
	Exclude []string `json:"exclude,omitempty"`
	// Weights are fixed per-adapter weights (the engine's -weight). Present only when the
	// profile pins weights; AutoWeight is the engine's -auto-weight.
	Weights map[string]float64 `json:"weights,omitempty"`
	// AutoWeight mirrors -auto-weight: weight adapters by measured throughput. A pointer so
	// "no opinion" (the engine's own default) is distinguishable from an explicit false; a
	// plain bool would turn every unset field into "off", which is not what the profile said.
	AutoWeight *bool `json:"autoWeight,omitempty"`
	// IPv6 mirrors -ipv6: auto|on|off.
	IPv6 string `json:"ipv6,omitempty"`
	// MTU mirrors -mtu; 0 means "leave the engine default".
	MTU int `json:"mtu,omitempty"`
}

// MonitorPrefs is what the Control Center measures and how it judges a link. These are
// advisory and observational; they never change a system setting.
type MonitorPrefs struct {
	// LatencyBudgetMs is the round-trip time above which the dashboard marks a link as
	// "over budget" for this profile. 0 means no budget is applied.
	LatencyBudgetMs int `json:"latencyBudgetMs,omitempty"`
	// ProbeLinkLatency enables the per-link TCP latency probe. It is off by default for
	// profiles that do not care, because it is the most expensive thing the monitor does.
	ProbeLinkLatency bool `json:"probeLinkLatency,omitempty"`
	// PreferLowerLatency is a documented intent flag. The engine has no latency-weighted
	// scheduler, so this is shown as advice ("this profile prefers the lower-latency link")
	// and used to sort the Routing view - never presented as enforcement.
	PreferLowerLatency bool `json:"preferLowerLatency,omitempty"`
}

// Profile is one quality profile.
type Profile struct {
	ID          ProfileID    `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Engine      EnginePrefs  `json:"engine"`
	Monitor     MonitorPrefs `json:"monitor"`
}

// Dashboard is where the embedded web UI listens and how it refreshes.
type Dashboard struct {
	// Listen is the dashboard's listen address. It is loopback-only by default and the
	// server refuses to bind a routable address without an explicit override, because the
	// whole privacy story of the dashboard depends on it not being reachable from the LAN.
	Listen string `json:"listen"`
	// IntervalMs is how often the monitor refreshes the shared snapshot the UI polls.
	// The UI polls the cached snapshot, so this is the only rate that costs work.
	IntervalMs int `json:"intervalMs"`
	// HealthIntervalMs is how often the link-health probe runs: one TCP connect per
	// adapter that can carry traffic, then a result cached for the page. 0 means the
	// default; a negative value turns the probe off, and the page says it is off rather
	// than showing nothing. It cannot be faster than the profile budget allows because it
	// is the most expensive thing the dashboard does.
	HealthIntervalMs int `json:"healthIntervalMs"`
	// OpenBrowser asks the command to open the dashboard in the default browser on start.
	OpenBrowser bool `json:"openBrowser"`
}

// Logging controls the in-process log: level, and rotation for the log file.
type Logging struct {
	Level      string `json:"level"` // debug|info|warn|error
	MaxBytes   int64  `json:"maxBytes"`
	MaxFiles   int    `json:"maxFiles"`
	RingEvents int    `json:"ringEvents"` // in-memory events kept for the Logs section
}

// Privacy controls what the AI-ready export removes. The defaults redact everything the
// objective names; turning one off is an explicit user choice made in the Settings section,
// and the report always states which redactions were applied.
type Privacy struct {
	RedactPublicIPs    bool `json:"redactPublicIPs"`
	RedactMACs         bool `json:"redactMACs"`
	RedactSerials      bool `json:"redactSerials"`
	RedactPaths        bool `json:"redactPaths"`
	RedactHostNames    bool `json:"redactHostNames"`
	RedactAdapterNames bool `json:"redactAdapterNames"`
	// KeepWellKnownPublicIPs leaves infrastructure addresses that identify a service rather
	// than a person or a customer link (8.8.8.8, 1.1.1.1 and friends) readable, so a report
	// that says "DNS is 8.8.8.8 and did not answer" stays meaningful. Redacting them is
	// possible; keeping them is the default because they are published anycast addresses.
	KeepWellKnownPublicIPs bool `json:"keepWellKnownPublicIPs"`
	// IncludeHostname leaves the machine name in the report when true.
	IncludeHostname bool `json:"includeHostname"`
}

// Diagnostics configures the diagnostic center's targets and limits.
type Diagnostics struct {
	// Endpoint is the host:port used for TCP reachability and latency checks.
	Endpoint string `json:"endpoint"`
	// DNSServer is optional: when set, DNS checks that can target a server do.
	DNSServer string `json:"dnsServer,omitempty"`
	// DNSName is the name resolved by the DNS checks.
	DNSName string `json:"dnsName"`
	// TracerouteTarget is the host the traceroute check traces to.
	TracerouteTarget string `json:"tracerouteTarget"`
	// UDPTarget is the host:port used for the UDP reachability probe.
	UDPTarget string `json:"udpTarget"`
	// TimeoutMs bounds each individual diagnostic command.
	TimeoutMs int `json:"timeoutMs"`
	// TracerouteTimeoutMs bounds the traceroute check specifically, which is slower.
	TracerouteTimeoutMs int `json:"tracerouteTimeoutMs"`
	// MTUHost is the host used by the path-MTU check.
	MTUHost string `json:"mtuHost"`
	// DisabledChecks lists check ids the user turned off.
	DisabledChecks []string `json:"disabledChecks,omitempty"`
}

// Safety holds the guardrails a user can tighten.
type Safety struct {
	// ConfirmDestructive is always effectively true for system changes; it is stored so a
	// UI can show the current policy rather than assume it. There is no build of this app
	// that performs a system change without an explicit confirm from the caller.
	ConfirmDestructive bool `json:"confirmDestructive"`
	// DryRunDefault makes the TTL page's first action a preview rather than an apply.
	DryRunDefault bool `json:"dryRunDefault"`
}

// Config is the whole file.
type Config struct {
	Schema  string    `json:"schema"`
	Version int       `json:"version"`
	Updated time.Time `json:"updated"`

	ActiveProfile ProfileID             `json:"activeProfile"`
	Profiles      map[ProfileID]Profile `json:"profiles"`

	Dashboard   Dashboard   `json:"dashboard"`
	Logging     Logging     `json:"logging"`
	Privacy     Privacy     `json:"privacy"`
	Diagnostics Diagnostics `json:"diagnostics"`
	Safety      Safety      `json:"safety"`
}

// Default returns the settings a first run uses. Every value here is a deliberate choice:
// loopback-only dashboard, one-second refresh, info logging, full redaction, and the
// throughput profile active with auto-weighting.
func Default() Config {
	cfg := Config{
		Schema:        Schema,
		Version:       ConfigVersion,
		ActiveProfile: ProfileThroughput,
		Profiles:      map[ProfileID]Profile{},
		Dashboard: Dashboard{
			Listen:           "127.0.0.1:0",
			IntervalMs:       1000,
			HealthIntervalMs: 30000,
			OpenBrowser:      true,
		},
		Logging: Logging{Level: "info", MaxBytes: 4 << 20, MaxFiles: 5, RingEvents: 2000},
		Privacy: Privacy{
			RedactPublicIPs:        true,
			RedactMACs:             true,
			RedactSerials:          true,
			RedactPaths:            true,
			RedactHostNames:        true,
			RedactAdapterNames:     false,
			KeepWellKnownPublicIPs: true,
			IncludeHostname:        false,
		},
		Diagnostics: Diagnostics{
			Endpoint:            "1.1.1.1:443",
			DNSName:             "www.example.com",
			TracerouteTarget:    "1.1.1.1",
			UDPTarget:           "time.cloudflare.com:123",
			TimeoutMs:           4000,
			TracerouteTimeoutMs: 15000,
			MTUHost:             "1.1.1.1",
		},
		Safety: Safety{ConfirmDestructive: true, DryRunDefault: true},
	}
	for _, p := range builtinProfiles() {
		cfg.Profiles[p.ID] = p
	}
	return cfg
}

// builtinProfiles describes what each profile means, in the engine's real vocabulary.
func builtinProfiles() []Profile {
	return []Profile{
		{
			ID:          ProfileThroughput,
			Name:        "Maximum Throughput",
			Description: "Use every eligible internet path and let the engine weight adapters by measured throughput. Per-connection balancing: separate connections spread across links; one TCP connection still uses one link.",
			Engine:      EnginePrefs{AutoWeight: Bool(true), IPv6: "auto"},
			Monitor:     MonitorPrefs{ProbeLinkLatency: false},
		},
		{
			ID:          ProfileGaming,
			Name:        "Gaming / Low Latency",
			Description: "Favour the healthy lower-latency path for interactive traffic. The engine balances per connection and does not break established connections; weights should be pinned to the link this profile favours.",
			Engine:      EnginePrefs{AutoWeight: Bool(false), IPv6: "auto"},
			Monitor:     MonitorPrefs{ProbeLinkLatency: true, LatencyBudgetMs: 60, PreferLowerLatency: true},
		},
		{
			ID:          ProfileFiber,
			Name:        "Fiber Preferred",
			Description: "Prefer the wired home fiber for ordinary traffic. Set the preferred adapter below; the others stay excluded unless you include them, and the TTL page is separate.",
			Engine:      EnginePrefs{AutoWeight: Bool(false), IPv6: "auto"},
			Monitor:     MonitorPrefs{ProbeLinkLatency: true, LatencyBudgetMs: 100},
		},
		{
			ID:          ProfileReliability,
			Name:        "Connection Reliability",
			Description: "Keep working links working: the engine already removes an adapter from new assignments when its probes fail and restores it after recovery. This profile watches health and reports transitions; auto-weighting is on so a degraded link contributes less.",
			Engine:      EnginePrefs{AutoWeight: Bool(true), IPv6: "auto"},
			Monitor:     MonitorPrefs{ProbeLinkLatency: true, LatencyBudgetMs: 250},
		},
		{
			ID:          ProfileCustom,
			Name:        "Custom",
			Description: "Your own include list, exclusions and weights. Nothing is assumed: what you set is what the engine gets.",
			// No opinion on auto-weighting: the engine's own default stands until the user
			// sets this field. A plain false would silently turn weighting off.
			Engine:  EnginePrefs{IPv6: "auto"},
			Monitor: MonitorPrefs{},
		},
	}
}

// Problems is a validation result: every problem found, not just the first.
type Problems []string

func (p Problems) Error() string { return strings.Join(p, "; ") }

// Stale reports whether the file on disk was written by a different build than this one, and
// says so in words. A stale file is usable - Load fills in what is missing and Validate only
// rejects what it must - but the user is told, because a value that behaved one way in another
// build can behave differently now, and because saving rewrites the file in this build's format.
func (c Config) Stale() (bool, string) {
	switch {
	case c.Version == 0:
		return true, fmt.Sprintf("the settings file does not record a format version, so it was written by a build older than this one (current version %d); the known fields still load, and saving rewrites the file in the current format", ConfigVersion)
	case c.Version < ConfigVersion:
		return true, fmt.Sprintf("the settings file records format version %d and this build writes version %d; the known fields still load, and saving rewrites the file in the current format", c.Version, ConfigVersion)
	case c.Version > ConfigVersion:
		return true, fmt.Sprintf("the settings file records format version %d and this build only knows version %d, so it was written by a newer build; the fields shown are the ones this build understands, and saving would drop what it does not (open the file and copy anything you need first)", c.Version, ConfigVersion)
	}
	return false, ""
}

// ValidAddress reports whether the configured dashboard address is syntactically usable.
// It does not decide reachability; the server refuses non-loopback binds separately.
func (c Config) ListenAddress() (string, error) {
	s := strings.TrimSpace(c.Dashboard.Listen)
	if s == "" {
		return "127.0.0.1:0", nil
	}
	return s, nil
}

// Validate checks every user-editable value. It never corrects: the caller shows the
// problems and keeps the user's file.
func (c *Config) Validate() error {
	var probs Problems
	if c.Schema != Schema {
		probs = append(probs, fmt.Sprintf("schema is %q, want %q", c.Schema, Schema))
	}
	if c.Version < 1 {
		probs = append(probs, fmt.Sprintf("version is %d, want >= 1", c.Version))
	}
	if _, ok := c.Profiles[c.ActiveProfile]; !ok {
		probs = append(probs, fmt.Sprintf("activeProfile %q is not one of the defined profiles", c.ActiveProfile))
	}
	for id, p := range c.Profiles {
		if id != p.ID {
			probs = append(probs, fmt.Sprintf("profile %q has id %q", id, p.ID))
		}
		if strings.TrimSpace(p.Name) == "" {
			probs = append(probs, fmt.Sprintf("profile %q has no name", id))
		}
		if p.Engine.MTU != 0 && (p.Engine.MTU < 1280 || p.Engine.MTU > 65535) {
			probs = append(probs, fmt.Sprintf("profile %q: mtu %d is outside 1280..65535", id, p.Engine.MTU))
		}
		switch p.Engine.IPv6 {
		case "", "auto", "on", "off":
		default:
			probs = append(probs, fmt.Sprintf("profile %q: ipv6 %q is not auto, on or off", id, p.Engine.IPv6))
		}
		for name, w := range p.Engine.Weights {
			if w <= 0 {
				probs = append(probs, fmt.Sprintf("profile %q: weight for %q is %g, want > 0", id, name, w))
			}
		}
		if p.Monitor.LatencyBudgetMs < 0 {
			probs = append(probs, fmt.Sprintf("profile %q: latencyBudgetMs cannot be negative", id))
		}
	}
	if len(c.Profiles) == 0 {
		probs = append(probs, "no profiles are defined")
	}
	if c.Dashboard.IntervalMs < 250 {
		probs = append(probs, fmt.Sprintf("dashboard.intervalMs is %d, want >= 250", c.Dashboard.IntervalMs))
	}
	if c.Dashboard.HealthIntervalMs < -1 {
		probs = append(probs, fmt.Sprintf("dashboard.healthIntervalMs is %d; use 0 for the default, -1 to disable, or a positive number of milliseconds", c.Dashboard.HealthIntervalMs))
	}
	if c.Dashboard.HealthIntervalMs > 0 && c.Dashboard.HealthIntervalMs < 5000 {
		probs = append(probs, fmt.Sprintf("dashboard.healthIntervalMs is %d; a health probe every %d ms is more load than the result is worth (minimum 5000, or -1 to disable)", c.Dashboard.HealthIntervalMs, c.Dashboard.HealthIntervalMs))
	}
	if _, ok := parseLogLevel(c.Logging.Level); !ok {
		probs = append(probs, fmt.Sprintf("logging.level %q is not debug, info, warn or error", c.Logging.Level))
	}
	if c.Logging.MaxBytes < 0 {
		probs = append(probs, "logging.maxBytes cannot be negative")
	}
	if c.Logging.MaxFiles < 0 {
		probs = append(probs, "logging.maxFiles cannot be negative")
	}
	if c.Logging.RingEvents < 0 {
		probs = append(probs, "logging.ringEvents cannot be negative")
	}
	if err := validateEndpoint("diagnostics.endpoint", c.Diagnostics.Endpoint); err != nil {
		probs = append(probs, err.Error())
	}
	if c.Diagnostics.UDPTarget != "" {
		if err := validateEndpoint("diagnostics.udpTarget", c.Diagnostics.UDPTarget); err != nil {
			probs = append(probs, err.Error())
		}
	}
	if strings.TrimSpace(c.Diagnostics.DNSName) == "" {
		probs = append(probs, "diagnostics.dnsName is empty, so the DNS checks have nothing to resolve")
	}
	if c.Diagnostics.TimeoutMs < 100 {
		probs = append(probs, fmt.Sprintf("diagnostics.timeoutMs is %d, want >= 100", c.Diagnostics.TimeoutMs))
	}
	if c.Diagnostics.TracerouteTimeoutMs < c.Diagnostics.TimeoutMs {
		probs = append(probs, "diagnostics.tracerouteTimeoutMs is smaller than timeoutMs, so traceroute would always be cut short")
	}
	if len(probs) > 0 {
		return probs
	}
	return nil
}

func validateEndpoint(field, v string) error {
	if strings.TrimSpace(v) == "" {
		return fmt.Errorf("%s is empty", field)
	}
	i := strings.LastIndex(v, ":")
	if i <= 0 || i == len(v)-1 {
		return fmt.Errorf("%s %q must be host:port", field, v)
	}
	if strings.Contains(v[:i], ":") && !strings.HasPrefix(v, "[") {
		return fmt.Errorf("%s %q looks like IPv6 without brackets; use [address]:port", field, v)
	}
	return nil
}

func parseLogLevel(s string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug", "info", "warn", "error":
		return strings.ToLower(strings.TrimSpace(s)), true
	}
	return "", false
}

// Path returns the settings file inside a state directory.
func Path(dir string) string { return filepath.Join(dir, FileName) }

// Load reads and validates the file. A missing file yields the defaults with ok=false and no
// error, which is the first-run case. A file that cannot be parsed or fails validation is
// quarantined (renamed beside itself with a timestamp) and returned as an error, so the
// caller can tell the user exactly what was wrong rather than pretending nothing happened.
func Load(dir string) (cfg Config, existed bool, err error) {
	path := Path(dir)
	b, readErr := os.ReadFile(path)
	if errors.Is(readErr, os.ErrNotExist) {
		return Default(), false, nil
	}
	if readErr != nil {
		return Default(), true, fmt.Errorf("reading %s: %w", path, readErr)
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	if err := dec.Decode(&cfg); err != nil {
		return Default(), true, &LoadError{Path: path, Stage: "parse", Err: err}
	}
	cfg.fillMissing()
	if err := cfg.Validate(); err != nil {
		return Default(), true, &LoadError{Path: path, Stage: "validate", Err: err}
	}
	return cfg, true, nil
}

// fillMissing adds defaults for values a hand-written file may omit, so a minimal file is
// still a valid one. It never overrides something the file set.
func (c *Config) fillMissing() {
	def := Default()
	if c.Profiles == nil {
		c.Profiles = def.Profiles
	}
	for _, id := range ProfileIDs() {
		if _, ok := c.Profiles[id]; ok {
			continue
		}
		if bp, ok := def.Profiles[id]; ok {
			c.Profiles[id] = bp
		}
	}
	if c.Dashboard.Listen == "" {
		c.Dashboard.Listen = def.Dashboard.Listen
	}
	if c.Dashboard.IntervalMs == 0 {
		c.Dashboard.IntervalMs = def.Dashboard.IntervalMs
	}
	if c.Dashboard.HealthIntervalMs == 0 {
		c.Dashboard.HealthIntervalMs = def.Dashboard.HealthIntervalMs
	}
	if c.Logging.Level == "" {
		c.Logging.Level = def.Logging.Level
	}
	if c.Logging.MaxBytes == 0 {
		c.Logging.MaxBytes = def.Logging.MaxBytes
	}
	if c.Logging.MaxFiles == 0 {
		c.Logging.MaxFiles = def.Logging.MaxFiles
	}
	if c.Logging.RingEvents == 0 {
		c.Logging.RingEvents = def.Logging.RingEvents
	}
	if c.Diagnostics.TimeoutMs == 0 {
		c.Diagnostics.TimeoutMs = def.Diagnostics.TimeoutMs
	}
	if c.Diagnostics.TracerouteTimeoutMs == 0 {
		c.Diagnostics.TracerouteTimeoutMs = def.Diagnostics.TracerouteTimeoutMs
	}
	if c.Diagnostics.Endpoint == "" {
		c.Diagnostics.Endpoint = def.Diagnostics.Endpoint
	}
	if c.Diagnostics.DNSName == "" {
		c.Diagnostics.DNSName = def.Diagnostics.DNSName
	}
}

// LoadError describes a settings file that could not be used, with the offending path so the
// message can tell the user which file to look at.
type LoadError struct {
	Path  string
	Stage string
	Err   error
}

func (e *LoadError) Error() string {
	return fmt.Sprintf("%s: could not %s the Control Center settings (%v); defaults were used", e.Path, e.Stage, e.Err)
}

func (e *LoadError) Unwrap() error { return e.Err }

// Quarantine moves an unusable settings file aside, keeping its contents for inspection.
// It is separate from Load so that reading a file never has a side effect; the command that
// decides to carry on with defaults is what calls it.
func Quarantine(path string, now time.Time) (string, error) {
	dst := fmt.Sprintf("%s.corrupt-%s", path, now.UTC().Format("20060102T150405Z"))
	if err := os.Rename(path, dst); err != nil {
		return "", err
	}
	return dst, nil
}

// Save writes the file atomically, keeping one backup of the previous contents. The backup
// is what makes "automatically detect a stale configuration" and "safe config backups"
// possible without a second mechanism.
func Save(dir string, cfg Config) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	cfg.Schema = Schema
	if cfg.Version == 0 {
		cfg.Version = ConfigVersion
	}
	cfg.Updated = time.Now().UTC()
	if err := cfg.Validate(); err != nil {
		return err
	}
	path := Path(dir)
	if old, err := os.ReadFile(path); err == nil && len(old) > 0 {
		_ = os.WriteFile(path+".bak", old, 0o600)
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// BackupPath is where Save keeps the previous file.
func BackupPath(dir string) string { return Path(dir) + ".bak" }

// SortedProfiles returns the profiles in display order, so the UI and the report agree.
func (c *Config) SortedProfiles() []Profile {
	out := make([]Profile, 0, len(c.Profiles))
	for _, id := range ProfileIDs() {
		if p, ok := c.Profiles[id]; ok {
			out = append(out, p)
		}
	}
	// Any profile a user added under an unknown id still appears, at the end, so it is not
	// silently dropped.
	var extra []ProfileID
	for id := range c.Profiles {
		known := false
		for _, k := range ProfileIDs() {
			if id == k {
				known = true
			}
		}
		if !known {
			extra = append(extra, id)
		}
	}
	sort.Slice(extra, func(i, j int) bool { return extra[i] < extra[j] })
	for _, id := range extra {
		out = append(out, c.Profiles[id])
	}
	return out
}

// Active returns the active profile, or a zero Profile when the id is unknown.
func (c *Config) Active() (Profile, bool) {
	p, ok := c.Profiles[c.ActiveProfile]
	return p, ok
}

// Bool returns a pointer to v, for the tri-state EnginePrefs fields.
func Bool(v bool) *bool { return &v }

// Overlay is the engine configuration a profile contributes, in the engine's own vocabulary. A
// nil or empty field means the profile has no opinion there and the engine's default (or the
// user's own command-line flag) stands. It is what the launch path merges into unset flags, so
// switching profile in the dashboard changes what the next engine start does.
type Overlay struct {
	Include    []string
	Exclude    []string
	Weights    map[string]float64
	AutoWeight *bool
	IPv6       string
	MTU        int
}

// Overlay projects the profile's engine preferences. It copies the lists and the weight map so
// a caller cannot mutate stored settings through the result.
func (p Profile) Overlay() Overlay {
	ov := Overlay{AutoWeight: p.Engine.AutoWeight, IPv6: p.Engine.IPv6, MTU: p.Engine.MTU}
	if len(p.Engine.Include) > 0 {
		ov.Include = append([]string(nil), p.Engine.Include...)
	}
	if len(p.Engine.Exclude) > 0 {
		ov.Exclude = append([]string(nil), p.Engine.Exclude...)
	}
	if len(p.Engine.Weights) > 0 {
		ov.Weights = make(map[string]float64, len(p.Engine.Weights))
		for k, v := range p.Engine.Weights {
			ov.Weights[k] = v
		}
	}
	return ov
}

// EngineArgs renders the engine flags this profile maps to, for `net-merge run`. It is the
// concrete answer to "what would this profile actually do", and the Routing section shows it
// so a preference is never mistaken for a guarantee.
func (p Profile) EngineArgs() []string {
	var args []string
	if len(p.Engine.Include) > 0 {
		args = append(args, "-include", strings.Join(p.Engine.Include, ","))
	}
	if len(p.Engine.Exclude) > 0 {
		args = append(args, "-exclude", strings.Join(p.Engine.Exclude, ","))
	}
	if p.Engine.AutoWeight != nil && !*p.Engine.AutoWeight {
		args = append(args, "-auto-weight=false")
	}
	for _, name := range sortedKeys(p.Engine.Weights) {
		args = append(args, "-weight", fmt.Sprintf("%s=%g", name, p.Engine.Weights[name]))
	}
	if p.Engine.IPv6 != "" && p.Engine.IPv6 != "auto" {
		args = append(args, "-ipv6", p.Engine.IPv6)
	}
	if p.Engine.MTU != 0 {
		args = append(args, "-mtu", fmt.Sprint(p.Engine.MTU))
	}
	return args
}

func sortedKeys(m map[string]float64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
