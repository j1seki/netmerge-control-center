package appcfg

// Tests for the Control Center's settings file.
//
// Everything happens in a temporary directory. The tests pin the two properties the rest of the
// application relies on: a file the user edited is never silently replaced (it is reported and
// quarantined, and every problem is listed, not just the first), and what a profile does is
// rendered from its stored values as real engine flags rather than described.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultIsValidAndComplete(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the shipped defaults do not validate: %v", err)
	}
	if cfg.Schema != Schema || cfg.Version != ConfigVersion {
		t.Errorf("schema/version = %q/%d", cfg.Schema, cfg.Version)
	}
	if len(cfg.Profiles) != len(ProfileIDs()) {
		t.Errorf("got %d profiles, want %d", len(cfg.Profiles), len(ProfileIDs()))
	}
	for _, id := range ProfileIDs() {
		p, ok := cfg.Profiles[id]
		if !ok {
			t.Fatalf("built-in profile %q is missing", id)
		}
		if p.Name == "" || p.Description == "" {
			t.Errorf("profile %q has no name or description", id)
		}
	}
	if !cfg.Privacy.RedactPublicIPs || !cfg.Privacy.RedactMACs || !cfg.Privacy.RedactSerials || !cfg.Privacy.RedactPaths {
		t.Error("the default privacy settings must redact; a user has to opt out explicitly")
	}
	if cfg.Dashboard.Listen != "127.0.0.1:0" {
		t.Errorf("the dashboard must default to loopback, got %q", cfg.Dashboard.Listen)
	}
}

func TestLoadMissingFileYieldsDefaults(t *testing.T) {
	dir := t.TempDir()
	cfg, existed, err := Load(dir)
	if err != nil {
		t.Fatalf("a missing file is the first run, not an error: %v", err)
	}
	if existed {
		t.Error("existed = true for a missing file")
	}
	if cfg.ActiveProfile != Default().ActiveProfile {
		t.Errorf("active profile = %q, want the default", cfg.ActiveProfile)
	}
}

func TestSaveLoadRoundTripAndBackup(t *testing.T) {
	dir := t.TempDir()
	cfg := Default()
	cfg.ActiveProfile = ProfileGaming
	cfg.Logging.Level = "debug"
	if err := Save(dir, cfg); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(Path(dir))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(BackupPath(dir)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the first save should not create a backup of a file that did not exist, stat err = %v", err)
	}

	// Second save: the previous contents must be kept beside the file.
	cfg.ActiveProfile = ProfileFiber
	if err := Save(dir, cfg); err != nil {
		t.Fatal(err)
	}
	bak, err := os.ReadFile(BackupPath(dir))
	if err != nil {
		t.Fatalf("the second save must keep a backup: %v", err)
	}
	if string(bak) != string(first) {
		t.Error("the backup is not the previous file's contents")
	}

	got, existed, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !existed {
		t.Error("existed = false for a file that is present")
	}
	if got.ActiveProfile != ProfileFiber {
		t.Errorf("active profile = %q, want %q", got.ActiveProfile, ProfileFiber)
	}
	if got.Logging.Level != "debug" {
		t.Errorf("logging level = %q, want debug", got.Logging.Level)
	}
	if got.Updated.IsZero() {
		t.Error("a saved file must record when it was written")
	}
}

func TestCorruptFileIsReportedAndQuarantinedNotReplaced(t *testing.T) {
	dir := t.TempDir()
	path := Path(dir)
	const garbage = "{ this is not json"
	if err := os.WriteFile(path, []byte(garbage), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, existed, err := Load(dir)
	if err == nil {
		t.Fatal("a corrupt file must be reported, not silently tolerated")
	}
	if !existed {
		t.Error("existed = false for a corrupt file that is present")
	}
	if cfg.Schema != Schema {
		t.Errorf("a failed load must still yield usable defaults, got schema %q", cfg.Schema)
	}
	var le *LoadError
	if !errors.As(err, &le) || le.Stage != "parse" {
		t.Fatalf("want a parse LoadError, got %v", err)
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("Load must not move the user's file: %v", statErr)
	}

	// Quarantine is a separate, deliberate step; the original contents survive.
	dst, err := Quarantine(path, time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(filepath.Base(dst), ".corrupt-20261018T120000Z") {
		t.Errorf("quarantined file name = %q", dst)
	}
	kept, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(kept) != garbage {
		t.Error("quarantine must keep the file as it was, so the user can see what they typed")
	}
}

func TestValidationListsEveryProblem(t *testing.T) {
	cfg := Default()
	cfg.ActiveProfile = "no-such-profile"
	boom := cfg.Profiles[ProfileThroughput]
	boom.Engine.IPv6 = "maybe"
	boom.Engine.MTU = 100
	boom.Engine.Weights = map[string]float64{"Ethernet": 0}
	boom.Monitor.LatencyBudgetMs = -5
	cfg.Profiles[ProfileThroughput] = boom
	cfg.Dashboard.IntervalMs = 10
	cfg.Logging.Level = "loud"
	cfg.Diagnostics.Endpoint = "noport"
	cfg.Diagnostics.DNSName = ""
	cfg.Diagnostics.TracerouteTimeoutMs = 100 // smaller than TimeoutMs

	err := cfg.Validate()
	if err == nil {
		t.Fatal("an invalid configuration must not validate")
	}
	var probs Problems
	if !errors.As(err, &probs) {
		t.Fatalf("want Problems, got %T", err)
	}
	if len(probs) < 9 {
		t.Errorf("every problem must be listed, not just the first: got %d: %v", len(probs), probs)
	}
	joined := err.Error()
	for _, want := range []string{
		"activeProfile", "ipv6", "mtu", "weight", "latencyBudgetMs",
		"intervalMs", "logging.level", "must be host:port", "dnsName", "tracerouteTimeoutMs",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("the problem list is missing something about %q: %v", want, probs)
		}
	}
}

func TestValidationNeverCorrectsTheFile(t *testing.T) {
	cfg := Default()
	cfg.Dashboard.IntervalMs = 1
	if err := Save(t.TempDir(), cfg); err == nil {
		t.Fatal("Save must refuse an invalid configuration")
	}
}

func TestSaveDoesNotWriteAnInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	cfg := Default()
	cfg.Logging.Level = "verbose"
	if err := Save(dir, cfg); err == nil {
		t.Fatal("expected Save to refuse")
	}
	if _, err := os.Stat(Path(dir)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("an invalid config must not be written at all, stat err = %v", err)
	}
	if _, err := os.Stat(Path(dir) + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Error("a refused save must not leave a temp file behind")
	}
}

// A hand-written file that sets only what the user cares about is still valid: everything else
// is filled from the defaults, and nothing the file set is overridden.
func TestHandWrittenFileGetsDefaultsForOmittedFields(t *testing.T) {
	dir := t.TempDir()
	minimal := map[string]any{
		"schema":        Schema,
		"version":       ConfigVersion,
		"activeProfile": string(ProfileCustom),
		"profiles": map[string]any{
			"custom": map[string]any{"id": "custom", "name": "Custom", "engine": map[string]any{"ipv6": "auto"}},
		},
	}
	b, err := json.Marshal(minimal)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(Path(dir), b, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, existed, err := Load(dir)
	if err != nil {
		t.Fatalf("a minimal file should load: %v", err)
	}
	if !existed {
		t.Error("existed = false for a file that is present")
	}
	if cfg.ActiveProfile != ProfileCustom {
		t.Errorf("active profile = %q, want custom", cfg.ActiveProfile)
	}
	for _, id := range ProfileIDs() {
		if _, ok := cfg.Profiles[id]; !ok {
			t.Errorf("built-in profile %q was not filled in", id)
		}
	}
	if cfg.Logging.Level != Default().Logging.Level {
		t.Errorf("logging level = %q, want the default", cfg.Logging.Level)
	}
	if cfg.Dashboard.IntervalMs != Default().Dashboard.IntervalMs {
		t.Errorf("interval = %d, want the default", cfg.Dashboard.IntervalMs)
	}
	if cfg.Diagnostics.Endpoint != Default().Diagnostics.Endpoint {
		t.Errorf("endpoint = %q, want the default", cfg.Diagnostics.Endpoint)
	}
}

func TestEngineArgsAreRealEngineFlags(t *testing.T) {
	p := Profile{
		Engine: EnginePrefs{
			Include:    []string{"Ethernet", "Wi-Fi"},
			Weights:    map[string]float64{"Wi-Fi": 2, "Ethernet": 1.5},
			AutoWeight: false,
			IPv6:       "off",
			MTU:        1400,
		},
	}
	args := strings.Join(p.EngineArgs(), " ")
	for _, want := range []string{
		"-include Ethernet,Wi-Fi",
		"-auto-weight=false",
		"-weight Ethernet=1.5",
		"-weight Wi-Fi=2",
		"-ipv6 off",
		"-mtu 1400",
	} {
		if !strings.Contains(args, want) {
			t.Errorf("engine args missing %q: %s", want, args)
		}
	}
	// Weights are rendered in a stable order so the same profile always shows the same line.
	if strings.Index(args, "Ethernet=1.5") > strings.Index(args, "Wi-Fi=2") {
		t.Errorf("weights must be sorted by name: %s", args)
	}

	// The engine has no -exclude; an exclusion-only profile says what it cannot express, rather
	// than inventing a flag.
	ex := Profile{Engine: EnginePrefs{Exclude: []string{"Wi-Fi"}, AutoWeight: true, IPv6: "auto"}}
	exArgs := strings.Join(ex.EngineArgs(), " ")
	if !strings.Contains(exArgs, "-include <all except: Wi-Fi>") {
		t.Errorf("exclusion should be surfaced honestly: %s", exArgs)
	}
	if strings.Contains(exArgs, "-auto-weight=false") {
		t.Errorf("auto-weight is on, so no override flag should appear: %s", exArgs)
	}
	if strings.Contains(exArgs, "-ipv6") {
		t.Errorf("IPv6 auto is the engine default and should not be passed explicitly: %s", exArgs)
	}
}

func TestBuiltinProfilesRenderWithoutInventedFlags(t *testing.T) {
	cfg := Default()
	known := map[string]bool{"-include": true, "-auto-weight": true, "-weight": true, "-ipv6": true, "-mtu": true}
	for _, p := range cfg.SortedProfiles() {
		args := p.EngineArgs()
		for i := 0; i < len(args); i += 2 {
			flag := args[i]
			if strings.HasPrefix(flag, "-include") && strings.Contains(flag, "=") {
				flag = "-include"
			}
			if !known[flag] && !known[strings.SplitN(flag, "=", 2)[0]] {
				t.Errorf("profile %q renders a flag the engine does not have: %q", p.ID, args[i])
			}
		}
	}
}

func TestSortedProfilesOrderAndUnknownAtEnd(t *testing.T) {
	cfg := Default()
	cfg.Profiles["zzz-custom-added"] = Profile{ID: "zzz-custom-added", Name: "Added"}
	ordered := cfg.SortedProfiles()
	if len(ordered) != len(cfg.Profiles) {
		t.Fatalf("got %d profiles, want %d - an unknown profile must not be dropped", len(ordered), len(cfg.Profiles))
	}
	want := ProfileIDs()
	for i, id := range want {
		if ordered[i].ID != id {
			t.Errorf("profile %d = %q, want %q", i, ordered[i].ID, id)
		}
	}
	if ordered[len(ordered)-1].ID != "zzz-custom-added" {
		t.Errorf("a user-added profile should sort last, got %q", ordered[len(ordered)-1].ID)
	}
}

func TestActiveUnknownIDIsReported(t *testing.T) {
	cfg := Default()
	cfg.ActiveProfile = "ghost"
	if _, ok := cfg.Active(); ok {
		t.Error("Active must report an unknown id rather than returning a zero profile as if it were real")
	}
}

func TestListenAddress(t *testing.T) {
	var cfg Config
	if got, err := cfg.ListenAddress(); err != nil || got != "127.0.0.1:0" {
		t.Errorf("empty listen should fall back to loopback, got %q (err %v)", got, err)
	}
	cfg.Dashboard.Listen = "127.0.0.1:8765"
	if got, _ := cfg.ListenAddress(); got != "127.0.0.1:8765" {
		t.Errorf("ListenAddress = %q", got)
	}
}
