package main

// Tests for the launch path's quality-profile resolution. They read and write only temporary
// directories written by the test itself: no real settings file is touched, no engine is
// started, and nothing here touches a network adapter.

import (
	"flag"
	"testing"

	"net-merge/internal/appcfg"
	"net-merge/internal/tun"
)

// gamingWithEverything returns a settings file whose active profile pins every overlay field,
// so one resolveProfile call exercises all of them.
func gamingWithEverything(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cfg := appcfg.Default()
	cfg.ActiveProfile = appcfg.ProfileGaming
	p := cfg.Profiles[appcfg.ProfileGaming]
	p.Engine = appcfg.EnginePrefs{
		Include:    []string{"Ethernet"},
		Exclude:    []string{"Wi-Fi"},
		Weights:    map[string]float64{"Ethernet": 3},
		AutoWeight: appcfg.Bool(false),
		IPv6:       "off",
		MTU:        1400,
	}
	cfg.Profiles[appcfg.ProfileGaming] = p
	if err := appcfg.Save(dir, cfg); err != nil {
		t.Fatalf("saving the test settings: %v", err)
	}
	return dir
}

func resolve(t *testing.T, dir string, args ...string) *common {
	t.Helper()
	c := &common{}
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	c.register(fs)
	// The state directory is addressed the way a user would address it, after register has run:
	// register sets every flag's default, so assigning c.stateDir directly would be undone.
	all := append([]string{"-state-dir", dir}, args...)
	if err := fs.Parse(all); err != nil {
		t.Fatalf("parsing %v: %v", all, err)
	}
	c.resolveProfile(fs)
	return c
}

func TestResolveProfileFillsUnsetSettings(t *testing.T) {
	dir := gamingWithEverything(t)
	c := resolve(t, dir)
	if c.profile != string(appcfg.ProfileGaming) {
		t.Errorf("profile = %q, want the game profile to be recorded", c.profile)
	}
	if c.include != "Ethernet" {
		t.Errorf("include = %q, want the profile's list", c.include)
	}
	if c.exclude != "Wi-Fi" {
		t.Errorf("exclude = %q, want the profile's exclusion list", c.exclude)
	}
	if got := c.weights["Ethernet"]; got != 3 {
		t.Errorf("weight Ethernet = %v, want 3", got)
	}
	if c.auto {
		t.Error("auto-weight = true, want the profile's explicit false")
	}
	if c.ipv6 != "off" {
		t.Errorf("ipv6 = %q, want off", c.ipv6)
	}
	if c.mtu != 1400 {
		t.Errorf("mtu = %d, want 1400", c.mtu)
	}
}

func TestExplicitFlagsWinOverProfile(t *testing.T) {
	dir := gamingWithEverything(t)
	// Naming adapters on the command line answers "which adapters" completely, so the
	// profile's lists do not apply; the other settings are still merged field by field.
	c := resolve(t, dir, "-include", "Ethernet 2", "-exclude", "Ethernet 3", "-ipv6", "on")
	if c.include != "Ethernet 2" || c.exclude != "Ethernet 3" {
		t.Errorf("explicit adapter lists were overridden: include=%q exclude=%q", c.include, c.exclude)
	}
	if c.ipv6 != "on" {
		t.Errorf("ipv6 = %q, want the explicit on", c.ipv6)
	}
	if c.auto {
		t.Error("auto-weight = true, want the profile's false to still apply (it was not set explicitly)")
	}
	if c.mtu != 1400 {
		t.Errorf("mtu = %d, want the profile's 1400 to still apply", c.mtu)
	}
	if c.weights["Ethernet"] != 3 {
		t.Errorf("weights = %v, want the profile's weights to still apply", c.weights)
	}
}

func TestNoProfileFlagIgnoresSettings(t *testing.T) {
	dir := gamingWithEverything(t)
	c := resolve(t, dir, "-no-profile")
	if c.profile != "" || c.include != "" || c.exclude != "" {
		t.Errorf("-no-profile still applied settings: %+v", c)
	}
	if c.auto != true {
		t.Error("auto-weight was changed without the profile")
	}
	if len(c.weights) != 0 {
		t.Errorf("weights were applied without the profile: %v", c.weights)
	}
	if c.mtu != tun.DefaultMTU {
		t.Errorf("mtu = %d, want the engine's own default %d", c.mtu, tun.DefaultMTU)
	}
	if c.ipv6 != "auto" {
		t.Errorf("ipv6 = %q, want the engine's own default auto", c.ipv6)
	}
}

func TestResolveProfileWithoutSettingsFile(t *testing.T) {
	c := resolve(t, t.TempDir()) // empty directory: nothing to load
	// With no settings file the Control Center's default profile is active - that is what the
	// dashboard shows too, so the engine agrees with it. Its overlay (auto-weight on, IPv6
	// auto) is identical to the engine's own defaults, so nothing is changed or claimed.
	if c.profile != string(appcfg.ProfileThroughput) {
		t.Errorf("profile = %q, want the Control Center's default profile", c.profile)
	}
	if c.auto != true || c.include != "" || c.exclude != "" {
		t.Errorf("engine settings changed by a no-op overlay: %+v", c)
	}
	if c.mtu != tun.DefaultMTU || c.ipv6 != "auto" {
		t.Errorf("mtu=%d ipv6=%q, want the engine's own defaults", c.mtu, c.ipv6)
	}
}
