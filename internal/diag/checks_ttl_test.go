package diag

// Behaviour tests for the TTL/hop-limit check.
//
// The check is exercised against a simulated manager report, supplied through Env.InspectTTL,
// which is exactly the injection point the real caller uses. No test here reads or writes a real
// TTL: the manager's own write path is tested in internal/ttlmgr, and this check has no write
// path at all.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"net-merge/internal/inventory"
	"net-merge/internal/ttlmgr"
)

func hasItem(res Result, scope, code string) bool {
	for _, it := range res.Items {
		if it.Code == code && (scope == "" || it.Scope == scope) {
			return true
		}
	}
	return false
}

func establishedText(res Result) string { return strings.Join(res.Established, "\n") }

// A run with no inspector wired must skip and say so, rather than guessing at values or
// reporting zero.
func TestTTLCheckSkipsWithoutAnInspector(t *testing.T) {
	env, _, _ := testEnv("windows")
	env.InspectTTL = nil
	res := runOne(t, env, "ttl.inspect")
	if res.Status != StatusSkipped {
		t.Fatalf("status = %s, want skipped (summary: %s)", res.Status, res.Summary)
	}
	if len(res.Items) != 0 {
		t.Errorf("a skipped check must produce no observations, got %+v", res.Items)
	}
	if len(res.Inconclusive) == 0 {
		t.Error("a skipped check must state what it failed to establish")
	}
}

func TestTTLCheckReportsSettingsCapturesAndInterfaces(t *testing.T) {
	env, _, _ := testEnv("windows")
	env.SnapshotValue = snap([]inventory.Adapter{
		adapter("Ethernet", 12, "192.168.1.20"),
		adapter("Wi-Fi", 7, "192.168.1.31"),
	})

	v4, v6 := 128, 64
	var gotIfaces []ttlmgr.IfaceInfo
	env.InspectTTL = func(_ context.Context, ifaces []ttlmgr.IfaceInfo) (ttlmgr.Report, error) {
		gotIfaces = ifaces
		return ttlmgr.Report{
			Capabilities: ttlmgr.Capabilities{
				Platform: "windows", Supported: true, Readable: true,
				Notes: []string{"packet-header values only; DNS record TTLs are a different concept"},
			},
			Settings: []ttlmgr.Setting{
				{
					SettingRef: ttlmgr.SettingRef{
						ID: ttlmgr.IDv4Default, Kind: ttlmgr.KindPacketTTL,
						Family: ttlmgr.FamilyIPv4, Scope: ttlmgr.ScopeSystemGlobal,
					},
					Value: &v4, ValueOrigin: "Get-NetIPv4Protocol", Writable: true,
				},
				{
					SettingRef: ttlmgr.SettingRef{
						ID:   ttlmgr.InterfaceSettingID(ttlmgr.FamilyIPv6, 7, "Wi-Fi"),
						Kind: ttlmgr.KindPacketHopLimit, Family: ttlmgr.FamilyIPv6,
						Scope: ttlmgr.ScopePerInterface, Interface: "Wi-Fi", InterfaceIdx: 7,
					},
					Value: &v6, ValueOrigin: "Get-NetIPInterface",
					Writable: false, WritableReason: "requires elevation",
				},
				{
					// An unwritten value means the platform default applies; it is not zero.
					SettingRef: ttlmgr.SettingRef{
						ID:   ttlmgr.InterfaceSettingID(ttlmgr.FamilyIPv4, 7, "Wi-Fi"),
						Kind: ttlmgr.KindPacketTTL, Family: ttlmgr.FamilyIPv4,
						Scope: ttlmgr.ScopePerInterface, Interface: "Wi-Fi", InterfaceIdx: 7,
					},
					Value: nil, ValueOrigin: "os-default", Writable: false, WritableReason: "the adapter is not present",
				},
			},
			NotSettings: []ttlmgr.Setting{
				{SettingRef: ttlmgr.SettingRef{ID: "dns.record-ttl", Kind: ttlmgr.KindDNSRecordTTL, Scope: ttlmgr.ScopeNotApplicable}},
			},
			Captured: map[ttlmgr.SettingID]ttlmgr.Original{
				ttlmgr.IDv4Default: {
					ID: ttlmgr.IDv4Default, Family: ttlmgr.FamilyIPv4, Scope: ttlmgr.ScopeSystemGlobal,
					Value: &v4, Explicit: false, Origin: "Get-NetIPv4Protocol",
					CapturedAt: time.Date(2026, 10, 18, 11, 0, 0, 0, time.UTC),
				},
			},
			Elevated: true, Elevation: "administrator (elevated)",
		}, nil
	}

	res := runOne(t, env, "ttl.inspect")
	if res.Status != StatusPass {
		t.Fatalf("status = %s, want pass (summary: %s)", res.Status, res.Summary)
	}
	if !hasItem(res, "", "ttl_supported") {
		t.Errorf("a supported platform must be recorded as an item, got %+v", res.Items)
	}
	if !hasItem(res, string(ttlmgr.IDv4Default), "ttl_captured") {
		t.Errorf("a setting with a captured original must be recorded, got %+v", res.Items)
	}
	if hasItem(res, "dns.record-ttl", "ttl_captured") {
		t.Errorf("a non-setting must never be recorded as captured: %+v", res.Items)
	}

	est := establishedText(res)
	for _, want := range []string{
		"128 (read from Get-NetIPv4Protocol)",
		"not changeable: requires elevation",
		"not configured (the system's own default applies)",
		"reported separately, and not a settable value here: dns.record-ttl",
		"an original value of 128 is captured",
		"the platform's own default was in effect",
		"capability note: packet-header values only",
	} {
		if !strings.Contains(est, want) {
			t.Errorf("observations are missing %q; got:\n%s", want, est)
		}
	}
	if !strings.Contains(res.Summary, "1 original value(s)") {
		t.Errorf("summary should say how many originals are held, got %q", res.Summary)
	}
	// The per-interface view must use the same adapter names as the rest of the report.
	names := map[string]int{}
	for _, i := range gotIfaces {
		names[i.Name] = i.Index
	}
	if names["Ethernet"] != 12 || names["Wi-Fi"] != 7 {
		t.Errorf("inspector received the wrong interfaces: %+v", gotIfaces)
	}
}

func TestTTLCheckWarnsOnPartialRead(t *testing.T) {
	env, _, _ := testEnv("windows")
	env.IsAdmin = false
	env.InspectTTL = func(context.Context, []ttlmgr.IfaceInfo) (ttlmgr.Report, error) {
		return ttlmgr.Report{
			Capabilities: ttlmgr.Capabilities{Platform: "windows", Supported: true, Readable: true},
			ReadErrors: []ttlmgr.ReadFailure{{
				Setting: ttlmgr.SettingRef{
					ID:   ttlmgr.InterfaceSettingID(ttlmgr.FamilyIPv6, 7, "Wi-Fi"),
					Kind: ttlmgr.KindPacketHopLimit, Family: ttlmgr.FamilyIPv6,
					Scope: ttlmgr.ScopePerInterface, Interface: "Wi-Fi", InterfaceIdx: 7,
				},
				Code:    "ttl_permission_denied",
				Message: "access is denied",
			}},
		}, nil
	}
	res := runOne(t, env, "ttl.inspect")
	if res.Status != StatusWarn {
		t.Fatalf("status = %s, want warn (summary: %s)", res.Status, res.Summary)
	}
	if !hasCode(res, "diag_ttl_read_partial") {
		t.Errorf("codes %v do not include diag_ttl_read_partial", res.ErrorCodes)
	}
	inc := strings.Join(res.Inconclusive, "\n")
	if !strings.Contains(inc, "access is denied") || !strings.Contains(inc, "ttl_permission_denied") {
		t.Errorf("the unreadable setting must be named with its code, got %q", inc)
	}
	joined := strings.Join(res.NextSteps, " ")
	if !strings.Contains(joined, "elevated") {
		t.Errorf("an unelevated partial read should say that elevation may help, got %q", joined)
	}
}

func TestTTLCheckUnsupportedPlatformIsInformationOnly(t *testing.T) {
	env, _, _ := testEnv("linux")
	env.InspectTTL = func(context.Context, []ttlmgr.IfaceInfo) (ttlmgr.Report, error) {
		return ttlmgr.Report{
			Capabilities: ttlmgr.Capabilities{
				Platform: "linux", Supported: false,
				Notes: []string{"no supported mechanism for the packet-header values is implemented on this platform"},
			},
		}, nil
	}
	res := runOne(t, env, "ttl.inspect")
	if res.Status != StatusInfo {
		t.Fatalf("status = %s, want info: an unsupported platform is not a fault (summary: %s)", res.Status, res.Summary)
	}
	if !hasItem(res, "", "ttl_unsupported") {
		t.Errorf("the unsupported platform must be recorded, got %+v", res.Items)
	}
	if !strings.Contains(establishedText(res), "does not provide a mechanism") {
		t.Errorf("observations should state the absence of a mechanism, got:\n%s", establishedText(res))
	}
	if !strings.Contains(res.Summary, "nothing is read and nothing is changed") {
		t.Errorf("summary = %q", res.Summary)
	}
}

func TestTTLCheckInspectFailureIsReportedNotHidden(t *testing.T) {
	env, _, _ := testEnv("windows")
	env.InspectTTL = func(context.Context, []ttlmgr.IfaceInfo) (ttlmgr.Report, error) {
		return ttlmgr.Report{}, errors.New("store file is unreadable")
	}
	res := runOne(t, env, "ttl.inspect")
	if res.Status != StatusError {
		t.Fatalf("status = %s, want error", res.Status)
	}
	if !hasCode(res, "diag_ttl_inspect_failed") {
		t.Errorf("codes %v do not include diag_ttl_inspect_failed", res.ErrorCodes)
	}
	if !strings.Contains(res.Summary, "store file is unreadable") {
		t.Errorf("the failure reason must survive into the summary, got %q", res.Summary)
	}
}

// An enabled configuration record is reported as a record and nothing else: the check must never
// present it as an action taken, and must never act on it.
func TestTTLCheckDoesNotActOnEnabledConfig(t *testing.T) {
	env, _, _ := testEnv("windows")
	v4 := 128
	env.InspectTTL = func(context.Context, []ttlmgr.IfaceInfo) (ttlmgr.Report, error) {
		return ttlmgr.Report{
			Capabilities: ttlmgr.Capabilities{Platform: "windows", Supported: true, Readable: true},
			Settings: []ttlmgr.Setting{{
				SettingRef: ttlmgr.SettingRef{ID: ttlmgr.IDv4Default, Kind: ttlmgr.KindPacketTTL, Family: ttlmgr.FamilyIPv4, Scope: ttlmgr.ScopeSystemGlobal},
				Value:      &v4, ValueOrigin: "cmdlet", Writable: true,
			}},
			Config:   ttlmgr.Config{Schema: "netmerge.ttlmgr.config/1", Version: 1, Enabled: true},
			Elevated: true,
		}, nil
	}
	res := runOne(t, env, "ttl.inspect")
	if res.Status != StatusPass {
		t.Fatalf("status = %s, want pass (summary: %s)", res.Status, res.Summary)
	}
	est := establishedText(res)
	if !strings.Contains(est, "records TTL management as enabled by the user") {
		t.Errorf("the enabled record should be reported, got:\n%s", est)
	}
	if !strings.Contains(est, "changes nothing") {
		t.Errorf("the record must not read as an action this check took, got:\n%s", est)
	}
	for _, s := range res.Established {
		if strings.Contains(s, "changed") && !strings.Contains(s, "changes nothing") {
			t.Errorf("a read-only check must not claim a change: %q", s)
		}
	}
}

// Without an inventory source the check still runs; the manager simply gets no interface list,
// which is a smaller report rather than a failure.
func TestTTLCheckRunsWithoutInventory(t *testing.T) {
	env, _, _ := testEnv("windows")
	called := false
	env.InspectTTL = func(_ context.Context, ifaces []ttlmgr.IfaceInfo) (ttlmgr.Report, error) {
		called = true
		if len(ifaces) != 0 {
			t.Errorf("no inventory source should mean no interfaces, got %+v", ifaces)
		}
		return ttlmgr.Report{Capabilities: ttlmgr.Capabilities{Platform: "windows", Supported: true, Readable: true}}, nil
	}
	res := runOne(t, env, "ttl.inspect")
	if !called {
		t.Fatal("the inspector was not called")
	}
	if res.Status != StatusPass {
		t.Errorf("status = %s, want pass (summary: %s)", res.Status, res.Summary)
	}
}
