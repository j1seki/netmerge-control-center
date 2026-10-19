package ttlmgr

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeProc serves a scripted /proc tree so the Linux backend is tested against realistic
// contents instead of the kernel's live layout.
func fakeProc(files map[string]string) procReader {
	return func(path string) ([]byte, error) {
		v, ok := files[path]
		if !ok {
			return nil, errors.New("open " + path + ": no such file or directory")
		}
		return []byte(v), nil
	}
}

func TestLinuxBackendReadsRealProcValues(t *testing.T) {
	l := newLinuxBackendWithReader(fakeProc(map[string]string{
		"/proc/sys/net/ipv4/ip_default_ttl":     "64\n",
		"/proc/sys/net/ipv6/conf/all/hop_limit": "64\n",
	}))
	m, _ := newTestManager(t, l)

	rep, err := m.Inspect(context.Background(), nil)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if rep.Capabilities.Supported {
		t.Fatal("the Linux backend must not report itself writable")
	}
	if !rep.Capabilities.Readable {
		t.Fatal("the Linux backend must report itself readable")
	}

	sys4, ok := settingByID(rep, IDv4Default)
	if !ok {
		t.Fatal("report is missing the system-global IPv4 setting")
	}
	if sys4.Value == nil || *sys4.Value != 64 {
		t.Fatalf("IPv4 TTL = %v, want 64", sys4.Value)
	}
	if sys4.Writable {
		t.Error("IPv4 TTL must not be writable on Linux")
	}
	if !strings.Contains(sys4.ValueOrigin, "ip_default_ttl") {
		t.Errorf("IPv4 origin = %q, want it to name ip_default_ttl", sys4.ValueOrigin)
	}

	sys6, ok := settingByID(rep, IDv6Default)
	if !ok {
		t.Fatal("report is missing the system-global IPv6 setting")
	}
	if sys6.Value == nil || *sys6.Value != 64 {
		t.Fatalf("IPv6 hop limit = %v, want 64", sys6.Value)
	}
	if !strings.Contains(sys6.ValueOrigin, "conf/all/hop_limit") {
		t.Errorf("IPv6 origin = %q, want it to name conf/all/hop_limit", sys6.ValueOrigin)
	}

	// A read-only host must never be presented as able to write, and every setting must say why.
	for _, s := range rep.Settings {
		if s.Writable {
			t.Errorf("%s reported writable on a read-only host", s.ID)
		}
		if s.WritableReason == "" {
			t.Errorf("%s is not writable but gives no reason", s.ID)
		}
	}
}

// TestLinuxBackendMissingProcFailsHonestly pins that a missing /proc source surfaces as a read
// error with the offending path, rather than a silent zero or an invented default.
func TestLinuxBackendMissingProcFailsHonestly(t *testing.T) {
	l := newLinuxBackendWithReader(fakeProc(map[string]string{}))
	m, _ := newTestManager(t, l)

	rep, err := m.Inspect(context.Background(), nil)
	if err != nil {
		t.Fatalf("Inspect must still succeed when a read fails: %v", err)
	}
	if len(rep.ReadErrors) != 2 {
		t.Fatalf("read errors = %d, want 2 (both system-global settings missing)", len(rep.ReadErrors))
	}
	for _, e := range rep.ReadErrors {
		if e.Code != CodeReadFailed {
			t.Errorf("%s: code = %q, want %q", e.Setting.ID, e.Code, CodeReadFailed)
		}
		if len(e.Details) == 0 || !strings.Contains(strings.Join(e.Details, " "), "/proc/sys/net") {
			t.Errorf("%s: details = %v, want them to name the /proc path", e.Setting.ID, e.Details)
		}
	}
	// The settings are still present, marked unreadable, with a reason - never silently dropped.
	for _, id := range []SettingID{IDv4Default, IDv6Default} {
		s, ok := settingByID(rep, id)
		if !ok {
			t.Fatalf("%s was omitted instead of shown as failed", id)
		}
		if s.Value != nil || s.Writable || s.WritableReason == "" {
			t.Errorf("%s = %+v, want no value, not writable, with a reason", id, s)
		}
	}
}
