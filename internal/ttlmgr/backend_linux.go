//go:build linux

package ttlmgr

import (
	"context"
	"os"
	"strconv"
	"strings"
)

// The Linux backend reads the two system-global packet-header values straight out of /proc and
// exposes no write path at all. It exists so the Control Center can show a Linux user their
// real current IPv4 TTL and IPv6 hop limit instead of an unhelpful "default" placeholder. Every
// read is a plain file read; nothing on the host is modified, and Write and Unset always refuse.
//
// The mapping is deliberately narrow. Linux's writable knobs (per-socket setsockopt and the
// per-interface sysctls) do not correspond to Windows' system-global defaults, so this backend
// reads only the two closest system-global sources and reports their exact path as the origin,
// rather than inventing an equivalence that a user could mistake for a settable Windows value.

// procReader reads the contents of a /proc path. It is a field so tests can supply a fake
// filesystem instead of depending on the kernel's real layout.
type procReader func(path string) ([]byte, error)

// linuxBackend is the read-only Linux implementation of Backend.
type linuxBackend struct {
	read procReader
}

// NewLinuxBackend returns the read-only backend, wired to the real /proc filesystem.
func NewLinuxBackend() Backend {
	return &linuxBackend{read: os.ReadFile}
}

// newLinuxBackendWithReader lets tests drive the backend against a fake /proc tree.
func newLinuxBackendWithReader(r procReader) *linuxBackend {
	return &linuxBackend{read: r}
}

// Name implements Backend.
func (l *linuxBackend) Name() string { return "linux-procfs-read-only" }

// procPaths names the exact source for each system-global setting. They are exported into the
// report as the value's origin so a user can re-read the number by hand and get the same value.
var procPaths = map[Family]string{
	FamilyIPv4: "/proc/sys/net/ipv4/ip_default_ttl",
	FamilyIPv6: "/proc/sys/net/ipv6/conf/all/hop_limit",
}

// Capabilities implements Backend.
//
// The host is readable but not writable: the values are real and current, while every change is
// refused. Supported stays false so the rest of the package treats this host as inspection-only.
func (l *linuxBackend) Capabilities(context.Context) Capabilities {
	return Capabilities{
		Platform:  "linux",
		Supported: false,
		Readable:  true,
		Notes: []string{
			"The current IPv4 TTL is read from /proc/sys/net/ipv4/ip_default_ttl and the IPv6 hop " +
				"limit from /proc/sys/net/ipv6/conf/all/hop_limit; both are the values in effect on " +
				"this host right now.",
			"These are read-only here. Changing IPv4 TTL / IPv6 hop limit is a Windows feature in " +
				"this build, so no change is attempted and no system setting on this Linux host is touched.",
			"Linux also exposes per-interface hop limits and per-socket overrides; those are not the " +
				"same as the Windows system-global setting and are not presented as such.",
		},
	}
}

// Read implements Backend.
//
// Only the two system-global settings have a faithful /proc source, so a per-interface reference
// is refused with an explanation rather than answered with a value that would misrepresent it as
// a Windows-style per-interface setting.
func (l *linuxBackend) Read(_ context.Context, ref SettingRef) (Observed, error) {
	if !ref.Kind.IsConfigurable() {
		return Observed{}, newError(CodeUnsupported,
			string(ref.Kind)+" is not a host setting on Linux",
			ref.Kind.Explain())
	}
	if ref.Scope == ScopePerInterface {
		return Observed{}, newError(CodeUnsupported,
			"per-interface packet-header settings are not read on Linux",
			"Linux exposes per-interface hop limits, but they do not correspond to the Windows "+
				"per-interface setting this view describes, so no value is shown rather than a "+
				"misleading one.",
			"interface: "+ref.Interface)
	}

	path, ok := procPaths[ref.Family]
	if !ok {
		return Observed{}, newError(CodeUnsupported,
			"no Linux source is known for "+string(ref.Family),
			"Only the IPv4 TTL and IPv6 hop limit have a system-global /proc source.")
	}

	raw, err := l.read(path)
	if err != nil {
		return Observed{}, newError(CodeReadFailed,
			"could not read "+path,
			"The value lives in /proc; a failure here usually means the kernel did not expose it.",
			"path: "+path, "error: "+err.Error())
	}

	val, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		return Observed{}, newError(CodeReadFailed,
			"the value in "+path+" was not an integer",
			"This is a reporting problem rather than a network problem.",
			"path: "+path, "contents: "+strings.TrimSpace(string(raw)))
	}

	return Observed{
		Value:    intPtr(val),
		Explicit: false, // /proc reports the effective default, not a user-written override
		Origin:   "proc:" + path,
	}, nil
}

// Write implements Backend. The Linux backend has no write path by design.
func (l *linuxBackend) Write(context.Context, SettingRef, int) error {
	return newError(CodeUnsupported,
		"changing packet TTL / hop limit is not supported on this Linux build",
		"No change was attempted, so nothing on this host was altered.",
		"The writable Linux knobs do not map to the Windows system-global setting this view "+
			"describes, so this build changes settings on Windows only.")
}

// Unset implements Backend. The Linux backend has no unset path by design.
func (l *linuxBackend) Unset(context.Context, SettingRef) error {
	return newError(CodeUnsupported,
		"restoring packet TTL / hop limit is not supported on this Linux build",
		"No change was attempted, so nothing on this host was altered.")
}
