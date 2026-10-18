package ttlmgr

import (
	"context"
	"os/exec"
	"runtime"

	"net-merge/internal/execx"
)

// The TTL manager drives Windows command-line tools through the shared runner in
// internal/execx. The names below are kept as aliases so the manager, its tests and anything
// built on the package keep one vocabulary for "a command was run and here is what happened"
// regardless of which layer ran it.

// Result is everything that happened when an external command was run.
type Result = execx.Result

// Runner executes an external command; it is an interface so the TTL layer can be exercised
// without a Windows host.
type Runner = execx.Runner

// ExecRunner is the Runner used outside tests.
type ExecRunner = execx.ExecRunner

// NewExecRunner returns an ExecRunner with a sensible default timeout.
func NewExecRunner() *execx.ExecRunner { return execx.NewExecRunner() }

// Backend is the platform mechanism that reads and writes packet-header settings. Every
// implementation states its own capabilities, because the honest answer to "can this host do
// it?" is discovered at runtime rather than assumed from the OS name.
type Backend interface {
	// Name identifies the mechanism for logs and reports, e.g. "windows-powershell".
	Name() string

	// Capabilities probes what this host actually supports. It must never assume a command
	// or a parameter exists: a missing parameter is reported, not worked around.
	Capabilities(ctx context.Context) Capabilities

	// Read returns the setting's current value. A nil Value with a nil error means the
	// setting is not explicitly configured on this host.
	Read(ctx context.Context, ref SettingRef) (Observed, error)

	// Write sets the value. Returning nil means the write ran; the caller re-reads to confirm
	// it had an effect, so a backend must not claim success it has not observed.
	Write(ctx context.Context, ref SettingRef, value int) error

	// Unset removes an explicit configuration so the platform's own default applies again.
	// A backend that has no documented way to do this returns an error explaining that, which
	// is a truthful answer and is surfaced rather than hidden.
	Unset(ctx context.Context, ref SettingRef) error
}

// UnsupportedBackend is used on hosts with no mechanism for these settings. It reports the
// lack in Capabilities and refuses Read, Write and Unset with CodeUnsupported, so the rest of
// the application degrades to "inspection unavailable" instead of failing to start.
type UnsupportedBackend struct {
	// Reason explains the absence, and is shown to the user.
	Reason string
	// Platform is runtime.GOOS, carried into the report.
	Platform string
}

// NewUnsupportedBackend returns a backend for a host with no supported mechanism.
func NewUnsupportedBackend(reason string) *UnsupportedBackend {
	return &UnsupportedBackend{Reason: reason, Platform: runtime.GOOS}
}

// Name implements Backend.
func (u *UnsupportedBackend) Name() string { return "unsupported" }

// Capabilities implements Backend.
func (u *UnsupportedBackend) Capabilities(context.Context) Capabilities {
	return Capabilities{
		Platform:  u.Platform,
		Supported: false,
		Notes: []string{
			u.Reason,
			"IPv4 packet TTL and IPv6 hop limit are Windows settings. On this host they were not " +
				"inspected or changed, and no system setting was touched.",
		},
	}
}

// Read implements Backend.
func (u *UnsupportedBackend) Read(context.Context, SettingRef) (Observed, error) {
	return Observed{}, newError(CodeUnsupported, u.Reason,
		"Inspect this report on the Windows PC where the setting lives.")
}

// Write implements Backend.
func (u *UnsupportedBackend) Write(context.Context, SettingRef, int) error {
	return newError(CodeUnsupported, u.Reason,
		"No change was attempted, so nothing on this host was altered.")
}

// Unset implements Backend.
func (u *UnsupportedBackend) Unset(context.Context, SettingRef) error {
	return newError(CodeUnsupported, u.Reason,
		"No change was attempted, so nothing on this host was altered.")
}

// firstLine trims output to its first non-empty line so a report stays readable and a long
// PowerShell transcript cannot swamp a history entry.
func firstLine(s string) string { return execx.FirstLine(s) }

// intPtr returns a pointer to a copy, so callers cannot alias a loop variable.
func intPtr(v int) *int { return &v }

// prepareCommand is kept for the platform tests; the implementation lives in execx so every
// subprocess in the application is windowless on Windows for the same reason.
func prepareCommand(cmd *exec.Cmd) { execx.PrepareCommand(cmd) }
