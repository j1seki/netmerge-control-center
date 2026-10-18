package ttlmgr

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Result is everything that happened when an external command was run. It is a value rather
// than an error return because a non-zero exit is data, not a transport failure: the exit
// status, the output and the duration all belong in the change history and the exported
// report, and a caller that only received an error would lose them.
type Result struct {
	Command  string        `json:"command"`
	Stdout   string        `json:"stdout,omitempty"`
	Stderr   string        `json:"stderr,omitempty"`
	ExitCode int           `json:"exitCode"`
	Started  bool          `json:"started"`
	TimedOut bool          `json:"timedOut,omitempty"`
	Duration time.Duration `json:"duration"`
	Err      string        `json:"err,omitempty"`
}

// Failed reports whether the command did not complete successfully. A timeout counts as
// failure even though the process may still have been running when it was killed.
func (r Result) Failed() bool { return !r.Started || r.TimedOut || r.ExitCode != 0 || r.Err != "" }

// Output returns stdout and stderr together, which is what a diagnosis needs.
func (r Result) Output() string {
	switch {
	case r.Stderr == "":
		return r.Stdout
	case r.Stdout == "":
		return r.Stderr
	default:
		return r.Stdout + "\n" + r.Stderr
	}
}

// FirstLine returns the most informative single line, used for compact history entries.
func (r Result) FirstLine() string {
	for _, line := range strings.Split(strings.TrimSpace(r.Output()), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			return line
		}
	}
	return ""
}

// Runner executes an external command. It is an interface so the TTL layer can be exercised
// without a Windows host, which is how the failure paths get tested at all: a fake runner can
// return a refusal, a timeout, malformed output or a write that silently does nothing.
type Runner interface {
	// Run executes the command and always returns a Result describing what happened. It does
	// not return an error: start failures and timeouts are reported inside the Result so no
	// caller can accidentally drop the diagnostic detail.
	Run(ctx context.Context, name string, args ...string) Result

	// LookPath reports whether a command can be resolved, returning the path when it can.
	LookPath(name string) (string, error)
}

// ExecRunner is the Runner used outside tests. It is deliberately thin: the caller owns the
// timeout through ctx, and the output is captured verbatim because the report shows it.
type ExecRunner struct {
	// Timeout bounds a single command. It is a field so tests and unusual environments can
	// change it, and it is always applied even when the caller supplies no deadline.
	Timeout time.Duration
}

// NewExecRunner returns an ExecRunner with a sensible default timeout. Windows cmdlets are
// slow to start (PowerShell module autoloading commonly costs 0.5-2 s), so the default is
// generous enough to avoid a false timeout while still bounding a hung command.
func NewExecRunner() *ExecRunner { return &ExecRunner{Timeout: 30 * time.Second} }

// Run implements Runner.
func (e *ExecRunner) Run(ctx context.Context, name string, args ...string) Result {
	timeout := e.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	res := Result{Command: formatCommand(name, args)}
	start := time.Now()
	cmd := exec.CommandContext(ctx, name, args...)
	prepareCommand(cmd) // platform-specific: no console window on Windows
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr

	err := cmd.Run()
	res.Duration = time.Since(start)
	res.Stdout, res.Stderr = stdout.String(), stderr.String()
	res.Started = true

	switch {
	case ctx.Err() == context.DeadlineExceeded:
		res.TimedOut = true
		res.ExitCode = -1
		res.Err = "timed out after " + timeout.String()
	case ctx.Err() == context.Canceled:
		res.Err = "cancelled"
		res.ExitCode = -1
	case err != nil:
		var ee *exec.ExitError
		if ok := asExitError(err, &ee); ok {
			// The process ran and exited non-zero: that is a result, not a start failure.
			res.ExitCode = ee.ExitCode()
		} else {
			res.Started = false
			res.ExitCode = -1
			res.Err = err.Error()
		}
	}
	return res
}

// LookPath implements Runner.
func (e *ExecRunner) LookPath(name string) (string, error) {
	return exec.LookPath(name)
}

// formatCommand renders a command the way a person would retype it, quoting only when needed.
func formatCommand(name string, args []string) string {
	parts := append([]string{name}, args...)
	for i, p := range parts {
		if strings.ContainsAny(p, " \t\"'") {
			parts[i] = "'" + strings.ReplaceAll(p, "'", "''") + "'"
		}
	}
	return strings.Join(parts, " ")
}

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

// asExitError is a tiny indirection so the exec error type is unwrapped in one place.
func asExitError(err error, target **exec.ExitError) bool {
	ee, ok := err.(*exec.ExitError)
	if ok {
		*target = ee
	}
	return ok
}

// firstLine trims output to its first non-empty line so a report stays readable and a long
// PowerShell transcript cannot swamp a history entry.
func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			return line
		}
	}
	return ""
}

// intPtr returns a pointer to a copy, so callers cannot alias a loop variable.
func intPtr(v int) *int { return &v }
