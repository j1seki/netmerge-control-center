// Package execx runs external commands and reports what happened.
//
// It exists because three parts of the application - the TTL manager, the network inventory and
// the diagnostic centre - all drive Windows command-line tools and all need the same three
// things from a run: the captured output, the exit status, and an honest account of a timeout or
// a failure to start. Duplicating that per package would mean three places to get cancellation
// and timeouts wrong, and three different shapes in the exported diagnostic report.
//
// The runner is an interface so everything built on it can be exercised without a Windows host:
// a fake can return a refusal, a timeout, malformed output, or a write that silently does
// nothing, and the calling logic is the same logic that runs on Windows.
package execx

import (
	"context"
	"os/exec"
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

// FirstLine returns the most informative single line, used for compact history and log entries.
func (r Result) FirstLine() string { return FirstLine(r.Output()) }

// Detail returns the output trimmed to at most max lines, so one noisy command cannot swamp a
// report while a failure still carries its evidence.
func (r Result) Detail(max int) []string { return Detail(r.Output(), max) }

// FirstLine returns the first non-empty line of s, trimmed. It is exported because the TTL
// manager, the inventory probe and the diagnostics page all summarise command output the same
// way and a second implementation would eventually disagree with this one.
func FirstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if line = strings.TrimSpace(strings.TrimSuffix(line, "\r")); line != "" {
			return line
		}
	}
	return ""
}

// Detail splits s into its non-empty lines, keeping at most max of them (0 means all) and
// noting where it stopped.
func Detail(s string, max int) []string {
	var out []string
	for _, line := range strings.Split(strings.TrimRight(s, "\r\n"), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		out = append(out, line)
		if max > 0 && len(out) >= max {
			out = append(out, "... (output truncated)")
			break
		}
	}
	return out
}

// Runner executes an external command.
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

	res := Result{Command: FormatCommand(name, args)}
	start := time.Now()
	cmd := exec.CommandContext(ctx, name, args...)
	PrepareCommand(cmd) // platform-specific: no console window on Windows
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

// FormatCommand renders a command the way a person would retype it, quoting only when needed.
func FormatCommand(name string, args []string) string {
	parts := append([]string{name}, args...)
	for i, p := range parts {
		if strings.ContainsAny(p, " \t\"'") {
			parts[i] = "'" + strings.ReplaceAll(p, "'", "''") + "'"
		}
	}
	return strings.Join(parts, " ")
}

// asExitError is a tiny indirection so the exec error type is unwrapped in one place.
func asExitError(err error, target **exec.ExitError) bool {
	ee, ok := err.(*exec.ExitError)
	if ok {
		*target = ee
	}
	return ok
}
