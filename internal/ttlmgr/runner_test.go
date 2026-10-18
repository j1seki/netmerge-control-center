package ttlmgr

// Tests for the real subprocess runner. They use ordinary system utilities (sleep, sh) and
// verify that output, exit status, timeouts and cancellation are all reported rather than
// dropped. A timeout must produce a Result, not a silent hang; a cancelled run must be
// distinguishable from a timed-out one.

import (
	"context"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

func skipWithout(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s is not available on this host: %v", name, err)
	}
}

func TestExecRunnerCapturesOutputAndExitCode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell helper")
	}
	skipWithout(t, "sh")

	r := &ExecRunner{Timeout: 5 * time.Second}
	res := r.Run(context.Background(), "sh", "-c", "echo out; echo err >&2; exit 3")

	if !res.Started {
		t.Fatalf("result = %+v, want the command marked as started", res)
	}
	if res.ExitCode != 3 {
		t.Errorf("exit code = %d, want 3", res.ExitCode)
	}
	if strings.TrimSpace(res.Stdout) != "out" {
		t.Errorf("stdout = %q, want %q", res.Stdout, "out")
	}
	if strings.TrimSpace(res.Stderr) != "err" {
		t.Errorf("stderr = %q, want %q", res.Stderr, "err")
	}
	if !res.Failed() {
		t.Error("a non-zero exit must count as a failure")
	}
	if res.Duration <= 0 {
		t.Error("duration was not recorded")
	}
}

func TestExecRunnerTimeoutIsReportedNotDropped(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX sleep helper")
	}
	skipWithout(t, "sleep")

	r := &ExecRunner{Timeout: 250 * time.Millisecond}
	start := time.Now()
	res := r.Run(context.Background(), "sleep", "5")

	if !res.TimedOut {
		t.Fatalf("result = %+v, want a timeout", res)
	}
	if res.Err == "" || !strings.Contains(res.Err, "timed out") {
		t.Errorf("err = %q, want the timeout stated", res.Err)
	}
	if !res.Failed() {
		t.Error("a timeout must count as a failure")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("the timeout did not bound the command: %s elapsed", elapsed)
	}
}

func TestExecRunnerCancellationIsDistinctFromTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX sleep helper")
	}
	skipWithout(t, "sleep")

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	res := (&ExecRunner{Timeout: 10 * time.Second}).Run(ctx, "sleep", "5")
	if res.TimedOut {
		t.Fatal("a cancelled run was reported as a timeout")
	}
	if res.Err != "cancelled" {
		t.Fatalf("err = %q, want %q", res.Err, "cancelled")
	}
	if res.ExitCode != -1 {
		t.Errorf("exit code = %d, want -1", res.ExitCode)
	}
}

func TestExecRunnerStartFailure(t *testing.T) {
	res := (&ExecRunner{Timeout: time.Second}).Run(context.Background(),
		"definitely-not-a-real-binary-netmerge-test")
	if res.Started {
		t.Fatal("a command that could not start was reported as started")
	}
	if res.Err == "" {
		t.Error("a start failure carries no error text")
	}
	if !res.Failed() {
		t.Error("a start failure must count as a failure")
	}
}

func TestResultHelpers(t *testing.T) {
	r := Result{Started: true, Stdout: "first\nsecond", Stderr: "problem"}
	if r.Failed() {
		t.Error("a zero exit with output is not a failure")
	}
	out := r.Output()
	if !strings.Contains(out, "first") || !strings.Contains(out, "problem") {
		t.Errorf("Output() = %q, want stdout and stderr together", out)
	}
	if got := r.FirstLine(); got != "first" {
		t.Errorf("FirstLine() = %q, want %q", got, "first")
	}
	if !(Result{}).Failed() {
		t.Error("the zero Result never started and must count as a failure")
	}
	if !(Result{Started: true, TimedOut: true}).Failed() {
		t.Error("a timeout must count as a failure")
	}
}
