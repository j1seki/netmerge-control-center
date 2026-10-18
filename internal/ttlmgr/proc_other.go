//go:build !windows

package ttlmgr

import (
	"errors"
	"os/exec"
	"syscall"
)

// prepareCommand is a no-op away from Windows; there is no console-window problem to solve.
func prepareCommand(*exec.Cmd) {}

// processAlive reports whether a process with the given pid is still running. Signal 0 is the
// portable liveness probe: it performs the permission check without delivering anything. Like
// the Windows implementation, "cannot tell" answers true so a lock is never reclaimed from a
// process that might still hold it; EPERM means the process exists under another account.
func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	if err == nil {
		return true
	}
	return errors.Is(err, syscall.EPERM)
}
