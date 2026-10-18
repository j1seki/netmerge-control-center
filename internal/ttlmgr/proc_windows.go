//go:build windows

package ttlmgr

import (
	"errors"

	"golang.org/x/sys/windows"
)

// processAlive reports whether a process with the given pid is still running.
//
// It is used only to decide whether a lock file may be reclaimed as stale, so "cannot tell"
// answers true: a lock is never taken away from a process that might still hold it. An
// access-denied result is exactly that case - the process exists but belongs to another
// account - while anything else means the pid is gone.
func processAlive(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err == nil {
		windows.CloseHandle(h)
		return true
	}
	return errors.Is(err, windows.ERROR_ACCESS_DENIED)
}
