//go:build windows

package ttlmgr

// NewBackend returns the TTL backend for this host. On Windows that is the PowerShell and
// registry implementation, which is the only platform with a documented mechanism for these
// settings.
func NewBackend(r Runner) Backend { return NewWindowsBackend(r) }
