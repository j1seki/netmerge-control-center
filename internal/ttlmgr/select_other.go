//go:build !windows && !linux

package ttlmgr

import "runtime"

// NewBackend returns the TTL backend for this host.
//
// On macOS (and any other non-Windows, non-Linux host) there is no equivalent of the Windows
// stack defaults, so the backend reports itself unsupported and refuses every read and write.
// This is a deliberate choice over inventing a mapping: the Darwin knobs are per-socket and
// per-interface in ways that do not correspond to Windows' system-global value, and silently
// writing something that looked similar would be a worse answer than saying "not available
// here". Linux is handled separately by a read-only backend that reports the real current
// values without offering any change.
//
// The rest of the Control Center keeps working: inspection reports the absence, the change
// history stays empty, and no system setting on this host is touched.
func NewBackend(Runner) Backend {
	return NewUnsupportedBackend(
		"IPv4 packet TTL and IPv6 hop limit are configured through the Windows networking cmdlets, " +
			"which do not exist on " + runtime.GOOS + ".")
}
