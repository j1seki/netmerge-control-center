//go:build linux

package ttlmgr

// NewBackend returns the TTL backend for this host.
//
// On Linux the current IPv4 TTL and IPv6 hop limit are readable straight from /proc, so the
// backend reports the real values with a read-only capability. It deliberately exposes no
// write path: the writable knobs (per-socket setsockopt and per-interface sysctls) do not
// correspond to Windows' system-global defaults, and this build changes settings on Windows
// only. Reading here never touches a system setting.
func NewBackend(Runner) Backend { return NewLinuxBackend() }
