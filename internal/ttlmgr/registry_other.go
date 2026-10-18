//go:build !windows

package ttlmgr

// readRegistryDWORD does not exist away from Windows. The PowerShell backend is compiled on
// every host so its logic can be exercised by the test suite, and this is the one piece of it
// that has no meaning here: there is no Windows registry to consult, so no setting is ever
// reported as explicitly configured. In production this stub is never reached, because the
// non-Windows NewBackend returns the unsupported backend instead.
func readRegistryDWORD(string, string) (int, bool) { return 0, false }
