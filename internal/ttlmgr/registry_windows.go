//go:build windows

package ttlmgr

import "golang.org/x/sys/windows/registry"

// readRegistryDWORD reads a REG_DWORD and reports whether it was present. A missing value is
// reported as absent rather than as zero, because absent means "use the built-in default".
//
// The registry is read-only here on purpose: the cmdlets are the documented mechanism for
// changing these settings, and a direct registry write is neither the documented route nor
// something this code could verify had taken effect.
func readRegistryDWORD(key, value string) (int, bool) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.QUERY_VALUE)
	if err != nil {
		return 0, false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(value)
	if err != nil {
		return 0, false
	}
	return int(v), true
}
