//go:build windows

package inventory

import "net-merge/internal/execx"

// NewPlatformSource returns the inventory source for this platform: the Windows cmdlets with the
// IP Helper API as the fallback. It exists so a command can wire the real source without a build
// tag of its own; the source itself is chosen at compile time, where the platform is known.
func NewPlatformSource() Source { return NewWindowsSource(execx.NewExecRunner()) }
