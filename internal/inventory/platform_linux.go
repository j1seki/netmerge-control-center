//go:build linux

package inventory

// NewPlatformSource returns the inventory source for this platform. It exists so a command can
// wire the real source without a build tag of its own; the source itself is chosen at compile
// time, where the platform is known.
func NewPlatformSource() Source { return NewLinuxSource() }
