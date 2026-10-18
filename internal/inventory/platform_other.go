//go:build !windows && !linux

package inventory

// NewPlatformSource returns the inventory source for this platform. Platforms without a native
// source get one that reports the host as unsupported rather than inventing data.
func NewPlatformSource() Source { return NewOtherSource() }
