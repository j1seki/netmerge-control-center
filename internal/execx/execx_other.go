//go:build !windows

package execx

import "os/exec"

// PrepareCommand is a no-op away from Windows; there is no console-window problem to solve.
func PrepareCommand(*exec.Cmd) {}
