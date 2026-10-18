//go:build windows

package execx

import (
	"os/exec"
	"syscall"
)

// PrepareCommand stops Windows from flashing a console window for every probe and write. A
// windowless build has no console to inherit, so without this each PowerShell invocation would
// briefly steal focus, which would be visible and unpleasant during a diagnostic run.
func PrepareCommand(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}
