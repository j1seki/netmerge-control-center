//go:build windows

package main

import (
	"context"
	"time"

	"net-merge/internal/execx"
)

// openBrowser asks Windows to hand a local URL to the user's default browser. The dashboard
// address is on loopback and carries a one-time token, which is exactly what the standard
// URL handler is for. rundll32 is the documented entry point for it and needs no shell.
func openBrowser(url string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	res := execx.NewExecRunner().Run(ctx, "rundll32.exe", "url.dll,FileProtocolHandler", url)
	return commandStarted(res)
}
