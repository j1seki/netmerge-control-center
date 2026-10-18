//go:build !windows

package main

import (
	"context"
	"runtime"
	"time"

	"net-merge/internal/execx"
)

// openBrowser hands a local URL to the platform's default browser. It is a convenience only:
// the command prints the address either way, and a failure here never stops the dashboard.
func openBrowser(url string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	name := "xdg-open"
	if runtime.GOOS == "darwin" {
		name = "open"
	}
	res := execx.NewExecRunner().Run(ctx, name, url)
	return commandStarted(res)
}
