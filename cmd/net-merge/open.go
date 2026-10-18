package main

import "net-merge/internal/execx"

// commandStarted turns a runner result into an error for the "did it even launch" question. A
// browser helper that launched and exited non-zero (a headless session, no default browser) is
// reported too, because silence would look like success.
func commandStarted(res execx.Result) error {
	if !res.Started {
		return &launchError{cmd: res.Command, err: res.Err}
	}
	if res.ExitCode != 0 {
		return &launchError{cmd: res.Command, err: res.Stderr}
	}
	return nil
}

type launchError struct {
	cmd string
	err string
}

func (e *launchError) Error() string {
	if e.err == "" {
		return e.cmd + " failed"
	}
	return e.cmd + ": " + e.err
}
