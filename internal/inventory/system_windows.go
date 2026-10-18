//go:build windows

package inventory

import (
	"context"
	"fmt"
	"strings"

	"net-merge/internal/execx"
	"net-merge/internal/nics"
)

// powershellExe is the interpreter the probe drives. Windows PowerShell 5.1 ships with every
// Windows 10 and 11 install, so it is the baseline; the NetTCPIP cmdlets it can reach are the
// documented mechanism for reading this configuration.
const powershellExe = "powershell.exe"

// WindowsSource reads the inventory through the documented Windows networking cmdlets, with the
// IP Helper API as a fallback for the parts that do not need them.
//
// The cmdlets are the primary mechanism because they are what Microsoft documents and what a
// support engineer would run by hand, so the report can be reproduced outside the application.
// The fallback matters for the machines where PowerShell is unavailable by policy: an inventory
// from GetAdaptersAddresses is narrower (no DHCP state, no interface metric) but real, and the
// missing fields are declared as gaps rather than left looking like zeros.
type WindowsSource struct {
	runner execx.Runner
	// LookPath is used to decide whether powershell.exe can be resolved at all.
	lookPath func(string) (string, error)
}

// NewWindowsSource returns the Windows inventory source over the given runner.
func NewWindowsSource(r execx.Runner) *WindowsSource {
	if r == nil {
		r = execx.NewExecRunner()
	}
	return &WindowsSource{runner: r, lookPath: r.LookPath}
}

// Name implements Source.
func (w *WindowsSource) Name() string { return "windows-powershell" }

// Adapters implements Source.
func (w *WindowsSource) Adapters(ctx context.Context) ([]Adapter, []string, error) {
	var gaps []string
	if w.lookPath != nil {
		if _, err := w.lookPath(powershellExe); err != nil {
			gaps = append(gaps, fmt.Sprintf(
				"powershell.exe could not be resolved (%v): adapter configuration falls back to the IP Helper API, which does not report DHCP state or interface metrics", err))
			return w.nativeAdapters(gaps)
		}
	}
	res := w.runner.Run(ctx, powershellExe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", psProbeScript)
	if !res.Started || res.TimedOut {
		gaps = append(gaps, "the PowerShell inventory probe could not run ("+firstNonEmpty(res.Err, "did not start")+
			"): adapter configuration falls back to the IP Helper API")
		return w.nativeAdapters(gaps)
	}
	adapters, _, pgaps, errs, err := parseProbe([]byte(res.Stdout))
	if err != nil {
		gaps = append(gaps, "the PowerShell inventory probe output could not be read: "+err.Error()+
			"; adapter configuration falls back to the IP Helper API")
		return w.nativeAdapters(gaps)
	}
	gaps = append(gaps, pgaps...)
	if len(errs) > 0 {
		gaps = append(gaps, "the PowerShell inventory probe reported: "+strings.Join(errs, "; "))
	}
	// Counters come from the native API when it can answer, because it costs no process start and
	// the dashboard polls it; the probe's coarser statistics remain as the fallback.
	for i := range adapters {
		if in, out, ok := nics.Octets(adapters[i].Index); ok {
			c := Counters{In: in, Out: out}
			adapters[i].Counters = &c
		} else if adapters[i].ProbeCounters != nil {
			adapters[i].Counters = adapters[i].ProbeCounters
			adapters[i].Gaps = append(adapters[i].Gaps, "byte counters come from the probe's coarser statistics")
		}
	}
	return adapters, gaps, nil
}

// Routes implements Source.
func (w *WindowsSource) Routes(ctx context.Context) ([]Route, []string, error) {
	if w.lookPath != nil {
		if _, err := w.lookPath(powershellExe); err != nil {
			return nil, []string{"routing table not read: powershell.exe could not be resolved"}, nil
		}
	}
	res := w.runner.Run(ctx, powershellExe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", psProbeScript)
	if !res.Started || res.TimedOut {
		return nil, []string{"routing table not read: the PowerShell probe did not run"}, nil
	}
	_, routes, _, _, err := parseProbe([]byte(res.Stdout))
	if err != nil {
		return nil, []string{"routing table not read: " + err.Error()}, nil
	}
	return routes, nil, nil
}

// Counters implements Source. The native MIB read is the fast path; the probe is not consulted
// here because a counter is a per-second value and starting PowerShell to fetch one would cost
// more than the data is worth.
func (w *WindowsSource) Counters(_ context.Context, index int) (Counters, bool) {
	in, out, ok := nics.Octets(index)
	if !ok {
		return Counters{}, false
	}
	return Counters{In: in, Out: out}, true
}

// Supported reports whether the NetTCPIP cmdlets can be reached, so the dashboard can say which
// mechanism is behind the numbers instead of leaving it ambiguous.
func (w *WindowsSource) Supported(ctx context.Context) (bool, []string) {
	res := w.runner.Run(ctx, powershellExe, "-NoProfile", "-NonInteractive", "-Command",
		"@('Get-NetAdapter','Get-NetRoute','Get-NetIPInterface','Get-DnsClientServerAddress','Get-NetIPAddress') | ForEach-Object { [bool](Get-Command $_ -ErrorAction SilentlyContinue) } | ConvertTo-Json -Compress")
	if !res.Started || res.TimedOut {
		return false, []string{"could not ask PowerShell which networking cmdlets exist: " + firstNonEmpty(res.Err, "no output")}
	}
	var flags []bool
	if err := jsonUnmarshalLoose(res.Stdout, &flags); err != nil {
		return false, []string{"the cmdlet capability probe returned output that could not be read: " + err.Error()}
	}
	var missing []string
	names := []string{"Get-NetAdapter", "Get-NetRoute", "Get-NetIPInterface", "Get-DnsClientServerAddress", "Get-NetIPAddress"}
	for i, name := range names {
		if i < len(flags) && !flags[i] {
			missing = append(missing, name)
		}
	}
	return len(missing) == 0, missing
}
