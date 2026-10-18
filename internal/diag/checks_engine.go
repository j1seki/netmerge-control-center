package diag

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"net-merge/internal/inventory"
	"net-merge/internal/state"
)

// engineCmdTimeout bounds the engine CLI calls this file makes. They read the status file and
// enumerate adapters, so they are fast, but a stuck process must not hang a diagnostic run.
const engineCmdTimeout = 10 * time.Second

// selfPath returns the executable to invoke for the engine's own CLI, preferring whatever the
// caller supplied (a test can point at a fake) over the running binary.
func selfPath(env *Env) string {
	if env.Self != "" {
		return env.Self
	}
	p, err := os.Executable()
	if err != nil {
		return ""
	}
	return p
}

// engineRunArgs builds the argv for one engine CLI call. The state directory is passed
// explicitly so a diagnostic run against a custom state directory reads the same files the
// user's engine writes.
func engineRunArgs(env *Env, args ...string) []string {
	out := append([]string{}, args...)
	if env.StateDir != "" {
		out = append(out, "-state-dir", env.StateDir)
	}
	return out
}

func checkEngineStatus() Check {
	return funcCheck{
		meta: Meta{
			ID:       "engine.status",
			Title:    "net-merge engine status",
			Category: CatEngine,
			Purpose:  "Ask the engine itself whether it is on, which mode it is in, and what it reports per adapter.",
			Establishes: []string{
				"whether a net-merge instance is running, its mode (system-wide or SOCKS), its process id, and how long it has been up",
				"per-adapter counters and rates as the engine itself measures them, which is the only source for 'what did net-merge relay'",
			},
			DoesNotEstablish: []string{
				"'via net-merge' rates are only that engine's relayed traffic: traffic that bypasses the app (an app bound directly to an adapter, or ordinary OS traffic while the engine is off) never appears in them",
			},
		},
		run: func(ctx context.Context, env *Env) Result {
			res := Result{}
			st, on := state.Read(env.StateDir)
			if !on {
				res.Status = StatusInfo
				res.Summary = "net-merge is not running (no fresh status file)"
				res.Established = append(res.Established,
					fmt.Sprintf("no running engine has written a status file in %s within the freshness window", env.StateDir))
				res.Inconclusive = append(res.Inconclusive,
					"everything about engine-side scheduling: with the engine off, traffic goes through the OS exactly as it would without this application")
				res.NextSteps = append(res.NextSteps, "Start the tray or the Control Center to bring the engine up, then re-run this check.")
			} else {
				res.Status = StatusPass
				res.Summary = fmt.Sprintf("net-merge is ON in %s mode (pid %d, up %s)", st.Mode, st.PID, time.Since(st.Since).Truncate(time.Second))
				res.Established = append(res.Established,
					fmt.Sprintf("an engine has been running for %s in %s mode", time.Since(st.Since).Truncate(time.Second), st.Mode))
				if st.V6 != "" {
					res.Established = append(res.Established, "IPv6 handling: "+st.V6)
				}
				for _, n := range st.NICs {
					line := fmt.Sprintf("%s: engine state %s, %d active connection(s), %d total, %.2f/%.2f weight",
						n.Name, nonEmpty(n.State, "unknown"), n.Active, n.Total, n.Weight, n.Weight6)
					if n.RateIn > 0 || n.RateOut > 0 {
						line += fmt.Sprintf(", relaying %.1f kB/s in / %.1f kB/s out", n.RateIn/1000, n.RateOut/1000)
					}
					if n.Failed > 0 {
						line += fmt.Sprintf(", %d probe failure(s)", n.Failed)
					}
					if !n.Present {
						line += " (the adapter is gone)"
					}
					res.Established = append(res.Established, line)
				}
			}

			// The engine's own status command is run as evidence: it is the supported surface,
			// so a disagreement between it and the status file is itself a finding.
			if self := selfPath(env); self != "" {
				r, e := env.run(ctx, "engine's own status command", engineCmdTimeout, self, engineRunArgs(env, "status")...)
				if r.Started {
					res.Evidence = append(res.Evidence, e)
					line := strings.TrimSpace(r.Stdout)
					if line == "" {
						line = strings.TrimSpace(r.Stderr)
					}
					viaCmd := strings.Contains(strings.ToLower(line), "is on")
					if on != viaCmd {
						res.Status = Worse(res.Status, StatusWarn)
						res.Inconclusive = append(res.Inconclusive,
							"the engine's status command and its status file disagree about whether the engine is running; the status file is only trusted when it is fresh, so trust the command")
					}
				} else {
					res.Inconclusive = append(res.Inconclusive, "the engine's own status command could not be run: "+nonEmpty(r.Err, "unknown reason"))
				}
			}
			return res
		},
	}
}

func checkEngineEligibility() Check {
	return funcCheck{
		meta: Meta{
			ID:       "engine.eligibility",
			Title:    "Engine adapter eligibility",
			Category: CatEngine,
			Purpose:  "Read the engine's own adapter list, so the dashboard and the engine cannot disagree about which links are in use.",
			Establishes: []string{
				"the exact adapter names the engine would use (net-merge list), and for each one it skips, the engine's own reason",
				"whether an adapter that the inventory considers usable is being skipped by the engine, which is the usual explanation for 'the interface is there but carries no traffic'",
			},
			DoesNotEstablish: []string{
				"that a listed adapter is carrying traffic right now: that is the engine status check's per-adapter counters",
			},
		},
		run: func(ctx context.Context, env *Env) Result {
			self := selfPath(env)
			if self == "" {
				return Result{Status: StatusSkipped, Summary: "the net-merge executable path could not be determined, so the engine's own list cannot be read"}
			}
			r, e := env.run(ctx, "engine's own adapter list", engineCmdTimeout, self, engineRunArgs(env, "list")...)
			res := Result{Evidence: []Evidence{e}}
			if !r.Started {
				res.Status = StatusSkipped
				res.Summary = "the engine's adapter list could not be run: " + nonEmpty(r.Err, "unknown reason")
				res.ErrorCodes = append(res.ErrorCodes, "diag_engine_cli_unavailable")
				return res
			}
			use, skip := parseEngineList(r.Output())
			for _, u := range use {
				res.Established = append(res.Established, "engine will use "+u)
			}
			for _, s := range skip {
				res.Established = append(res.Established, "engine skips "+s)
			}
			if len(use) == 0 && len(skip) == 0 {
				res.Status = StatusWarn
				res.Summary = "the engine's list command produced nothing readable"
				res.Inconclusive = append(res.Inconclusive, "the engine's view of the adapters; the inventory view is still shown in the Connections section")
				res.ErrorCodes = append(res.ErrorCodes, "diag_parse_failed")
				return res
			}
			// Cross-check with the inventory: a usable adapter the engine does not list is the
			// case worth surfacing.
			snap, err := env.snapshot(ctx)
			if err == nil && snap != nil {
				for _, a := range snap.Usable() {
					if !containsName(use, a.Name) {
						res.Status = Worse(res.Status, StatusWarn)
						res.Inconclusive = append(res.Inconclusive, fmt.Sprintf(
							"%s is usable according to the inventory but is not in the engine's list; the engine may be excluding it for a reason above, or it may have been found after the engine's last re-scan",
							a.Name))
					}
				}
			}
			if len(res.Inconclusive) > 0 {
				res.Status = Worse(res.Status, StatusWarn)
				res.Summary = fmt.Sprintf("engine will use %d of %d known adapter(s); see the differences noted", len(use), len(use)+len(skip))
			} else {
				res.Status = StatusPass
				res.Summary = fmt.Sprintf("engine will use %d adapter(s) and skips %d, with reasons", len(use), len(skip))
			}
			return res
		},
	}
}

// parseEngineList reads `net-merge list` output: "USE   name (index N)" and "skip  name: reason".
func parseEngineList(out string) (use []string, skip []string) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(strings.TrimSuffix(line, "\r"), " ")
		switch {
		case strings.HasPrefix(line, "USE"):
			rest := strings.TrimSpace(strings.TrimPrefix(line, "USE"))
			if i := strings.LastIndex(rest, "(index"); i > 0 {
				rest = strings.TrimSpace(rest[:i])
			}
			if rest != "" {
				use = append(use, rest)
			}
		case strings.HasPrefix(line, "skip"):
			rest := strings.TrimSpace(strings.TrimPrefix(line, "skip"))
			if rest != "" {
				skip = append(skip, rest)
			}
		}
	}
	return use, skip
}

func containsName(list []string, name string) bool {
	for _, s := range list {
		if strings.EqualFold(s, name) || strings.HasPrefix(strings.ToLower(s), strings.ToLower(name)+" ") {
			return true
		}
	}
	return false
}

func checkEngineStale() Check {
	return funcCheck{
		meta: Meta{
			ID:       "engine.stale",
			Title:    "Leftover state after a crash",
			Category: CatEngine,
			Purpose:  "Look for the adapter and routes a crashed run can leave behind, and name the supported cleanup.",
			Establishes: []string{
				"whether a net-merge TUN adapter is present while the engine is not running",
				"whether any route names an interface that no longer exists",
			},
			DoesNotEstablish: []string{
				"that removing anything is safe: the repair is net-merge's own cleanup command, which removes only routes it created",
			},
		},
		run: func(ctx context.Context, env *Env) Result {
			snap, err := env.snapshot(ctx)
			if err != nil {
				return Result{Status: StatusError, Summary: err.Error(), ErrorCodes: []string{"diag_inventory_failed"}}
			}
			_, running := state.Read(env.StateDir)
			res := Result{}
			var tunAdapters []string
			for _, a := range snap.Adapters {
				if isTunAdapter(a) {
					tunAdapters = append(tunAdapters, a.Name)
				}
			}
			missing := map[int]bool{}
			for _, a := range snap.Adapters {
				missing[a.Index] = true
			}
			stale := 0
			for _, r := range snap.Routes {
				if r.Index > 0 && !missing[r.Index] {
					stale++
				}
			}
			switch {
			case len(tunAdapters) > 0 && !running:
				res.Status = StatusWarn
				res.Summary = fmt.Sprintf("a net-merge adapter (%s) exists while the engine is not running", strings.Join(tunAdapters, ", "))
				res.Established = append(res.Established,
					fmt.Sprintf("the TUN adapter %s is present and no engine is running", strings.Join(tunAdapters, ", ")))
				res.NextSteps = append(res.NextSteps,
					"Run `net-merge cleanup` (elevated): it removes the routes net-merge created on that adapter. The adapter itself goes away with a reboot or when the driver is released.",
					"Confirm nothing else is using that adapter before removing anything.")
				res.ErrorCodes = append(res.ErrorCodes, "engine_stale_adapter")
			case stale > 0:
				res.Status = StatusWarn
				res.Summary = fmt.Sprintf("%d route(s) name an interface that is no longer present", stale)
				res.Established = append(res.Established, "at least one route points at a missing interface index")
			default:
				res.Status = StatusPass
				res.Summary = "no leftover engine adapter and no route pointing at a missing interface"
				if running {
					res.Established = append(res.Established, "a net-merge adapter exists and an engine is running, which is the normal state while system-wide mode is on")
				}
			}
			return res
		},
	}
}

// isTunAdapter recognises net-merge's own adapter by name or by its well-known address.
func isTunAdapter(a inventory.Adapter) bool {
	if strings.Contains(strings.ToLower(a.Name), tunAdapterHint) || strings.Contains(strings.ToLower(a.Description), tunAdapterHint) {
		return true
	}
	for _, addr := range a.IPv4 {
		if addr.Address == tunAdapterAddr {
			return true
		}
	}
	return false
}

// ---- health: counters and families ----------------------------------------------------------

func checkCountersMovement() Check {
	return funcCheck{
		meta: Meta{
			ID:       "counters.movement",
			Title:    "Byte counters over a short window",
			Category: CatAdapters,
			Purpose:  "Sample every adapter's byte counters, wait, sample again, and report which links actually moved bytes.",
			Establishes: []string{
				"per adapter, how many bytes this host sent and received during the sampling window, counted by the OS",
			},
			DoesNotEstablish: []string{
				"which application or connection caused that traffic, and that a link with no movement is faulty: an idle link is idle",
			},
			Slow: true,
		},
		run: func(ctx context.Context, env *Env) Result {
			window := counterWindow(env)
			before, err := env.snapshot(ctx)
			if err != nil {
				return Result{Status: StatusError, Summary: err.Error(), ErrorCodes: []string{"diag_inventory_failed"}}
			}
			if err := env.Sleep(ctx, window); err != nil {
				return Result{Status: StatusSkipped, Summary: "the sampling window was cancelled: " + err.Error()}
			}
			after, err := env.snapshot(ctx)
			if err != nil {
				return Result{Status: StatusError, Summary: "the second sample failed: " + err.Error(), ErrorCodes: []string{"diag_inventory_failed"}}
			}
			res := Result{
				Evidence: []Evidence{{Label: fmt.Sprintf("two counter samples %s apart", window), Started: true, Note: "counters are the OS's totals for the adapter, covering every application"}},
			}
			moved, idle := 0, 0
			for _, a := range after.Adapters {
				if a.Status == inventory.StateDisconnected {
					continue
				}
				b, ok := before.Adapter(a.Index)
				if !ok || a.Counters == nil || b.Counters == nil {
					res.Inconclusive = append(res.Inconclusive, a.Name+": counters are not available on this platform")
					continue
				}
				in := int64(a.Counters.In) - int64(b.Counters.In)
				out := int64(a.Counters.Out) - int64(b.Counters.Out)
				if in < 0 || out < 0 {
					res.Inconclusive = append(res.Inconclusive, fmt.Sprintf("%s: the counters went backwards (adapter reset), so this window is discarded", a.Name))
					continue
				}
				if in == 0 && out == 0 {
					idle++
					res.Established = append(res.Established, fmt.Sprintf("%s: no bytes in %s", a.Name, window))
					continue
				}
				moved++
				res.Established = append(res.Established, fmt.Sprintf("%s: %s in, %s out during %s", a.Name, humanBytes(uint64(in)), humanBytes(uint64(out)), window))
			}
			switch {
			case moved == 0 && idle == 0:
				res.Status = StatusWarn
				res.Summary = "no adapter produced a usable counter sample"
				res.ErrorCodes = append(res.ErrorCodes, "diag_counters_unavailable")
			case moved == 0:
				res.Status = StatusInfo
				res.Summary = fmt.Sprintf("no traffic on any adapter during %s", window)
				res.Inconclusive = append(res.Inconclusive, "whether the links work: counters need traffic to move, and an idle host looks exactly like this")
			default:
				res.Status = StatusPass
				res.Summary = fmt.Sprintf("%d adapter(s) moved traffic, %d were idle, over %s", moved, idle, window)
			}
			return res
		},
	}
}

func counterWindow(env *Env) time.Duration {
	// Two seconds is long enough for a busy link and short enough not to stall a diagnostic
	// run. Tests shorten it.
	return 2 * time.Second
}

func humanBytes(n uint64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f kB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d bytes", n)
	}
}

func checkCountersIdle() Check {
	return funcCheck{
		meta: Meta{
			ID:       "counters.assigned-idle",
			Title:    "Assigned connections with no traffic",
			Category: CatEngine,
			Purpose:  "Compare what the engine says it has assigned with what the OS counters show, and report the mismatch as uncertainty rather than a verdict.",
			Establishes: []string{
				"whether an adapter the engine reports as carrying connections moved any bytes at all during the sample window",
			},
			DoesNotEstablish: []string{
				"that a mismatch is a fault: idle connections (a keep-alive, an idle tab) are assigned and move nothing, and some traffic bypasses the engine entirely",
			},
			Slow: true,
		},
		run: func(ctx context.Context, env *Env) Result {
			st, on := state.Read(env.StateDir)
			if !on {
				return Result{
					Status:       StatusSkipped,
					Summary:      "the engine is not running, so there are no assigned connections to compare",
					Inconclusive: []string{"engine-side assignment versus observed traffic"},
				}
			}
			window := counterWindow(env)
			before, err := env.snapshot(ctx)
			if err != nil {
				return Result{Status: StatusError, Summary: err.Error(), ErrorCodes: []string{"diag_inventory_failed"}}
			}
			if err := env.Sleep(ctx, window); err != nil {
				return Result{Status: StatusSkipped, Summary: "the sampling window was cancelled: " + err.Error()}
			}
			after, err := env.snapshot(ctx)
			if err != nil {
				return Result{Status: StatusError, Summary: "the second sample failed: " + err.Error(), ErrorCodes: []string{"diag_inventory_failed"}}
			}
			res := Result{}
			checked := 0
			for _, n := range st.NICs {
				if n.Active <= 0 {
					continue
				}
				a, ok := after.ByName(n.Name)
				if !ok || a.Counters == nil {
					res.Inconclusive = append(res.Inconclusive, n.Name+": the engine reports connections but the inventory has no counters for it")
					continue
				}
				b, ok := before.ByName(n.Name)
				if !ok || b.Counters == nil {
					res.Inconclusive = append(res.Inconclusive, n.Name+": only one counter sample was available")
					continue
				}
				checked++
				delta := int64(a.Counters.In) - int64(b.Counters.In) + int64(a.Counters.Out) - int64(b.Counters.Out)
				if delta <= 0 {
					res.Established = append(res.Established, fmt.Sprintf(
						"%s: engine reports %d assigned connection(s) and the adapter's counters did not move in %s", n.Name, n.Active, window))
					res.Inconclusive = append(res.Inconclusive, fmt.Sprintf(
						"%s: whether those connections are simply idle, or their traffic is not leaving through this adapter", n.Name))
				} else {
					res.Established = append(res.Established, fmt.Sprintf(
						"%s: engine reports %d assigned connection(s) and the adapter moved %s in %s", n.Name, n.Active, humanBytes(uint64(delta)), window))
				}
			}
			switch {
			case checked == 0:
				res.Status = StatusSkipped
				res.Summary = "no adapter had both engine assignments and counter samples"
			case len(res.Inconclusive) > 0:
				res.Status = StatusWarn
				res.Summary = "some adapters were reported as carrying connections without observable traffic"
			default:
				res.Status = StatusPass
				res.Summary = fmt.Sprintf("every adapter carrying engine connections also moved traffic (%d checked)", checked)
			}
			return res
		},
	}
}

func checkSplitFamilies() Check {
	return funcCheck{
		meta: Meta{
			ID:       "families.split",
			Title:    "IPv4 / IPv6 split behaviour",
			Category: CatPath,
			Purpose:  "Show which links carry which address family, so a family-specific failure is visible instead of looking like 'the internet is broken'.",
			Establishes: []string{
				"per usable adapter: whether it has IPv4, IPv6, or both, and whether its IPv6 is link-local only",
			},
			DoesNotEstablish: []string{
				"that IPv6 works end to end: connectivity is tested separately, and IPv6 is configured independently of IPv4",
			},
		},
		run: func(ctx context.Context, env *Env) Result {
			snap, err := env.snapshot(ctx)
			if err != nil {
				return Result{Status: StatusError, Summary: err.Error(), ErrorCodes: []string{"diag_inventory_failed"}}
			}
			res := Result{}
			var only4, only6, both, neither []string
			for _, a := range snap.Usable() {
				has4 := false
				if _, ok := a.RoutableIPv4(); ok {
					has4 = true
				}
				has6 := false
				if _, ok := a.RoutableIPv6(); ok {
					has6 = true
				}
				switch {
				case has4 && has6:
					both = append(both, a.Name)
				case has4:
					only4 = append(only4, a.Name)
				case has6:
					only6 = append(only6, a.Name)
				default:
					neither = append(neither, a.Name)
				}
			}
			if len(only4) > 0 {
				res.Established = append(res.Established, "IPv4 only: "+strings.Join(only4, ", "))
			}
			if len(only6) > 0 {
				res.Established = append(res.Established, "IPv6 only: "+strings.Join(only6, ", "))
			}
			if len(both) > 0 {
				res.Established = append(res.Established, "dual-stack: "+strings.Join(both, ", "))
			}
			if len(neither) > 0 {
				res.Established = append(res.Established, "no usable address: "+strings.Join(neither, ", "))
			}
			switch {
			case len(both) == 0 && len(only4) > 0 && len(only6) == 0:
				res.Status = StatusWarn
				res.Summary = "no usable link has IPv6: this host is IPv4-only right now"
				res.NextSteps = append(res.NextSteps, "IPv6 is left enabled and untouched by this application; if a link should have IPv6, check the adapter's IPv6 configuration.")
			case len(only4) > 0 || len(only6) > 0:
				res.Status = StatusWarn
				res.Summary = "adapters differ in address families, so a family-specific failure is possible"
				res.Inconclusive = append(res.Inconclusive, "whether IPv6 traffic works over the links that have IPv6: the IPv6 connectivity check tests that")
			default:
				res.Status = StatusPass
				res.Summary = fmt.Sprintf("family coverage recorded for %d usable adapter(s)", len(snap.Usable()))
			}
			return res
		},
	}
}

// ---- security and conflicts -----------------------------------------------------------------

func checkPortsConflict() Check {
	return funcCheck{
		meta: Meta{
			ID:       "ports.conflict",
			Title:    "Port and instance conflicts",
			Category: CatSecurity,
			Purpose:  "Check the fixed ports net-merge uses, and whether a second instance is running.",
			Establishes: []string{
				"whether the SOCKS listen port is already bound by something (tested by binding it and releasing it)",
				"whether another net-merge instance is alive, from its own instance lock",
			},
			DoesNotEstablish: []string{
				"which process holds a busy port unless the OS exposes a process list for it; the report states the conflict, not a guessed owner",
			},
		},
		run: func(ctx context.Context, env *Env) Result {
			res := Result{}
			const socks = "127.0.0.1:1080"
			free, err := env.Probes.PortFree(ctx, socks)
			ev := Evidence{Label: "bind test on " + socks, Started: true}
			switch {
			case err != nil:
				res.Inconclusive = append(res.Inconclusive, "the port test itself failed: "+err.Error())
			case free:
				res.Established = append(res.Established, socks+" is free: no other process is listening there")
			default:
				res.Established = append(res.Established, socks+" is already bound by another process")
				res.Status = Worse(res.Status, StatusWarn)
				res.Summary = socks + " is in use by another process"
				res.NextSteps = append(res.NextSteps,
					"'net-merge socks' would fail to start on that address; find the owner with `netstat -ano | findstr 1080` (Windows) or `ss -ltnp` (Linux), or choose another -listen address.")
				res.ErrorCodes = append(res.ErrorCodes, "port_in_use")
			}
			res.Evidence = append(res.Evidence, ev)

			// A second instance is refused by net-merge's own single-instance guard; this check
			// reports whether one is alive so "nothing happens when I start it" has an answer.
			if running, ok := oneInstanceRunning(env); ok {
				if running {
					res.Established = append(res.Established, "another net-merge process is alive (its instance lock is held)")
				} else {
					res.Established = append(res.Established, "no other net-merge process holds the instance lock")
				}
			} else {
				res.Inconclusive = append(res.Inconclusive, "whether another instance is running: the platform has no instance check available to this process")
			}
			if res.Status == "" {
				res.Status = StatusPass
				res.Summary = "no port conflict found"
			} else if res.Summary == "" {
				res.Summary = "port checked; see the notes"
			}
			return res
		},
	}
}

// oneInstanceRunning reports whether another instance holds net-merge's single-instance lock.
// It uses the engine's own mechanism (platform.InstanceRunning) via a subprocess-free path on
// Windows (a named mutex) and a lock file elsewhere; this function only calls out when the
// platform provides an answer.
func oneInstanceRunning(env *Env) (bool, bool) {
	if env.instanceRunning == nil {
		return false, false
	}
	return env.instanceRunning(), true
}

func checkSecurityFirewall() Check {
	return funcCheck{
		meta: Meta{
			ID:       "security.firewall",
			Title:    "Firewall profiles",
			Category: CatSecurity,
			Purpose:  "Report the firewall's configuration so a filtered-connection hypothesis has a basis. Nothing here is changed.",
			Establishes: []string{
				"which firewall profiles are enabled and their default inbound/outbound actions (Windows: Get-NetFirewallProfile)",
			},
			DoesNotEstablish: []string{
				"that the firewall blocked a specific connection: it reports configuration, not a verdict, and this application never disables a security control",
			},
			Platforms: []string{"windows"},
		},
		run: func(ctx context.Context, env *Env) Result {
			spec, ok := cmds("windows")["firewall"]
			if !ok {
				return missingCommandResult(env, Meta{}, "Get-NetFirewallProfile")
			}
			r, e := env.run(ctx, "firewall profiles (Get-NetFirewallProfile)", 0, spec.Name, spec.Args...)
			res := Result{Evidence: []Evidence{e}}
			if !r.Started {
				res.Status = StatusSkipped
				res.Summary = "Get-NetFirewallProfile could not be run: " + nonEmpty(r.Err, "not available")
				res.ErrorCodes = append(res.ErrorCodes, "diag_cmd_unavailable")
				return res
			}
			objs, err := psJSON(r.Stdout)
			if err != nil || len(objs) == 0 {
				res.Status = StatusWarn
				res.Summary = "the firewall query produced nothing that could be parsed"
				if err != nil {
					res.Inconclusive = append(res.Inconclusive, err.Error())
				}
				res.ErrorCodes = append(res.ErrorCodes, "diag_parse_failed")
				return res
			}
			enabled := 0
			for _, o := range objs {
				name := psStr(o, "Name")
				on, _ := psBool(o, "Enabled")
				in := psStr(o, "DefaultInboundAction")
				out := psStr(o, "DefaultOutboundAction")
				state := "disabled"
				if on {
					enabled++
					state = "enabled"
				}
				res.Established = append(res.Established, fmt.Sprintf("%s profile: %s (inbound %s, outbound %s)", name, state, nonEmpty(in, "?"), nonEmpty(out, "?")))
			}
			res.Status = StatusInfo
			res.Summary = fmt.Sprintf("%d of %d firewall profile(s) enabled; this is configuration, not a diagnosis", enabled, len(objs))
			res.Inconclusive = append(res.Inconclusive,
				"whether a specific connection was filtered: the per-adapter and TCP checks decide that, and this application never changes firewall state")
			return res
		},
	}
}

func checkSecurityAV() Check {
	return funcCheck{
		meta: Meta{
			ID:       "security.av",
			Title:    "Registered security products",
			Category: CatSecurity,
			Purpose:  "Name the security products Windows registers, because their network filters are a common cause of traffic that vanishes.",
			Establishes: []string{
				"the products Windows Security Center registers (Windows: root/SecurityCenter2 AntiVirusProduct)",
			},
			DoesNotEstablish: []string{
				"that a product is blocking anything: this is a list of what is installed, used only to make a hypothesis checkable",
			},
			Platforms: []string{"windows"},
		},
		run: func(ctx context.Context, env *Env) Result {
			spec, ok := cmds("windows")["av"]
			if !ok {
				return missingCommandResult(env, Meta{}, "Get-CimInstance AntiVirusProduct")
			}
			r, e := env.run(ctx, "registered security products", 0, spec.Name, spec.Args...)
			res := Result{Evidence: []Evidence{e}}
			if !r.Started {
				res.Status = StatusSkipped
				res.Summary = "the security product query could not be run: " + nonEmpty(r.Err, "not available")
				return res
			}
			out := strings.TrimSpace(r.Stdout)
			if out == "" || out == "null" {
				res.Status = StatusInfo
				res.Summary = "no third-party security product is registered (Windows Security Center returned nothing)"
				res.Established = append(res.Established, "the SecurityCenter2 namespace lists no antivirus product")
				return res
			}
			objs, err := psJSON(r.Stdout)
			if err != nil {
				res.Status = StatusWarn
				res.Summary = "the security product query produced output that could not be parsed"
				res.Inconclusive = append(res.Inconclusive, err.Error())
				return res
			}
			for _, o := range objs {
				name := psStr(o, "displayName")
				if name == "" {
					continue
				}
				res.Established = append(res.Established, "registered: "+name)
			}
			res.Status = StatusInfo
			res.Summary = fmt.Sprintf("%d security product(s) registered", len(objs))
			res.Inconclusive = append(res.Inconclusive, "whether any of them filters traffic: if a connection fails while everything else passes, a product filter is the next thing to check")
			return res
		},
	}
}
