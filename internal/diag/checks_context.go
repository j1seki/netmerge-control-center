package diag

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"net-merge/internal/inventory"
)

// tunAdapterHint is how a net-merge TUN adapter is recognised in the inventory. The engine
// creates its adapter as "net-merge" (internal/tun), and the address is the well-known
// 198.18.0.1; both are checked because the adapter's name is the OS's to keep.
const (
	tunAdapterHint = "net-merge"
	tunAdapterAddr = "198.18.0.1"
)

// funcCheck adapts a function to the Check interface, so each check below is one small struct
// with a description and a body instead of a type per check.
type funcCheck struct {
	meta Meta
	run  func(ctx context.Context, env *Env) Result
}

func (f funcCheck) Meta() Meta { return f.meta }

func (f funcCheck) Run(ctx context.Context, env *Env) Result { return f.run(ctx, env) }

// allChecks is the registry's contents. Order here is the order the UI lists them.
func allChecks() []Check {
	return []Check{
		checkPlatformInfo(),
		checkPermissions(),
		checkTunDriver(),
		checkAdaptersInventory(),
		checkAdaptersLink(),
		checkAdaptersConfig(),
		checkAdaptersDriver(),
		checkRoutingTable(),
		checkRoutingDefault(),
		checkRoutingMetrics(),
		checkRoutingConflicts(),
		checkDNSServers(),
		checkDNSResolve(),
		checkDNSAtServer(),
		checkDNSCache(),
		checkGatewayReach(),
		checkIPv4Connect(),
		checkIPv6Connect(),
		checkAdapterConnect(),
		checkMTUPath(),
		checkTraceroute(),
		checkUDPProbe(),
		checkPortsConflict(),
		checkCountersMovement(),
		checkCountersIdle(),
		checkSplitFamilies(),
		checkEngineStatus(),
		checkEngineEligibility(),
		checkEngineStale(),
		checkSecurityFirewall(),
		checkSecurityAV(),
	}
}

// ---- platform ------------------------------------------------------------------------------

func checkPlatformInfo() Check {
	return funcCheck{
		meta: Meta{
			ID:       "platform.info",
			Title:    "Platform and application information",
			Category: CatPlatform,
			Purpose:  "Record what this report describes: the operating system, the app version, and where the app keeps its files.",
			Establishes: []string{
				"the operating system, architecture and (on Windows) edition and build reported by the OS itself",
				"the net-merge version and the directory holding its configuration and state",
			},
			DoesNotEstablish: []string{
				"which adapter a connection will use",
			},
		},
		run: func(ctx context.Context, env *Env) Result {
			var est []string
			var ev []Evidence
			est = append(est, fmt.Sprintf("this report was produced by net-merge %s on %s/%s", nonEmpty(env.AppVersion, "dev"), env.Platform, runtime.GOARCH))
			if env.StateDir != "" {
				est = append(est, "configuration and state live in "+env.StateDir)
			}
			est = append(est, fmt.Sprintf("the process has been running for %s", time.Since(logxStart()).Truncate(time.Second)))
			if env.Platform == "windows" {
				if r, evi := env.run(ctx, "windows edition and build", 0, "cmd", "/c", "ver"); r.Started && !r.Failed() {
					if line := strings.TrimSpace(r.Stdout); line != "" {
						est = append(est, "the OS reports: "+line)
					}
					ev = append(ev, evi)
				}
			} else {
				if b, err := os.ReadFile("/etc/os-release"); err == nil {
					if name := osReleaseField(string(b), "PRETTY_NAME"); name != "" {
						est = append(est, "the OS reports: "+name)
					}
				}
				if r, evi := env.run(ctx, "kernel", 0, "uname", "-sr"); r.Started && !r.Failed() {
					ev = append(ev, evi)
				}
			}
			return Result{
				Status:      StatusInfo,
				Summary:     fmt.Sprintf("%s/%s, net-merge %s", env.Platform, runtime.GOARCH, nonEmpty(env.AppVersion, "dev")),
				Established: est,
				Evidence:    ev,
			}
		},
	}
}

// logxStart is separated so the platform check has no import cycle risk and the value is
// stable in tests.
func logxStart() time.Time { return processStart }

var processStart = time.Now()

// osReleaseField reads one KEY=value from /etc/os-release.
func osReleaseField(s, key string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, key+"=") {
			continue
		}
		v := strings.TrimPrefix(line, key+"=")
		return strings.Trim(v, `"`)
	}
	return ""
}

func checkPermissions() Check {
	return funcCheck{
		meta: Meta{
			ID:       "platform.permissions",
			Title:    "Permissions and elevation",
			Category: CatPlatform,
			Purpose:  "State whether this process can change system settings, and exactly what needs elevation.",
			Establishes: []string{
				"whether this process is elevated right now",
				"what elevation gates in this application: net-merge's system-wide mode (a TUN adapter and routes), and TTL/hop-limit writes",
			},
			DoesNotEstablish: []string{
				"that an elevated process is safe to run: elevation is requested only for these specific operations",
			},
		},
		run: func(ctx context.Context, env *Env) Result {
			res := Result{}
			if env.IsAdmin {
				res.Status = StatusPass
				res.Summary = "running elevated: system-wide mode and TTL changes are possible"
				res.Established = append(res.Established,
					"this process is elevated, so it can create the TUN adapter, adjust routes, and write TTL/hop-limit values when explicitly asked")
				res.Inconclusive = append(res.Inconclusive,
					"elevation is not required for inspection: every read-only check in this report works without it")
			} else {
				res.Status = StatusInfo
				res.Summary = "not elevated: inspection works, system changes are refused with an explanation"
				res.Established = append(res.Established,
					"this process is not elevated, so net-merge's system-wide mode and TTL/hop-limit writes cannot run from it")
				res.NextSteps = append(res.NextSteps,
					"To start system-wide mode, use the tray or Control Center's Start action, which requests elevation for that operation only.")
			}
			if env.Platform == "windows" {
				// Whoami is the OS's own answer, used as evidence rather than trusting our own flag.
				if r, e := env.run(ctx, "whoami /groups (elevation evidence)", 0, "whoami", "/groups"); r.Started {
					s := strings.ToLower(r.Output())
					has := strings.Contains(s, "s-1-16-12288") || strings.Contains(s, "s-1-16-16384")
					res.Evidence = append(res.Evidence, e)
					res.Established = append(res.Established, fmt.Sprintf(
						"the OS token reports the high-integrity group as present=%t (S-1-16-12288 is 'High Mandatory Level')", has))
				}
			}
			return res
		},
	}
}

func checkTunDriver() Check {
	return funcCheck{
		meta: Meta{
			ID:       "tun.driver",
			Title:    "TUN driver availability",
			Category: CatTunnel,
			Purpose:  "Check the virtual adapter driver net-merge needs for system-wide mode.",
			Establishes: []string{
				"on Windows: whether wintun.dll is present next to the executable, which is what net-merge loads",
				"on Linux: whether /dev/net/tun exists and can be opened by this process",
			},
			DoesNotEstablish: []string{
				"that the adapter can be created: creating it also needs elevation and a free adapter name",
			},
		},
		run: func(ctx context.Context, env *Env) Result {
			switch env.Platform {
			case "windows":
				exe, err := os.Executable()
				if err != nil {
					return Result{Status: StatusSkipped, Summary: "the executable path could not be determined: " + err.Error()}
				}
				dll := filepath.Join(filepath.Dir(exe), "wintun.dll")
				st, statErr := os.Stat(dll)
				ev := Evidence{Label: "wintun.dll beside the executable", Started: true, Note: dll}
				if statErr != nil {
					res := Result{
						Status:  StatusFail,
						Summary: "wintun.dll is not next to the executable, so system-wide mode cannot start",
						Established: []string{
							"net-merge's TUN driver is missing from " + filepath.Dir(exe),
						},
						NextSteps:  []string{"Run scripts/fetch-wintun.ps1 (or copy wintun.dll from the release archive) next to net-merge.exe."},
						ErrorCodes: []string{"tun_driver_missing"},
						Evidence:   []Evidence{ev},
					}
					return res
				}
				ev.Note = fmt.Sprintf("%s (%d bytes)", dll, st.Size())
				return Result{
					Status:      StatusPass,
					Summary:     "wintun.dll is present next to the executable",
					Established: []string{fmt.Sprintf("the Wintun driver library exists at %s (%d bytes)", dll, st.Size())},
					Inconclusive: []string{
						"whether the driver loads: loading it needs elevation and only happens when system-wide mode starts",
					},
					Evidence: []Evidence{ev},
				}
			case "linux":
				dev := "/dev/net/tun"
				f, err := os.OpenFile(dev, os.O_RDWR, 0)
				if err != nil {
					return Result{
						Status:       StatusFail,
						Summary:      dev + " is not usable: " + err.Error(),
						Established:  []string{"the kernel TUN device is missing or not accessible to this process"},
						Inconclusive: []string{"whether it would work with more privileges"},
						NextSteps:    []string{"Load the tun module (modprobe tun) or run with the privileges the device requires."},
						ErrorCodes:   []string{"tun_driver_missing"},
						Evidence:     []Evidence{{Label: dev, Started: true, Err: err.Error()}},
					}
				}
				_ = f.Close()
				return Result{
					Status:      StatusPass,
					Summary:     dev + " is present and opens for reading and writing",
					Established: []string{"the kernel TUN device exists and this process can open it"},
					Inconclusive: []string{
						"whether a TUN interface can be created: that also needs the NET_ADMIN capability",
					},
					Evidence: []Evidence{{Label: dev, Started: true, Note: "opened and closed for inspection"}},
				}
			default:
				return Result{
					Status:       StatusSkipped,
					Summary:      "this platform has no supported TUN mechanism in this build",
					Established:  []string{},
					Inconclusive: []string{"driver availability, because there is no driver check for " + env.Platform},
				}
			}
		},
	}
}

// ---- adapters ------------------------------------------------------------------------------

func checkAdaptersInventory() Check {
	return funcCheck{
		meta: Meta{
			ID:       "adapters.inventory",
			Title:    "Adapter discovery",
			Category: CatAdapters,
			Purpose:  "Enumerate every interface the OS reports and say which can carry internet traffic, with the reason where they cannot.",
			Establishes: []string{
				"the complete interface list this application can see, dynamically enumerated (nothing is hard-coded)",
				"per adapter: link state, addresses, gateways, DNS, DHCP state, metric and byte counters as far as the platform exposes them",
				"an exclusion reason for every interface that cannot be used",
			},
			DoesNotEstablish: []string{
				"that an addressable adapter can reach the internet: gateway and reachability checks do that separately",
			},
		},
		run: func(ctx context.Context, env *Env) Result {
			snap, err := env.snapshot(ctx)
			if err != nil {
				return Result{
					Status:       StatusError,
					Summary:      "the adapter inventory could not be collected: " + err.Error(),
					Established:  []string{},
					Inconclusive: []string{"every adapter question: the inventory is the source for all of them"},
					ErrorCodes:   []string{"diag_inventory_failed"},
				}
			}
			res := Result{Evidence: []Evidence{{Label: "inventory source", Started: true, Note: snap.Source}}}
			res.Established = append(res.Established, fmt.Sprintf("%d interface(s) are present; %s", len(snap.Adapters), snap.Summary()))
			var unusable []string
			for _, a := range snap.Unusable() {
				unusable = append(unusable, fmt.Sprintf("%s: %s", a.Name, nonEmpty(a.Exclusion, string(a.Status))))
			}
			sort.Strings(unusable)
			for _, u := range unusable {
				res.Established = append(res.Established, "excluded - "+u)
			}
			if len(snap.Gaps) > 0 {
				res.Inconclusive = append(res.Inconclusive, "the platform could not provide: "+strings.Join(snap.Gaps, "; "))
			}
			for _, e := range snap.Errors {
				res.Inconclusive = append(res.Inconclusive, "collection problem: "+e)
			}
			switch {
			case len(snap.Adapters) == 0:
				res.Status = StatusFail
				res.Summary = "no network adapters were found at all"
				res.NextSteps = append(res.NextSteps, "Check that this process can read network configuration (on Windows, run the app as a normal user first; a restricted token can hide adapters).")
			case len(snap.Usable()) == 0:
				res.Status = StatusFail
				res.Summary = "adapters exist but none can carry internet traffic"
				res.NextSteps = append(res.NextSteps, "Connect a link or fix the exclusion reasons listed above, then re-run.")
			default:
				res.Status = StatusPass
				res.Summary = snap.Summary()
			}
			return res
		},
	}
}

func checkAdaptersLink() Check {
	return funcCheck{
		meta: Meta{
			ID:       "adapters.link",
			Title:    "Link state and speed",
			Category: CatAdapters,
			Purpose:  "Report each adapter's link, media and speed as the driver reports them.",
			Establishes: []string{
				"which adapters have a link (cable plugged, radio associated, phone tether established)",
				"the link speed the driver negotiated, when the driver exposes it",
			},
			DoesNotEstablish: []string{
				"throughput: a 1 Gbps link is a link rate, not a measured transfer rate",
			},
		},
		run: func(ctx context.Context, env *Env) Result {
			snap, err := env.snapshot(ctx)
			if err != nil {
				return Result{Status: StatusError, Summary: err.Error(), ErrorCodes: []string{"diag_inventory_failed"}}
			}
			res := Result{}
			var down, unknownSpeed []string
			for _, a := range snap.Adapters {
				if a.Status == inventory.StateDisconnected || a.Link == inventory.LinkDown {
					down = append(down, a.Name)
				}
				if a.Link == inventory.LinkUp && a.Status != inventory.StateExcluded && a.SpeedBps == 0 {
					unknownSpeed = append(unknownSpeed, a.Name)
				}
				if a.SpeedBps > 0 {
					res.Established = append(res.Established, fmt.Sprintf("%s: link %s, %s negotiated", a.Name, a.Link, humanRate(a.SpeedBps)))
				}
			}
			for _, d := range down {
				res.Established = append(res.Established, d+" has no link (disconnected at the OS level)")
			}
			switch {
			case len(unknownSpeed) > 0:
				res.Status = StatusWarn
				res.Summary = "link speed is not reported for " + strings.Join(unknownSpeed, ", ")
				res.Inconclusive = append(res.Inconclusive, "the negotiated speed for those adapters: the driver does not expose it, so no rate claim can be made")
			case len(down) > 0:
				res.Status = StatusInfo
				res.Summary = fmt.Sprintf("%d adapter(s) have no link: %s", len(down), strings.Join(down, ", "))
			default:
				res.Status = StatusPass
				res.Summary = "every adapter reports a link"
			}
			return res
		},
	}
}

func checkAdaptersConfig() Check {
	return funcCheck{
		meta: Meta{
			ID:       "adapters.config",
			Title:    "Adapter IP configuration",
			Category: CatAdapters,
			Purpose:  "Read the OS's own configuration view: addresses, prefixes, gateways, DNS and interface metrics per adapter.",
			Establishes: []string{
				"the addresses, default gateways, DNS servers and interface metric the OS reports for each adapter",
				"whether each family is configured by DHCP or manually (Windows: Get-NetIPConfiguration, Linux: ip -j addr)",
			},
			DoesNotEstablish: []string{
				"that a configured adapter works: a configured gateway can be unreachable and a configured DNS server can be silent",
			},
		},
		run: func(ctx context.Context, env *Env) Result {
			res := Result{}
			snap, err := env.snapshot(ctx)
			if err != nil {
				return Result{Status: StatusError, Summary: err.Error(), ErrorCodes: []string{"diag_inventory_failed"}}
			}
			for _, a := range snap.Usable() {
				parts := []string{}
				for _, addr := range a.IPv4 {
					parts = append(parts, addr.Address+"/"+strconv.Itoa(addr.Prefix))
				}
				for _, addr := range a.IPv6 {
					if addr.LinkLocal {
						continue
					}
					parts = append(parts, addr.Address+"/"+strconv.Itoa(addr.Prefix))
				}
				line := a.Name + ": " + strings.Join(parts, ", ")
				if len(a.Gateways4) > 0 || len(a.Gateways6) > 0 {
					gws := append(append([]string{}, a.Gateways4...), a.Gateways6...)
					line += "; gateway " + strings.Join(gws, ", ")
				}
				res.Established = append(res.Established, line)
			}
			key := "ipconfig"
			if env.Platform == "windows" {
				key = "ipconfig"
			}
			spec, ok := cmds(env.Platform)[key]
			if ok {
				r, e := env.run(ctx, "adapter configuration as reported by the OS", 0, spec.Name, spec.Args...)
				res.Evidence = append(res.Evidence, e)
				if !r.Started {
					res.Inconclusive = append(res.Inconclusive, "the platform configuration command could not be run: "+nonEmpty(r.Err, "unknown reason"))
					res.ErrorCodes = append(res.ErrorCodes, "diag_cmd_unavailable")
				} else if r.Failed() {
					res.Inconclusive = append(res.Inconclusive, "the platform configuration command failed, so only the inventory values above are reported: "+r.FirstLine())
					res.ErrorCodes = append(res.ErrorCodes, "diag_cmd_failed")
				}
			} else {
				res.Inconclusive = append(res.Inconclusive, "no configuration command is defined for "+env.Platform+"; the values above come from the shared inventory")
			}
			res.Status = StatusPass
			if len(snap.Usable()) == 0 {
				res.Status = StatusWarn
				res.Summary = "no usable adapter has a configuration to report"
			} else {
				res.Summary = fmt.Sprintf("configuration read for %d usable adapter(s)", len(snap.Usable()))
			}
			if len(res.Inconclusive) > 0 {
				res.Status = Worse(res.Status, StatusWarn)
			}
			return res
		},
	}
}

func checkAdaptersDriver() Check {
	return funcCheck{
		meta: Meta{
			ID:       "adapters.driver",
			Title:    "Adapter driver identity",
			Category: CatAdapters,
			Purpose:  "Record the vendor driver behind each adapter, which is what a 'known bad driver' hypothesis has to name.",
			Establishes: []string{
				"the driver provider and version the OS reports for each adapter (Windows: Get-NetAdapter)",
			},
			DoesNotEstablish: []string{
				"that a driver is faulty: a version is a fact, not a diagnosis",
			},
			Platforms: []string{"windows"},
		},
		run: func(ctx context.Context, env *Env) Result {
			spec, ok := cmds("windows")["adapters"]
			if !ok {
				return missingCommandResult(env, Meta{}, "Get-NetAdapter")
			}
			r, e := env.run(ctx, "adapter and driver details (Get-NetAdapter)", 0, spec.Name, spec.Args...)
			res := Result{Evidence: []Evidence{e}}
			if !r.Started {
				res.Status = StatusSkipped
				res.Summary = "Get-NetAdapter could not be run: " + nonEmpty(r.Err, "not available")
				res.ErrorCodes = []string{"diag_cmd_unavailable"}
				return res
			}
			objs, err := psJSON(r.Stdout)
			if err != nil {
				res.Status = StatusWarn
				res.Summary = "Get-NetAdapter ran but its output could not be parsed"
				res.Inconclusive = append(res.Inconclusive, err.Error())
				res.ErrorCodes = []string{"diag_parse_failed"}
				return res
			}
			var withDriver int
			for _, o := range objs {
				name := psStr(o, "Name")
				prov, ver := psStr(o, "DriverProvider"), psStr(o, "DriverVersion")
				if name == "" {
					continue
				}
				if prov != "" || ver != "" {
					withDriver++
					res.Established = append(res.Established, fmt.Sprintf("%s: driver %s %s", name, nonEmpty(prov, "unknown provider"), nonEmpty(ver, "unknown version")))
				}
			}
			switch {
			case len(objs) == 0:
				res.Status = StatusWarn
				res.Summary = "Get-NetAdapter returned no adapters"
			case withDriver == 0:
				res.Status = StatusWarn
				res.Summary = "no driver provider or version is reported by any adapter"
			default:
				res.Status = StatusPass
				res.Summary = fmt.Sprintf("driver identity recorded for %d adapter(s)", withDriver)
			}
			return res
		},
	}
}

// humanRate renders bits per second the way a person reads a link speed.
func humanRate(bps uint64) string {
	switch {
	case bps >= 1_000_000_000:
		return fmt.Sprintf("%.1f Gbps", float64(bps)/1e9)
	case bps >= 1_000_000:
		return fmt.Sprintf("%.0f Mbps", float64(bps)/1e6)
	case bps >= 1_000:
		return fmt.Sprintf("%.0f kbps", float64(bps)/1e3)
	default:
		return fmt.Sprintf("%d bps", bps)
	}
}

// ---- routing -------------------------------------------------------------------------------

func checkRoutingTable() Check {
	return funcCheck{
		meta: Meta{
			ID:       "routing.table",
			Title:    "Routing table",
			Category: CatRouting,
			Purpose:  "Read the OS routing table and count the entries that decide where traffic goes.",
			Establishes: []string{
				"how many routes exist, how many are default routes, and which interfaces they name",
				"the exact route command output, kept as evidence (Windows: Get-NetRoute, Linux: ip -j route)",
			},
			DoesNotEstablish: []string{
				"which route a particular connection will use: the OS applies prefix length, metric and policy rules",
			},
		},
		run: func(ctx context.Context, env *Env) Result {
			res := Result{}
			snap, err := env.snapshot(ctx)
			if err != nil {
				return Result{Status: StatusError, Summary: err.Error(), ErrorCodes: []string{"diag_inventory_failed"}}
			}
			def := 0
			for _, r := range snap.Routes {
				if r.Default {
					def++
				}
			}
			res.Established = append(res.Established,
				fmt.Sprintf("%d route(s) in the table, %d of them default routes", len(snap.Routes), def))
			spec, ok := cmds(env.Platform)["routes"]
			if ok {
				r, e := env.run(ctx, "routing table as reported by the OS", 0, spec.Name, spec.Args...)
				res.Evidence = append(res.Evidence, e)
				if r.Failed() {
					res.Inconclusive = append(res.Inconclusive, "the route command did not complete; the counts above come from the shared inventory")
					res.ErrorCodes = append(res.ErrorCodes, "diag_cmd_failed")
				}
			} else {
				res.Inconclusive = append(res.Inconclusive, "no route command is defined for "+env.Platform)
			}
			switch {
			case len(snap.Routes) == 0:
				res.Status = StatusWarn
				res.Summary = "the routing table is empty or could not be read"
			case def == 0:
				res.Status = StatusFail
				res.Summary = "there is no default route, so no traffic can leave this machine for the internet"
				res.NextSteps = append(res.NextSteps, "Connect an adapter or fix its gateway; a default route appears when the OS has one.")
			default:
				res.Status = StatusPass
				res.Summary = fmt.Sprintf("%d routes, %d default", len(snap.Routes), def)
			}
			return res
		},
	}
}

func checkRoutingDefault() Check {
	return funcCheck{
		meta: Meta{
			ID:       "routing.default",
			Title:    "Default route selection",
			Category: CatRouting,
			Purpose:  "Show which default routes exist and flag the ambiguous case of several with equal preference.",
			Establishes: []string{
				"every default route with its interface and metric",
				"whether the OS has one clear best default route or several competing ones",
			},
			DoesNotEstablish: []string{
				"which one the OS will pick for a given destination when metrics tie: that depends on policy rules outside the route table",
			},
		},
		run: func(ctx context.Context, env *Env) Result {
			snap, err := env.snapshot(ctx)
			if err != nil {
				return Result{Status: StatusError, Summary: err.Error(), ErrorCodes: []string{"diag_inventory_failed"}}
			}
			type def struct {
				line   string
				metric int
			}
			var defs []def
			for _, r := range snap.Routes {
				if !r.Default {
					continue
				}
				line := fmt.Sprintf("%s via %s on %s (metric %d)", nonEmpty(r.Destination, "default"), nonEmpty(r.NextHop, "on-link"), nonEmpty(r.Name, fmt.Sprint(r.Index)), r.Metric)
				defs = append(defs, def{line: line, metric: r.Metric})
			}
			res := Result{}
			for _, d := range defs {
				res.Established = append(res.Established, d.line)
			}
			if len(defs) == 0 {
				res.Status = StatusFail
				res.Summary = "no default route exists"
				res.NextSteps = append(res.NextSteps, "Bring up a link and confirm it receives a gateway (DHCP or manual).")
				return res
			}
			// Equal metrics on different interfaces is the ambiguous case.
			byMetric := map[int]int{}
			for _, d := range defs {
				byMetric[d.metric]++
			}
			ambiguous := 0
			for _, n := range byMetric {
				if n > 1 {
					ambiguous++
				}
			}
			switch {
			case ambiguous > 0:
				res.Status = StatusWarn
				res.Summary = fmt.Sprintf("%d default routes with tied metrics: the OS preference is not determined by the table alone", ambiguous)
				res.Inconclusive = append(res.Inconclusive,
					"which of the tied routes wins for a new connection; use the per-adapter connect checks to see which links actually carry traffic")
				res.NextSteps = append(res.NextSteps, "If a link never carries traffic while others do, compare its interface metric (Routing > Interface metrics) before assuming a fault.")
			case len(defs) > 1:
				res.Status = StatusPass
				res.Summary = fmt.Sprintf("%d default routes; the lowest metric wins for ordinary traffic", len(defs))
			default:
				res.Status = StatusPass
				res.Summary = "exactly one default route"
			}
			return res
		},
	}
}

func checkRoutingMetrics() Check {
	return funcCheck{
		meta: Meta{
			ID:       "routing.metrics",
			Title:    "Interface metrics",
			Category: CatRouting,
			Purpose:  "Report the interface metric that orders otherwise equal routes.",
			Establishes: []string{
				"each usable adapter's interface metric as the OS reports it (lower is preferred)",
			},
			DoesNotEstablish: []string{
				"that the metric is what stopped traffic: net-merge's TUN mode overrides the default route by design",
			},
		},
		run: func(ctx context.Context, env *Env) Result {
			snap, err := env.snapshot(ctx)
			if err != nil {
				return Result{Status: StatusError, Summary: err.Error(), ErrorCodes: []string{"diag_inventory_failed"}}
			}
			res := Result{}
			known := 0
			for _, a := range snap.Usable() {
				switch {
				case a.Metric4 != nil && a.Metric6 != nil:
					res.Established = append(res.Established, fmt.Sprintf("%s: IPv4 metric %d, IPv6 metric %d", a.Name, *a.Metric4, *a.Metric6))
					known++
				case a.Metric4 != nil:
					res.Established = append(res.Established, fmt.Sprintf("%s: IPv4 metric %d (no IPv6 metric reported)", a.Name, *a.Metric4))
					known++
				case a.Metric6 != nil:
					res.Established = append(res.Established, fmt.Sprintf("%s: IPv6 metric %d (no IPv4 metric reported)", a.Name, *a.Metric6))
					known++
				}
			}
			spec, ok := cmds(env.Platform)["metrics"]
			if ok {
				r, e := env.run(ctx, "interface metrics as reported by the OS", 0, spec.Name, spec.Args...)
				res.Evidence = append(res.Evidence, e)
				if r.Failed() {
					res.Inconclusive = append(res.Inconclusive, "the metrics command failed; values above come from the inventory")
				}
			}
			switch {
			case known == 0:
				res.Status = StatusWarn
				res.Summary = "no interface metric could be read for any usable adapter"
				res.ErrorCodes = append(res.ErrorCodes, "diag_metric_unavailable")
			default:
				res.Status = StatusPass
				res.Summary = fmt.Sprintf("metrics recorded for %d adapter(s)", known)
			}
			return res
		},
	}
}

func checkRoutingConflicts() Check {
	return funcCheck{
		meta: Meta{
			ID:       "routing.conflicts",
			Title:    "Route conflicts",
			Category: CatRouting,
			Purpose:  "Look for the route-table shapes that make traffic behaviour surprising: duplicate defaults, split families, stale entries.",
			Establishes: []string{
				"cross-adapter warnings computed from the live table (several default routes, DNS that differs between links, IPv4-only or IPv6-only links)",
			},
			DoesNotEstablish: []string{
				"that a conflict is harmful: several default routes are normal when the OS has a metric preference",
			},
		},
		run: func(ctx context.Context, env *Env) Result {
			snap, err := env.snapshot(ctx)
			if err != nil {
				return Result{Status: StatusError, Summary: err.Error(), ErrorCodes: []string{"diag_inventory_failed"}}
			}
			res := Result{}
			seen := map[string]bool{}
			for _, w := range snap.Warnings {
				if seen[w] {
					continue
				}
				seen[w] = true
				res.Established = append(res.Established, w)
			}
			// A route whose interface is no longer present is a stale entry.
			byIndex := map[int]bool{}
			for _, a := range snap.Adapters {
				byIndex[a.Index] = true
			}
			stale := 0
			for _, r := range snap.Routes {
				if r.Index > 0 && !byIndex[r.Index] {
					stale++
				}
			}
			if stale > 0 {
				res.Established = append(res.Established, fmt.Sprintf("%d route(s) name an interface this host no longer reports", stale))
			}
			switch {
			case len(res.Established) == 0:
				res.Status = StatusPass
				res.Summary = "no route conflicts or cross-adapter warnings"
			case stale > 0:
				res.Status = StatusWarn
				res.Summary = fmt.Sprintf("%d route(s) reference an interface that is not present", stale)
				res.NextSteps = append(res.NextSteps, "If a removed phone or adapter left these behind, an engine cleanup removes net-merge's own routes; OS routes clear with a reboot or when the adapter returns.")
			default:
				res.Status = StatusWarn
				res.Summary = fmt.Sprintf("%d cross-adapter observation(s) worth reading", len(res.Established))
			}
			return res
		},
	}
}

// ---- DNS -----------------------------------------------------------------------------------

func checkDNSServers() Check {
	return funcCheck{
		meta: Meta{
			ID:       "dns.servers",
			Title:    "DNS server configuration",
			Category: CatDNS,
			Purpose:  "Show which DNS servers each adapter is configured with, and whether they differ.",
			Establishes: []string{
				"the DNS servers configured per adapter and family",
				"whether the adapters disagree about DNS, which makes resolution depend on which link wins the route",
			},
			DoesNotEstablish: []string{
				"that a configured server answers: the DNS responsiveness check asks it directly",
			},
		},
		run: func(ctx context.Context, env *Env) Result {
			snap, err := env.snapshot(ctx)
			if err != nil {
				return Result{Status: StatusError, Summary: err.Error(), ErrorCodes: []string{"diag_inventory_failed"}}
			}
			res := Result{}
			any := false
			sets := map[string][]string{}
			for _, a := range snap.Adapters {
				if len(a.DNS4) == 0 && len(a.DNS6) == 0 {
					continue
				}
				any = true
				all := append(append([]string{}, a.DNS4...), a.DNS6...)
				res.Established = append(res.Established, fmt.Sprintf("%s: DNS %s", a.Name, strings.Join(all, ", ")))
				sort.Strings(a.DNS4)
				sets[a.Name] = a.DNS4
			}
			if !any {
				res.Status = StatusWarn
				res.Summary = "no adapter reports configured DNS servers"
				res.Inconclusive = append(res.Inconclusive, "whether DNS works: with no configured server, resolution may still use a fallback configured elsewhere")
				res.ErrorCodes = append(res.ErrorCodes, "diag_dns_unconfigured")
			} else if differingDNS(sets) {
				res.Status = StatusWarn
				res.Summary = "adapters use different DNS servers"
				res.Inconclusive = append(res.Inconclusive, "which server answered a given lookup: the OS resolver picks by interface order and caching")
			} else {
				res.Status = StatusPass
				res.Summary = "DNS servers recorded for every configured adapter"
			}
			if spec, ok := cmds(env.Platform)["dns"]; ok {
				r, e := env.run(ctx, "DNS configuration as reported by the OS", 0, spec.Name, spec.Args...)
				res.Evidence = append(res.Evidence, e)
				if r.Failed() {
					res.Inconclusive = append(res.Inconclusive, "the DNS configuration command failed; values above come from the inventory")
				}
			}
			return res
		},
	}
}

// differingDNS reports whether adapters carry different IPv4 DNS sets. An adapter with no DNS
// of its own does not count as a disagreement - it simply has none.
func differingDNS(sets map[string][]string) bool {
	var first []string
	firstSet := false
	for _, v := range sets {
		if len(v) == 0 {
			continue
		}
		if !firstSet {
			first, firstSet = v, true
			continue
		}
		if strings.Join(first, ",") != strings.Join(v, ",") {
			return true
		}
	}
	return false
}

func checkDNSResolve() Check {
	return funcCheck{
		meta: Meta{
			ID:       "dns.resolve",
			Title:    "DNS resolution",
			Category: CatDNS,
			Purpose:  "Resolve a known name using this host's resolver configuration and range-check any answers received, flagging spoofed or sinkholed results.",
			Establishes: []string{
				"whether this host can resolve names right now, and to which addresses",
				"whether a returned address is in a reserved or documentation range, which would indicate interception or a sinkhole",
			},
			DoesNotEstablish: []string{
				"which adapter or DNS server was used: resolution is a host-level operation, and the OS chooses the server",
			},
		},
		run: func(ctx context.Context, env *Env) Result {
			name := env.Config.DNSName
			if name == "" {
				return Result{Status: StatusSkipped, Summary: "no DNS name is configured for this check", Inconclusive: []string{"name resolution"}}
			}
			timeout := time.Duration(env.Config.TimeoutMs) * time.Millisecond
			cctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			start := env.Now()
			ips, err := env.Probes.LookupIP(cctx, name)
			took := env.Now().Sub(start)
			res := Result{Evidence: []Evidence{{Label: "resolve " + name + " with the host resolver", Started: true, Duration: took}}}
			if err != nil {
				res.Status = StatusFail
				res.Summary = "resolving " + name + " failed: " + err.Error()
				res.Established = append(res.Established, "this host could not resolve "+name+" through its configured resolver")
				var dnsErr *net.DNSError
				if asDNS(err, &dnsErr) {
					switch {
					case dnsErr.IsNotFound:
						res.Established = append(res.Established, "the resolver answered that the name does not exist (NXDOMAIN), so the server was reachable and replied")
						res.NextSteps = append(res.NextSteps, "Confirm the configured resolution name in Settings; a typo produces exactly this result.")
					case dnsErr.IsTimeout:
						res.Established = append(res.Established, "the resolver did not answer before the timeout, which points at DNS server reachability rather than the name")
						res.ErrorCodes = append(res.ErrorCodes, "diag_dns_timeout")
						res.NextSteps = append(res.NextSteps, "Run the DNS server responsiveness check to see whether a specific configured server answers.")
					default:
						res.ErrorCodes = append(res.ErrorCodes, "diag_dns_error")
					}
				}
				return res
			}
			var public, reserved []string
			for _, ip := range ips {
				res.Established = append(res.Established, fmt.Sprintf("%s resolved to %s", name, ip))
				if isReservedOrDocumentation(ip) {
					reserved = append(reserved, ip.String())
				} else if isPublic(ip) {
					public = append(public, ip.String())
				}
			}
			switch {
			case len(reserved) > 0:
				res.Status = StatusWarn
				res.Summary = fmt.Sprintf("%s resolved, but to reserved/documentation addresses: %s", name, strings.Join(reserved, ", "))
				res.Inconclusive = append(res.Inconclusive, "whether the answer is genuine: addresses in documentation ranges usually mean a sinkhole, a captive portal or a break-in-testing setup")
				res.ErrorCodes = append(res.ErrorCodes, "diag_dns_reserved_answer")
			case len(public) > 0:
				res.Status = StatusPass
				res.Summary = fmt.Sprintf("%s resolved to %d public address(es)", name, len(public))
			default:
				res.Status = StatusPass
				res.Summary = fmt.Sprintf("%s resolved to %d address(es)", name, len(ips))
			}
			return res
		},
	}
}

func asDNS(err error, target **net.DNSError) bool {
	for err != nil {
		if d, ok := err.(*net.DNSError); ok {
			*target = d
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func checkDNSAtServer() Check {
	return funcCheck{
		meta: Meta{
			ID:       "dns.server",
			Title:    "DNS server responsiveness",
			Category: CatDNS,
			Purpose:  "Ask one specific DNS server — the one configured in Settings, or an adapter's — for a name, rather than the host resolver.",
			Establishes: []string{
				"that a specific DNS server answered a query, and how long it took",
			},
			DoesNotEstablish: []string{
				"that ordinary lookups use that server, or that the adapter that carries it is the one your traffic uses",
			},
			Slow: true,
		},
		run: func(ctx context.Context, env *Env) Result {
			name := env.Config.DNSName
			server := env.Config.DNSServer
			if name == "" {
				return Result{Status: StatusSkipped, Summary: "no DNS name is configured for this check"}
			}
			if server == "" {
				// Fall back to the first adapter's first DNS server, and say so: querying the
				// wrong server and reporting a failure would be misleading.
				snap, err := env.snapshot(ctx)
				if err == nil {
					for _, a := range snap.Adapters {
						if len(a.DNS4) > 0 {
							server = a.DNS4[0]
							break
						}
					}
				}
			}
			if server == "" {
				return Result{
					Status:       StatusWarn,
					Summary:      "no DNS server is configured to query",
					Inconclusive: []string{"DNS server responsiveness: neither Settings nor any adapter names a server"},
					NextSteps:    []string{"Set a DNS server in Settings > Diagnostics if you want this check to run."},
				}
			}
			timeout := time.Duration(env.Config.TimeoutMs) * time.Millisecond
			cctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			start := env.Now()
			ips, err := env.Probes.LookupAtServer(cctx, name, server)
			took := env.Now().Sub(start)
			ev := Evidence{Label: fmt.Sprintf("query %s at %s", name, server), Started: true, Duration: took}
			if err != nil {
				return Result{
					Status:  StatusFail,
					Summary: fmt.Sprintf("%s did not answer within %s: %v", server, timeout, err),
					Established: []string{
						fmt.Sprintf("the DNS server %s did not produce an answer for %s within %s", server, name, timeout),
					},
					Inconclusive: []string{
						"whether the server is unreachable or simply does not answer this query type",
					},
					NextSteps:  []string{"Compare with the DNS resolution check; if that succeeds, the host is using a different server than this one."},
					ErrorCodes: []string{"diag_dns_server_unresponsive"},
					Evidence:   []Evidence{ev},
				}
			}
			ipsStr := make([]string, 0, len(ips))
			for _, ip := range ips {
				ipsStr = append(ipsStr, ip.String())
			}
			res := Result{
				Status:      StatusPass,
				Summary:     fmt.Sprintf("%s answered in %s", server, took.Truncate(time.Millisecond)),
				Established: []string{fmt.Sprintf("the DNS server %s answered for %s with %s", server, name, strings.Join(ipsStr, ", "))},
				Inconclusive: []string{
					"that the adapter whose DNS list contains this server carried the query",
				},
				Evidence: []Evidence{ev},
			}
			return res
		},
	}
}

func checkDNSCache() Check {
	return funcCheck{
		meta: Meta{
			ID:       "dns.cache",
			Title:    "DNS record cache",
			Category: CatDNS,
			Purpose:  "Show a few cached DNS records with their record TTLs, which is the 'other TTL' that has nothing to do with packet TTL.",
			Establishes: []string{
				"that the resolver cache holds records, each with the record TTL the zone published",
			},
			DoesNotEstablish: []string{
				"anything about the IPv4 TTL or IPv6 hop limit of outbound packets: a DNS record TTL is a caching duration published by the zone",
			},
			Platforms: []string{"windows"},
		},
		run: func(ctx context.Context, env *Env) Result {
			spec, ok := cmds("windows")["dnscache"]
			if !ok {
				return missingCommandResult(env, Meta{}, "Get-DnsClientCache")
			}
			r, e := env.run(ctx, "resolver cache (Get-DnsClientCache)", 0, spec.Name, spec.Args...)
			res := Result{Evidence: []Evidence{e}}
			if !r.Started {
				res.Status = StatusSkipped
				res.Summary = "Get-DnsClientCache could not be run: " + nonEmpty(r.Err, "not available")
				return res
			}
			objs, err := psJSON(r.Stdout)
			if err != nil {
				res.Status = StatusWarn
				res.Summary = "the cache command ran but its output could not be parsed"
				res.Inconclusive = append(res.Inconclusive, err.Error())
				res.ErrorCodes = []string{"diag_parse_failed"}
				return res
			}
			if len(objs) == 0 {
				res.Status = StatusInfo
				res.Summary = "the resolver cache is empty"
				return res
			}
			shown := 0
			for _, o := range objs {
				if shown >= 8 {
					break
				}
				name, ttl := psStr(o, "Name", "Entry"), psStr(o, "TimeToLive")
				if name == "" {
					continue
				}
				res.Established = append(res.Established, fmt.Sprintf("cached %s with a record TTL of %s seconds", name, nonEmpty(ttl, "unknown")))
				shown++
			}
			res.Status = StatusInfo
			res.Summary = fmt.Sprintf("%d cached record(s); these TTLs are DNS caching times, not packet TTLs", len(objs))
			return res
		},
	}
}

// isPublic reports whether an address is a globally routable unicast address.
func isPublic(ip net.IP) bool {
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !isCGNAT(ip) && !isDocumentation(ip)
}

// isCGNAT covers 100.64.0.0/10, which is neither private nor public and appears in tethering.
func isCGNAT(ip net.IP) bool {
	v4 := ip.To4()
	return v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127
}

// isDocumentation covers the RFC 5737/3849 ranges used in examples, plus 0.0.0.0/8.
func isDocumentation(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 192 && v4[1] == 0 && v4[2] == 2:
			return true
		case v4[0] == 198 && v4[1] == 51 && v4[2] == 100:
			return true
		case v4[0] == 203 && v4[1] == 0 && v4[2] == 113:
			return true
		case v4[0] == 0:
			return true
		}
		return false
	}
	return ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x0d && ip[3] == 0xb8
}

func isReservedOrDocumentation(ip net.IP) bool {
	return isDocumentation(ip) || isCGNAT(ip)
}
