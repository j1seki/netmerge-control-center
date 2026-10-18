package diag

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"net-merge/internal/inventory"
)

// ---- gateway -------------------------------------------------------------------------------

func checkGatewayReach() Check {
	return funcCheck{
		meta: Meta{
			ID:       "gateway.reach",
			Title:    "Gateway reachability",
			Category: CatGateway,
			Purpose:  "Ping each default gateway. This is the first hop, and it is where 'connected but nothing works' usually starts.",
			Establishes: []string{
				"whether each default gateway answers ICMP echo on this host",
			},
			DoesNotEstablish: []string{
				"that the gateway is broken when it does not answer: many gateways and all Windows machines by default drop ICMP, so silence is not proof",
			},
			Slow: true,
		},
		run: func(ctx context.Context, env *Env) Result {
			snap, err := env.snapshot(ctx)
			if err != nil {
				return Result{Status: StatusError, Summary: err.Error(), ErrorCodes: []string{"diag_inventory_failed"}}
			}
			c := cmds(env.Platform)["ping"]
			if c.Name == "" {
				return missingCommandResult(env, Meta{}, "ping")
			}
			res := Result{}
			ok, bad, indeterminate := 0, 0, 0
			for _, a := range snap.Adapters {
				if a.Status == inventory.StateDisconnected {
					continue
				}
				gws := append(append([]string{}, a.Gateways4...), a.Gateways6...)
				for _, gw := range gws {
					args := append(append([]string{}, c.Args...), gw)
					r, e := env.run(ctx, "ping gateway "+gw+" ("+a.Name+")", 0, c.Name, args...)
					res.Evidence = append(res.Evidence, e)
					if !r.Started {
						indeterminate++
						res.Inconclusive = append(res.Inconclusive, "ping could not run for "+gw+": "+nonEmpty(r.Err, "unknown reason"))
						continue
					}
					loss, _, parsed := parsePingLoss(r.Output())
					switch {
					case !parsed:
						indeterminate++
						res.Inconclusive = append(res.Inconclusive, fmt.Sprintf("could not read a loss figure for %s from ping output (exit %d)", gw, r.ExitCode))
					case loss >= 100:
						bad++
						res.Established = append(res.Established, fmt.Sprintf("gateway %s on %s did not answer ICMP", gw, a.Name))
						res.Items = append(res.Items, Item{Scope: a.Name, Code: "gateway_silent", Detail: gw})
					default:
						ok++
						res.Established = append(res.Established, fmt.Sprintf("gateway %s on %s answered (%.0f%% loss)", gw, a.Name, loss))
						res.Items = append(res.Items, Item{Scope: a.Name, Code: "gateway_answered", Detail: gw})
					}
				}
			}
			switch {
			case ok == 0 && bad == 0:
				res.Status = StatusWarn
				res.Summary = "no gateway could be tested (no gateways configured, or ping produced nothing readable)"
				for _, gw := range snap.Adapters {
					_ = gw
				}
			case bad > 0:
				res.Status = StatusWarn
				res.Summary = fmt.Sprintf("%d of %d gateway(s) did not answer ICMP", bad, ok+bad)
				res.Inconclusive = append(res.Inconclusive, "whether those gateways are down or simply block ICMP: the per-adapter TCP checks settle that")
			default:
				res.Status = StatusPass
				res.Summary = fmt.Sprintf("every tested gateway answered (%d)", ok)
			}
			if indeterminate > 0 {
				res.Status = Worse(res.Status, StatusWarn)
			}
			return res
		},
	}
}

// ---- connectivity --------------------------------------------------------------------------

func checkIPv4Connect() Check {
	return funcCheck{
		meta: Meta{
			ID:       "ipv4.connect",
			Title:    "IPv4 TCP connectivity",
			Category: CatPath,
			Purpose:  "Open a TCP connection to the configured endpoint over IPv4 and time the handshake.",
			Establishes: []string{
				"that this host completed a TCP handshake to the endpoint's IPv4 address, and how long it took",
				"the difference between 'refused' (the path works, the port is closed) and 'timed out' (no answer at all), which point at different faults",
			},
			DoesNotEstablish: []string{
				"that every adapter works: the OS picks the egress link, and the per-adapter checks test each one",
			},
		},
		run: func(ctx context.Context, env *Env) Result {
			return tcpConnectCheck(ctx, env, "ipv4", nil, 0)
		},
	}
}

func checkIPv6Connect() Check {
	return funcCheck{
		meta: Meta{
			ID:       "ipv6.connect",
			Title:    "IPv6 TCP connectivity",
			Category: CatPath,
			Purpose:  "Test IPv6 the same way, so a split IPv4/IPv6 condition is visible instead of hidden.",
			Establishes: []string{
				"whether this host has a usable IPv6 path to a public destination, when one is configured",
			},
			DoesNotEstablish: []string{
				"that IPv4 is fine because IPv6 is: the two are independent and this application configures them separately",
			},
			Slow: true,
		},
		run: func(ctx context.Context, env *Env) Result {
			return tcpConnectCheck(ctx, env, "ipv6", nil, 0)
		},
	}
}

// tcpConnectCheck runs the family-specific connectivity check. localIP, when set, prefers one
// adapter's source address; ifIndex, when set, pins egress to that adapter. The per-adapter
// case passes both, because source binding alone does not decide the route.
func tcpConnectCheck(ctx context.Context, env *Env, mode string, localIP net.IP, ifIndex int) Result {
	endpoint := env.Config.Endpoint
	if endpoint == "" {
		return Result{Status: StatusSkipped, Summary: "no endpoint is configured for this check"}
	}
	host, port, err := splitEndpoint(endpoint)
	if err != nil {
		return Result{
			Status:     StatusSkipped,
			Summary:    "the configured endpoint is not usable: " + err.Error(),
			ErrorCodes: []string{"diag_endpoint_invalid"},
		}
	}

	// Resolve the endpoint for the family under test. For IPv6 we ask explicitly for AAAA, so
	// "no IPv6 address" is reported as such rather than as a connection failure.
	target := net.JoinHostPort(host, port)
	resolved := ""
	if ip := net.ParseIP(host); ip == nil {
		timeout := time.Duration(env.Config.TimeoutMs) * time.Millisecond
		rctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		ips, err := env.Probes.LookupIP(rctx, host)
		if err != nil {
			return Result{
				Status:       StatusFail,
				Summary:      "the endpoint " + host + " could not be resolved: " + err.Error(),
				Established:  []string{},
				Inconclusive: []string{"connectivity: the endpoint name does not resolve on this host"},
				ErrorCodes:   []string{"diag_endpoint_unresolved"},
				Items:        []Item{{Code: "endpoint_unresolved", Detail: host}},
				Evidence:     []Evidence{{Label: "resolve " + host, Started: true, Err: err.Error()}},
			}
		}
		var pick net.IP
		for _, ip := range ips {
			is4 := ip.To4() != nil
			if mode == "ipv4" && is4 || mode == "ipv6" && !is4 {
				pick = ip
				break
			}
		}
		if pick == nil {
			res := Result{
				Status:  StatusSkipped,
				Summary: fmt.Sprintf("%s has no %s address, so this check does not apply", host, mode),
				Established: []string{
					fmt.Sprintf("%s resolved to addresses without a %s family member", host, mode),
				},
				Inconclusive: []string{"whether " + mode + " works at all: this endpoint does not offer it"},
				Items:        []Item{{Code: "family_absent", Detail: mode}},
				Evidence:     []Evidence{{Label: "resolve " + host, Started: true, Note: fmt.Sprintf("%d address(es), none of family %s", len(ips), mode)}},
			}
			return res
		}
		target = net.JoinHostPort(pick.String(), port)
		resolved = pick.String()
	} else {
		is4 := ip.To4() != nil
		if mode == "ipv4" && !is4 || mode == "ipv6" && is4 {
			return Result{
				Status:       StatusSkipped,
				Summary:      fmt.Sprintf("the configured endpoint %s is not an %s address", endpoint, mode),
				Inconclusive: []string{"connectivity: the endpoint does not match this check's family"},
			}
		}
	}

	timeout := time.Duration(env.Config.TimeoutMs) * time.Millisecond
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := env.Now()
	took, err := env.Probes.TCPConnect(cctx, target, localIP, ifIndex)
	if took == 0 {
		took = env.Now().Sub(start)
	}
	label := fmt.Sprintf("TCP connect to %s", target)
	if localIP != nil {
		label += " from " + localIP.String()
	}
	if ifIndex > 0 {
		label += fmt.Sprintf(" pinned to interface %d", ifIndex)
	}
	ev := Evidence{Label: label, Started: true, Duration: took}
	if resolved != "" {
		ev.Note = "endpoint resolved to " + resolved
	}
	res := Result{Evidence: []Evidence{ev}}
	if err == nil {
		res.Status = StatusPass
		res.Summary = fmt.Sprintf("connected to %s in %s", target, took.Truncate(time.Millisecond))
		res.Established = append(res.Established, fmt.Sprintf("a TCP handshake to %s %s completed in %s",
			target, viaLocal(localIP, ifIndex), took.Truncate(time.Millisecond)))
		res.Items = append(res.Items, Item{Code: "connected", Detail: target})
		res.Measure = &Measurement{Kind: "latency", Ms: float64(took.Microseconds()) / 1000, Target: target, At: env.Now()}
		return res
	}
	lower := strings.ToLower(err.Error())
	switch {
	case isTimeout(err, lower):
		res.Status = StatusFail
		res.Summary = fmt.Sprintf("%s did not answer within %s", target, timeout)
		res.Established = append(res.Established, fmt.Sprintf("no TCP response from %s %s within %s", target, viaLocal(localIP, ifIndex), timeout))
		res.Inconclusive = append(res.Inconclusive, "whether the far side is down, the path is filtered, or a security product is dropping it")
		res.ErrorCodes = append(res.ErrorCodes, "diag_tcp_timeout")
		res.Items = append(res.Items, Item{Code: "timeout", Detail: target})
		res.NextSteps = append(res.NextSteps,
			"Compare with the gateway and DNS checks: a reachable gateway with a dead TCP path points at filtering rather than a missing route.",
			"If a third-party security product is installed, check its network filter (the security check lists what is installed).")
	case strings.Contains(lower, "refused"):
		res.Status = StatusWarn
		res.Summary = fmt.Sprintf("%s actively refused the connection", target)
		res.Established = append(res.Established,
			"the packet reached the destination and it answered with a TCP reset, so the path works and the port is closed")
		res.Inconclusive = append(res.Inconclusive, "whether a different port would answer: this probe tests the configured one")
		res.ErrorCodes = append(res.ErrorCodes, "diag_tcp_refused")
		res.Items = append(res.Items, Item{Code: "refused", Detail: target})
	case strings.Contains(lower, "unreachable"), strings.Contains(lower, "no route"),
		strings.Contains(lower, "network is down"), strings.Contains(lower, "host is down"):
		res.Status = StatusFail
		res.Summary = fmt.Sprintf("the local stack has no route to %s: %v", target, err)
		res.Established = append(res.Established, "the OS reported the destination as unreachable, before any packet left this machine")
		res.Inconclusive = append(res.Inconclusive, "whether that is true after the routes settle: re-run if an adapter just changed state")
		res.ErrorCodes = append(res.ErrorCodes, "diag_no_route")
		res.Items = append(res.Items, Item{Code: "no_route", Detail: target})
	default:
		res.Status = StatusFail
		res.Summary = fmt.Sprintf("%s: %v", target, err)
		res.ErrorCodes = append(res.ErrorCodes, "diag_tcp_error")
		res.Items = append(res.Items, Item{Code: "error", Detail: err.Error()})
	}
	return res
}

func viaLocal(ip net.IP, ifIndex int) string {
	switch {
	case ip != nil && ifIndex > 0:
		return fmt.Sprintf("from %s on interface %d", ip, ifIndex)
	case ip != nil:
		return "from " + ip.String()
	case ifIndex > 0:
		return fmt.Sprintf("on interface %d", ifIndex)
	}
	return "(OS-selected link)"
}

func isTimeout(err error, lower string) bool {
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	return strings.Contains(lower, "timeout") || strings.Contains(lower, "timed out") || strings.Contains(lower, "deadline exceeded")
}

func splitEndpoint(ep string) (host, port string, err error) {
	// Accept both host:port and [v6]:port, and reject anything without a port rather than
	// guessing one.
	if strings.HasPrefix(ep, "[") {
		i := strings.LastIndex(ep, "]")
		if i < 0 {
			return "", "", fmt.Errorf("unbalanced brackets in %q", ep)
		}
		h := ep[1:i]
		rest := ep[i+1:]
		if !strings.HasPrefix(rest, ":") || len(rest) < 2 {
			return "", "", fmt.Errorf("no port in %q", ep)
		}
		return h, rest[1:], nil
	}
	i := strings.LastIndex(ep, ":")
	if i <= 0 || i == len(ep)-1 {
		return "", "", fmt.Errorf("want host:port, got %q", ep)
	}
	if strings.Contains(ep[:i], ":") {
		return "", "", fmt.Errorf("%q looks like IPv6 without brackets; use [address]:port", ep)
	}
	if _, err := strconv.Atoi(ep[i+1:]); err != nil {
		return "", "", fmt.Errorf("port %q is not a number", ep[i+1:])
	}
	return ep[:i], ep[i+1:], nil
}

// ---- per-adapter ---------------------------------------------------------------------------

func checkAdapterConnect() Check {
	return funcCheck{
		meta: Meta{
			ID:       "adapters.connect",
			Title:    "Per-adapter connectivity",
			Category: CatAdapters,
			Purpose:  "Prove each eligible adapter can reach the endpoint, by pinning the probe to that adapter's egress interface and source address.",
			Establishes: []string{
				"for every adapter that reports an address: whether a TCP connection to the configured endpoint succeeds when the probe is pinned to that adapter (egress interface and source address)",
				"which adapter each result belongs to: the evidence names the interface the probe was pinned to",
			},
			DoesNotEstablish: []string{
				"that other applications' traffic uses the same adapter: this probe is pinned, while ordinary traffic is routed by the operating system",
				"throughput or stability: one handshake is a reachability fact, not a speed test",
			},
			Slow: true,
		},
		run: func(ctx context.Context, env *Env) Result {
			snap, err := env.snapshot(ctx)
			if err != nil {
				return Result{Status: StatusError, Summary: err.Error(), ErrorCodes: []string{"diag_inventory_failed"}}
			}
			adapters := eligibleAdapters(snap)
			if len(adapters) == 0 {
				return Result{
					Status:       StatusWarn,
					Summary:      "no eligible adapter has an address to bind a probe to",
					Inconclusive: []string{"whether the registered links can reach the internet"},
				}
			}
			res := Result{}
			okN, failN := 0, 0
			for _, a := range adapters {
				ip := localIPFor(a)
				idx := a.Index
				if ip != nil && ip.To4() == nil && a.IndexV6 != 0 {
					// Pin the v6 probe by its IPv6 interface index; the two can differ on Windows.
					idx = a.IndexV6
				}
				r := tcpConnectCheck(ctx, env, familyOf(ip), ip, idx)
				res.Evidence = append(res.Evidence, r.Evidence...)
				// Re-scope the probe's machine-readable items to the adapter under test, so
				// the report's analysis can attribute an outcome to one link.
				for _, it := range r.Items {
					it.Scope = a.Name
					res.Items = append(res.Items, it)
				}
				switch r.Status {
				case StatusPass:
					okN++
					res.Established = append(res.Established, fmt.Sprintf("%s: reachable (%s)", a.Name, r.Summary))
				case StatusWarn:
					res.Established = append(res.Established, fmt.Sprintf("%s: path works but the port answered with a refusal", a.Name))
				default:
					failN++
					res.Established = append(res.Established, fmt.Sprintf("%s: %s", a.Name, r.Summary))
					for _, s := range r.NextSteps {
						res.NextSteps = append(res.NextSteps, a.Name+": "+s)
					}
				}
			}
			switch {
			case failN == 0:
				res.Status = StatusPass
				res.Summary = fmt.Sprintf("all %d eligible adapter(s) reached the endpoint", okN)
			case okN == 0:
				res.Status = StatusFail
				res.Summary = "no eligible adapter could reach the endpoint with the probe pinned to it"
				res.Inconclusive = append(res.Inconclusive, "whether the interface pinning itself failed: the evidence shows each probe's error, and a pinning failure appears there as a socket-option error, not as a silent timeout")
			default:
				res.Status = StatusWarn
				res.Summary = fmt.Sprintf("%d of %d adapter(s) reached the endpoint", okN, okN+failN)
			}
			res.Measure = nil
			return res
		},
	}
}

func familyOf(ip net.IP) string {
	if ip.To4() != nil {
		return "ipv4"
	}
	return "ipv6"
}

// ---- MTU -----------------------------------------------------------------------------------

// mtuLadder are the payload sizes tried, largest first. 1472 payload + 28 bytes of IPv4 and
// ICMP header = the classic 1500 mark; 1452 covers a 1480 PPPoE path; 1400 and 1280 are the
// usual tunnel and IPv6 minimum figures.
var mtuLadder = []int{1472, 1452, 1400, 1280, 1172, 552}

func checkMTUPath() Check {
	return funcCheck{
		meta: Meta{
			ID:       "mtu.path",
			Title:    "Path MTU",
			Category: CatPath,
			Purpose:  "Find the largest packet that reaches the target without fragmentation. Large packets that vanish are a classic cause of 'small sites load, big ones hang'.",
			Establishes: []string{
				"the largest probe size that was carried to the target unfragmented",
			},
			DoesNotEstablish: []string{
				"that this is the path's exact MTU: it is the largest size that worked from the ladder above, so the true value lies between it and the next size up",
			},
			Slow: true,
		},
		run: func(ctx context.Context, env *Env) Result {
			host := env.Config.MTUHost
			if host == "" {
				host = strings.Split(env.Config.Endpoint, ":")[0]
			}
			if host == "" {
				return Result{Status: StatusSkipped, Summary: "no host is configured for the path-MTU check"}
			}
			c := cmds(env.Platform)["pingPath"]
			if c.Name == "" {
				return missingCommandResult(env, Meta{}, "a ping with a do-not-fragment option")
			}
			res := Result{}
			best := -1
			for _, size := range mtuLadder {
				args := append(append([]string{}, c.Args...), strconv.Itoa(size), host)
				r, e := env.run(ctx, fmt.Sprintf("do-not-fragment ping of %d bytes to %s", size, host), 0, c.Name, args...)
				res.Evidence = append(res.Evidence, e)
				if !r.Started {
					res.Inconclusive = append(res.Inconclusive, "the ping tool could not be run: "+nonEmpty(r.Err, "unknown reason"))
					break
				}
				loss, _, parsed := parsePingLoss(r.Output())
				mustFragment := strings.Contains(strings.ToLower(r.Output()), "fragmented") || strings.Contains(strings.ToLower(r.Output()), "message too long")
				switch {
				case mustFragment:
					continue // expected on the way down the ladder
				case !parsed:
					res.Inconclusive = append(res.Inconclusive, fmt.Sprintf("could not interpret the ping output for a %d-byte payload", size))
					continue
				case loss >= 100:
					continue
				default:
					best = size + 28
					break
				}
				if best > 0 {
					break
				}
			}
			switch {
			case best > 0 && best >= 1472+28-4:
				res.Status = StatusPass
				res.Summary = fmt.Sprintf("a %d-byte payload (%d-byte IPv4 packet) reached %s unfragmented: the standard 1500 path", best-28, best, host)
				res.Established = append(res.Established, fmt.Sprintf("the path to %s carries %d-byte IPv4 packets without fragmentation", host, best))
				res.Items = append(res.Items, Item{Code: "mtu_standard", Detail: strconv.Itoa(best)})
			case best > 0:
				res.Status = StatusWarn
				res.Summary = fmt.Sprintf("packets above about %d bytes did not reach %s unfragmented", best, host)
				res.Established = append(res.Established, fmt.Sprintf("the largest unfragmented IPv4 packet observed toward %s was %d bytes", host, best))
				res.Items = append(res.Items, Item{Code: "mtu_below_standard", Detail: strconv.Itoa(best)})
				res.NextSteps = append(res.NextSteps,
					"Compare the adapter MTU with this figure; when the path is smaller, a lower TUN MTU keeps large transfers from stalling.")
			default:
				res.Status = StatusWarn
				res.Summary = "no probe size worked, or the results could not be interpreted"
				res.Inconclusive = append(res.Inconclusive, "the path MTU: a target that blocks ICMP cannot be measured this way")
				res.Items = append(res.Items, Item{Code: "mtu_unknown"})
			}
			res.Measure = nil
			return res
		},
	}
}

// ---- traceroute ----------------------------------------------------------------------------

func checkTraceroute() Check {
	return funcCheck{
		meta: Meta{
			ID:       "routing.trace",
			Title:    "Hop-by-hop path",
			Category: CatPath,
			Purpose:  "Trace the route to the configured target and report how far the probes consistently get.",
			Establishes: []string{
				"how many hops answered within the probe budget, and whether the target itself was reached",
			},
			DoesNotEstablish: []string{
				"that a silent hop is broken: intermediate routers commonly do not answer ICMP, and a trace that stops early is not proof of a fault",
			},
			Slow: true,
		},
		run: func(ctx context.Context, env *Env) Result {
			host := env.Config.TracerouteTarget
			if host == "" {
				return Result{Status: StatusSkipped, Summary: "no traceroute target is configured for this check"}
			}
			c := cmds(env.Platform)["tracert"]
			if c.Name == "" {
				return missingCommandResult(env, Meta{}, "traceroute")
			}
			if _, ok := env.hasCommand(c.Name); !ok {
				return missingCommandResult(env, Meta{}, c.Name)
			}
			timeout := time.Duration(env.Config.TracerouteTimeoutMs) * time.Millisecond
			args := append(append([]string{}, c.Args...), host)
			r, e := env.run(ctx, "traceroute to "+host, timeout, c.Name, args...)
			res := Result{Evidence: []Evidence{e}}
			if !r.Started {
				res.Status = StatusSkipped
				res.Summary = c.Name + " could not be run: " + nonEmpty(r.Err, "not available")
				res.ErrorCodes = append(res.ErrorCodes, "diag_tool_missing")
				return res
			}
			hops, reached := parseTracerouteHops(r.Output())
			res.Established = append(res.Established, fmt.Sprintf("%d hop(s) produced a line within %s", hops, timeout))
			switch {
			case r.TimedOut:
				res.Status = StatusWarn
				res.Summary = fmt.Sprintf("the trace was cut short after %s with %d hop(s) reported", timeout, hops)
				res.Inconclusive = append(res.Inconclusive, "the rest of the path: the tool was still running when the budget expired")
			case reached && hops > 0:
				res.Status = StatusPass
				res.Summary = fmt.Sprintf("last hop with an address is within %d hop(s)", hops)
				res.Established = append(res.Established, "at least one hop answered with an address, so the trace is progressing")
			case hops > 0:
				res.Status = StatusWarn
				res.Summary = fmt.Sprintf("%d hop(s) were reported but none showed an address", hops)
				res.Inconclusive = append(res.Inconclusive, "whether the path is filtered or the probes simply go unanswered")
			default:
				res.Status = StatusFail
				res.Summary = "no hop answered at all"
				res.Inconclusive = append(res.Inconclusive, "whether outbound ICMP is blocked locally rather than the path failing")
			}
			res.Measure = nil
			return res
		},
	}
}

// ---- UDP -----------------------------------------------------------------------------------

// ntpRequest is a minimal NTPv4 client packet: mode 3 (client), version 4, transmit timestamp
// set to a fixed non-zero value. A conforming server answers with mode 4/5 in 48 bytes.
func ntpRequest() []byte {
	b := make([]byte, 48)
	b[0] = 0x23 // LI 0, VN 4, mode 3 (client)
	binary.BigEndian.PutUint64(b[40:], 0xE000000000000000)
	return b
}

// parseNTP validates an NTP reply: at least 48 bytes, mode 4 (server) or 5 (broadcast), LI not
// 3 (unsynchronised), and a non-zero transmit timestamp. This is meaningful verification: a
// stray UDP packet cannot pass it.
func parseNTP(b []byte) (stratum int, ok bool) {
	if len(b) < 48 {
		return 0, false
	}
	mode := b[0] & 0x07
	li := b[0] >> 6
	if mode != 4 && mode != 5 {
		return 0, false
	}
	if li == 3 {
		return 0, false
	}
	if binary.BigEndian.Uint64(b[40:]) == 0 {
		return 0, false
	}
	return int(b[1]), true
}

func checkUDPProbe() Check {
	return funcCheck{
		meta: Meta{
			ID:       "udp.probe",
			Title:    "UDP round trip",
			Category: CatPath,
			Purpose:  "Send an NTP client request over UDP and validate the reply, so UDP is tested with something that can prove it worked.",
			Establishes: []string{
				"that a UDP request to the configured NTP server returned a well-formed NTP reply with a real stratum",
			},
			DoesNotEstablish: []string{
				"that all UDP works: a filtered port, a blocked server or a rate-limited service fails this probe alone",
			},
			Slow: true,
		},
		run: func(ctx context.Context, env *Env) Result {
			target := env.Config.UDPTarget
			if target == "" {
				return Result{Status: StatusSkipped, Summary: "no UDP target is configured for this check"}
			}
			if _, _, err := net.SplitHostPort(target); err != nil {
				return Result{Status: StatusSkipped, Summary: "the configured UDP target is not host:port: " + err.Error(), ErrorCodes: []string{"diag_endpoint_invalid"}}
			}
			timeout := time.Duration(env.Config.TimeoutMs) * time.Millisecond
			cctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			start := env.Now()
			reply, took, err := env.Probes.UDPExchange(cctx, target, ntpRequest(), 64)
			if took == 0 {
				took = env.Now().Sub(start)
			}
			ev := Evidence{Label: "NTP request to " + target, Started: true, Duration: took}
			if err != nil {
				return Result{
					Status:  StatusWarn,
					Summary: fmt.Sprintf("no UDP reply from %s within %s: %v", target, timeout, err),
					Established: []string{
						fmt.Sprintf("the UDP request to %s produced no reply in %s", target, timeout),
					},
					Inconclusive: []string{
						"whether UDP is blocked entirely or only this server/port is filtered; many networks rate-limit NTP",
					},
					ErrorCodes: []string{"diag_udp_no_reply"},
					Items:      []Item{{Code: "udp_no_reply", Detail: target}},
					Evidence:   []Evidence{ev},
				}
			}
			stratum, ok := parseNTP(reply)
			if !ok {
				return Result{
					Status:       StatusWarn,
					Summary:      fmt.Sprintf("%s replied with %d bytes that are not a valid NTP response", target, len(reply)),
					Established:  []string{"a UDP datagram came back, but its contents do not validate as NTP"},
					Inconclusive: []string{"whether that is a non-NTP service on the port or an interception by a middlebox"},
					ErrorCodes:   []string{"diag_udp_unexpected_reply"},
					Items:        []Item{{Code: "udp_reply_invalid", Detail: target}},
					Evidence:     []Evidence{ev},
				}
			}
			return Result{
				Status:  StatusPass,
				Summary: fmt.Sprintf("UDP round trip to %s validated (NTP stratum %d, %s)", target, stratum, took.Truncate(time.Millisecond)),
				Established: []string{
					fmt.Sprintf("a UDP request to %s returned a valid NTP reply (stratum %d) in %s", target, stratum, took.Truncate(time.Millisecond)),
				},
				Inconclusive: []string{"whether other UDP services work: this proves one destination, not the protocol"},
				Items:        []Item{{Code: "udp_reply_valid", Detail: target}},
				Measure:      &Measurement{Kind: "latency", Ms: float64(took.Microseconds()) / 1000, Target: target, At: env.Now()},
				Evidence:     []Evidence{ev},
			}
		},
	}
}
