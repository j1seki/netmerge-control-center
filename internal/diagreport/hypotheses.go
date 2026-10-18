package diagreport

// The analysis layer: turning what the checks observed into candidate explanations, without ever
// dressing a guess up as a measurement.
//
// The distinction the report is built on is:
//
//   - a Fact is something a check established by running (see report.go's factsFrom);
//   - a Hypothesis is an explanation that fits those facts but has not been proven.
//
// A hypothesis is emitted with the checks that support it, so a reader can go and read them,
// and with the next step that would settle it. Nothing here claims a cause from correlation
// alone: "the firewall is enabled and TCP timed out" produces a candidate to test, not "the
// firewall blocked it".

import (
	"fmt"
	"sort"
	"strings"
)

// Hypothesis kinds.
const (
	// KindVerified marks a conclusion drawn from two or more observations that the checks
	// themselves established, e.g. "the failure is specific to one link" when another link
	// passed the same probe.
	KindVerified = "verified"
	// KindHypothesis marks an explanation that fits the observations but is not proven.
	KindHypothesis = "hypothesis"
)

type rule struct {
	id string
	// match returns the hypotheses this rule contributes for the document under analysis.
	match func(*Document) []Hypothesis
}

// Analyze runs every rule over the document, ranks what it finds and returns it.
//
// Ordering: verified conclusions first, then hypotheses by confidence (high, medium, low), then
// by the rule's own order. Ranks are 1-based and stable, so two runs over the same document
// produce the same numbering.
func Analyze(d *Document) []Hypothesis {
	if d == nil {
		return nil
	}
	var found []Hypothesis
	for _, r := range rules() {
		hs := r.match(d)
		for i := range hs {
			if hs[i].Statement == "" {
				continue
			}
			found = append(found, hs[i])
		}
	}
	sort.SliceStable(found, func(i, j int) bool {
		return kindRank(found[i]) < kindRank(found[j])
	})
	for i := range found {
		found[i].Rank = i + 1
	}
	return found
}

func kindRank(h Hypothesis) int {
	if h.Kind == KindVerified {
		return 0
	}
	switch h.Confidence {
	case "high":
		return 1
	case "medium":
		return 2
	default:
		return 3
	}
}

// ---- understanding the run --------------------------------------------------------------------

// checkResults indexes the run by check id, projecting each result into the small view the rules
// reason over.
func checkResults(d *Document) map[string]ResultView {
	out := map[string]ResultView{}
	for _, r := range d.Diagnostics {
		view := ResultView{Status: string(r.Status), Summary: r.Summary, Codes: r.ErrorCodes, Established: r.Established}
		for _, it := range r.Items {
			view.Items = append(view.Items, ItemView{Scope: it.Scope, Code: it.Code, Detail: it.Detail})
		}
		out[r.ID] = view
	}
	return out
}

// ResultView is the slice of a diagnostic result the rules need, keeping the rules clear of the
// full result shape.
type ResultView struct {
	Status      string
	Summary     string
	Codes       []string
	Items       []ItemView
	Established []string
}

// ItemView mirrors diag.Item without importing the package into every rule signature.
type ItemView struct {
	Scope  string
	Code   string
	Detail string
}

// hasStatus reports whether the named check ran and ended with one of the given statuses.
func hasStatus(d map[string]ResultView, id string, statuses ...string) bool {
	r, ok := d[id]
	if !ok {
		return false
	}
	for _, s := range statuses {
		if r.Status == s {
			return true
		}
	}
	return false
}

// hadCode reports whether any check carries an error code.
func hadCode(d map[string]ResultView, code string) bool {
	for _, r := range d {
		for _, c := range r.Codes {
			if c == code {
				return true
			}
		}
	}
	return false
}

// items returns every item with the given code, in result order.
func items(d map[string]ResultView, code string) []ItemView {
	var out []ItemView
	for _, id := range sortedKeys(d) {
		for _, it := range d[id].Items {
			if it.Code == code {
				out = append(out, it)
			}
		}
	}
	return out
}

// itemsOfCheck returns the items of one check with the given code.
func itemsOfCheck(d map[string]ResultView, check, code string) []ItemView {
	var out []ItemView
	r, ok := d[check]
	if !ok {
		return out
	}
	for _, it := range r.Items {
		if it.Code == code {
			out = append(out, it)
		}
	}
	return out
}

func sortedKeys(m map[string]ResultView) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func scopes(items []ItemView) []string {
	var out []string
	for _, it := range items {
		if it.Scope != "" {
			out = append(out, it.Scope)
		}
	}
	return distinct(out)
}

// label names the subject of an item. Adapter-scoped observations carry it in Scope; things that
// are not adapters (a DNS server, an endpoint, a port) carry it in Detail, and a statement that
// says "the DNS server  did not answer" is worse than useless.
func label(it ItemView) string { return nonEmptyStr(it.Scope, it.Detail) }

// labels names the subjects of a set of items, in order and without repeats.
func labels(items []ItemView) []string {
	var out []string
	for _, it := range items {
		out = append(out, label(it))
	}
	return distinct(out)
}

func distinct(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// ---- the rules ---------------------------------------------------------------------------------

func rules() []rule {
	return []rule{
		rLinkSpecificFailure(),
		rAllLinksFailed(),
		rRefusedVsFiltered(),
		rFilteredPath(),
		rDNSFailure(),
		rDNSServerDead(),
		rReservedAnswer(),
		rMTU(),
		rStaleEngine(),
		rEngineNotUsingAdapter(),
		rAssignedNoTraffic(),
		rIPv6Gap(),
		rEndpointUnresolved(),
		rPortConflict(),
		rSecurityFilterCandidate(),
		rTTLPartialRead(),
	}
}

// linkProbeStates reads the per-adapter connectivity outcomes once.
func linkProbeStates(d map[string]ResultView) (ok, bad, skipped []string) {
	r, present := d["adapters.connect"]
	if !present {
		return nil, nil, nil
	}
	for _, it := range r.Items {
		switch it.Code {
		case "connected":
			ok = append(ok, it.Scope)
		case "timeout", "no_route", "error":
			bad = append(bad, it.Scope)
		case "refused":
			// The path works; the far port is closed. Not a link failure.
			ok = append(ok, it.Scope)
		case "family_absent":
			skipped = append(skipped, it.Scope)
		}
	}
	return distinct(ok), distinct(bad), distinct(skipped)
}

// rLinkSpecificFailure: some links reached the endpoint and others did not. That is a verified
// conclusion about where the problem is, because the same probe produced different outcomes.
func rLinkSpecificFailure() rule {
	return rule{
		id: "link-specific-failure",
		match: func(d *Document) []Hypothesis {
			probes := checkResults(d)
			ok, bad, _ := linkProbeStates(probes)
			if len(ok) == 0 || len(bad) == 0 {
				return nil
			}
			return []Hypothesis{{
				Kind: KindVerified,
				Statement: fmt.Sprintf("the connectivity failure is specific to %s: %s reached the same endpoint in the same run",
					strings.Join(bad, ", "), strings.Join(ok, ", ")),
				Supports: []string{"adapters.connect"},
				NextSteps: []string{
					"Read the per-adapter evidence above for " + strings.Join(bad, ", ") + ": the failure mode (timeout vs no route) narrows the cause to filtering, routing or the link itself.",
					"Compare the failing adapter's gateway and DNS values with the working one's in the Interfaces section.",
				},
			}}
		},
	}
}

// rAllLinksFailed: every link failed the same probe. The interesting candidates are then shared
// causes, and it is stated as a hypothesis because a check cannot see which one it is.
func rAllLinksFailed() rule {
	return rule{
		id: "all-links-failed",
		match: func(d *Document) []Hypothesis {
			probes := checkResults(d)
			ok, bad, _ := linkProbeStates(probes)
			if len(bad) == 0 || len(ok) > 0 {
				return nil
			}
			shared := hasStatus(probes, "dns.resolve", "fail") || hadCode(probes, "diag_endpoint_unresolved")
			h := Hypothesis{
				Kind:       KindHypothesis,
				Confidence: "medium",
				Statement: fmt.Sprintf("every eligible adapter failed the same probe (%s), so the cause is more likely shared than specific to one link",
					strings.Join(bad, ", ")),
				Supports: []string{"adapters.connect", "ipv4.connect"},
				NextSteps: []string{
					"Test a second destination (a different endpoint in Settings) before concluding the host is offline: one unreachable endpoint is not an outage.",
					"Check the gateway and DNS results: a shared DNS or first-hop problem produces exactly this pattern.",
				},
			}
			if shared {
				h.Confidence = "high"
				h.Statement += ", and name resolution also failed in the same run"
				h.Supports = append(h.Supports, "dns.resolve")
			}
			return []Hypothesis{h}
		},
	}
}

// rRefusedVsFiltered: a refusal is a working path to a closed port, and is worth saying so that
// nobody hunts a network fault for a service that is simply not listening.
func rRefusedVsFiltered() rule {
	return rule{
		id: "refused-vs-filtered",
		match: func(d *Document) []Hypothesis {
			probes := checkResults(d)
			var hosts []string
			for _, it := range itemsOfCheck(probes, "ipv4.connect", "refused") {
				hosts = append(hosts, it.Detail)
			}
			for _, it := range itemsOfCheck(probes, "ipv6.connect", "refused") {
				hosts = append(hosts, it.Detail)
			}
			if len(hosts) == 0 {
				return nil
			}
			return []Hypothesis{{
				Kind: KindVerified,
				Statement: fmt.Sprintf("the path to %s works and the port is closed: the connection was actively refused, which requires the packet to have arrived",
					strings.Join(distinct(hosts), ", ")),
				Supports:  []string{"ipv4.connect"},
				NextSteps: []string{"Point the endpoint at a service that is actually listening, or confirm the port number in Settings."},
			}}
		},
	}
}

// rFilteredPath: the first hop answers but TCP to the endpoint does not. Classic filtering
// signature - still a hypothesis, because the far side could equally be down.
func rFilteredPath() rule {
	return rule{
		id: "filtered-path",
		match: func(d *Document) []Hypothesis {
			probes := checkResults(d)
			timedOut := hadCode(probes, "diag_tcp_timeout")
			if !timedOut {
				return nil
			}
			answered := items(probes, "gateway_answered")
			if len(answered) == 0 {
				return nil
			}
			return []Hypothesis{{
				Kind:       KindHypothesis,
				Confidence: "medium",
				Statement: fmt.Sprintf("TCP to the endpoint timed out while %s answered on the first hop, so the break is beyond this host's gateway",
					strings.Join(scopes(answered), ", ")),
				Supports: []string{"gateway.reach", "ipv4.connect"},
				NextSteps: []string{
					"Try a second endpoint on a different port: a filter that allows one destination and not another is common.",
					"If a VPN or security product is installed, its network filter is a candidate (the security check lists what is installed).",
				},
			}}
		},
	}
}

// rDNSFailure combines the resolver and the specific-server results. Which of the two failures
// happened changes what a person should do next, so the statement says both.
func rDNSFailure() rule {
	return rule{
		id: "dns-failure",
		match: func(d *Document) []Hypothesis {
			probes := checkResults(d)
			resolveFailed := hasStatus(probes, "dns.resolve", "fail")
			serverDead := hasStatus(probes, "dns.server", "fail")
			switch {
			case resolveFailed && serverDead:
				return []Hypothesis{{
					Kind:       KindHypothesis,
					Confidence: "high",
					Statement:  "name resolution failed and the configured DNS server did not answer when asked directly, so the resolution failure is explained by that server",
					Supports:   []string{"dns.resolve", "dns.server"},
					NextSteps: []string{
						"Check whether the adapter that carries that DNS server has a working gateway (the gateway check answers this).",
						"Set a second DNS server in Settings and re-run: a resolver with no reachable server falls back to nothing.",
					},
				}}
			case resolveFailed && !serverDead:
				return []Hypothesis{{
					Kind:       KindHypothesis,
					Confidence: "medium",
					Statement:  "resolution through the host resolver failed while a directly queried DNS server answered, so the problem is in how this host uses its resolvers rather than a dead server",
					Supports:   []string{"dns.resolve", "dns.server"},
					NextSteps:  []string{"Compare the per-adapter DNS lists in the Interfaces section: which adapter wins is decided by interface order and metrics."},
				}}
			}
			return nil
		},
	}
}

func rDNSServerDead() rule {
	return rule{
		id: "dns-server-dead",
		match: func(d *Document) []Hypothesis {
			probes := checkResults(d)
			dead := itemsOfCheck(probes, "dns.server", "dns_unresponsive")
			if len(dead) == 0 {
				return nil
			}
			return []Hypothesis{{
				Kind: KindVerified,
				Statement: fmt.Sprintf("the DNS server %s did not answer a direct query, so it cannot be relied on for resolution",
					strings.Join(labels(dead), ", ")),
				Supports:  []string{"dns.server"},
				NextSteps: []string{"Either point Settings at a server that answers, or accept that this one must recover on its own."},
			}}
		},
	}
}

// rReservedAnswer: a public name resolving into a reserved range is the signature of a sinkhole
// or a captive portal, and the check cannot tell those two apart, so it says so.
func rReservedAnswer() rule {
	return rule{
		id: "reserved-answer",
		match: func(d *Document) []Hypothesis {
			probes := checkResults(d)
			reserved := itemsOfCheck(probes, "dns.resolve", "reserved_answer")
			if len(reserved) == 0 {
				return nil
			}
			return []Hypothesis{{
				Kind:       KindHypothesis,
				Confidence: "high",
				Statement: fmt.Sprintf("a name resolved into a reserved/documentation address range (%s), which a public resolver would not normally return",
					strings.Join(labels(reserved), ", ")),
				Supports: []string{"dns.resolve"},
				NextSteps: []string{
					"If this host is behind a captive portal, complete its sign-in page and re-run.",
					"Check whether a DNS-filtering product or a hosts-file entry is rewriting answers; the DNS server check shows which server answered.",
				},
			}}
		},
	}
}

func rMTU() rule {
	return rule{
		id: "mtu",
		match: func(d *Document) []Hypothesis {
			probes := checkResults(d)
			below := itemsOfCheck(probes, "mtu.path", "mtu_below_standard")
			if len(below) == 0 {
				return nil
			}
			size := ""
			if len(below) > 0 {
				size = below[0].Detail
			}
			return []Hypothesis{{
				Kind:       KindHypothesis,
				Confidence: "medium",
				Statement: fmt.Sprintf("the path carries packets up to about %s bytes, so anything larger risks being dropped when a hop or a tunnel cannot fragment it",
					nonEmptyStr(size, "the measured figure")),
				Supports: []string{"mtu.path"},
				NextSteps: []string{
					"Set the engine's TUN MTU at or below this figure (`net-merge -mtu`) so large transfers do not stall.",
					"If a VPN or PPPoE link sits in the path, its own overhead is usually the reason.",
				},
			}}
		},
	}
}

func rStaleEngine() rule {
	return rule{
		id: "stale-engine",
		match: func(d *Document) []Hypothesis {
			probes := checkResults(d)
			stale := items(probes, "stale_adapter")
			if len(stale) == 0 {
				return nil
			}
			return []Hypothesis{{
				Kind: KindVerified,
				Statement: fmt.Sprintf("the net-merge adapter %s is present while no engine is running, which is the state a crash or a forced stop leaves behind",
					strings.Join(scopes(stale), ", ")),
				Supports:  []string{"engine.stale"},
				NextSteps: []string{"Run `net-merge cleanup` elevated; it removes only the routes net-merge created. Nothing here deletes anything on its own."},
			}}
		},
	}
}

func rEngineNotUsingAdapter() rule {
	return rule{
		id: "engine-skips-usable-adapter",
		match: func(d *Document) []Hypothesis {
			probes := checkResults(d)
			unlisted := itemsOfCheck(probes, "engine.eligibility", "usable_not_listed")
			if len(unlisted) == 0 {
				return nil
			}
			return []Hypothesis{{
				Kind:       KindHypothesis,
				Confidence: "medium",
				Statement: fmt.Sprintf("%s can carry traffic but is not in the engine's adapter list, so it is not contributing to the bond",
					strings.Join(scopes(unlisted), ", ")),
				Supports: []string{"engine.eligibility"},
				NextSteps: []string{
					"Run `net-merge list` yourself: it prints the engine's own reason for skipping each adapter.",
					"If the adapter appeared after the engine started, restart the engine so it re-scans.",
				},
			}}
		},
	}
}

func rAssignedNoTraffic() rule {
	return rule{
		id: "assigned-no-traffic",
		match: func(d *Document) []Hypothesis {
			probes := checkResults(d)
			idle := itemsOfCheck(probes, "counters.assigned-idle", "assigned_no_traffic")
			if len(idle) == 0 {
				return nil
			}
			return []Hypothesis{{
				Kind:       KindHypothesis,
				Confidence: "low",
				Statement: fmt.Sprintf("the engine reports connections on %s while the adapter's own counters did not move during the sample window",
					strings.Join(scopes(idle), ", ")),
				Supports: []string{"counters.assigned-idle", "counters.movement"},
				NextSteps: []string{
					"Generate traffic and re-run before drawing a conclusion: idle connections (a keep-alive, an open tab) look exactly like this.",
					"If traffic keeps not moving, compare with the per-adapter connectivity result for that adapter.",
				},
			}}
		},
	}
}

func rIPv6Gap() rule {
	return rule{
		id: "ipv6-gap",
		match: func(d *Document) []Hypothesis {
			probes := checkResults(d)
			only4 := itemsOfCheck(probes, "families.split", "ipv4_only")
			if len(only4) == 0 {
				return nil
			}
			return []Hypothesis{{
				Kind: KindVerified,
				Statement: fmt.Sprintf("%s carry IPv4 but no global IPv6 address, so anything that requires IPv6 will fail on them while IPv4 keeps working",
					strings.Join(scopes(only4), ", ")),
				Supports:  []string{"families.split"},
				NextSteps: []string{"Nothing here disables IPv6 or works around its absence; if the link should have IPv6, check the adapter and, for a tethered phone, the phone's own settings."},
			}}
		},
	}
}

func rEndpointUnresolved() rule {
	return rule{
		id: "endpoint-unresolved",
		match: func(d *Document) []Hypothesis {
			probes := checkResults(d)
			unresolved := items(probes, "endpoint_unresolved")
			if len(unresolved) == 0 {
				return nil
			}
			return []Hypothesis{{
				Kind:      KindVerified,
				Statement: fmt.Sprintf("the configured test endpoint %s does not resolve on this host, so the connectivity checks could not run against it", strings.Join(labels(unresolved), ", ")),
				Supports:  []string{"ipv4.connect"},
				NextSteps: []string{"Fix the endpoint in Settings (it takes host:port) or correct the DNS problem first, then re-run."},
			}}
		},
	}
}

func rPortConflict() rule {
	return rule{
		id: "port-conflict",
		match: func(d *Document) []Hypothesis {
			probes := checkResults(d)
			busy := itemsOfCheck(probes, "ports.conflict", "port_in_use")
			if len(busy) == 0 {
				return nil
			}
			return []Hypothesis{{
				Kind: KindVerified,
				Statement: fmt.Sprintf("%s is already bound by another process, so starting a listener there would fail until that process is identified",
					strings.Join(labels(busy), ", ")),
				Supports:  []string{"ports.conflict"},
				NextSteps: []string{"Find the owner (the navigate step in the check lists the platform command) or start on a different -listen address."},
			}}
		},
	}
}

// rSecurityFilterCandidate combines a timeout with an enabled firewall: this is the classic
// pairing that tempts a report to blame the firewall. It is kept as a low-confidence candidate
// on purpose, with the reasoning stated.
func rSecurityFilterCandidate() rule {
	return rule{
		id: "security-filter-candidate",
		match: func(d *Document) []Hypothesis {
			probes := checkResults(d)
			if !hadCode(probes, "diag_tcp_timeout") {
				return nil
			}
			fw := items(probes, "firewall_enabled")
			if len(fw) == 0 {
				return nil
			}
			var profiles []string
			for _, it := range fw {
				profiles = append(profiles, it.Scope)
			}
			return []Hypothesis{{
				Kind:       KindHypothesis,
				Confidence: "low",
				Statement: fmt.Sprintf("a connection timed out while the %s firewall profile(s) are enabled; the firewall is a candidate but this report cannot prove it dropped anything",
					strings.Join(distinct(profiles), ", ")),
				Supports: []string{"ipv4.connect", "security.firewall"},
				NextSteps: []string{
					"Test the same endpoint from another application on this host: if it also times out, the endpoint or the path is the cause, not this application.",
					"Look at the firewall's own log for that connection; this application never changes firewall state to test a theory.",
				},
			}}
		},
	}
}

func rTTLPartialRead() rule {
	return rule{
		id: "ttl-partial-read",
		match: func(d *Document) []Hypothesis {
			if d.TTL == nil || len(d.TTL.ReadErrors) == 0 {
				return nil
			}
			var ids []string
			for _, e := range d.TTL.ReadErrors {
				ids = append(ids, string(e.Setting.ID))
			}
			return []Hypothesis{{
				Kind:      KindVerified,
				Statement: fmt.Sprintf("%d TTL/hop-limit setting(s) could not be read (%s), so this report's TTL section is partial", len(ids), strings.Join(ids, ", ")),
				Supports:  []string{"ttl.inspect"},
				NextSteps: []string{"Re-run the TTL inspection elevated: the packet-header values usually require administrator rights to read."},
			}}
		},
	}
}

func nonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
