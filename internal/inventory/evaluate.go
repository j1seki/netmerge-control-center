package inventory

import (
	"fmt"
	"net"
	"strings"
)

// Options are the inputs to the eligibility decision that do not come from the operating
// system: what the user asked for, and what the engine and the health monitor know.
type Options struct {
	// Include, when non-empty, is an explicit list of adapter names to use. Like the engine's
	// -include flag it overrides the automatic checks, and the effect is reported: an adapter
	// that only got in because it was named explicitly still shows up as virtual or link-down
	// in Status, with the warning attached.
	Include []string
	// Exclude is the user's exclusion list from the active profile.
	Exclude []string
	// EngineUsed is the set of adapter names the bonding engine is currently using (from its
	// status file, not guessed).
	EngineUsed map[string]bool
	// EngineAssigned is the engine's per-adapter connection count when it reports one.
	EngineAssigned map[string]int
	// Health is the last reachability result per adapter name.
	Health map[string]Health
}

// Includes reports whether the adapter is in the explicit include list.
func (o Options) Includes(name string) bool { return containsFold(o.Include, name) }

// Excludes reports whether the adapter is in the user's exclusion list.
func (o Options) Excludes(name string) bool { return containsFold(o.Exclude, name) }

// Evaluate fills in every adapter's Status, exclusion and warnings. It is the only place that
// decides what the dashboard shows, so the rules are stated once, in order, with the reason
// attached to the rule that fired.
func Evaluate(adapters []Adapter, opts Options) []Adapter {
	out := make([]Adapter, len(adapters))
	copy(out, adapters)
	for i := range out {
		evaluateOne(&out[i], opts)
	}
	return out
}

// evaluateOne applies the rules in order. First match wins, which is why the order matters: the
// user's own exclusions come first (they are a decision, not a diagnosis), then the reasons the
// engine cannot use a link, then health.
func evaluateOne(a *Adapter, opts Options) {
	// The engine's view and the monitor's view are always attached, whatever the verdict, so a
	// row can say "excluded, but Windows is relaying traffic over it" if that is what is true.
	a.Engine = opts.EngineUsed[a.Name]
	if n, ok := opts.EngineAssigned[a.Name]; ok {
		count := n
		a.EngineAssigned = &count
	}
	if h, ok := opts.Health[a.Name]; ok {
		health := h
		a.Health = &health
	}

	explicit := opts.Includes(a.Name)

	if opts.Excludes(a.Name) {
		setExcluded(a, ExclUserExcluded)
		return
	}
	if len(opts.Include) > 0 && !explicit {
		setExcluded(a, ExclNotSelected)
		return
	}
	if a.Link == LinkDisabled {
		setExcluded(a, ExclDisabled)
		return
	}
	if a.Link == LinkDown {
		a.Status = StateDisconnected
		a.ExclusionCode = ExclLinkDown
		a.Exclusion = ExclusionText(ExclLinkDown, *a)
		return
	}
	if !a.Hardware {
		if explicit {
			// Named explicitly: the engine will use it, so report it as usable with the caveat
			// rather than pretending it is fine.
			a.Warnings = append(a.Warnings, "explicitly included although it is not real network hardware: "+a.VirtualReason)
		} else {
			setExcluded(a, ExclVirtual)
			return
		}
	}
	if !hasRoutableAddress(*a) {
		if hasLinkLocalOnly(*a) {
			setExcluded(a, ExclLinkLocal)
		} else {
			setExcluded(a, ExclNoAddress)
		}
		return
	}
	if !hasDefaultRoute(*a) {
		setExcluded(a, ExclNoGateway)
		return
	}
	if a.Health != nil && a.Health.Checked && !a.Health.OK {
		a.Status = StateUnhealthy
		a.ExclusionCode = ExclNoInternet
		a.Exclusion = ExclusionText(ExclNoInternet, *a)
		return
	}
	if a.Engine {
		a.Status = StateActive
	} else {
		a.Status = StateEligible
	}
	a.ExclusionCode = ""
	a.Exclusion = ""
	addWarnings(a)
}

func setExcluded(a *Adapter, code string) {
	a.Status = StateExcluded
	a.ExclusionCode = code
	a.Exclusion = ExclusionText(code, *a)
}

// addWarnings records conditions that do not stop an adapter being used but do change what a
// user should expect from it. They are never presented as failures.
func addWarnings(a *Adapter) {
	if len(a.DefaultRoutes) > 1 {
		a.Warnings = append(a.Warnings, fmt.Sprintf(
			"%d default routes on this adapter; Windows picks one by route and interface metric", len(a.DefaultRoutes)))
	}
	if len(a.Gateways4) > 0 && len(a.Gateways6) == 0 && len(a.IPv6) > 0 {
		a.Warnings = append(a.Warnings, "IPv6 addresses present but no IPv6 default gateway: IPv6 traffic cannot leave through this adapter")
	}
	if a.Metric4 != nil && *a.Metric4 >= 5000 {
		a.Warnings = append(a.Warnings, fmt.Sprintf(
			"interface metric %d is high, so this adapter is the last resort for IPv4", *a.Metric4))
	}
	if a.MTU4 != nil && *a.MTU4 > 0 && *a.MTU4 < 1280 {
		a.Warnings = append(a.Warnings, fmt.Sprintf(
			"IPv4 MTU %d is below 1280, which breaks IPv6 tunnelling and some VPNs", *a.MTU4))
	}
	if len(a.DNS4) == 0 && len(a.DNS6) == 0 && (len(a.IPv4) > 0 || len(a.IPv6) > 0) {
		a.Warnings = append(a.Warnings, "no DNS servers configured on this adapter")
	}
}

// hasDefaultRoute reports whether traffic can leave this adapter for the internet. A default
// route counts even when its next hop is on-link: an IPv6 router that advertises itself produces
// a ::/0 route with no gateway address, and treating that as "no gateway" would exclude a working
// link. Conversely, an adapter whose platform source only knows gateway addresses is judged by
// them, which is why both are consulted.
func hasDefaultRoute(a Adapter) bool {
	return a.DefaultRoute4 || a.DefaultRoute6 || len(a.Gateways4) > 0 || len(a.Gateways6) > 0
}

// RoutableIPv4 returns the adapter's first non-link-local IPv4 address, if it has one.
func (a Adapter) RoutableIPv4() (net.IP, bool) {
	for _, addr := range a.IPv4 {
		if !addressUsable(addr) {
			continue
		}
		ip := net.ParseIP(addr.Address)
		if ip == nil || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			continue
		}
		return ip, true
	}
	return nil, false
}

// RoutableIPv6 returns the adapter's first global IPv6 address, if it has one. Unique-local
// (fd00::/8) addresses are reported by Addresses but are not a route to the internet.
func (a Adapter) RoutableIPv6() (net.IP, bool) {
	for _, addr := range a.IPv6 {
		if !addressUsable(addr) {
			continue
		}
		ip := net.ParseIP(addr.Address)
		if ip == nil || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			continue
		}
		if ip.IsPrivate() {
			continue
		}
		return ip, true
	}
	return nil, false
}

// addressUsable reports whether an address can carry new traffic. A tentative or duplicate
// address cannot (Duplicate Address Detection has not finished, or found a conflict), and saying
// so is the difference between "no internet because the adapter is broken" and "no internet
// because IPv6 is mid-setup".
func addressUsable(addr Address) bool {
	switch strings.ToLower(addr.Status) {
	case "tentative", "duplicate", "dadfailed", "invalid":
		return false
	}
	return true
}

func hasRoutableAddress(a Adapter) bool {
	_, v4 := a.RoutableIPv4()
	_, v6 := a.RoutableIPv6()
	return v4 || v6
}

// hasLinkLocalOnly distinguishes "the adapter has an address but it is useless" from "the
// adapter has no address at all". The first means DHCP failed or no address was set - a
// diagnosis - while the second is usually just a disconnected adapter.
func hasLinkLocalOnly(a Adapter) bool {
	if len(a.IPv4) == 0 && len(a.IPv6) == 0 {
		return false
	}
	for _, addr := range a.IPv4 {
		if !addr.LinkLocal {
			return false
		}
	}
	for _, addr := range a.IPv6 {
		if !addr.LinkLocal {
			return false
		}
	}
	return true
}

// CrossChecks records the host-wide observations that only make sense across adapters: several
// default routes, DNS that differs between links, and split IPv4/IPv6 behaviour. Each is a
// warning about the machine's configuration, never a claim about any single adapter.
func CrossChecks(adapters []Adapter) []string {
	var warnings []string

	var withDefault []string
	for _, a := range adapters {
		if len(a.Gateways4) > 0 || len(a.Gateways6) > 0 {
			withDefault = append(withDefault, a.Name)
		}
	}
	if len(withDefault) > 1 {
		warnings = append(warnings, fmt.Sprintf(
			"%d adapters have a default route (%s); Windows sends a new connection through whichever has the best metric, not all of them",
			len(withDefault), strings.Join(withDefault, ", ")))
	}

	dnsSets := map[string][]string{}
	for _, a := range adapters {
		if len(a.DNS4) == 0 && len(a.DNS6) == 0 {
			continue
		}
		dnsSets[a.Name] = append(append([]string{}, a.DNS4...), a.DNS6...)
	}
	if differingDNS(dnsSets) {
		warnings = append(warnings, "adapters are configured with different DNS servers; name resolution follows the adapter Windows chooses, so a link can appear to have no DNS at all")
	}

	var v4Only, v6Only []string
	for _, a := range adapters {
		_, has4 := a.RoutableIPv4()
		_, has6 := a.RoutableIPv6()
		switch {
		case has4 && !has6:
			v4Only = append(v4Only, a.Name)
		case has6 && !has4:
			v6Only = append(v6Only, a.Name)
		}
	}
	if len(v4Only) > 0 && len(v6Only) > 0 {
		warnings = append(warnings, fmt.Sprintf(
			"split families across adapters: %s carry IPv4 only while %s carry IPv6 only",
			strings.Join(v4Only, ", "), strings.Join(v6Only, ", ")))
	}
	return warnings
}

func differingDNS(sets map[string][]string) bool {
	if len(sets) < 2 {
		return false
	}
	var first string
	for _, servers := range sets {
		key := strings.Join(sortedLower(servers), ",")
		if first == "" {
			first = key
			continue
		}
		if key != first {
			return true
		}
	}
	return false
}

func sortedLower(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, strings.ToLower(s))
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func containsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}
