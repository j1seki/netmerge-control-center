// Package inventory is the one place that answers "what network interfaces does this machine
// have, and what is each of them actually doing?".
//
// The bonding engine in internal/nics answers a narrower question - which adapters can it bind a
// flow to right now - and it does so by silently dropping anything it will not use. The Control
// Center has to show the ones it drops, with the reason, alongside addressing, gateways, DNS,
// DHCP state, metrics, routes and live byte counters. That is this package.
//
// Three properties are deliberate:
//
//   - Nothing here is Windows-only. The model, the eligibility rules and the PowerShell output
//     decoding carry no build constraint, so they are exercised by tests on any host. The
//     platform-specific part is a Source (system_windows.go, system_linux.go) behind an
//     interface, which is what keeps the test suite honest: the fake Source used in tests is
//     labelled as a simulation, and the real one runs no commands during tests.
//
//   - Missing data is data. A field a host cannot provide is left empty and named in Gaps rather
//     than filled with a plausible default, because "we could not read this" and "this is zero"
//     lead to different diagnoses.
//
//   - Eligibility is evaluated, not guessed, and every exclusion carries a stable code plus a
//     sentence a person can act on.
package inventory

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Kind is what sort of link an interface is. The phone-tether kinds exist because the whole
// application exists to use those links, and they need to be recognisable at a glance: a tether
// that is present but disconnected is a different problem from an Ethernet port with no cable.
type Kind string

const (
	KindEthernet  Kind = "ethernet"
	KindWiFi      Kind = "wifi"
	KindWWAN      Kind = "wwan"       // mobile broadband modem built into the machine
	KindUSBTether Kind = "usb-tether" // a phone sharing its connection over USB
	KindVirtual   Kind = "virtual"    // VPN, tunnel, virtual switch, container bridge
	KindOther     Kind = "other"
	KindUnknown   Kind = "unknown"
)

// LinkState is the interface's own idea of itself, from the OS.
type LinkState string

const (
	LinkUp       LinkState = "up"
	LinkDown     LinkState = "down"
	LinkDisabled LinkState = "disabled"
	LinkUnknown  LinkState = "unknown"
)

// State is the single verdict the dashboard shows per adapter. It combines what the operating
// system says, what this package can prove about the link, and what the engine is doing.
type State string

const (
	// StateActive: eligible, and the bonding engine is using it for traffic now.
	StateActive State = "active"
	// StateEligible: usable as an internet path, not currently carrying engine traffic.
	StateEligible State = "eligible"
	// StateExcluded: present but not usable, for the reason in Exclusion.
	StateExcluded State = "excluded"
	// StateDisconnected: the OS reports no link (no cable, phone unplugged, radio off).
	StateDisconnected State = "disconnected"
	// StateUnhealthy: configured and linked, but traffic to the test endpoint is not working.
	StateUnhealthy State = "unhealthy"
	// StateUnknown: not enough information to judge.
	StateUnknown State = "unknown"
)

// Exclusion codes. Stable strings, greppable in a log and safe to switch on in a UI, with the
// human sentence alongside in Adapter.Exclusion.
const (
	ExclVirtual      = "virtual_adapter"
	ExclUserExcluded = "excluded_by_user"
	ExclNotSelected  = "not_selected"
	ExclDisabled     = "admin_disabled"
	ExclLinkDown     = "link_down"
	ExclNoAddress    = "no_usable_address"
	ExclLinkLocal    = "link_local_only"
	ExclNoGateway    = "no_default_gateway"
	ExclNoInternet   = "no_internet_reachability"
	ExclUnsupported  = "unsupported_platform"
)

// Tri is a three-valued flag. DHCP is reported per address family and "unknown" is a real
// answer: a host that cannot be asked must not be reported as either enabled or disabled.
type Tri string

const (
	TriYes     Tri = "yes"
	TriNo      Tri = "no"
	TriUnknown Tri = "unknown"
)

// Address is one address assigned to an interface.
type Address struct {
	Address string `json:"address"`
	Prefix  int    `json:"prefixLength,omitempty"`
	// Origin is where the address came from: dhcp, static, manual, router-advertisement,
	// wellknown, link-layer, or empty when the host does not say.
	Origin string `json:"origin,omitempty"`
	// Status is the address's own state: preferred, tentative, deprecated, duplicate.
	Status string `json:"status,omitempty"`
	// LinkLocal marks 169.254/16 and fe80::/10 addresses.
	LinkLocal bool `json:"linkLocal,omitempty"`
	// Virtual marks an address the platform reports as a synthetic alias.
	Virtual bool `json:"virtual,omitempty"`
}

// Route is one entry of the routing table, attributed to an interface where the platform says so.
type Route struct {
	Family      string `json:"family"` // ipv4 or ipv6
	Destination string `json:"destination"`
	NextHop     string `json:"nextHop,omitempty"`
	Index       int    `json:"interfaceIndex,omitempty"`
	Name        string `json:"interfaceName,omitempty"`
	Metric      int    `json:"metric,omitempty"`
	// Protocol is the mechanism that installed the route (dhcp, ra, static, kernel, ...) when
	// the platform reports it. It matters: a DHCP-installed default route disappears with the
	// lease, while a static one does not.
	Protocol string `json:"protocol,omitempty"`
	// Default marks a default route (0.0.0.0/0 or ::/0) - the ones that decide where traffic
	// goes when nothing more specific matches.
	Default bool `json:"default,omitempty"`
}

// Counters are the platform's own byte totals for an interface. They cover every application's
// traffic, not just what the engine relays.
type Counters struct {
	In  uint64 `json:"in"`
	Out uint64 `json:"out"`
}

// Health is the result of an active reachability check performed elsewhere (internal/monitor).
// It is carried into the inventory rather than measured here so that a state query stays
// cheap: the dashboard polls state every second and must not run a connectivity test each time.
type Health struct {
	// Checked distinguishes "we tested and it failed" from "we have not tested yet".
	Checked bool    `json:"checked"`
	OK      bool    `json:"ok"`
	RTTms   float64 `json:"rttMs,omitempty"`
	Loss    float64 `json:"lossPct,omitempty"`
	Jitter  float64 `json:"jitterMs,omitempty"`
	// Endpoint is what was tested, so a failure message can say what it failed to reach.
	Endpoint string    `json:"endpoint,omitempty"`
	At       time.Time `json:"at,omitempty"`
	Detail   string    `json:"detail,omitempty"`
}

// Adapter is the full picture of one interface.
type Adapter struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	// GUID is the Windows interface GUID (the stable identity across reboots and re-plugs);
	// empty where the platform has no such notion.
	GUID    string `json:"guid,omitempty"`
	IfAlias string `json:"ifAlias,omitempty"` // Windows per-address alias, e.g. "Ethernet 2"

	Index   int `json:"index"`             // IPv4 interface index (the key everything else uses)
	IndexV6 int `json:"indexV6,omitempty"` // IPv6 interface index when the platform has one

	Kind   Kind  `json:"kind"`
	Status State `json:"status"` // one of the State values

	// Hardware is false when something marks this as a virtual/tunnel/software interface.
	Hardware      bool   `json:"hardware"`
	VirtualReason string `json:"virtualReason,omitempty"`

	Link      LinkState `json:"link"`
	Admin     string    `json:"adminState,omitempty"` // up|down|unknown, from the driver
	Media     string    `json:"mediaState,omitempty"` // connected|disconnected|unknown
	MediaType string    `json:"mediaType,omitempty"`  // for example 802.11 or 802.3
	SpeedBps  uint64    `json:"speedBps,omitempty"`   // link speed, 0 when unknown
	MTU       int       `json:"mtu,omitempty"`
	MAC       string    `json:"mac,omitempty"` // rendered; the exporter redacts it

	IPv4      []Address `json:"ipv4,omitempty"`
	IPv6      []Address `json:"ipv6,omitempty"`
	Gateways4 []string  `json:"gateways4,omitempty"`
	Gateways6 []string  `json:"gateways6,omitempty"`
	DNS4      []string  `json:"dns4,omitempty"`
	DNS6      []string  `json:"dns6,omitempty"`

	DHCP4 Tri `json:"dhcp4,omitempty"`
	DHCP6 Tri `json:"dhcp6,omitempty"`

	Metric4 *int `json:"metric4,omitempty"`
	Metric6 *int `json:"metric6,omitempty"`
	MTU4    *int `json:"mtu4,omitempty"`
	MTU6    *int `json:"mtu6,omitempty"`

	Routes        []Route `json:"routes,omitempty"`
	RouteCount    int     `json:"routeCount,omitempty"`
	DefaultRoutes []Route `json:"defaultRoutes,omitempty"`
	// DefaultRoute4/6 record that a default route exists for that family even when its next hop
	// is on-link (Windows reports :: with no gateway address for IPv6 routers that advertise
	// themselves by router advertisement), so eligibility never depends on the gateway list
	// alone.
	DefaultRoute4 bool `json:"defaultRoute4,omitempty"`
	DefaultRoute6 bool `json:"defaultRoute6,omitempty"`

	// DriverProvider and DriverVersion identify the vendor's driver, which is what a "known bad
	// driver" hypothesis in a report has to name.
	DriverProvider string `json:"driverProvider,omitempty"`
	DriverVersion  string `json:"driverVersion,omitempty"`

	Counters *Counters `json:"counters,omitempty"`
	Rates    *Rates    `json:"rates,omitempty"`
	// ProbeCounters are the coarser counters the PowerShell probe reports, kept when the faster
	// native read is unavailable so the dashboard can still show movement.
	ProbeCounters *Counters `json:"probeCounters,omitempty"`

	// Health is the last reachability result for this adapter, when anything has tested it.
	Health *Health `json:"health,omitempty"`

	// Engine is true when the bonding engine currently uses this adapter for egress.
	Engine bool `json:"engine"`
	// EngineAssigned is the number of connections the engine reports on this adapter, or nil
	// when the engine does not report it. nil is not zero: one means "none assigned", the other
	// means "not known".
	EngineAssigned *int `json:"engineAssigned,omitempty"`

	ExclusionCode string   `json:"exclusionCode,omitempty"`
	Exclusion     string   `json:"exclusion,omitempty"`
	Gaps          []string `json:"gaps,omitempty"`
	Warnings      []string `json:"warnings,omitempty"`
}

// Rates are per-second byte rates derived from two counter samples. They are always attributed
// to the interval they were measured over, because a rate without a window is a guess.
type Rates struct {
	InPerSec  float64   `json:"inPerSec"`
	OutPerSec float64   `json:"outPerSec"`
	Span      float64   `json:"spanSeconds"`
	At        time.Time `json:"at"`
}

// Snapshot is every adapter, route and caveat at one instant.
type Snapshot struct {
	Taken    time.Time `json:"taken"`
	Source   string    `json:"source"`
	Adapters []Adapter `json:"adapters"`
	Routes   []Route   `json:"routes,omitempty"`

	// Totals are the sum of the adapters' measured link speeds and rates. They are NOT a claim
	// about achievable throughput and are documented as such where they are displayed.
	LinkSpeedTotalBps uint64  `json:"linkSpeedTotalBps,omitempty"`
	InPerSecTotal     float64 `json:"inPerSecTotal,omitempty"`
	OutPerSecTotal    float64 `json:"outPerSecTotal,omitempty"`

	// Gaps are host-wide limitations ("this platform exposes no DHCP state"), kept separate from
	// per-adapter gaps so a report can state the shape of what is missing.
	Gaps []string `json:"gaps,omitempty"`
	// Warnings are cross-adapter observations: several default routes, DNS that differs between
	// links, split IPv4/IPv6 behaviour.
	Warnings []string `json:"warnings,omitempty"`
	Notes    []string `json:"notes,omitempty"`
	Errors   []string `json:"errors,omitempty"` // collection problems that did not stop the snapshot
}

// Adapter returns the adapter with the given interface index.
func (s *Snapshot) Adapter(index int) (Adapter, bool) {
	for _, a := range s.Adapters {
		if a.Index == index {
			return a, true
		}
	}
	return Adapter{}, false
}

// ByName returns the adapter with the given name, case-insensitively.
func (s *Snapshot) ByName(name string) (Adapter, bool) {
	for _, a := range s.Adapters {
		if strings.EqualFold(a.Name, name) {
			return a, true
		}
	}
	return Adapter{}, false
}

// Usable returns the adapters the engine can carry traffic on right now.
func (s *Snapshot) Usable() []Adapter {
	var out []Adapter
	for _, a := range s.Adapters {
		if a.Status == StateActive || a.Status == StateEligible {
			out = append(out, a)
		}
	}
	return out
}

// Unusable returns the adapters that are present but cannot carry engine traffic, each with its
// reason already attached.
func (s *Snapshot) Unusable() []Adapter {
	var out []Adapter
	for _, a := range s.Adapters {
		switch a.Status {
		case StateExcluded, StateDisconnected, StateUnhealthy, StateUnknown:
			out = append(out, a)
		}
	}
	return out
}

// Sort orders adapters the way the dashboard lists them: engine-carrying first, then usable,
// then everything else, each group by interface index so the order is stable between polls.
func (s *Snapshot) Sort() {
	rank := func(st State) int {
		switch st {
		case StateActive:
			return 0
		case StateEligible:
			return 1
		case StateUnhealthy:
			return 2
		case StateDisconnected:
			return 3
		case StateExcluded:
			return 4
		default:
			return 5
		}
	}
	sort.SliceStable(s.Adapters, func(i, j int) bool {
		ri, rj := rank(s.Adapters[i].Status), rank(s.Adapters[j].Status)
		if ri != rj {
			return ri < rj
		}
		if s.Adapters[i].Index != s.Adapters[j].Index {
			return s.Adapters[i].Index < s.Adapters[j].Index
		}
		return s.Adapters[i].Name < s.Adapters[j].Name
	})
}

// Summary is the one-line description shown in the header of the dashboard's Overview section.
// It describes each family of verdict honestly: "3 links, 2 usable (1 carrying traffic), 1
// excluded (no default gateway)".
func (s *Snapshot) Summary() string {
	var active, eligible, excluded, disconnected, unhealthy, unknown int
	for _, a := range s.Adapters {
		switch a.Status {
		case StateActive:
			active++
		case StateEligible:
			eligible++
		case StateExcluded:
			excluded++
		case StateDisconnected:
			disconnected++
		case StateUnhealthy:
			unhealthy++
		default:
			unknown++
		}
	}
	total := len(s.Adapters)
	if total == 0 {
		return "no network adapters detected"
	}
	usable := active + eligible
	parts := []string{fmt.Sprintf("%d link(s)", total), fmt.Sprintf("%d usable", usable)}
	if active > 0 {
		parts = append(parts, fmt.Sprintf("%d carrying engine traffic", active))
	}
	if excluded > 0 {
		parts = append(parts, fmt.Sprintf("%d excluded", excluded))
	}
	if disconnected > 0 {
		parts = append(parts, fmt.Sprintf("%d disconnected", disconnected))
	}
	if unhealthy > 0 {
		parts = append(parts, fmt.Sprintf("%d failing reachability", unhealthy))
	}
	if unknown > 0 {
		parts = append(parts, fmt.Sprintf("%d unknown", unknown))
	}
	return strings.Join(parts, ", ")
}

// ExclusionText turns a code into the sentence shown next to the adapter. Returning a readable
// string for every code (rather than leaving it blank) is deliberate: an exclusion the user
// cannot understand is a bug report waiting to happen.
func ExclusionText(code string, a Adapter) string {
	switch code {
	case ExclVirtual:
		if a.VirtualReason != "" {
			return "not real network hardware: " + a.VirtualReason
		}
		return "not real network hardware (virtual or tunnel adapter)"
	case ExclUserExcluded:
		return "excluded in the selected profile"
	case ExclNotSelected:
		return "not in the selected adapter list"
	case ExclDisabled:
		return "disabled in Windows (the adapter is administratively down)"
	case ExclLinkDown:
		return "no link: the adapter is disconnected"
	case ExclNoAddress:
		return "no usable IP address"
	case ExclLinkLocal:
		return "link-local address only (169.254.x.x or fe80::): no DHCP lease and no hand-set address"
	case ExclNoGateway:
		return "no default gateway for IPv4 or IPv6, so no route to the internet"
	case ExclNoInternet:
		if a.Health != nil && a.Health.Endpoint != "" {
			return "reachability test to " + a.Health.Endpoint + " failed"
		}
		return "reachability test failed"
	case ExclUnsupported:
		return "not inspected: this host has no supported mechanism to read adapter configuration"
	}
	return "excluded"
}
