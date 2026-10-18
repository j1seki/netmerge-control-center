// Package ttlmgr manages the host's outbound IPv4 Time-To-Live and IPv6 Hop Limit
// settings through documented, supported mechanisms.
//
// Scope and honesty rules that the whole package is built around:
//
//   - IPv4 packet TTL, IPv6 packet hop limit, DNS record TTL and traceroute hop count are
//     four different things that happen to share the word "TTL". They are modelled as
//     distinct Kind values and are never converted into, or presented as, one another.
//   - A setting's Scope is part of its identity. "System-global" affects traffic on every
//     adapter; "per-interface" affects one adapter. A change that reaches beyond the
//     adapter the user is looking at must say so, which is why Scope is carried on every
//     setting and surfaced by Inspect.
//   - Nothing in this package changes a setting on its own initiative. Apply and Restore
//     only run when called, and both are explicit, confirmed operations.
//
// The package deliberately contains no carrier-evasion behaviour: it exists to make an
// outbound header field inspectable and, when the user asks for it, configurable for
// authorised testing, troubleshooting and administered environments.
package ttlmgr

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Kind is which of the four unrelated "TTL"-named concepts a setting describes.
type Kind string

const (
	// KindPacketTTL is the 8-bit Time-To-Live field written into outbound IPv4 packets.
	KindPacketTTL Kind = "packet-ttl"
	// KindPacketHopLimit is the 8-bit Hop Limit field written into outbound IPv6 packets.
	// It is the IPv6 counterpart of the IPv4 TTL field, not a separate mechanism.
	KindPacketHopLimit Kind = "packet-hoplimit"
	// KindDNSRecordTTL is how many seconds a DNS resolver may cache a record. It is a
	// property of a DNS answer, not of this host, and is not configurable here.
	KindDNSRecordTTL Kind = "dns-record-ttl"
	// KindTracerouteHops is the per-probe hop budget a traceroute tool uses. It is a
	// diagnostic parameter, not a host setting, and is not configurable here.
	KindTracerouteHops Kind = "traceroute-hops"
)

// IsConfigurable reports whether the kind maps to a host setting this package can write.
func (k Kind) IsConfigurable() bool { return k == KindPacketTTL || k == KindPacketHopLimit }

// Explain returns the plain-language description shown next to a kind in the UI and the
// exported diagnostic report. It states what the value affects and what it cannot do.
func (k Kind) Explain() string {
	switch k {
	case KindPacketTTL:
		return "IPv4 Time-To-Live: the hop budget stamped into IPv4 packets this PC sends. " +
			"Each router that forwards the packet subtracts one; at zero the packet is discarded. " +
			"Changing it does not affect UDP or TCP payloads, does not change DNS caching, and does " +
			"not alter traffic that merely passes through this PC."
	case KindPacketHopLimit:
		return "IPv6 Hop Limit: the exact IPv6 equivalent of the IPv4 TTL - the hop budget stamped " +
			"into IPv6 packets this PC sends. IPv4 and IPv6 are configured independently; changing one " +
			"never changes the other."
	case KindDNSRecordTTL:
		return "DNS record TTL: how long a resolver may cache a DNS answer. It comes from the zone " +
			"that published the record, is not a host setting, and cannot be set on this PC."
	case KindTracerouteHops:
		return "Traceroute hop count: how many hops a traceroute probe is allowed to travel. It is a " +
			"diagnostic parameter, is set by the traceroute tool for the duration of one run, and is " +
			"not a system setting."
	default:
		return string(k)
	}
}

// Family is the address family whose header field a setting applies to.
type Family string

const (
	FamilyIPv4 Family = "ipv4"
	FamilyIPv6 Family = "ipv6"
)

// Scope is how much traffic a setting actually reaches. It is deliberately prominent:
// a user looking at one adapter must be able to see that a value is system-wide.
type Scope string

const (
	// ScopeSystemGlobal means the value applies to traffic leaving the machine on every
	// adapter. On Windows this is the stack default written by Set-NetIPv4Protocol /
	// Set-NetIPv6Protocol -DefaultHopLimit.
	ScopeSystemGlobal Scope = "system-global"
	// ScopePerInterface means the value applies to one adapter. On Windows this is the
	// per-interface value exposed by Get/Set-NetIPInterface -CurrentHopLimit. It takes
	// precedence over the system-global value for packets sent on that adapter.
	ScopePerInterface Scope = "per-interface"
	// ScopeNotApplicable marks a Kind that has no host-level setting at all.
	ScopeNotApplicable Scope = "not-applicable"
	// ScopePerRoute is reserved for a future per-route mechanism. Windows has no supported
	// documented per-route TTL/hop-limit setting, so nothing currently reports this scope.
	ScopePerRoute Scope = "per-route"
)

// Explain returns the user-facing consequence of a scope, including the blast radius of a
// system-global change. This wording is what the UI and the export show, so it is written
// to be read by a person deciding whether to change something.
func (s Scope) Explain() string {
	switch s {
	case ScopeSystemGlobal:
		return "Applies to every adapter at once. A change here affects traffic on all of this " +
			"PC's connections, including any you are not looking at."
	case ScopePerInterface:
		return "Applies only to the named adapter. It overrides the system-global value for " +
			"packets sent on that adapter."
	case ScopeNotApplicable:
		return "Not a setting on this PC. Shown for completeness so it is not confused with the " +
			"packet header values above."
	case ScopePerRoute:
		return "Applies to one route only."
	default:
		return string(s)
	}
}

// SettingID is a stable identifier for one inspectable setting. It survives restarts and is
// used as the key for captured original values and change history, so it must not be renamed
// once released.
type SettingID string

const (
	// IDv4Default is the system-global IPv4 packet TTL.
	IDv4Default SettingID = "ipv4.system.default-ttl"
	// IDv6Default is the system-global IPv6 hop limit.
	IDv6Default SettingID = "ipv6.system.default-hoplimit"
)

// InterfaceSettingID builds the per-interface setting id for one adapter.
//
// The adapter's interface index is included so that two adapters which briefly share a
// display name cannot alias each other in the capture log. The name is included because it
// is what a person reads and what a Windows cmdlet accepts.
func InterfaceSettingID(f Family, index int, name string) SettingID {
	return SettingID(fmt.Sprintf("%s.iface.%d.%s.default-hoplimit", f, index, name))
}

// ParseInterfaceSettingID reverses InterfaceSettingID. It reports ok=false for any id that
// was not produced by it, which is how callers tell a system setting from an adapter one.
func ParseInterfaceSettingID(id SettingID) (f Family, index int, name string, ok bool) {
	parts := strings.SplitN(string(id), ".", 4)
	if len(parts) != 4 || parts[1] != "iface" || !strings.HasSuffix(parts[3], ".default-hoplimit") {
		return "", 0, "", false
	}
	switch Family(parts[0]) {
	case FamilyIPv4, FamilyIPv6:
		f = Family(parts[0])
	default:
		return "", 0, "", false
	}
	idx, err := strconv.Atoi(parts[2])
	if err != nil || idx <= 0 {
		return "", 0, "", false
	}
	name = strings.TrimSuffix(parts[3], ".default-hoplimit")
	if name == "" {
		return "", 0, "", false
	}
	return f, idx, name, true
}

// SettingRef identifies a setting without its value: enough to read, write or capture it.
type SettingRef struct {
	ID     SettingID `json:"id"`
	Kind   Kind      `json:"kind"`
	Family Family    `json:"family"`
	Scope  Scope     `json:"scope"`

	// Interface is set only when Scope is ScopePerInterface.
	Interface    string `json:"interface,omitempty"`
	InterfaceIdx int    `json:"interfaceIdx,omitempty"`
}

// SystemRef returns the reference for a system-global packet-header setting.
func SystemRef(f Family) SettingRef {
	k, id := KindPacketTTL, IDv4Default
	if f == FamilyIPv6 {
		k, id = KindPacketHopLimit, IDv6Default
	}
	return SettingRef{ID: id, Kind: k, Family: f, Scope: ScopeSystemGlobal}
}

// IfaceRef returns the reference for one adapter's per-interface packet-header setting.
func IfaceRef(f Family, index int, name string) SettingRef {
	k := KindPacketTTL
	if f == FamilyIPv6 {
		k = KindPacketHopLimit
	}
	return SettingRef{
		ID:           InterfaceSettingID(f, index, name),
		Kind:         k,
		Family:       f,
		Scope:        ScopePerInterface,
		Interface:    name,
		InterfaceIdx: index,
	}
}

// Compact renders a reference for logs and history, e.g. "ipv4.system.default-ttl" or
// "ipv6 per-interface Wi-Fi (7)".
func (r SettingRef) Compact() string {
	if r.Scope == ScopePerInterface {
		return fmt.Sprintf("%s %s %s (%d)", r.Family, r.Scope, r.Interface, r.InterfaceIdx)
	}
	return string(r.ID)
}

// Setting is one inspectable value with everything needed to judge and display it.
type Setting struct {
	SettingRef

	// Value is the effective value, or nil when it is not configured or could not be read.
	// It is a pointer on purpose: on Windows the relevant registry values are frequently
	// absent, which means "use the built-in default", and that is NOT the same as zero.
	Value *int `json:"value"`

	// ValueOrigin says where Value came from, e.g. "cmdlet", "registry", "os-default".
	ValueOrigin string `json:"valueOrigin,omitempty"`

	// Writable reports whether this package can change the value, and WritableReason says
	// why not when it cannot. Both are always populated so the UI never has to guess.
	Writable       bool   `json:"writable"`
	WritableReason string `json:"writableReason,omitempty"`
}

// Display renders the value for a UI or report, distinguishing "not configured" from a
// number, which matters because the two mean different things.
func (s Setting) Display() string {
	if s.Value == nil {
		return "not configured"
	}
	return strconv.Itoa(*s.Value)
}

// Observed is a read result from a backend before it is decorated with writability.
type Observed struct {
	// Value is the value in effect. On Windows an absent registry value means the operating
	// system's built-in default is in effect, so the effective value is still known and is
	// reported here; nil is reserved for a read that genuinely could not produce a value.
	Value *int

	// Explicit reports whether the platform had this setting written down, as opposed to
	// falling back to its own default. It is what lets a restore choose between writing the
	// value back and asking the backend to unset it, and it is shown to the user so a
	// restore can describe what it actually did.
	Explicit bool

	// Origin names where the value was read from. Never empty on success.
	Origin string
}

// Capabilities describes what the running platform actually supports. It is discovered at
// runtime rather than assumed, because Windows builds differ in which cmdlets and parameters
// are present, and because non-Windows hosts have no equivalent at all.
type Capabilities struct {
	// Platform is runtime.GOOS, carried so reports are self-describing.
	Platform string `json:"platform"`

	// Supported is false when this host has no mechanism for the setting at all.
	Supported bool `json:"supported"`

	// Commands lists the inspected command capabilities, keyed by command name.
	Commands []CommandCapability `json:"commands,omitempty"`

	// Notes are human-readable caveats shown in the UI and the export.
	Notes []string `json:"notes,omitempty"`
}

// CommandCapability is the result of probing one external command for one parameter. The
// point of probing is that a command existing does not mean a parameter exists, and an
// argument that is accepted is not proof it had an effect - hence VerifiedBy.Verify reads
// the value back after writing.
type CommandCapability struct {
	Command    string `json:"command"`              // e.g. "Get-NetIPv4Protocol"
	Present    bool   `json:"present"`              // the command resolves
	Parameter  string `json:"parameter,omitempty"`  // parameter that was probed, if any
	HasParam   bool   `json:"hasParam,omitempty"`   // the parameter is accepted
	Detail     string `json:"detail,omitempty"`     // why it is missing, or the probed syntax
	CheckError string `json:"checkError,omitempty"` // the probing error, verbatim and unedited
}

// SettingRefs returns every reference a backend should attempt to read on this platform,
// given the adapters that exist. Ordering is deterministic so reports diff cleanly.
func SettingRefs(ifaces []IfaceInfo) []SettingRef {
	refs := []SettingRef{SystemRef(FamilyIPv4), SystemRef(FamilyIPv6)}
	for _, i := range ifaces {
		refs = append(refs,
			IfaceRef(FamilyIPv4, i.Index, i.Name),
			IfaceRef(FamilyIPv6, i.Index, i.Name),
		)
	}
	sort.SliceStable(refs, func(a, b int) bool { return refs[a].ID < refs[b].ID })
	return refs
}

// IfaceInfo is the minimum an adapter must expose for the TTL manager to address it.
// It is deliberately tiny so the inventory package can build it without an import cycle.
type IfaceInfo struct {
	Index int
	Name  string
}

// NonConfigurableKinds returns the Kinds that are reported for clarity but exist only to be
// distinguished from the configurable ones. They are always ScopeNotApplicable and never
// writable.
func NonConfigurableKinds() []Setting {
	return []Setting{
		{
			SettingRef:     SettingRef{ID: "descriptive.dns-record-ttl", Kind: KindDNSRecordTTL, Scope: ScopeNotApplicable},
			ValueOrigin:    "not-a-host-setting",
			Writable:       false,
			WritableReason: "DNS record TTL is published by the DNS zone that owns the record, not by this PC.",
		},
		{
			SettingRef:     SettingRef{ID: "descriptive.traceroute-hops", Kind: KindTracerouteHops, Scope: ScopeNotApplicable},
			ValueOrigin:    "not-a-host-setting",
			Writable:       false,
			WritableReason: "Traceroute hop count is chosen by the traceroute tool for one run, not stored on this PC.",
		},
	}
}
