// Package file: decoding of the Windows inventory probe.
//
// This file carries no build constraint on purpose. Everything in it is pure logic over the
// bytes a PowerShell probe returns, so the decoding, the PowerShell quirks it tolerates and the
// shapes it refuses are all exercised by the test suite on any host. Only the decision to run
// PowerShell at all lives behind a build constraint (system_windows.go).
package inventory

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// windowsProbeSchema is the shape of the JSON document the probe emits. It is versioned because
// the report and the dashboard both read it, and a probe from an older build of the application
// must be recognisable rather than silently misread.
const windowsProbeSchema = "netmerge.inventory.windows/1"

// psProbeScript queries the documented Windows networking cmdlets and emits one JSON document.
//
// Rules this script follows, because each of them is a way the whole probe could fail:
//
//   - Every cmdlet is optional. A missing cmdlet is reported in `capabilities` and its collector
//     is skipped; a machine with a constrained PowerShell still produces a usable inventory.
//   - A cmdlet that throws does not abort the probe: the message is recorded under `errors` and
//     the collector is left empty, so the dashboard shows "not read" instead of nothing at all.
//   - Only documented properties are selected, and only configuration ones. Nothing here reads
//     a device serial, IMEI, SIM identifier or any other per-device secret: those are not needed
//     to diagnose a link, and not collecting them is stronger than redacting them later.
//   - `elevated` is read without requesting anything, so the dashboard can say honestly whether
//     a settings change will need a UAC prompt.
const psProbeScript = `
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$out = [ordered]@{}
$out.schema = '` + windowsProbeSchema + `'
$out.errors = @()
$out.capabilities = [ordered]@{}
$names = @('Get-NetAdapter','Get-NetIPAddress','Get-NetRoute','Get-NetIPInterface','Get-DnsClientServerAddress','Get-NetAdapterStatistics')
foreach ($n in $names) { $out.capabilities[$n] = [bool](Get-Command $n -ErrorAction SilentlyContinue) }
function Collect([string]$key, [string]$cmdlet, [scriptblock]$body) {
  if (-not $out.capabilities[$cmdlet]) { return }
  try { $out[$key] = @(& $body) } catch { $out.errors += @([ordered]@{ collector = $key; message = $_.Exception.Message }); $out[$key] = @() }
}
try {
  Collect 'adapters' 'Get-NetAdapter' {
    Get-NetAdapter | Select-Object Name,InterfaceDescription,InterfaceIndex,ifIndex,InterfaceGuid,Status,AdminStatus,MediaConnectionState,MediaType,PhysicalMediaType,MacAddress,LinkSpeed,MtuSize,InterfaceType,DriverProvider,DriverVersion
  }
  Collect 'ipv4' 'Get-NetIPAddress' {
    Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceIndex,InterfaceAlias,IPAddress,PrefixLength,PrefixOrigin,SuffixOrigin,AddressOrigin,AddressState,Dhcp,SkipAsSource
  }
  Collect 'ipv6' 'Get-NetIPAddress' {
    Get-NetIPAddress -AddressFamily IPv6 | Select-Object InterfaceIndex,InterfaceAlias,IPAddress,PrefixLength,PrefixOrigin,SuffixOrigin,AddressOrigin,AddressState,Dhcp,SkipAsSource
  }
  Collect 'routes' 'Get-NetRoute' {
    Get-NetRoute | Select-Object AddressFamily,InterfaceIndex,InterfaceAlias,DestinationPrefix,NextHop,RouteMetric,InterfaceMetric,Protocol,Store,State
  }
  Collect 'ipinterfaces' 'Get-NetIPInterface' {
    Get-NetIPInterface | Select-Object InterfaceIndex,InterfaceAlias,AddressFamily,ConnectionState,Dhcp,NlMtu,InterfaceMetric,Forwarding,AdvertiseDefaultRoute,IgnoreDefaultRoutes
  }
  Collect 'dns' 'Get-DnsClientServerAddress' {
    Get-DnsClientServerAddress | Select-Object InterfaceIndex,InterfaceAlias,AddressFamily,ServerAddresses
  }
  Collect 'statistics' 'Get-NetAdapterStatistics' {
    Get-NetAdapterStatistics | Select-Object Name,InterfaceIndex,ReceivedBytes,SentBytes,ReceivedUnicastPackets,SentUnicastPackets,ReceivedDiscardedPackets,OutboundDiscardedPackets,ReceivedPacketErrors,OutboundPacketErrors
  }
} catch {
  $out.errors += @([ordered]@{ collector = 'probe'; message = $_.Exception.Message })
}
$out.elevated = $false
try {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $out.elevated = ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { }
$out | ConvertTo-Json -Depth 4 -Compress
`

// probeDoc is the decoded probe. Collections are kept as raw JSON because PowerShell's
// ConvertTo-Json emits a bare object instead of a one-element array, which is the single most
// common way a decoder written against the array shape breaks on a real machine.
type probeDoc struct {
	Schema       string          `json:"schema"`
	Errors       []probeError    `json:"errors"`
	Capabilities map[string]bool `json:"capabilities"`
	Elevated     bool            `json:"elevated"`
	Adapters     json.RawMessage `json:"adapters"`
	IPv4         json.RawMessage `json:"ipv4"`
	IPv6         json.RawMessage `json:"ipv6"`
	Routes       json.RawMessage `json:"routes"`
	IPInterfaces json.RawMessage `json:"ipinterfaces"`
	DNS          json.RawMessage `json:"dns"`
	Statistics   json.RawMessage `json:"statistics"`
	parseErr     error           `json:"-"`
}

// probeError is one collector that could not run.
type probeError struct {
	Collector string `json:"collector"`
	Message   string `json:"message"`
}

// parseProbe decodes the probe document into adapters and routes plus the gaps and errors worth
// reporting. It is tolerant by design: a missing collection is a gap, an unparsable one is an
// error, and either way the caller still gets whatever the other collectors returned.
func parseProbe(raw []byte) (adapters []Adapter, routes []Route, gaps []string, errs []string, err error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, nil, nil, nil, fmt.Errorf("the inventory probe returned no output at all")
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber() // PowerShell emits 64-bit counters; float64 would silently round them
	var doc probeDoc
	if derr := dec.Decode(&doc); derr != nil {
		// A transcript can carry a warning line before the JSON. Find the document rather than
		// failing outright, because that is what actually happens on a real machine.
		if idx := bytes.IndexByte(trimmed, '{'); idx > 0 {
			dec = json.NewDecoder(bytes.NewReader(trimmed[idx:]))
			dec.UseNumber()
			derr = dec.Decode(&doc)
		}
		if derr != nil {
			return nil, nil, nil, nil, fmt.Errorf("the inventory probe output was not JSON: %w", derr)
		}
	}
	if doc.Schema != windowsProbeSchema {
		gaps = append(gaps, fmt.Sprintf(
			"the inventory probe reported schema %q, expected %q: fields it does not carry are reported as gaps",
			doc.Schema, windowsProbeSchema))
	}
	for _, e := range doc.Errors {
		errs = append(errs, fmt.Sprintf("%s collector: %s", e.Collector, strings.TrimSpace(e.Message)))
	}

	byIndex := map[int]*Adapter{}
	order := []int{}

	adapterRows := psObjs(doc.Adapters)
	if len(adapterRows) == 0 {
		if !doc.Capabilities["Get-NetAdapter"] {
			gaps = append(gaps, "Get-NetAdapter is not available on this host, so adapters could not be listed by the NetTCPIP module")
		} else {
			errs = append(errs, "Get-NetAdapter returned no adapters")
		}
	}
	for _, obj := range adapterRows {
		a := Adapter{
			Name:        obj.str("Name"),
			Description: obj.str("InterfaceDescription"),
			GUID:        obj.str("InterfaceGuid"),
			IfAlias:     obj.str("InterfaceAlias", "Name"),
			Index:       obj.intOf("ifIndex", "InterfaceIndex"),
			IndexV6:     obj.intOf("ifIndex", "InterfaceIndex"),
			MAC:         obj.str("MacAddress"),
			MediaType:   firstNonEmpty(obj.str("MediaType"), obj.str("PhysicalMediaType")),
			Admin:       strings.ToLower(obj.str("AdminStatus")),
			Media:       obj.mediaConnectionState(),
			SpeedBps:    ParseLinkSpeed(obj.str("LinkSpeed")),
			MTU:         obj.intOf("MtuSize"),
			DHCP4:       TriUnknown,
			DHCP6:       TriUnknown,
			Link:        obj.linkState(),
		}
		ifType, _ := obj.enum("InterfaceType")
		a.DriverProvider = obj.str("DriverProvider")
		a.DriverVersion = obj.str("DriverVersion")
		kind, reason := Classify(ClassifyInput{
			Name: a.Name, Description: a.Description, IfType: ifType, MediaType: a.MediaType,
		})
		a.Kind, a.VirtualReason = kind, reason
		a.Hardware = reason == ""

		if a.Index == 0 {
			errs = append(errs, fmt.Sprintf("adapter %q has no interface index and cannot be attributed", a.Name))
			continue
		}
		ifa := a
		byIndex[a.Index] = &ifa
		order = append(order, a.Index)
	}

	// Addresses, per family.
	attachAddresses := func(raw json.RawMessage, family string) {
		for _, obj := range psObjs(raw) {
			idx := obj.intOf("InterfaceIndex")
			a, ok := byIndex[idx]
			if !ok {
				continue
			}
			addr := Address{
				Address: obj.str("IPAddress"),
				Prefix:  obj.intOf("PrefixLength"),
				Origin:  firstNonEmpty(obj.str("PrefixOrigin"), obj.str("AddressOrigin")),
				Status:  obj.str("AddressState"),
			}
			if obj.boolOf("SkipAsSource") {
				addr.Virtual = true
			}
			if addr.Address == "" {
				continue
			}
			addr.LinkLocal = isLinkLocalText(addr.Address, family)
			if family == "v4" {
				a.IPv4 = append(a.IPv4, addr)
			} else {
				a.IPv6 = append(a.IPv6, addr)
			}
		}
	}
	attachAddresses(doc.IPv4, "v4")
	attachAddresses(doc.IPv6, "v6")

	// Routes: the routing table is returned in full, and each default route is attributed to its
	// adapter as its gateway. A default route with an on-link next hop (0.0.0.0 or ::) has no
	// gateway address but is still a route to the internet, which is why the family flag is
	// tracked separately from the gateway list.
	for _, obj := range psObjs(doc.Routes) {
		idx := obj.intOf("InterfaceIndex")
		family := familyOf(obj.str("AddressFamily"))
		dest := obj.str("DestinationPrefix")
		nextHop := obj.str("NextHop")
		r := Route{
			Family:      family,
			Destination: dest,
			NextHop:     nextHop,
			Index:       idx,
			Name:        obj.str("InterfaceAlias"),
			Metric:      obj.intOf("RouteMetric", "InterfaceMetric"),
			Protocol:    strings.ToLower(obj.str("Protocol")),
			Default:     isDefaultRoute(dest),
		}
		routes = append(routes, r)
		a, ok := byIndex[idx]
		if !ok {
			continue
		}
		if a.Name == "" {
			a.Name = r.Name
		}
		if !r.Default {
			continue
		}
		if family == "v6" {
			a.DefaultRoute6 = true
			if !isOnLink(nextHop) && !containsFold(a.Gateways6, nextHop) {
				a.Gateways6 = append(a.Gateways6, nextHop)
			}
			if obj.intOf("InterfaceMetric") > 0 {
				a.Metric6 = intPtrOf(obj.intOf("InterfaceMetric"))
			}
			continue
		}
		a.DefaultRoute4 = true
		if !isOnLink(nextHop) && !containsFold(a.Gateways4, nextHop) {
			a.Gateways4 = append(a.Gateways4, nextHop)
		}
		if obj.intOf("InterfaceMetric") > 0 {
			a.Metric4 = intPtrOf(obj.intOf("InterfaceMetric"))
		}
	}

	// Per-family interface settings: DHCP state, metric and MTU.
	for _, obj := range psObjs(doc.IPInterfaces) {
		a, ok := byIndex[obj.intOf("InterfaceIndex")]
		if !ok {
			continue
		}
		switch familyOf(obj.str("AddressFamily")) {
		case "v6":
			a.DHCP6 = triFrom(obj.str("Dhcp"))
			if v := obj.intOf("InterfaceMetric"); v > 0 {
				a.Metric6 = intPtrOf(v)
			}
			if v := obj.intOf("NlMtu", "NlMtuBytes", "Mtu"); v > 0 {
				a.MTU6 = intPtrOf(v)
			}
		default:
			a.DHCP4 = triFrom(obj.str("Dhcp"))
			if v := obj.intOf("InterfaceMetric"); v > 0 {
				a.Metric4 = intPtrOf(v)
			}
			if v := obj.intOf("NlMtu", "NlMtuBytes", "Mtu"); v > 0 {
				a.MTU4 = intPtrOf(v)
			}
		}
	}

	// DNS servers per family.
	for _, obj := range psObjs(doc.DNS) {
		a, ok := byIndex[obj.intOf("InterfaceIndex")]
		if !ok {
			continue
		}
		servers := obj.strList("ServerAddresses")
		if len(servers) == 0 {
			continue
		}
		if familyOf(obj.str("AddressFamily")) == "v6" {
			a.DNS6 = append(a.DNS6, servers...)
		} else {
			a.DNS4 = append(a.DNS4, servers...)
		}
	}

	// Statistics are a fallback for byte counters when the native API cannot be read.
	for _, obj := range psObjs(doc.Statistics) {
		a, ok := byIndex[obj.intOf("InterfaceIndex")]
		if !ok {
			continue
		}
		in, okIn := obj.uintOf("ReceivedBytes")
		out, okOut := obj.uintOf("SentBytes")
		if okIn || okOut {
			a.ProbeCounters = &Counters{In: in, Out: out}
		}
	}

	for _, idx := range order {
		adapters = append(adapters, *byIndex[idx])
	}
	for i := range adapters {
		adapters[i].Gaps = dropEmpty(adapters[i].Gaps)
		if adapters[i].Media == "" {
			adapters[i].Gaps = append(adapters[i].Gaps, "media connection state not reported by this Windows build")
		}
		if adapters[i].MTU4 == nil && adapters[i].MTU6 == nil && adapters[i].MTU == 0 {
			adapters[i].Gaps = append(adapters[i].Gaps, "MTU not reported")
		}
		if adapters[i].DHCP4 == TriUnknown && adapters[i].DHCP6 == TriUnknown {
			adapters[i].Gaps = append(adapters[i].Gaps, "DHCP state not reported (Get-NetIPInterface unavailable)")
		}
	}
	if !doc.Capabilities["Get-NetRoute"] {
		gaps = append(gaps, "Get-NetRoute is not available: gateways were read from the address table instead of the routing table")
	}
	if !doc.Capabilities["Get-DnsClientServerAddress"] {
		gaps = append(gaps, "Get-DnsClientServerAddress is not available: DNS servers could not be read")
	}
	if !doc.Capabilities["Get-NetAdapterStatistics"] {
		gaps = append(gaps, "Get-NetAdapterStatistics is not available: the probe's byte counters are not collected on this host")
	}
	return adapters, routes, gaps, errs, nil
}

// psArray normalises the three shapes ConvertTo-Json produces for a collection: an array, a
// single bare object (one element), or null/absent (none). Getting this wrong is the classic
// "works on my machine with two adapters, breaks on the laptop with one" bug.
func psArray(raw json.RawMessage) []json.RawMessage {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	switch trimmed[0] {
	case '[':
		var items []json.RawMessage
		if err := json.Unmarshal(trimmed, &items); err != nil {
			return nil
		}
		return items
	case '{':
		return []json.RawMessage{trimmed}
	default:
		return nil
	}
}

// psObjs decodes a collection of PowerShell objects, skipping any element that is not an
// object. A single bad row must not lose the rows around it.
func psObjs(raw json.RawMessage) []psObj {
	items := psArray(raw)
	out := make([]psObj, 0, len(items))
	for _, item := range items {
		var o psObj
		if err := json.Unmarshal(item, &o); err != nil {
			continue
		}
		out = append(out, o)
	}
	return out
}

// psObj is one PowerShell object, with the property access helpers below. Keeping the raw
// messages means a property that changed type between PowerShell versions (an enum serialised
// as a name on one build and a number on another) is handled at the point of use instead of
// failing the whole decode.
type psObj map[string]json.RawMessage

func (o psObj) raw(keys ...string) (json.RawMessage, bool) {
	for _, k := range keys {
		if v, ok := o[k]; ok {
			trimmed := bytes.TrimSpace(v)
			if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
				continue
			}
			return v, true
		}
	}
	return nil, false
}

// str returns the first present value as text. Numbers and booleans are rendered rather than
// rejected: PowerShell reports some enums as booleans and some identifiers as numbers.
func (o psObj) str(keys ...string) string {
	v, ok := o.raw(keys...)
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(v, &s); err == nil {
		return strings.TrimSpace(s)
	}
	var n json.Number
	if err := json.Unmarshal(v, &n); err == nil {
		return n.String()
	}
	var b bool
	if err := json.Unmarshal(v, &b); err == nil {
		return strconv.FormatBool(b)
	}
	return strings.Trim(strings.TrimSpace(string(v)), `"`)
}

// intOf returns the first present value as an integer, and 0 when it cannot be read. Callers that
// must distinguish 0 from absent use the boolean variant.
func (o psObj) intOf(keys ...string) int {
	v, ok := o.intOk(keys...)
	if !ok {
		return 0
	}
	return v
}

func (o psObj) intOk(keys ...string) (int, bool) {
	raw, ok := o.raw(keys...)
	if !ok {
		return 0, false
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err == nil {
		if i, err := n.Int64(); err == nil {
			return int(i), true
		}
		if f, err := n.Float64(); err == nil {
			return int(f), true
		}
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if i, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
			return i, true
		}
	}
	return 0, false
}

func (o psObj) uintOf(keys ...string) (uint64, bool) {
	raw, ok := o.raw(keys...)
	if !ok {
		return 0, false
	}
	var n json.Number
	if err := json.Unmarshal(raw, &n); err == nil {
		if u, err := strconv.ParseUint(n.String(), 10, 64); err == nil {
			return u, true
		}
		if f, err := n.Float64(); err == nil && f >= 0 {
			return uint64(f), true
		}
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if u, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64); err == nil {
			return u, true
		}
	}
	return 0, false
}

func (o psObj) boolOf(keys ...string) bool {
	raw, ok := o.raw(keys...)
	if !ok {
		return false
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		return b
	}
	switch strings.ToLower(o.str(keys...)) {
	case "true", "yes", "1", "enabled":
		return true
	}
	return false
}

// strList reads a property that is either a list of strings or a single string.
func (o psObj) strList(keys ...string) []string {
	raw, ok := o.raw(keys...)
	if !ok {
		return nil
	}
	if items := psArray(raw); len(items) > 0 {
		var out []string
		for _, item := range items {
			var s string
			if err := json.Unmarshal(item, &s); err == nil && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	}
	if s := o.str(keys...); s != "" {
		return strings.Split(s, ",")
	}
	return nil
}

// enum reads an IANA interface type, accepting either the number or the name PowerShell prints
// for it. Both appear in the wild: the same cmdlet emits 6 on one build and "Ethernet" on
// another, and a decoder that assumes one silently classifies every adapter as unknown.
func (o psObj) enum(keys ...string) (uint32, bool) {
	if v, ok := o.intOk(keys...); ok && v > 0 {
		return uint32(v), true
	}
	switch strings.ToLower(o.str(keys...)) {
	case "other":
		return 1, true
	case "ethernet", "ethernetcsma", "ethernet3mbit", "ethernetcsmacd", "fastethernet", "gigabitethernet":
		return 6, true
	case "ppp":
		return 23, true
	case "loopback", "softwareloopback":
		return 24, true
	case "proprietaryvirtual", "proprietaryvirtualinternal":
		return 53, true
	case "ieee80211", "wireless80211", "wifi", "wi-fi", "native80211":
		return 71, true
	case "tunnel":
		return 131, true
	case "wwanpp":
		return 243, true
	case "wwanpp2":
		return 244, true
	case "unknown", "unspecified":
		return 0, false
	}
	return 0, false
}

// mediaConnectionState decodes the media state enum, which Windows reports as Connected /
// Disconnected on most builds and as a number on some.
func (o psObj) mediaConnectionState() string {
	switch strings.ToLower(o.str("MediaConnectionState")) {
	case "connected", "1":
		return "connected"
	case "disconnected", "0":
		return "disconnected"
	case "", "unknown", "2", "3":
		return ""
	}
	return strings.ToLower(o.str("MediaConnectionState"))
}

// linkState normalises the several status vocabularies Windows uses for the same question.
func (o psObj) linkState() LinkState {
	status := strings.ToLower(o.str("Status"))
	if status == "" {
		switch strings.ToLower(o.str("AdminStatus")) {
		case "down", "disabled":
			return LinkDisabled
		}
		return LinkUnknown
	}
	switch status {
	case "up", "connected":
		return LinkUp
	case "down", "lowerlayerdown", "notpresent", "unreachable":
		return LinkDown
	case "disabled":
		return LinkDisabled
	}
	if m := strings.ToLower(o.str("MediaConnectionState")); m == "disconnected" || m == "0" {
		return LinkDown
	}
	return LinkUnknown
}

// familyOf normalises the family vocabulary: the cmdlets print IPv4/IPv6, the numeric values
// come from the AF_* constants, and some builds print "v4"/"v6".
func familyOf(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "ipv6", "v6", "23", "af_inet6":
		return "v6"
	case "ipv4", "v4", "2", "af_inet":
		return "v4"
	}
	return ""
}

// triFrom decodes the Dhcp property, which is Enabled/Disabled on most builds and 1/0 on some.
func triFrom(s string) Tri {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "enabled", "yes", "true", "1":
		return TriYes
	case "disabled", "no", "false", "0":
		return TriNo
	}
	return TriUnknown
}

// isLinkLocalText reports whether an address is link-local for its family. Windows reports
// 169.254.x.x for a failed DHCP lease and fe80:: on every IPv6-capable interface, and both mean
// "this address cannot reach the internet".
func isLinkLocalText(addr, family string) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return false
	}
	if family == "v6" {
		return strings.HasPrefix(strings.ToLower(addr), "fe80")
	}
	return strings.HasPrefix(addr, "169.254.")
}

// isOnLink reports whether a route's next hop is the interface itself rather than a gateway.
func isOnLink(nextHop string) bool {
	switch strings.TrimSpace(nextHop) {
	case "", "0.0.0.0", "::", "::0":
		return true
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func dropEmpty(in []string) []string {
	var out []string
	for _, s := range in {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

// jsonUnmarshalLoose decodes JSON that may be preceded by whatever else the interpreter printed.
// PowerShell writes warnings to the same stream as data, so a capability probe's output can
// legitimately start with a line that is not JSON; looking for the document is more truthful than
// failing the whole probe.
func jsonUnmarshalLoose(s string, v any) error {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return fmt.Errorf("no output to decode")
	}
	dec := json.NewDecoder(strings.NewReader(trimmed))
	dec.UseNumber()
	if err := dec.Decode(v); err == nil {
		return nil
	}
	if idx := strings.IndexByte(trimmed, '['); idx >= 0 {
		dec = json.NewDecoder(strings.NewReader(trimmed[idx:]))
		dec.UseNumber()
		return dec.Decode(v)
	}
	if idx := strings.IndexByte(trimmed, '{'); idx >= 0 {
		dec = json.NewDecoder(strings.NewReader(trimmed[idx:]))
		dec.UseNumber()
		return dec.Decode(v)
	}
	return fmt.Errorf("no JSON document in the output")
}

func intPtrOf(v int) *int { return &v }
