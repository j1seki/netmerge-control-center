package inventory

// Tests for decoding the Windows probe output.
//
// The fixtures below are the shapes ConvertTo-Json actually produces, including the ones that
// break naive decoders: a one-element collection arrives as a bare object rather than an array,
// enums arrive as names on one Windows build and numbers on another, and 64-bit byte counters
// exceed what a float64 can hold exactly. Everything here is a SIMULATION: the fixtures are
// recorded documents, no PowerShell process runs, and these tests cannot and do not claim that
// Windows behaves as described - they claim that the decoder handles what Windows is documented
// and observed to emit.

import (
	"strings"
	"testing"

	"net-merge/internal/nics"
)

// nics_PhysicalIfType keeps the assertion above reading as a statement about the shared rule.
func nics_PhysicalIfType(t uint32) bool { return nics.PhysicalIfType(t) }

// fullProbe is a document in the shape the probe emits for a machine with a wired link, a Wi-Fi
// adapter that has no default route, a USB-tethered phone that is unplugged, and a Hyper-V switch.
// Statistics arrive as a single bare object on purpose: that is the one-element case.
const fullProbe = `{
  "schema": "netmerge.inventory.windows/1",
  "errors": [{"collector":"ipv6","message":"No MSFT_NetIPAddress objects found"}],
  "capabilities": {"Get-NetAdapter":true,"Get-NetIPAddress":true,"Get-NetRoute":true,"Get-NetIPInterface":true,"Get-DnsClientServerAddress":true,"Get-NetAdapterStatistics":false},
  "elevated": true,
  "adapters": [
    {"Name":"Ethernet","InterfaceDescription":"Intel(R) Ethernet Connection (17) I219-V","InterfaceIndex":7,"ifIndex":7,"InterfaceGuid":"{4f6b1d6e-1111-4a2b-9c3d-000000000001}","Status":"Up","AdminStatus":"Up","MediaConnectionState":"Connected","MediaType":"802.3","PhysicalMediaType":"802.3","MacAddress":"AA-BB-CC-DD-EE-01","LinkSpeed":"1 Gbps","MtuSize":1500,"InterfaceType":6,"DriverProvider":"Intel","DriverVersion":"12.19.2.50"},
    {"Name":"Wi-Fi","InterfaceDescription":"Intel(R) Wi-Fi 6E AX211 160MHz","InterfaceIndex":12,"ifIndex":12,"InterfaceGuid":"{4f6b1d6e-1111-4a2b-9c3d-000000000002}","Status":"Up","AdminStatus":"Up","MediaConnectionState":1,"MediaType":"Native 802.11","PhysicalMediaType":"Native 802.11","MacAddress":"AA-BB-CC-DD-EE-02","LinkSpeed":"866.7 Mbps","MtuSize":1500,"InterfaceType":"Wireless80211","DriverProvider":"Intel","DriverVersion":"22.250.0.4"},
    {"Name":"Ethernet 3","InterfaceDescription":"Remote NDIS based Internet Sharing Device","InterfaceIndex":21,"ifIndex":21,"InterfaceGuid":"{4f6b1d6e-1111-4a2b-9c3d-000000000003}","Status":"Down","AdminStatus":"Up","MediaConnectionState":"Disconnected","MediaType":"802.3","PhysicalMediaType":"802.3","MacAddress":"02-1E-101-11-22-33","LinkSpeed":"426 Mbps","MtuSize":1500,"InterfaceType":6,"DriverProvider":"Microsoft","DriverVersion":"10.0.22621.1"},
    {"Name":"vEthernet (Default Switch)","InterfaceDescription":"Hyper-V Virtual Ethernet Adapter","InterfaceIndex":32,"ifIndex":32,"InterfaceGuid":"{4f6b1d6e-1111-4a2b-9c3d-000000000004}","Status":"Up","AdminStatus":"Up","MediaConnectionState":"Connected","MediaType":"802.3","PhysicalMediaType":"802.3","MacAddress":"00-15-5D-00-01-02","LinkSpeed":"10 Gbps","MtuSize":1500,"InterfaceType":6,"DriverProvider":"Microsoft","DriverVersion":"10.0.22621.1"}
  ],
  "ipv4": [
    {"InterfaceIndex":7,"InterfaceAlias":"Ethernet","IPAddress":"192.168.1.10","PrefixLength":24,"PrefixOrigin":"Dhcp","SuffixOrigin":"Dhcp","AddressState":"Preferred","Dhcp":"Enabled","SkipAsSource":false},
    {"InterfaceIndex":12,"InterfaceAlias":"Wi-Fi","IPAddress":"192.168.137.42","PrefixLength":24,"PrefixOrigin":"Manual","SuffixOrigin":"Manual","AddressState":"Preferred","Dhcp":"Disabled","SkipAsSource":false},
    {"InterfaceIndex":21,"InterfaceAlias":"Ethernet 3","IPAddress":"169.254.77.3","PrefixLength":16,"PrefixOrigin":"WellKnown","SuffixOrigin":"Link","AddressState":"Preferred","Dhcp":"Enabled","SkipAsSource":false},
    {"InterfaceIndex":32,"InterfaceAlias":"vEthernet (Default Switch)","IPAddress":"172.28.160.1","PrefixLength":20,"PrefixOrigin":"Manual","SuffixOrigin":"Manual","AddressState":"Preferred","Dhcp":"Disabled","SkipAsSource":false}
  ],
  "ipv6": [
    {"InterfaceIndex":7,"InterfaceAlias":"Ethernet","IPAddress":"2001:db8:1234::10","PrefixLength":64,"PrefixOrigin":"RouterAdvertisement","SuffixOrigin":"Random","AddressState":"Preferred","Dhcp":"Disabled","SkipAsSource":false},
    {"InterfaceIndex":7,"InterfaceAlias":"Ethernet","IPAddress":"fe80::3c4d:5e6f:7a8b:9c0d%7","PrefixLength":64,"PrefixOrigin":"WellKnown","SuffixOrigin":"Link","AddressState":"Preferred","Dhcp":"Disabled","SkipAsSource":false}
  ],
  "routes": [
    {"AddressFamily":"IPv4","InterfaceIndex":7,"InterfaceAlias":"Ethernet","DestinationPrefix":"0.0.0.0/0","NextHop":"192.168.1.1","RouteMetric":0,"InterfaceMetric":25,"Protocol":"Dhcp","Store":"Active"},
    {"AddressFamily":"IPv6","InterfaceIndex":7,"InterfaceAlias":"Ethernet","DestinationPrefix":"::/0","NextHop":"fe80::1","RouteMetric":0,"InterfaceMetric":25,"Protocol":"RouterAdvertisement","Store":"Active"},
    {"AddressFamily":"IPv4","InterfaceIndex":12,"InterfaceAlias":"Wi-Fi","DestinationPrefix":"192.168.137.0/24","NextHop":"0.0.0.0","RouteMetric":0,"InterfaceMetric":55,"Protocol":"NetMgmt","Store":"Active"},
    {"AddressFamily":"IPv4","InterfaceIndex":32,"InterfaceAlias":"vEthernet (Default Switch)","DestinationPrefix":"172.28.160.0/20","NextHop":"0.0.0.0","RouteMetric":0,"InterfaceMetric":5256,"Protocol":"NetMgmt","Store":"Active"}
  ],
  "ipinterfaces": [
    {"InterfaceIndex":7,"InterfaceAlias":"Ethernet","AddressFamily":"IPv4","ConnectionState":"Connected","Dhcp":"Enabled","NlMtu":1500,"InterfaceMetric":25},
    {"InterfaceIndex":7,"InterfaceAlias":"Ethernet","AddressFamily":"IPv6","ConnectionState":"Connected","Dhcp":"Disabled","NlMtu":1500,"InterfaceMetric":25},
    {"InterfaceIndex":12,"InterfaceAlias":"Wi-Fi","AddressFamily":"IPv4","ConnectionState":"Connected","Dhcp":"Disabled","NlMtu":1480,"InterfaceMetric":55},
    {"InterfaceIndex":21,"InterfaceAlias":"Ethernet 3","AddressFamily":"IPv4","ConnectionState":"Disconnected","Dhcp":"Enabled","NlMtu":1500,"InterfaceMetric":65},
    {"InterfaceIndex":32,"InterfaceAlias":"vEthernet (Default Switch)","AddressFamily":"IPv4","ConnectionState":"Connected","Dhcp":"Disabled","NlMtu":1500,"InterfaceMetric":5256}
  ],
  "dns": [
    {"InterfaceIndex":7,"InterfaceAlias":"Ethernet","AddressFamily":"IPv4","ServerAddresses":["192.168.1.1","9.9.9.9"]},
    {"InterfaceIndex":7,"InterfaceAlias":"Ethernet","AddressFamily":"IPv6","ServerAddresses":"2001:db8:1234::1"},
    {"InterfaceIndex":12,"InterfaceAlias":"Wi-Fi","AddressFamily":"IPv4","ServerAddresses":["192.168.137.1"]}
  ],
  "statistics": {"Name":"Ethernet","InterfaceIndex":7,"ReceivedBytes":9007199254740993,"SentBytes":12345678901234,"ReceivedDiscardedPackets":0,"OutboundPacketErrors":2}
}`

func TestParseProbeDecodesRealWindowsShapes(t *testing.T) {
	adapters, routes, gaps, errs, err := parseProbe([]byte(fullProbe))
	if err != nil {
		t.Fatalf("parseProbe: %v", err)
	}
	if len(adapters) != 4 {
		t.Fatalf("adapters = %d, want 4", len(adapters))
	}
	if len(errs) != 1 || !strings.Contains(errs[0], "ipv6 collector") {
		t.Errorf("errors = %v, want the ipv6 collector failure reported", errs)
	}
	if len(gaps) == 0 {
		t.Error("gaps is empty, want the unavailable Get-NetAdapterStatistics noted")
	}

	eth, ok := findByName(adapters, "Ethernet")
	if !ok {
		t.Fatal("the wired adapter was not decoded")
	}
	if eth.Index != 7 || eth.GUID == "" || eth.DriverVersion != "12.19.2.50" {
		t.Errorf("wired adapter = %+v, want index, GUID and driver version decoded", eth)
	}
	if eth.SpeedBps != 1_000_000_000 {
		t.Errorf("link speed = %d, want 1 Gbps parsed from %q", eth.SpeedBps, "1 Gbps")
	}
	if eth.Kind != KindEthernet || !eth.Hardware {
		t.Errorf("kind = %q hardware = %v, want a real Ethernet adapter", eth.Kind, eth.Hardware)
	}
	if !eth.DefaultRoute4 || len(eth.Gateways4) != 1 || eth.Gateways4[0] != "192.168.1.1" {
		t.Errorf("gateways = %v, want the IPv4 default route's next hop", eth.Gateways4)
	}
	if !eth.DefaultRoute6 || len(eth.Gateways6) != 1 {
		t.Errorf("IPv6 default route not decoded: %+v", eth.Gateways6)
	}
	if eth.Metric4 == nil || *eth.Metric4 != 25 {
		t.Errorf("IPv4 metric = %v, want 25", eth.Metric4)
	}
	if eth.DHCP4 != TriYes || eth.DHCP6 != TriNo {
		t.Errorf("DHCP = %q/%q, want yes/no per family", eth.DHCP4, eth.DHCP6)
	}
	if len(eth.DNS4) != 2 || len(eth.DNS6) != 1 {
		t.Errorf("DNS = %v / %v, want two IPv4 servers and one single-string IPv6 server", eth.DNS4, eth.DNS6)
	}
	if len(eth.IPv6) != 2 || !eth.IPv6[1].LinkLocal {
		t.Errorf("IPv6 addresses = %+v, want the link-local one flagged", eth.IPv6)
	}
	if got := eth.ProbeCounters; got == nil || got.In != 9007199254740993 {
		t.Errorf("probe counters = %+v, want the 64-bit value preserved exactly", got)
	}

	wifi, _ := findByName(adapters, "Wi-Fi")
	if wifi.Kind != KindWiFi {
		t.Errorf("Wi-Fi kind = %q, want wifi decoded from the enum name", wifi.Kind)
	}
	if wifi.Media != "connected" {
		t.Errorf("Wi-Fi media state = %q, want the numeric 1 decoded as connected", wifi.Media)
	}
	if wifi.DefaultRoute4 {
		t.Error("Wi-Fi has no default route in the fixture; it must not be marked as one")
	}
	if wifi.SpeedBps != 866_700_000 {
		t.Errorf("Wi-Fi speed = %d, want 866.7 Mbps", wifi.SpeedBps)
	}

	phone, _ := findByName(adapters, "Ethernet 3")
	if phone.Kind != KindUSBTether {
		t.Errorf("phone kind = %q, want usb-tether recognised from the RNDIS description", phone.Kind)
	}
	if phone.Link != LinkDown {
		t.Errorf("phone link = %q, want down", phone.Link)
	}
	if phone.IPv4[0].LinkLocal == false {
		t.Error("the 169.254 address must be flagged link-local")
	}

	vm, _ := findByName(adapters, "vEthernet (Default Switch)")
	if vm.Hardware || vm.VirtualReason == "" {
		t.Errorf("the Hyper-V switch must be classified as virtual: hardware=%v reason=%q", vm.Hardware, vm.VirtualReason)
	}

	if len(routes) != 4 {
		t.Fatalf("routes = %d, want 4", len(routes))
	}
	var defaults int
	for _, r := range routes {
		if r.Default {
			defaults++
		}
	}
	if defaults != 2 {
		t.Errorf("default routes = %d, want the IPv4 and IPv6 ones", defaults)
	}
}

func TestParseProbeHandlesOneElementCollections(t *testing.T) {
	// A bare object where an array is expected is the shape that breaks a decoder written
	// against two-element fixtures.
	const oneAdapter = `{"schema":"netmerge.inventory.windows/1","capabilities":{"Get-NetAdapter":true,"Get-NetRoute":true,"Get-NetIPInterface":true,"Get-DnsClientServerAddress":true},
      "adapters":{"Name":"Ethernet","InterfaceDescription":"Realtek PCIe GbE Family Controller","InterfaceIndex":4,"ifIndex":4,"Status":"Up","AdminStatus":"Up","MediaConnectionState":"Connected","LinkSpeed":"100 Mbps","MtuSize":1500,"InterfaceType":6},
      "ipv4":{"InterfaceIndex":4,"InterfaceAlias":"Ethernet","IPAddress":"10.0.0.5","PrefixLength":24,"PrefixOrigin":"Dhcp","AddressState":"Preferred","Dhcp":"Enabled"},
      "routes":{"AddressFamily":"IPv4","InterfaceIndex":4,"InterfaceAlias":"Ethernet","DestinationPrefix":"0.0.0.0/0","NextHop":"10.0.0.1","RouteMetric":0,"InterfaceMetric":5,"Protocol":"Dhcp"},
      "ipinterfaces":{"InterfaceIndex":4,"InterfaceAlias":"Ethernet","AddressFamily":"IPv4","ConnectionState":"Connected","Dhcp":"Enabled","NlMtu":1500,"InterfaceMetric":5},
      "dns":{"InterfaceIndex":4,"InterfaceAlias":"Ethernet","AddressFamily":"IPv4","ServerAddresses":["10.0.0.1"]}}`

	adapters, routes, _, _, err := parseProbe([]byte(oneAdapter))
	if err != nil {
		t.Fatalf("parseProbe: %v", err)
	}
	if len(adapters) != 1 || len(routes) != 1 {
		t.Fatalf("adapters = %d routes = %d, want one of each", len(adapters), len(routes))
	}
	a := adapters[0]
	if a.Index != 4 || a.Metric4 == nil || *a.Metric4 != 5 {
		t.Errorf("adapter = %+v, want the per-family metric decoded from the bare object", a)
	}
	if len(a.DNS4) != 1 || a.DNS4[0] != "10.0.0.1" {
		t.Errorf("DNS = %v, want the single server", a.DNS4)
	}
	if !a.DefaultRoute4 {
		t.Error("the single default route in the bare object was not attributed")
	}
}

func TestParseProbeRejectsGarbageWithoutInventingAdapters(t *testing.T) {
	cases := map[string]string{
		"empty output":       "",
		"whitespace":         "  \n\t ",
		"a PowerShell error": "powershell.exe : The term 'Get-NetAdapter' is not recognized as the name of a cmdlet.\nAt line:1 char:1\n+ Get-NetAdapter\n+ ~~~~~~~~~~~~~~",
		"truncated json":     `{"schema":"netmerge.inventory.windows/1","adapters":[{"Name":"Eth`,
	}
	for name, input := range cases {
		adapters, _, _, _, err := parseProbe([]byte(input))
		if err == nil {
			t.Errorf("%s: parseProbe returned no error and %d adapters", name, len(adapters))
			continue
		}
		if len(adapters) != 0 {
			t.Errorf("%s: adapters = %d, want none rather than a partial invention", name, len(adapters))
		}
	}
}

func TestParseProbeToleratesAPreambleBeforeTheDocument(t *testing.T) {
	const noisy = "WARNING: The names of some imported commands include unapproved verbs.\n" + oneElementProbe
	adapters, _, _, _, err := parseProbe([]byte(noisy))
	if err != nil {
		t.Fatalf("parseProbe with a warning line before the document: %v", err)
	}
	if len(adapters) != 1 {
		t.Fatalf("adapters = %d, want the document found after the warning", len(adapters))
	}
}

const oneElementProbe = `{"schema":"netmerge.inventory.windows/1","adapters":{"Name":"Ethernet","InterfaceIndex":4,"ifIndex":4,"Status":"Up","InterfaceType":6,"LinkSpeed":"1 Gbps"},"capabilities":{"Get-NetAdapter":true}}`

func TestParseProbeReportsASchemaMismatchAsAGap(t *testing.T) {
	adapters, _, gaps, _, err := parseProbe([]byte(`{"schema":"netmerge.inventory.windows/99","adapters":{"Name":"Ethernet","InterfaceIndex":4,"Status":"Up","LinkSpeed":"1 Gbps"}}`))
	if err != nil {
		t.Fatalf("parseProbe: %v", err)
	}
	if len(adapters) != 1 {
		t.Fatalf("adapters = %d, want the row kept", len(adapters))
	}
	if !strings.Contains(strings.Join(gaps, " | "), "netmerge.inventory.windows/99") {
		t.Errorf("gaps = %v, want the schema version called out", gaps)
	}
}

func TestParseProbeRecordsMissingCmdlets(t *testing.T) {
	adapters, _, gaps, errs, err := parseProbe([]byte(`{"schema":"netmerge.inventory.windows/1","capabilities":{"Get-NetAdapter":false}}`))
	if err != nil {
		t.Fatalf("parseProbe: %v", err)
	}
	if len(adapters) != 0 {
		t.Errorf("adapters = %d, want none", len(adapters))
	}
	joined := strings.Join(gaps, " | ") + strings.Join(errs, " | ")
	if !strings.Contains(joined, "Get-NetAdapter") {
		t.Errorf("gaps=%v errors=%v, want the missing cmdlet named", gaps, errs)
	}
}

func TestParseProbeSkipsRowsWithoutAnIndexInsteadOfGuessing(t *testing.T) {
	adapters, _, _, errs, err := parseProbe([]byte(`{"schema":"netmerge.inventory.windows/1","capabilities":{"Get-NetAdapter":true},
      "adapters":[{"Name":"Ethernet","Status":"Up","InterfaceType":6},{"Name":"Ethernet 2","InterfaceIndex":9,"ifIndex":9,"Status":"Up","InterfaceType":6,"LinkSpeed":"1 Gbps"}]}`))
	if err != nil {
		t.Fatalf("parseProbe: %v", err)
	}
	if len(adapters) != 1 || adapters[0].Index != 9 {
		t.Fatalf("adapters = %+v, want only the row that has an index", adapters)
	}
	if !strings.Contains(strings.Join(errs, " | "), "no interface index") {
		t.Errorf("errors = %v, want the skipped row reported rather than silently dropped", errs)
	}
}

func TestPSTypeHelpers(t *testing.T) {
	// One object exercising every accessor's tolerance, because these are what stand between a
	// changed PowerShell serialisation and a dashboard full of zeros.
	objs := psObjs([]byte(`[{"s":"text","n":42,"big":9007199254740993,"b":true,"bs":"true","list":["a","b"],"one":"c","enum":71,"enumName":"gigabitEthernet","nil":null,"f":1.5}]`))
	if len(objs) != 1 {
		t.Fatalf("objects = %d, want 1", len(objs))
	}
	o := objs[0]
	if got := o.str("s"); got != "text" {
		t.Errorf("str = %q", got)
	}
	if got := o.str("n"); got != "42" {
		t.Errorf("str of a number = %q, want it rendered", got)
	}
	if got := o.intOf("n"); got != 42 {
		t.Errorf("intOf = %d", got)
	}
	if u, ok := o.uintOf("big"); !ok || u != 9007199254740993 {
		t.Errorf("uintOf = %d/%v, want the exact 64-bit value", u, ok)
	}
	if !o.boolOf("b") || !o.boolOf("bs") {
		t.Error("boolOf failed for a JSON boolean or its string form")
	}
	if got := o.intOf("f"); got != 1 {
		t.Errorf("intOf of 1.5 = %d, want a truncation rather than a failure", got)
	}
	if got := o.strList("list"); len(got) != 2 {
		t.Errorf("strList = %v, want two entries", got)
	}
	if got := o.strList("one"); len(got) != 1 || got[0] != "c" {
		t.Errorf("strList of a single string = %v, want one entry", got)
	}
	// Every Ethernet variant name maps to the canonical Ethernet type. The exact variant number
	// decides nothing: PhysicalIfType accepts the whole family, and this is the mapping that
	// stops a name-form enum from being read as "unknown".
	if v, ok := o.enum("enumName"); !ok || v != 6 {
		t.Errorf("enum of a name = %d/%v, want Ethernet mapped to 6", v, ok)
	}
	if v, ok := o.enum("enum"); !ok || v != 71 {
		t.Errorf("enum of a number = %d/%v", v, ok)
	}
	if v, ok := o.enum("enumName"); ok && !nics_PhysicalIfType(v) {
		t.Errorf("the mapped type %d is not accepted by nics.PhysicalIfType", v)
	}
	if _, ok := o.raw("nil"); ok {
		t.Error("a null property must read as absent")
	}
	if _, ok := o.raw("missing"); ok {
		t.Error("a missing property must read as absent")
	}
}

func findByName(adapters []Adapter, name string) (Adapter, bool) {
	for _, a := range adapters {
		if a.Name == name {
			return a, true
		}
	}
	return Adapter{}, false
}
