package inventory

// Tests for the classification rules and the link-speed parser. These are SIMULATIONS in the
// sense that they feed the classifier the exact strings Windows and Linux report for these
// adapters; what they verify is that the strings this application will really see produce the
// right kind and the right virtual-adapter verdict.

import "testing"

func TestClassifyKindsFromRealDriverDescriptions(t *testing.T) {
	cases := []struct {
		in       ClassifyInput
		wantKind Kind
		wantHW   bool
	}{
		{ClassifyInput{Name: "Ethernet", Description: "Intel(R) Ethernet Connection (17) I219-V", IfType: 6}, KindEthernet, true},
		{ClassifyInput{Name: "eth0", Description: "r8169", HasHardwareDevice: boolPtr(true)}, KindEthernet, true},
		{ClassifyInput{Name: "Wi-Fi", Description: "Intel(R) Wi-Fi 6E AX211 160MHz", IfType: 71}, KindWiFi, true},
		{ClassifyInput{Name: "Wi-Fi", Description: "Qualcomm QCA61x4A", MediaType: "Native 802.11"}, KindWiFi, true},
		{ClassifyInput{Name: "wlan0", Description: "iwlwifi", HasHardwareDevice: boolPtr(true)}, KindWiFi, true},
		{ClassifyInput{Name: "Cellular", Description: "Fibocom L850-GL", IfType: 243}, KindWWAN, true},
		{ClassifyInput{Name: "Ethernet 3", Description: "Remote NDIS based Internet Sharing Device", IfType: 6}, KindUSBTether, true},
		{ClassifyInput{Name: "Ethernet 4", Description: "Apple Mobile Device Ethernet", IfType: 6}, KindUSBTether, true},
		{ClassifyInput{Name: "enp0s20u1", Description: "rndis_host", HasHardwareDevice: boolPtr(true)}, KindUSBTether, true},
		{ClassifyInput{Name: "usb0", Description: "cdc_ncm", HasHardwareDevice: boolPtr(true)}, KindUSBTether, true},
	}
	for _, c := range cases {
		kind, reason := Classify(c.in)
		if kind != c.wantKind {
			t.Errorf("Classify(%+v) kind = %q, want %q", c.in, kind, c.wantKind)
		}
		if c.wantHW && reason != "" {
			t.Errorf("Classify(%+v) = virtual (%q), want real hardware", c.in, reason)
		}
	}
}

func TestClassifyVirtualAdapters(t *testing.T) {
	cases := []ClassifyInput{
		{Name: "vEthernet (Default Switch)", Description: "Hyper-V Virtual Ethernet Adapter", IfType: 6},
		{Name: "Ethernet 8", Description: "TAP-Windows Adapter V9", IfType: 6},
		{Name: "net-merge", Description: "Wintun Userspace Tunnel", IfType: 6},
		{Name: "Ethernet 9", Description: "WireGuard Tunnel", IfType: 131},
		{Name: "wg0", Description: "WireGuard", HasHardwareDevice: boolPtr(false)},
		{Name: "docker0", Description: "bridge", HasHardwareDevice: boolPtr(false)},
		{Name: "br-abcd", Description: "bridge", HasHardwareDevice: boolPtr(false)},
		{Name: "Ethernet 10", Description: "Microsoft Wi-Fi Direct Virtual Adapter", IfType: 6},
	}
	for _, c := range cases {
		kind, reason := Classify(c)
		if kind != KindVirtual {
			t.Errorf("Classify(%+v) kind = %q, want virtual", c, kind)
		}
		if reason == "" {
			t.Errorf("Classify(%+v) gave no reason; an exclusion must always be explainable", c)
		}
	}
}

func TestClassifyUnknownStaysUnknown(t *testing.T) {
	kind, reason := Classify(ClassifyInput{Name: "some0", IfType: 0})
	if kind != KindUnknown {
		t.Errorf("kind = %q, want unknown when nothing identifies the interface", kind)
	}
	// Unknown is not virtual: not knowing what something is must never be reported as proof that
	// it is unusable, or an unusual-but-real adapter silently disappears from the dashboard.
	if reason != "" {
		t.Errorf("reason = %q, want no verdict for an unidentified interface", reason)
	}
}

func TestParseLinkSpeed(t *testing.T) {
	cases := map[string]uint64{
		"1 Gbps":         1_000_000_000,
		"10 Gbps":        10_000_000_000,
		"2.5 Gbps":       2_500_000_000,
		"100 Mbps":       100_000_000,
		"866.7 Mbps":     866_700_000,
		"10 Mbps":        10_000_000,
		"54 Mbps":        54_000_000,
		"1 Kbps":         1_000,
		"100 bps":        100,
		"":               0,
		"Unknown":        0,
		"not a number":   0,
		"Gbps":           0,
		"0 Mbps":         0,
		"2,5 Gbps":       2_500_000_000, // a locale that prints a comma
		"1000000000":     0,             // a bare number carries no unit, so it is refused
		"-1 Gbps":        0,
		"garbage 1 Gbps": 0,
	}
	for in, want := range cases {
		if got := ParseLinkSpeed(in); got != want {
			t.Errorf("ParseLinkSpeed(%q) = %d, want %d", in, got, want)
		}
	}
}

func boolPtr(v bool) *bool { return &v }
