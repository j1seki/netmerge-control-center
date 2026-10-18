package nics

import "strings"

import "testing"

// Tests for the shared classification rules. The engine and the Control Center both decide
// eligibility with these; a wrong answer here either offers the dashboard an adapter the engine
// will never schedule, or hides real hardware from both.

func TestPhysicalIfType(t *testing.T) {
	physical := map[uint32]string{
		6:   "ethernet",
		62:  "fast ethernet",
		69:  "gigabit ethernet",
		117: "gigabit ethernet (802.3)",
		71:  "IEEE 802.11 Wi-Fi",
		243: "mobile broadband WWAN",
		244: "mobile broadband WWAN",
	}
	for ifType, label := range physical {
		if !PhysicalIfType(ifType) {
			t.Errorf("ifType %d (%s) should count as physical hardware", ifType, label)
		}
	}
	notPhysical := map[uint32]string{
		1:   "other",
		23:  "PPP",
		24:  "software loopback",
		53:  "proprietary virtual (VPN drivers)",
		131: "tunnel",
		0:   "unspecified",
	}
	for ifType, label := range notPhysical {
		if PhysicalIfType(ifType) {
			t.Errorf("ifType %d (%s) must not count as physical hardware", ifType, label)
		}
	}
}

func TestVirtualReasonNamesRealAdaptersAsPhysical(t *testing.T) {
	// The descriptions below are what Windows actually reports for these adapters, including the
	// USB-tether ones the whole application exists to use.
	cases := []struct{ name, desc string }{
		{"Ethernet", "Intel(R) Ethernet Connection (17) I219-V"},
		{"Wi-Fi", "Intel(R) Wi-Fi 6E AX211 160MHz"},
		{"Ethernet 2", "Remote NDIS based Internet Sharing Device"},
		{"Ethernet 3", "Apple Mobile Device Ethernet"},
		{"Ethernet 4", "Realtek USB GbE Family Controller"},
		{"Ethernet 5", "SAMSUNG Mobile USB Connectivity Device"},
		{"Cellular", "Fibocom L850-GL"},
		{"eth0", "r8169"},
		{"enp3s0", "igc"},
		{"wlan0", "iwlwifi"},
		{"usb0", "rndis_host"},
	}
	for _, c := range cases {
		if got := VirtualReason(c.name, c.desc); got != "" {
			t.Errorf("VirtualReason(%q, %q) = %q, want real hardware", c.name, c.desc, got)
		}
	}
}

func TestVirtualReasonCatchesVirtualAdapters(t *testing.T) {
	cases := []struct {
		name, desc string
		wantSub    string
	}{
		{"vEthernet (Default Switch)", "Hyper-V Virtual Ethernet Adapter", "name"},
		{"net-merge", "Wintun Userspace Tunnel", "name"},
		{"wintun", "Wintun Userspace Tunnel", "name"},
		{"Tailscale", "Tailscale Tunnel", "name"},
		{"docker0", "bridge", "name"},
		{"wg0", "WireGuard", "name"},
		{"Ethernet 7", "TAP-Windows Adapter V9", "TAP"},
		{"Ethernet 8", "OpenVPN Data Channel Offload", "OpenVPN"},
		{"Ethernet 9", "VMware Virtual Ethernet Adapter for VMnet8", "VMware"},
		{"Ethernet 10", "SonicWall VPN Virtual Adapter", "virtual"},
		{"Ethernet 11", "Teredo Tunneling Pseudo-Interface", "Teredo"},
		{"Ethernet 12", "Microsoft Wi-Fi Direct Virtual Adapter", "virtual"},
	}
	for _, c := range cases {
		got := VirtualReason(c.name, c.desc)
		if got == "" {
			t.Errorf("VirtualReason(%q, %q) = \"\", want a virtual-adapter reason", c.name, c.desc)
			continue
		}
		if !containsFold2(got, c.wantSub) {
			t.Errorf("VirtualReason(%q, %q) = %q, want it to mention %q", c.name, c.desc, got, c.wantSub)
		}
	}
}

func TestVirtualReasonIgnoresEmptyInput(t *testing.T) {
	// An adapter whose description could not be read must not be condemned for it: a name-only
	// call is the fallback path, and "" means "nothing here says virtual".
	if got := VirtualReason("Ethernet", ""); got != "" {
		t.Errorf("VirtualReason with an unknown description = %q, want no verdict", got)
	}
	if got := VirtualReason("", ""); got != "" {
		t.Errorf("VirtualReason with nothing to go on = %q, want no verdict", got)
	}
}

// containsFold2 is a case-insensitive substring check used only by these tests.
func containsFold2(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}
