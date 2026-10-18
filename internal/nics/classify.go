package nics

import "fmt"

// This file holds the rules that decide whether a discovered interface is real network hardware
// and, if so, what kind. They are shared rather than duplicated because the bonding engine and
// the Control Center dashboard must agree: an adapter the dashboard offers as eligible while the
// engine refuses to use it (or the reverse) is worse than either answer alone.

// PhysicalIfType reports whether an IANA interface type is real network hardware. Tunnels (131),
// PPP (23), "proprietary virtual" (53, used by most VPN drivers) and software loopback (24) are
// not in this set, so a driver that lies about its name is still caught by its declared type.
func PhysicalIfType(t uint32) bool {
	switch t {
	case 6, 62, 69, 117, // ethernet (incl. fast / gigabit variants)
		71,       // IEEE 802.11 Wi-Fi
		243, 244: // mobile broadband (WWAN)
		return true
	}
	return false
}

// VirtualReason explains why a name/description pair is not real network hardware, or returns
// "" when nothing marks it as virtual.
//
// The second line of defence after the interface type check: virtual switches, VPN TAP drivers,
// VM host-only adapters and container bridges commonly present themselves as ordinary Ethernet,
// and only their name or driver description gives them away. The anchored names are Linux
// interface naming conventions.
func VirtualReason(name, desc string) string {
	switch {
	case name != "" && virtualName.MatchString(name):
		return "looks like a virtual/VPN adapter (name)"
	case desc != "" && virtualDesc.MatchString(desc):
		return fmt.Sprintf("virtual/VPN adapter (%s)", desc)
	}
	return ""
}
