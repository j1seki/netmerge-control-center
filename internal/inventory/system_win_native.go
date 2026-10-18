//go:build windows

package inventory

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"net-merge/internal/nics"
)

// nativeAdapters is the fallback inventory, read straight from the IP Helper API. It is used when
// PowerShell is unavailable or its probe cannot be parsed, and it is deliberately narrower than
// the cmdlet path: what it cannot know (per-interface DHCP toggles, the interface's own MTU row,
// the routing table) is reported as a gap.
//
// Every field here is read from a documented structure member, and nothing is inferred from a
// failed call: GetAdaptersAddresses either returns the table or an error that is reported.
func (w *WindowsSource) nativeAdapters(gaps []string) ([]Adapter, []string, error) {
	const flags = windows.GAA_FLAG_INCLUDE_GATEWAYS | windows.GAA_FLAG_INCLUDE_PREFIX |
		windows.GAA_FLAG_SKIP_ANYCAST | windows.GAA_FLAG_SKIP_MULTICAST
	size := uint32(32 << 10)
	var table *windows.IpAdapterAddresses
	var buf []byte
	var err error
	for try := 0; try < 4; try++ {
		buf = make([]byte, size)
		table = (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err = windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, table, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		break
	}
	if err != nil {
		return nil, gaps, fmt.Errorf("GetAdaptersAddresses: %w", err)
	}

	gaps = append(gaps, "adapter configuration was read from the IP Helper API: DHCP toggles, interface MTU rows and the routing table are not available through it")

	byIndex := map[int]*Adapter{}
	var order []int
	for a := table; a != nil; a = a.Next {
		// A family-specific entry can repeat an adapter; merge on the interface index.
		idx := int(a.IfIndex)
		if idx == 0 {
			idx = int(a.Ipv6IfIndex)
		}
		if idx == 0 {
			continue
		}
		existing, seen := byIndex[idx]
		if !seen {
			adapter := Adapter{
				Name:        windows.UTF16PtrToString(a.FriendlyName),
				Description: windows.UTF16PtrToString(a.Description),
				Index:       idx,
				IndexV6:     int(a.Ipv6IfIndex),
				MTU:         int(a.Mtu),
				DHCP4:       TriUnknown,
				DHCP6:       TriUnknown,
				Media:       "connected",
			}
			kind, reason := Classify(ClassifyInput{
				Name: adapter.Name, Description: adapter.Description, IfType: a.IfType,
			})
			adapter.Kind, adapter.VirtualReason = kind, reason
			adapter.Hardware = reason == ""

			adapter.Link = LinkUnknown
			adapter.Admin = "unknown"
			switch a.OperStatus {
			case windows.IfOperStatusUp:
				adapter.Link = LinkUp
			case windows.IfOperStatusDown, windows.IfOperStatusNotPresent, windows.IfOperStatusLowerLayerDown:
				adapter.Link = LinkDown
				adapter.Media = "disconnected"
			case windows.IfOperStatusDormant:
				adapter.Link = LinkUp
				adapter.Warnings = append(adapter.Warnings, "the interface is dormant: the link exists but no traffic is expected")
			default:
				adapter.Gaps = append(adapter.Gaps, fmt.Sprintf("unrecognised operational status %d", a.OperStatus))
			}
			if a.ReceiveLinkSpeed > 0 || a.TransmitLinkSpeed > 0 {
				adapter.SpeedBps = minU64(a.ReceiveLinkSpeed, a.TransmitLinkSpeed)
			}
			if a.PhysicalAddressLength > 0 && a.PhysicalAddressLength <= uint32(len(a.PhysicalAddress)) {
				adapter.MAC = formatMAC(a.PhysicalAddress[:a.PhysicalAddressLength])
			}
			if a.Ipv4Metric > 0 {
				adapter.Metric4 = intPtrOf(int(a.Ipv4Metric))
			}
			if a.Ipv6Metric > 0 {
				adapter.Metric6 = intPtrOf(int(a.Ipv6Metric))
			}
			if isNonZeroSockaddr(a.Dhcpv4Server) {
				adapter.DHCP4 = TriYes
			}
			if isNonZeroSockaddr(a.Dhcpv6Server) {
				adapter.DHCP6 = TriYes
			}
			adapter.MTU4, adapter.MTU6 = intPtrOf(int(a.Mtu)), intPtrOf(int(a.Mtu))
			byIndex[idx] = &adapter
			order = append(order, idx)
			existing = &adapter
		}

		for u := a.FirstUnicastAddress; u != nil; u = u.Next {
			if u.Address.Sockaddr == nil {
				continue
			}
			ip := u.Address.IP()
			if ip == nil {
				continue
			}
			addr := Address{
				Address:   ip.String(),
				Prefix:    int(u.OnLinkPrefixLength),
				LinkLocal: ip.IsLinkLocalUnicast(),
				Origin:    prefixOriginName(u.PrefixOrigin),
				Status:    dadStateName(u.DadState),
			}
			if ip.To4() != nil {
				existing.IPv4 = append(existing.IPv4, addr)
			} else {
				existing.IPv6 = append(existing.IPv6, addr)
			}
		}
		for g := a.FirstGatewayAddress; g != nil; g = g.Next {
			if g.Address.Sockaddr == nil {
				continue
			}
			ip := g.Address.IP()
			if ip == nil {
				continue
			}
			if ip.To4() != nil {
				existing.DefaultRoute4 = true
				if !containsFold(existing.Gateways4, ip.String()) {
					existing.Gateways4 = append(existing.Gateways4, ip.String())
				}
			} else {
				existing.DefaultRoute6 = true
				if !containsFold(existing.Gateways6, ip.String()) {
					existing.Gateways6 = append(existing.Gateways6, ip.String())
				}
			}
		}
		for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
			if d.Address.Sockaddr == nil {
				continue
			}
			ip := d.Address.IP()
			if ip == nil {
				continue
			}
			if ip.To4() != nil {
				existing.DNS4 = append(existing.DNS4, ip.String())
			} else {
				existing.DNS6 = append(existing.DNS6, ip.String())
			}
		}
	}

	var adapters []Adapter
	for _, idx := range order {
		a := *byIndex[idx]
		if a.Media == "" {
			a.Media = "unknown"
		}
		if in, out, ok := nics.Octets(a.Index); ok {
			c := Counters{In: in, Out: out}
			a.Counters = &c
		} else {
			a.Gaps = append(a.Gaps, "byte counters unavailable")
		}
		if a.DHCP4 == TriUnknown {
			a.Gaps = append(a.Gaps, "DHCP state not reported by the IP Helper API for this adapter")
		}
		adapters = append(adapters, a)
	}
	return adapters, gaps, nil
}

// isNonZeroSockaddr reports whether a DHCP server address is present, which is the IP Helper
// API's way of saying "this interface has a DHCP server", i.e. DHCP is in use on it.
func isNonZeroSockaddr(sa windows.SocketAddress) bool {
	if sa.Sockaddr == nil {
		return false
	}
	ip := sa.IP()
	return ip != nil && !ip.IsUnspecified()
}

func formatMAC(b []byte) string {
	parts := make([]string, 0, len(b))
	for _, x := range b {
		parts = append(parts, fmt.Sprintf("%02x", x))
	}
	return strings.Join(parts, ":")
}

func minU64(a, b uint64) uint64 {
	if a == 0 {
		return b
	}
	if b == 0 {
		return a
	}
	if a < b {
		return a
	}
	return b
}

// prefixOriginName and dadStateName name the enum values the API returns, so the dashboard shows
// "dhcp" rather than "3" and a report reads the same way a person would describe it.
func prefixOriginName(v int32) string {
	switch v {
	case 0:
		return "other"
	case 1:
		return "manual"
	case 2:
		return "wellknown"
	case 3:
		return "dhcp"
	case 4:
		return "router-advertisement"
	}
	return fmt.Sprintf("origin-%d", v)
}

func dadStateName(v int32) string {
	switch v {
	case 1:
		return "preferred"
	case 2:
		return "deprecated"
	case 3:
		return "tentative"
	case 4:
		return "duplicate"
	}
	return ""
}
