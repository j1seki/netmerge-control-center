//go:build linux

package inventory

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/vishvananda/netlink"

	"net-merge/internal/nics"
)

// LinuxSource reads the inventory from the kernel through netlink, plus sysfs for the facts
// netlink does not carry.
//
// It exists because this application is developed and tested on Linux before it is built for
// Windows: a dashboard that could only run on Windows could not be tested at all on the machine
// building it. It also keeps the model honest - every field the model claims to have is a field
// two different platforms can actually supply.
type LinuxSource struct{}

// NewLinuxSource returns the Linux inventory source.
func NewLinuxSource() *LinuxSource { return &LinuxSource{} }

// Name implements Source.
func (l *LinuxSource) Name() string { return "linux-netlink" }

// Adapters implements Source.
func (l *LinuxSource) Adapters(ctx context.Context) ([]Adapter, []string, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, nil, fmt.Errorf("list network interfaces: %w", err)
	}
	gaps := []string{
		"DHCP state is not exposed by the kernel on Linux; read /etc/resolv.conf or the network manager for it",
	}

	var adapters []Adapter
	for _, link := range links {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		attrs := link.Attrs()
		if attrs == nil {
			continue
		}
		if attrs.Flags&net.FlagLoopback != 0 || attrs.Name == "lo" {
			continue
		}
		a := Adapter{
			Name:   attrs.Name,
			Index:  attrs.Index,
			MAC:    attrs.HardwareAddr.String(),
			MTU:    attrs.MTU,
			DHCP4:  TriUnknown,
			DHCP6:  TriUnknown,
			Media:  "",
			Status: StateUnknown,
		}
		a.IndexV6 = attrs.Index
		switch {
		case attrs.OperState == netlink.OperUp:
			a.Link = LinkUp
		case attrs.OperState == netlink.OperDown:
			a.Link = LinkDown
		case attrs.OperState == netlink.OperNotPresent:
			a.Link = LinkDown
		default:
			a.Link = LinkUnknown
		}
		if attrs.OperState == netlink.OperUp {
			a.Media = "connected"
		} else if attrs.OperState == netlink.OperDown {
			a.Media = "disconnected"
		}
		if attrs.Flags&net.FlagUp == 0 {
			a.Link = LinkDisabled
			a.Admin = "down"
		} else {
			a.Admin = "up"
		}
		a.MTU4, a.MTU6 = intPtrOf(attrs.MTU), intPtrOf(attrs.MTU)

		// A device symlink in sysfs is the proof that real hardware backs this interface; the
		// driver name is what the engine's eligibility check matches against.
		sysDir := filepath.Join("/sys/class/net", attrs.Name)
		hardware := false
		if _, err := os.Stat(filepath.Join(sysDir, "device")); err == nil {
			hardware = true
		}
		if drv, err := os.Readlink(filepath.Join(sysDir, "device", "driver")); err == nil {
			a.Description = filepath.Base(drv)
		}
		kind, reason := Classify(ClassifyInput{
			Name: a.Name, Description: a.Description, HasHardwareDevice: &hardware,
		})
		a.Kind, a.VirtualReason = kind, reason
		a.Hardware = reason == ""

		addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			a.Gaps = append(a.Gaps, "addresses could not be read: "+err.Error())
		}
		for _, addr := range addrs {
			if addr.IPNet == nil {
				continue
			}
			status, virtual := linuxAddrFlags(addr.Flags)
			item := Address{
				Address: addr.IPNet.IP.String(),
				Prefix:  ones(addr.IPNet.Mask),
				Status:  status,
				Virtual: virtual,
			}
			item.LinkLocal = addr.IPNet.IP.IsLinkLocalUnicast()
			if addr.IPNet.IP.To4() != nil {
				a.IPv4 = append(a.IPv4, item)
			} else {
				a.IPv6 = append(a.IPv6, item)
			}
		}
		adapters = append(adapters, a)
	}
	return adapters, gaps, nil
}

// Routes implements Source.
func (l *LinuxSource) Routes(ctx context.Context) ([]Route, []string, error) {
	var out []Route
	gaps := []string{}
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		if ctx.Err() != nil {
			return out, gaps, ctx.Err()
		}
		routes, err := netlink.RouteListFiltered(fam, &netlink.Route{}, netlink.RT_FILTER_TABLE)
		if err != nil {
			// Trying again without the table filter is what makes this work on kernels and
			// namespaces where a filter is rejected; the failure is reported either way.
			routes, err = netlink.RouteList(nil, fam)
			if err != nil {
				return out, append(gaps, fmt.Sprintf("routing table for family %d could not be read: %v", fam, err)), nil
			}
			gaps = append(gaps, "the routing table was read without a table filter, so only the main table is present")
		}
		for _, r := range routes {
			item := Route{
				Family:      familyName(r.Family),
				Index:       r.LinkIndex,
				Metric:      r.Priority,
				Protocol:    protocolName(r.Protocol),
				Destination: "0.0.0.0/0",
			}
			if r.Dst != nil {
				if nm := r.Dst.String(); nm != "" {
					item.Destination = nm
				}
			} else {
				item.Destination = "0.0.0.0/0"
				if r.Family == netlink.FAMILY_V6 {
					item.Destination = "::/0"
				}
			}
			if r.Gw != nil {
				item.NextHop = r.Gw.String()
			}
			if link, err := netlink.LinkByIndex(r.LinkIndex); err == nil && link != nil {
				item.Name = link.Attrs().Name
			}
			item.Default = isDefaultRoute(item.Destination)
			out = append(out, item)
		}
	}
	return out, gaps, nil
}

// Counters implements Source.
func (l *LinuxSource) Counters(_ context.Context, index int) (Counters, bool) {
	in, out, ok := nics.Octets(index)
	if !ok {
		return Counters{}, false
	}
	return Counters{In: in, Out: out}, true
}

// ones counts the bits in a netmask, which is how the model carries a prefix length.
func ones(mask net.IPMask) int {
	if mask == nil {
		return 0
	}
	bits, _ := mask.Size()
	return bits
}

func familyName(fam int) string {
	if fam == netlink.FAMILY_V6 {
		return "v6"
	}
	return "v4"
}

// protocolName names the mechanism that installed a route. It matters for diagnosis: a DHCP
// route disappears with the lease, a kernel route does not.
func protocolName(p netlink.RouteProtocol) string {
	switch p {
	case 2:
		return "kernel"
	case 3:
		return "boot"
	case 4:
		return "static"
	case 8:
		return "ra"
	case 9:
		return "dhcp"
	case 10:
		return "mrouted"
	case 11:
		return "keepalived"
	case 12:
		return "bgp"
	case 13:
		return "isis"
	case 14:
		return "ospf"
	case 15:
		return "rip"
	case 16:
		return "eigrp"
	case 18:
		return "dhcp"
	}
	return fmt.Sprintf("protocol-%d", int(p))
}
