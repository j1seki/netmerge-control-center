//go:build !windows && !linux

package inventory

import (
	"context"
	"net"
)

// OtherSource is the honest fallback for hosts this application was not built for: it lists the
// interfaces the standard library can see, with their addresses, and declares everything it
// cannot read as a gap. It exists so that a macOS or BSD machine produces a truthful "not
// inspected here" inventory instead of an empty dashboard or, worse, an invented one.
type OtherSource struct{}

// NewOtherSource returns the fallback inventory source.
func NewOtherSource() *OtherSource { return &OtherSource{} }

// Name implements Source.
func (o *OtherSource) Name() string { return "unsupported-platform" }

// Adapters implements Source.
func (o *OtherSource) Adapters(context.Context) ([]Adapter, []string, error) {
	gaps := []string{
		"this platform has no adapter-configuration source implemented: adapters and addresses are listed, but gateways, DNS, DHCP state, interface metrics and routes are not read",
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, gaps, err
	}
	var adapters []Adapter
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		a := Adapter{
			Name:  ifc.Name,
			Index: ifc.Index,
			MAC:   ifc.HardwareAddr.String(),
			MTU:   ifc.MTU,
			DHCP4: TriUnknown,
			DHCP6: TriUnknown,
		}
		switch {
		case ifc.Flags&net.FlagUp == 0:
			a.Link = LinkDisabled
		default:
			a.Link = LinkUp
		}
		kind, reason := Classify(ClassifyInput{Name: a.Name, Description: a.Name})
		a.Kind, a.VirtualReason = kind, reason
		a.Hardware = reason == ""
		addrs, err := ifc.Addrs()
		if err != nil {
			a.Gaps = append(a.Gaps, "addresses could not be read: "+err.Error())
		}
		for _, addr := range addrs {
			ipn, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			item := Address{Address: ipn.IP.String(), LinkLocal: ipn.IP.IsLinkLocalUnicast()}
			if ones, _ := ipn.Mask.Size(); ones > 0 {
				item.Prefix = ones
			}
			if ipn.IP.To4() != nil {
				a.IPv4 = append(a.IPv4, item)
			} else {
				a.IPv6 = append(a.IPv6, item)
			}
		}
		a.Gaps = append(a.Gaps, "gateways, DNS servers, routes, DHCP state and interface metrics are unavailable on this platform")
		adapters = append(adapters, a)
	}
	return adapters, gaps, nil
}

// Routes implements Source. No routing table source is implemented here, and an empty table with
// a gap is the truthful answer.
func (o *OtherSource) Routes(context.Context) ([]Route, []string, error) {
	return nil, []string{"the routing table is not read on this platform"}, nil
}

// Counters implements Source.
func (o *OtherSource) Counters(context.Context, int) (Counters, bool) { return Counters{}, false }
