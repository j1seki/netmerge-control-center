package inventory

import (
	"fmt"
	"regexp"
	"strings"

	"net-merge/internal/nics"
)

// ClassifyInput is what a platform source can say about an interface's type. Every field is
// optional: a source that cannot determine something leaves it zero and the classifier says
// "unknown" rather than inventing an answer.
type ClassifyInput struct {
	Name        string
	Description string
	// IfType is the IANA interface type (Windows: IfType; Linux: ARPHRD type is a different
	// numbering and must not be passed here).
	IfType uint32
	// MediaType is the platform's media description, e.g. "802.11", "802.3", "Native 802.11".
	MediaType string
	// HasHardwareDevice is set where the platform can prove a physical device backs the
	// interface (Linux sysfs). nil means "this platform cannot tell".
	HasHardwareDevice *bool
}

// Tether and modem patterns. They are heuristics and are documented as such wherever they are
// shown: a mislabelled adapter is still eligible or excluded on its real link state and routes,
// so the label never decides whether an adapter is used. The patterns are the driver and product
// names that Windows and Linux actually report for a shared phone connection.
var (
	tetherDesc = regexp.MustCompile(`(?i)remote ndis|rndis|apple mobile device|iphone|ipad|ipheth|android|tether|mobile usb connectivity|samsung.*mobile|cdc[_-]?(ether|ncm|mbim|ecm)|usb.*(rndis|gadget)|ndis.*compatible`)
	wwanDesc   = regexp.MustCompile(`(?i)\bwwan\b|mobile broadband|cellular|lte\b|\b5g\b|\b4g\b|\b3g\b|modem|mbim|fibocom|quectel|sierra wireless|telit|thales|gemalto|simcom|netmotion`)
	wifiDesc   = regexp.MustCompile(`(?i)wi-?fi|wireless|802\.11|wlan`)
)

// Classify names the interface kind and explains why it is not real hardware, if that is the
// case. The two answers are independent: a virtual adapter has a kind (virtual) and a reason.
func Classify(in ClassifyInput) (Kind, string) {
	reason := virtualReason(in)
	if reason != "" {
		return KindVirtual, reason
	}
	switch {
	case in.IfType == 71 || matchesAny(in.MediaType, "802.11", "Native 802.11") || wifiDesc.MatchString(in.Name+" "+in.Description):
		return KindWiFi, ""
	case in.IfType == 243 || in.IfType == 244 || wwanDesc.MatchString(in.Description) || wwanDesc.MatchString(in.Name):
		return KindWWAN, ""
	case tetherDesc.MatchString(in.Description) || tetherDesc.MatchString(in.Name):
		return KindUSBTether, ""
	case nics.PhysicalIfType(in.IfType) || (in.IfType == 0 && in.HasHardwareDevice != nil && *in.HasHardwareDevice):
		return KindEthernet, ""
	case in.IfType != 0:
		return KindOther, ""
	default:
		return KindUnknown, ""
	}
}

// virtualReason merges the three places a software interface gives itself away: its name, its
// driver description (shared with the bonding engine so the two cannot disagree), its declared
// interface type, and - on Linux - the absence of a backing device.
func virtualReason(in ClassifyInput) string {
	if r := nics.VirtualReason(in.Name, in.Description); r != "" {
		return r
	}
	if in.IfType != 0 && !nics.PhysicalIfType(in.IfType) {
		return fmt.Sprintf("tunnel/virtual interface type %d (%s)", in.IfType, describe(in))
	}
	if in.HasHardwareDevice != nil && !*in.HasHardwareDevice {
		return fmt.Sprintf("software interface (%s, no hardware device)", describe(in))
	}
	return ""
}

// describe names the interface for a message, preferring the driver description because that is
// what a user sees in Device Manager.
func describe(in ClassifyInput) string {
	if in.Description != "" {
		return in.Description
	}
	if in.Name != "" {
		return in.Name
	}
	return "unnamed interface"
}

func matchesAny(s string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(strings.ToLower(s), strings.ToLower(n)) {
			return true
		}
	}
	return false
}

// ParseLinkSpeed turns the link-speed strings Windows reports ("1 Gbps", "100 Mbps", "2.5 Gbps")
// into bits per second. It returns 0 for anything it cannot read, so an unparsed speed is a gap
// rather than a wrong number.
func ParseLinkSpeed(s string) uint64 {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || s == "unknown" {
		return 0
	}
	mult := uint64(0)
	switch {
	case strings.HasSuffix(s, "gbps"):
		mult, s = 1_000_000_000, strings.TrimSpace(strings.TrimSuffix(s, "gbps"))
	case strings.HasSuffix(s, "mbps"):
		mult, s = 1_000_000, strings.TrimSpace(strings.TrimSuffix(s, "mbps"))
	case strings.HasSuffix(s, "kbps"):
		mult, s = 1_000, strings.TrimSpace(strings.TrimSuffix(s, "kbps"))
	case strings.HasSuffix(s, "bps"):
		mult, s = 1, strings.TrimSpace(strings.TrimSuffix(s, "bps"))
	default:
		return 0
	}
	value, err := parseDecimal(s)
	if err != nil || value <= 0 {
		return 0
	}
	return uint64(value*float64(mult) + 0.5)
}

// parseDecimal accepts "1", "2.5", "2,5" (some locales) and rejects anything else.
func parseDecimal(s string) (float64, error) {
	s = strings.ReplaceAll(strings.TrimSpace(s), ",", ".")
	var value float64
	var seenDot bool
	var digits int
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			value = value*10 + float64(r-'0')
			if seenDot {
				digits++
			}
		case r == '.' && !seenDot:
			seenDot = true
		default:
			return 0, fmt.Errorf("not a number: %q", s)
		}
	}
	for i := 0; i < digits; i++ {
		value /= 10
	}
	return value, nil
}
