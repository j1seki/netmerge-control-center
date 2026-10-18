//go:build linux

package inventory

// Linux address flags, from linux/if_addr.h. They are declared here rather than pulled from
// x/sys/unix so the meaning of each bit is visible next to the code that uses it.
const (
	ifaFlagSecondary  = 0x01
	ifaFlagNodad      = 0x02
	ifaFlagOptimistic = 0x04
	ifaFlagDadfailed  = 0x08
	ifaFlagHome       = 0x10
	ifaFlagDeprecated = 0x20
	ifaFlagTentative  = 0x40
	ifaFlagPermanent  = 0x80
	ifaFlagManaging   = 0x100
)

// linuxAddrFlags turns an address's flags into the status vocabulary the model uses and whether
// the address is a secondary alias. A tentative or duplicate address is reported as such because
// the eligibility rules refuse to treat it as a usable path.
func linuxAddrFlags(flags int) (status string, virtual bool) {
	switch {
	case flags&ifaFlagDadfailed != 0:
		status = "duplicate"
	case flags&ifaFlagTentative != 0:
		status = "tentative"
	case flags&ifaFlagDeprecated != 0:
		status = "deprecated"
	case flags&ifaFlagSecondary != 0:
		status = "preferred"
	default:
		status = "preferred"
	}
	return status, flags&ifaFlagSecondary != 0
}
