package diagreport

// The settings file describes what the user wants removed from a report; this file is the one
// place that turns that description into the redactor's rules. Both the dashboard's export and
// the command line's export call it, so the two cannot drift apart and a settings key that is
// added in one place cannot be silently ignored in the other.

import (
	"os"
	"os/user"
	"strings"

	"net-merge/internal/appcfg"
)

// PolicyFromPrivacy builds a redaction policy from the settings file's privacy section. extra
// holds exact literals the caller knows about and wants removed (adapter names, for example).
//
// Two rules are not taken from the settings, because there is no setting for them: credentials
// are always redacted, and the MAC vendor prefix is always kept (the vendor is what makes a
// report readable; the device part is what identifies a machine).
func PolicyFromPrivacy(pr appcfg.Privacy, extra ...string) Policy {
	p := Policy{
		RedactPublicIPs:        pr.RedactPublicIPs,
		KeepWellKnownPublicIPs: pr.KeepWellKnownPublicIPs,
		RedactMACs:             pr.RedactMACs,
		KeepMACVendor:          true,
		RedactPaths:            pr.RedactPaths,
		RedactSerials:          pr.RedactSerials,
		RedactCredentials:      true,
		Extra:                  extra,
	}
	// The machine name is only a secret when the user says so. IncludeHostname wins when both
	// are set, because it is the more specific statement.
	if pr.RedactHostNames && !pr.IncludeHostname {
		if h, err := os.Hostname(); err == nil && h != "" {
			p.Hostnames = []string{h}
		}
	}
	// The account name is what appears in the middle of a user-profile path, so it only needs
	// collecting when paths are being redacted.
	if pr.RedactPaths {
		if u, err := user.Current(); err == nil && u.Username != "" {
			name := u.Username
			if i := strings.LastIndexAny(name, `\/`); i >= 0 {
				name = name[i+1:]
			}
			if name != "" {
				p.Usernames = []string{name}
			}
		}
	}
	return p
}
