// Package diagreport turns live observations into a report a person can inspect and, if they
// choose, hand to someone else - including an AI assistant - without leaking their identity.
//
// Two properties are designed in rather than promised:
//
//   - Nothing leaves this machine. The package has no HTTP client, no upload path and no
//     telemetry: it renders bytes and hands them back to the caller, who writes a local file.
//     Sharing is a separate, deliberate act by the user.
//
//   - Redaction is a rendering pass, not a field-by-field hope. The document is rendered and
//     then rewritten by a redactor that recognises public addresses, MAC addresses, user
//     paths, device serials and credentials wherever they appear - including inside command
//     output, which is exactly where they hide. The placeholders it inserts are listed for the
//     user on their own terminal (never inside the exported file), so the user can see what was
//     hidden before deciding to share.
//
// What redaction cannot do is stated where the user will read it: a secret with no label and no
// recognisable shape is indistinguishable from ordinary text, so the report tells the reader to
// inspect it rather than implying it is guaranteed clean.
package diagreport

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
)

// Policy selects what is redacted. Every field defaults to on through DefaultPolicy; a caller
// that switches something off should say so to the user, because the exported file then carries
// that class of value verbatim.
type Policy struct {
	// RedactPublicIPs removes globally routable addresses (IPv4 and IPv6).
	RedactPublicIPs bool
	// KeepWellKnownPublicIPs leaves shared infrastructure addresses readable (1.1.1.1,
	// 8.8.8.8, ...). They identify nobody, and a report about DNS is much less useful without
	// them.
	KeepWellKnownPublicIPs bool
	// RedactPrivateIPs extends address redaction to RFC 1918 / ULA addresses. Off by default:
	// a home LAN address is not identifying on its own, and the topology is the diagnosis.
	RedactPrivateIPs bool
	// RedactMACs removes MAC addresses. With KeepMACVendor the first three octets stay, so a
	// reader can still tell an Intel adapter from a phone, while the device-specific part -
	// which is what identifies the machine - is removed.
	RedactMACs    bool
	KeepMACVendor bool
	// RedactPaths removes the account name from user-profile paths.
	RedactPaths bool
	// RedactSerials removes device serial numbers, IMEIs and USB instance paths.
	RedactSerials bool
	// RedactCredentials removes passwords, tokens and key material.
	RedactCredentials bool

	// Hostnames, Usernames and Extra are exact literals to remove. The caller passes the
	// machine name and account name it knows, because a pattern cannot recognise them.
	Hostnames []string
	Usernames []string
	Extra     []string
}

// DefaultPolicy is the recommended set: everything that identifies the user or their machine is
// removed, shared infrastructure addresses and private LAN addresses stay readable.
func DefaultPolicy() Policy {
	return Policy{
		RedactPublicIPs:        true,
		KeepWellKnownPublicIPs: true,
		RedactMACs:             true,
		KeepMACVendor:          true,
		RedactPaths:            true,
		RedactSerials:          true,
		RedactCredentials:      true,
	}
}

// wellKnownPublic are shared-infrastructure addresses that carry no identity. Kept readable so a
// DNS or connectivity report remains verifiable.
var wellKnownPublic = map[string]bool{
	"1.1.1.1": true, "1.0.0.1": true,
	"8.8.8.8": true, "8.8.4.4": true,
	"9.9.9.9": true, "149.112.112.112": true,
	"208.67.222.222": true, "208.67.220.220": true,
	"64.6.64.6": true, "64.6.65.6": true,
	"2606:4700:4700::1111": true, "2606:4700:4700::1001": true,
	"2001:4860:4860::8888": true, "2001:4860:4860::8844": true,
	"2620:fe::fe": true, "2620:fe::9": true,
}

// RedactionCounts says how many items of each kind were removed. It is the summary that travels
// inside the exported file: enough for a reader to know redaction happened and what it covered,
// with no values in it.
type RedactionCounts struct {
	PublicAddresses int `json:"publicAddresses,omitempty"`
	MACAddresses    int `json:"macAddresses,omitempty"`
	UserPaths       int `json:"userPaths,omitempty"`
	Serials         int `json:"serials,omitempty"`
	Credentials     int `json:"credentials,omitempty"`
	Names           int `json:"accountAndHostNames,omitempty"`
	Total           int `json:"total"`
}

func (c *RedactionCounts) add(cat string) {
	switch cat {
	case "ip":
		c.PublicAddresses++
	case "mac":
		c.MACAddresses++
	case "path":
		c.UserPaths++
	case "serial":
		c.Serials++
	case "secret":
		c.Credentials++
	case "name":
		c.Names++
	}
	c.Total++
}

// Merge folds another count set in, used when a caller renders more than one artifact.
func (c *RedactionCounts) Merge(o RedactionCounts) {
	c.PublicAddresses += o.PublicAddresses
	c.MACAddresses += o.MACAddresses
	c.UserPaths += o.UserPaths
	c.Serials += o.Serials
	c.Credentials += o.Credentials
	c.Names += o.Names
	c.Total += o.Total
}

// Entry is one replacement, for the user's own terminal. It is never written into an exported
// file: showing the user what was hidden is the point, publishing it is not.
type Entry struct {
	Category    string `json:"category"`
	Placeholder string `json:"placeholder"`
	Value       string `json:"value"`
}

// Redactor rewrites text, assigning a stable placeholder to each distinct value so the same
// address or serial reads the same way everywhere in the report.
type Redactor struct {
	policy  Policy
	byValue map[string]string
	counts  RedactionCounts
	entries []Entry
}

// NewRedactor prepares a redactor for one policy.
func NewRedactor(p Policy) *Redactor {
	return &Redactor{policy: p, byValue: map[string]string{}}
}

// Counts returns what has been redacted so far.
func (r *Redactor) Counts() RedactionCounts { return r.counts }

// Entries returns the user-facing list of replacements, sorted so two runs read the same.
func (r *Redactor) Entries() []Entry {
	out := append([]Entry(nil), r.entries...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].Placeholder < out[j].Placeholder
	})
	return out
}

// String applies every enabled rule. It is idempotent: running it over its own output changes
// nothing, because a placeholder matches none of the patterns.
func (r *Redactor) String(s string) string {
	if r.policy.RedactCredentials {
		s = r.secrets(s)
	}
	if r.policy.RedactSerials {
		s = r.serials(s)
	}
	if r.policy.RedactMACs {
		s = r.macs(s)
	}
	if r.policy.RedactPaths {
		s = r.paths(s)
	}
	s = r.literals(s)
	s = r.addresses(s)
	return s
}

// placeholderRe matches a placeholder this package produced. Every rule that could otherwise
// re-match its own output skips these, which is what makes String idempotent.
var placeholderRe = regexp.MustCompile(`\[(?:ip|mac|user|account|hostname|redacted|serial|secret)#\d+\]`)

// place returns the stable placeholder for a value and records the entry once. Placeholders look
// like [ip#1], [mac#2] ... - a form that cannot be mistaken for a device address and that no
// rule will match a second time, which is what makes redaction idempotent.
func (r *Redactor) place(cat, prefix, value string) string {
	if p, ok := r.byValue[value]; ok {
		return p
	}
	n := 1
	for _, exist := range r.byValue {
		if strings.HasPrefix(exist, "["+prefix+"#") {
			n++
		}
	}
	p := fmt.Sprintf("[%s#%d]", prefix, n)
	r.byValue[value] = p
	r.entries = append(r.entries, Entry{Category: cat, Placeholder: p, Value: value})
	r.counts.add(cat)
	return p
}

// ---- credentials ------------------------------------------------------------------------------

var (
	secretBlock = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)
	secretLabel = regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|authorization|cookie|set-cookie|passphrase)\b\s*[:=]\s*("[^"]*"|'[^']*'|\S{3,})`)
	bearer      = regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._\-+/=]{8,}`)
	keyShapes   = regexp.MustCompile(`\b(sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{35}|xox[baprs]-[A-Za-z0-9\-]{10,}|eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})\b`)
	urlCreds    = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.\-]*://)([^/\s:@]{1,64})(:[^/\s@]{1,64})?@`)
)

// authSchemeWords are the words that follow an Authorization label without being the secret.
var authSchemeWords = map[string]bool{
	"bearer": true, "basic": true, "digest": true, "negotiate": true, "ntlm": true,
}

func (r *Redactor) secrets(s string) string {
	repl := func(m string) string { return r.place("secret", "secret", m) }
	if strings.Contains(s, "PRIVATE KEY") {
		s = secretBlock.ReplaceAllStringFunc(s, func(string) string { return "[private key removed]" })
	}
	s = keyShapes.ReplaceAllStringFunc(s, repl)
	s = bearer.ReplaceAllStringFunc(s, func(m string) string { return "Bearer " + r.place("secret", "secret", m) })
	s = secretLabel.ReplaceAllStringFunc(s, func(m string) string {
		// Keep the label so the reader knows a value was there; replace the value.
		if i := strings.IndexAny(m, ":="); i > 0 {
			val := m[i+1:]
			// A value that is already a placeholder came from a previous pass; re-replacing it
			// would mint a second placeholder for the same secret.
			if v := strings.TrimSpace(val); placeholderRe.MatchString(v) {
				return m
			}
			// "Authorization: Bearer <token>" - the scheme word is part of the label, not the
			// secret, and the token itself is handled by the bearer rule above.
			if authSchemeWords[strings.ToLower(strings.TrimSpace(val))] {
				return m
			}
			sep := "="
			if m[i] == ':' {
				sep = ":"
			}
			return m[:i] + sep + " " + r.place("secret", "secret", val)
		}
		return r.place("secret", "secret", m)
	})
	s = urlCreds.ReplaceAllStringFunc(s, func(m string) string {
		sub := urlCreds.FindStringSubmatch(m)
		if len(sub) < 3 {
			return m
		}
		if placeholderRe.MatchString(sub[2]) || (len(sub) > 3 && placeholderRe.MatchString(sub[3])) {
			return m
		}
		// The user name in user:password@ is an account name, not secret material; the password
		// is. Keeping the categories right is what makes the counts mean anything.
		user := r.place("name", "account", sub[2])
		if len(sub) > 3 && sub[3] != "" {
			return sub[1] + user + ":" + r.place("secret", "secret", sub[3]) + "@"
		}
		return sub[1] + user + "@"
	})
	return s
}

// ---- serials and device identifiers -----------------------------------------------------------

var (
	serialLabeled = regexp.MustCompile(`(?i)\b(imei|meid|iccid|imsi|esn|serial(?:\s*(?:number|no|#))?|s/n|sn)\b\s*[:=#]?\s*([A-Za-z0-9._\-]{6,32})`)
	imeiBare      = regexp.MustCompile(`\b\d{15}\b|\b\d{19,20}\b`)
	samsungSerial = regexp.MustCompile(`\bR[0-9]{2}[A-Z0-9]{8,10}\b`)
	// The USB instance path is written with single backslashes in text and doubled ones in the
	// exported JSON, so the separators are captured rather than assumed.
	usbInstance = regexp.MustCompile(`(?i)\bUSB(\\{1,2})VID_([0-9A-F]{4})&PID_([0-9A-F]{4})(\\{1,2})([^\\\s"']+)`)
)

func (r *Redactor) serials(s string) string {
	s = usbInstance.ReplaceAllStringFunc(s, func(m string) string {
		sub := usbInstance.FindStringSubmatch(m)
		if len(sub) < 6 {
			return m
		}
		// Already replaced on a previous pass.
		if strings.HasPrefix(sub[5], "[") {
			return m
		}
		// The vendor and product ids identify the device model, which a reader needs; the
		// instance segment carries the unit's own serial, which they do not.
		return "USB" + sub[1] + "VID_" + sub[2] + "&PID_" + sub[3] + sub[4] + r.place("serial", "serial", sub[5])
	})
	s = serialLabeled.ReplaceAllStringFunc(s, func(m string) string {
		sub := serialLabeled.FindStringSubmatch(m)
		if len(sub) < 3 {
			return m
		}
		// "Serial Number" is one label. When the text after it has already been redacted - so
		// the serial slot holds a placeholder - the regex backtracks and would capture the word
		// "Number" as though it were a serial. It is part of the label, so leave the match alone.
		if serialLabelWords[strings.ToLower(sub[2])] {
			return m
		}
		return sub[1] + ": " + r.place("serial", "serial", sub[2])
	})
	s = imeiBare.ReplaceAllStringFunc(s, func(m string) string { return r.place("serial", "serial", m) })
	s = samsungSerial.ReplaceAllStringFunc(s, func(m string) string { return r.place("serial", "serial", m) })
	return s
}

// serialLabelWords are the words that form a serial label rather than its value.
var serialLabelWords = map[string]bool{
	"number": true, "no": true, "serial": true, "sn": true, "s/n": true,
	"imei": true, "meid": true, "iccid": true, "imsi": true, "esn": true,
}

// ---- MAC addresses ----------------------------------------------------------------------------

var macAddr = regexp.MustCompile(`\b[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}\b`)

func (r *Redactor) macs(s string) string {
	return macAddr.ReplaceAllStringFunc(s, func(m string) string {
		// The same device address can appear in several places; the mapping is decided once so
		// the report counts it once and reads identically wherever it appears.
		if p, ok := r.byValue[m]; ok {
			return p
		}
		if !r.policy.KeepMACVendor {
			return r.place("mac", "mac", m)
		}
		sep := byte(':')
		if strings.Contains(m, "-") {
			sep = '-'
		}
		parts := strings.FieldsFunc(m, func(c rune) bool { return c == ':' || c == '-' })
		if len(parts) != 6 {
			return r.place("mac", "mac", m)
		}
		// The vendor part stays (OUI); the three octets that identify this specific machine
		// are replaced with literal "xx" so the shape is obvious.
		masked := strings.Join(parts[:3], string(sep)) + string(sep) + "xx" + string(sep) + "xx" + string(sep) + "xx"
		if masked == m {
			return m
		}
		r.byValue[m] = masked
		r.entries = append(r.entries, Entry{Category: "mac", Placeholder: masked, Value: m})
		r.counts.add("mac")
		return masked
	})
}

// ---- user paths -------------------------------------------------------------------------------

var (
	// A Windows path appears in two shapes: as text (single backslashes) and inside the
	// exported JSON (each backslash doubled by JSON escaping). Both are redacted, and the
	// separators are preserved exactly as found, so the JSON stays valid JSON.
	winUserPath  = regexp.MustCompile(`(?i)\b([a-z]):(\\{1,2})Users(\\{1,2})([^\\\s"']+)`)
	winDocPath   = regexp.MustCompile(`(?i)\b([a-z]):(\\{1,2})Documents and Settings(\\{1,2})([^\\\s"']+)`)
	unixHomePath = regexp.MustCompile(`\B/(?:home|Users)/[^/\s"']+`)
)

func (r *Redactor) paths(s string) string {
	s = winUserPath.ReplaceAllStringFunc(s, func(m string) string {
		sub := winUserPath.FindStringSubmatch(m)
		if len(sub) < 5 {
			return m
		}
		// Already replaced on a previous pass.
		if strings.HasPrefix(sub[4], "[") {
			return m
		}
		return m[:len(m)-len(sub[4])] + r.place("path", "user", sub[4])
	})
	s = winDocPath.ReplaceAllStringFunc(s, func(m string) string {
		sub := winDocPath.FindStringSubmatch(m)
		if len(sub) < 5 {
			return m
		}
		if strings.HasPrefix(sub[4], "[") {
			return m
		}
		return m[:len(m)-len(sub[4])] + r.place("path", "user", sub[4])
	})
	s = unixHomePath.ReplaceAllStringFunc(s, func(m string) string {
		// Keep the directory's role (home or Users) so the reader still knows what kind of
		// path it is.
		for _, prefix := range []string{"/Users/", "/home/"} {
			if strings.HasPrefix(m, prefix) {
				tail := m[len(prefix):]
				if strings.HasPrefix(tail, "[") {
					return m
				}
				return prefix + r.place("path", "user", tail)
			}
		}
		return m
	})
	return s
}

// ---- exact literals ---------------------------------------------------------------------------
//
// A literal is a value only the caller knows: the machine name, the account name, anything else
// the user names. All literals are replaced in ONE pass over the text (longest first), so a
// replacement can never be re-scanned by a later literal - including the case where the literals
// overlap, or where the value happens to look like part of a placeholder already inserted.
func (r *Redactor) literals(s string) string {
	type lit struct{ value, prefix string }
	var evidence []lit
	for _, v := range r.policy.Usernames {
		evidence = append(evidence, lit{v, "account"})
	}
	for _, v := range r.policy.Hostnames {
		evidence = append(evidence, lit{v, "hostname"})
	}
	for _, v := range r.policy.Extra {
		evidence = append(evidence, lit{v, "redacted"})
	}
	use := evidence[:0:0]
	for _, l := range evidence {
		if len(strings.TrimSpace(l.value)) >= 3 {
			use = append(use, l)
		}
	}
	if len(use) == 0 {
		return s
	}
	sort.SliceStable(use, func(i, j int) bool { return len(use[i].value) > len(use[j].value) })

	byLower := make(map[string]lit, len(use))
	parts := make([]string, 0, len(use)+1)
	parts = append(parts, placeholderRe.String())
	for _, l := range use {
		byLower[strings.ToLower(strings.TrimSpace(l.value))] = l
		parts = append(parts, regexp.QuoteMeta(strings.TrimSpace(l.value)))
	}
	re := regexp.MustCompile("(?i)" + strings.Join(parts, "|"))
	return re.ReplaceAllStringFunc(s, func(m string) string {
		if strings.HasPrefix(m, "[") {
			// A placeholder from an earlier pass: leave it alone.
			return m
		}
		l, ok := byLower[strings.ToLower(m)]
		if !ok {
			return m
		}
		return r.place("name", l.prefix, l.value)
	})
}

// ---- addresses --------------------------------------------------------------------------------

var (
	ipv4Candidate = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	ipv6Candidate = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?:%[0-9a-z]+)?\b`)
)

func (r *Redactor) addresses(s string) string {
	if !r.policy.RedactPublicIPs && !r.policy.RedactPrivateIPs {
		return s
	}
	s = ipv4Candidate.ReplaceAllStringFunc(s, func(m string) string {
		return r.considerIP(m, m, "ip")
	})
	s = ipv6Candidate.ReplaceAllStringFunc(s, func(m string) string {
		// A candidate that already contains a placeholder must not be touched again.
		if strings.Contains(m, "[") {
			return m
		}
		// A MAC address is a valid IPv6 literal syntactically; if MAC redaction is off, the
		// reader asked to keep it readable, so it is not re-classified as an address here.
		if macLike.MatchString(m) {
			return m
		}
		host := m
		if i := strings.IndexByte(host, '%'); i > 0 {
			host = host[:i]
		}
		ip := net.ParseIP(host)
		if ip == nil || ip.To4() != nil {
			return m
		}
		// ULA and link-local addresses are not global; the policy decides whether they go.
		return r.considerIP(host, m, "ip")
	})
	return s
}

// macLike recognises a MAC address in either separator style.
var macLike = regexp.MustCompile(`(?i)^(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}$`)

// considerIP decides whether one address is removed. original is what the mapping records;
// matched is what appears in the text (they differ for an IPv6 candidate carrying a zone).
func (r *Redactor) considerIP(original, matched, prefix string) string {
	ip := net.ParseIP(original)
	if ip == nil {
		return matched
	}
	public := ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast()
	if public {
		if r.policy.KeepWellKnownPublicIPs && wellKnownPublic[original] {
			return matched
		}
		if !r.policy.RedactPublicIPs {
			return matched
		}
	} else if !r.policy.RedactPrivateIPs {
		return matched
	}
	if strings.Contains(matched, "[") {
		return matched
	}
	return r.place("ip", prefix, original)
}

// Describe renders the counts as one line for the user, in their words rather than ours.
func (c RedactionCounts) Describe() string {
	if c.Total == 0 {
		return "nothing needed redacting"
	}
	var parts []string
	if c.PublicAddresses > 0 {
		parts = append(parts, fmt.Sprintf("%d public address(es)", c.PublicAddresses))
	}
	if c.MACAddresses > 0 {
		parts = append(parts, fmt.Sprintf("%d MAC address(es)", c.MACAddresses))
	}
	if c.UserPaths > 0 {
		parts = append(parts, fmt.Sprintf("%d account path(s)", c.UserPaths))
	}
	if c.Serials > 0 {
		parts = append(parts, fmt.Sprintf("%d serial number(s)", c.Serials))
	}
	if c.Credentials > 0 {
		parts = append(parts, fmt.Sprintf("%d credential(s)", c.Credentials))
	}
	if c.Names > 0 {
		parts = append(parts, fmt.Sprintf("%d name(s)", c.Names))
	}
	return strings.Join(parts, ", ")
}
