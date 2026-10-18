package diagreport

// Tests for the redaction pass.
//
// Every value used here is synthetic: documentation/example addresses, reserved or invented
// serials, and made-up credentials. Nothing in this file came from a real host. The point of
// these tests is not that one pattern works, but that the two properties the export relies on
// hold: values are replaced everywhere they appear, and the pass is idempotent - which is what
// lets Bundle measure the counts with a first pass and then render with the same redactor.

import (
	"encoding/json"
	"strings"
	"testing"
)

// sampleText is a grab-bag of everything the policies are meant to cover, shaped like the text a
// diagnostic export contains: command output, paths, device data and a credential.
const sampleText = `[ipv4.connect] connected to 93.184.216.34:443 in 41ms
resolver 1.1.1.1 answered for example.com; resolver 9.9.9.9 timed out
host 2606:2800:0220:0001:0248:1893:25c8:1946 answered, local 10.0.0.7, gateway 192.168.1.254
adapter Ethernet (a4:5e:60:1a:2b:3c) link up, mtu 1500
config C:\Users\alex.smith\AppData\Local\net-merge\control-center.json
also /home/alex/Desktop/orcaproj/net-merge/state.json and C:\Users\alex.smith\Documents
device IMEI: 356938035643809
USB\VID_1234&PID_5678\SERIAL12345
Serial Number: R58M12ABCDE
connecting with password: hunter2!
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
api_key = ABCDEF0123456789xyz
key sk-abcdefghijklmnopqrstuv
https://alex:hunter2@example.internal/ws
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAB
-----END OPENSSH PRIVATE KEY-----`

func TestRedactsPublicAddressesAndKeepsInfrastructure(t *testing.T) {
	r := NewRedactor(DefaultPolicy())
	out := r.String(sampleText)

	for _, gone := range []string{
		"93.184.216.34",
		"2606:2800:0220:0001:0248:1893:25c8:1946",
	} {
		if strings.Contains(out, gone) {
			t.Errorf("public address %s was not redacted", gone)
		}
	}
	// Shared infrastructure addresses identify nobody, and a DNS report is unreadable without
	// them; private LAN addresses are the topology, which is the diagnosis.
	for _, kept := range []string{"1.1.1.1", "9.9.9.9", "10.0.0.7", "192.168.1.254"} {
		if !strings.Contains(out, kept) {
			t.Errorf("address %s should have been kept readable", kept)
		}
	}
	if got := r.Counts().PublicAddresses; got != 2 {
		t.Errorf("PublicAddresses = %d, want 2", got)
	}
}

func TestPrivateAddressesRedactedOnlyWhenAsked(t *testing.T) {
	p := DefaultPolicy()
	p.RedactPrivateIPs = true
	r := NewRedactor(p)
	out := r.String("lan 10.0.0.7 gw 192.168.1.254 infra 1.1.1.1")
	for _, gone := range []string{"10.0.0.7", "192.168.1.254"} {
		if strings.Contains(out, gone) {
			t.Errorf("private address %s was not redacted despite the policy", gone)
		}
	}
	if !strings.Contains(out, "1.1.1.1") {
		t.Errorf("a well-known infrastructure address must stay readable even then, got %q", out)
	}
}

func TestWellKnownAddressesRedactedWhenPolicySaysSo(t *testing.T) {
	p := DefaultPolicy()
	p.KeepWellKnownPublicIPs = false
	r := NewRedactor(p)
	out := r.String("resolver 1.1.1.1")
	if strings.Contains(out, "1.1.1.1") {
		t.Errorf("1.1.1.1 must be redacted when the allowlist is off, got %q", out)
	}
}

func TestMACKeepsVendorByDefault(t *testing.T) {
	r := NewRedactor(DefaultPolicy())
	out := r.String("adapter Ethernet (a4:5e:60:1a:2b:3c) link up")
	if strings.Contains(out, "1a:2b:3c") {
		t.Errorf("the device-specific part of the MAC must be removed, got %q", out)
	}
	if !strings.Contains(out, "a4:5e:60:xx:xx:xx") {
		t.Errorf("the OUI should stay readable so the reader can tell an Intel adapter from a phone, got %q", out)
	}
	if got := r.Counts().MACAddresses; got != 1 {
		t.Errorf("MACAddresses = %d, want 1", got)
	}
	// The mapping is recorded for the user's own terminal, not for the file.
	entries := r.Entries()
	if len(entries) != 1 || entries[0].Value != "a4:5e:60:1a:2b:3c" {
		t.Errorf("the user-facing entry should name the original value, got %+v", entries)
	}
}

func TestMACFullyRedactedWhenVendorNotKept(t *testing.T) {
	p := DefaultPolicy()
	p.KeepMACVendor = false
	r := NewRedactor(p)
	out := r.String("adapter (a4:5e:60:1a:2b:3c)")
	if strings.Contains(strings.ToLower(out), "a4") {
		t.Errorf("with KeepMACVendor off the whole address must go, got %q", out)
	}
	if !strings.Contains(out, "[mac#1]") {
		t.Errorf("expected a [mac#N] placeholder, got %q", out)
	}
}

// A MAC address is syntactically a valid IPv6 literal. When MAC redaction is deliberately off,
// the address pass must not re-classify it as a global address and remove it anyway: the user
// asked for those values to stay readable.
func TestMACIsNotReclassifiedAsIPv6(t *testing.T) {
	p := DefaultPolicy()
	p.RedactMACs = false
	r := NewRedactor(p)
	in := "adapter aa:bb:cc:dd:ee:ff"
	if out := r.String(in); out != in {
		t.Errorf("MAC left readable by policy was altered: %q -> %q", in, out)
	}
	if r.Counts().Total != 0 {
		t.Errorf("nothing should have been redacted, counts = %+v", r.Counts())
	}
}

func TestUserPathsRedacted(t *testing.T) {
	r := NewRedactor(DefaultPolicy())
	out := r.String(`C:\Users\alex.smith\AppData\Local\net-merge\control-center.json and C:\Users\alex.smith\Documents and /home/bianca/Desktop/orcaproj`)
	if strings.Contains(out, "alex.smith") || strings.Contains(out, "/home/bianca") {
		t.Errorf("account names must be removed from paths, got %q", out)
	}
	if !strings.Contains(out, `C:\Users\[user#1]\AppData`) {
		t.Errorf("the path shape (drive, Users, AppData) should survive redaction, got %q", out)
	}
	if !strings.Contains(out, "/home/[user#2]/Desktop") {
		t.Errorf("unix home shape should survive redaction, got %q", out)
	}
	// The same account appearing twice is one replacement, and the same placeholder both times.
	if n := strings.Count(out, "[user#1]"); n != 2 {
		t.Errorf("placeholder for the same account should appear twice, got %d in %q", n, out)
	}
	if got := r.Counts().UserPaths; got != 2 {
		t.Errorf("UserPaths = %d, want 2 (one Windows account, one unix account)", got)
	}
}

func TestSerialsAndDeviceIdentifiersRedacted(t *testing.T) {
	r := NewRedactor(DefaultPolicy())
	out := r.String(sampleText)
	for _, gone := range []string{"356938035643809", "SERIAL12345", "R58M12ABCDE"} {
		if strings.Contains(out, gone) {
			t.Errorf("device identifier %s was not redacted", gone)
		}
	}
	// The USB vendor and product ids identify the device model, which is diagnostically useful,
	// so they stay.
	if !strings.Contains(out, `USB\VID_1234&PID_5678`) {
		t.Errorf("vendor/product ids should stay readable, got %q", out)
	}
	if !strings.Contains(out, "IMEI: [serial#") {
		t.Errorf("the label should stay so the reader knows what was there, got %q", out)
	}
}

func TestCredentialsRedacted(t *testing.T) {
	r := NewRedactor(DefaultPolicy())
	out := r.String(sampleText)
	for _, gone := range []string{
		"hunter2!", "eyJhbGciOiJIUzI1NiJ9", "ABCDEF0123456789xyz",
		"sk-abcdefghijklmnopqrstuv", "b3BlbnNzaC1rZXktdjEAAAAB",
	} {
		if strings.Contains(out, gone) {
			t.Errorf("credential material %q survived redaction", gone)
		}
	}
	if !strings.Contains(out, "password: [secret#") {
		t.Errorf("the label should stay so the reader knows a value was removed, got %q", out)
	}
	if !strings.Contains(out, "[private key removed]") {
		t.Errorf("a private key block should be replaced wholesale, got %q", out)
	}
	if !strings.Contains(out, "Bearer [secret#") {
		t.Errorf("a bearer token should keep the scheme and lose the token, got %q", out)
	}
	if got := r.Counts().Credentials; got < 5 {
		t.Errorf("Credentials = %d, want at least 5", got)
	}
}

func TestLiteralNamesRedacted(t *testing.T) {
	p := DefaultPolicy()
	p.Hostnames = []string{"DESKTOP-ABC123"}
	p.Usernames = []string{"alex"}
	r := NewRedactor(p)
	out := r.String("host DESKTOP-ABC123 user alex and alex again on alex-phone")
	for _, gone := range []string{"DESKTOP-ABC123", "alex"} {
		if strings.Contains(out, gone) {
			t.Errorf("literal %s was not redacted: %q", gone, out)
		}
	}
	if got := r.Counts().Names; got != 2 {
		t.Errorf("Names = %d, want 2 (one host name, one account name)", got)
	}
	// Same literal, same placeholder everywhere.
	if n := strings.Count(out, "[account#1]"); n != 3 {
		t.Errorf("the same account should map to one placeholder in all three places, got %d in %q", n, out)
	}
}

// A literal shorter than three characters is skipped: replacing every "j" in a report would
// destroy it, and a one-character account name identifies nobody on its own.
func TestShortLiteralsAreIgnored(t *testing.T) {
	p := DefaultPolicy()
	p.Usernames = []string{"j1"}
	r := NewRedactor(p)
	in := "state directory /run/j1/net-merge"
	if out := r.String(in); out != in {
		t.Errorf("a two-character literal must not be replaced: %q -> %q", in, out)
	}
}

// The property Bundle depends on: the pass is a fixed point. Running it over its own output -
// with the same redactor and with a fresh one - must change nothing and add no entries, or the
// two-pass count measurement would over-report and the second render could mangle placeholders.
func TestRedactionIsIdempotent(t *testing.T) {
	r := NewRedactor(DefaultPolicy())
	once := r.String(sampleText)
	before := r.Counts()

	twice := r.String(once)
	if twice != once {
		t.Errorf("second pass changed the text:\n--- once ---\n%s\n--- twice ---\n%s", once, twice)
	}
	if got := r.Counts(); got != before {
		t.Errorf("second pass changed the counts: %+v -> %+v", before, got)
	}

	fresh := NewRedactor(DefaultPolicy())
	if again := fresh.String(once); again != once {
		t.Errorf("a fresh redactor changed already-redacted text:\n--- once ---\n%s\n--- again ---\n%s", once, again)
	}
	if fresh.Counts().Total != 0 {
		t.Errorf("a fresh redactor should find nothing new in redacted text, got %+v", fresh.Counts())
	}
}

// A literal that happens to be a word inside a placeholder must not corrupt the placeholder:
// "account" as an account name must not turn [account#1] into [account#2#1] on a later pass.
func TestLiteralMatchingInsidePlaceholderIsSafe(t *testing.T) {
	p := DefaultPolicy()
	p.Usernames = []string{"account", "alice"}
	r := NewRedactor(p)
	in := "the account alice logged in"
	once := r.String(in)
	twice := r.String(once)
	if once != twice {
		t.Errorf("placeholders corrupted by a literal that also appears in them: %q -> %q", once, twice)
	}
	if strings.Contains(once, "[account#2#") || strings.Contains(once, "[redacted#2#") {
		t.Errorf("a placeholder was spliced into another placeholder: %q", once)
	}
}

func TestPlaceholdersAreStableAcrossCalls(t *testing.T) {
	r := NewRedactor(DefaultPolicy())
	a := r.String("first mention of 93.184.216.34")
	b := r.String("second mention of 93.184.216.34")
	const want = "[ip#1]"
	if !strings.Contains(a, want) || !strings.Contains(b, want) {
		t.Errorf("the same value must get the same placeholder everywhere: %q / %q", a, b)
	}
}

func TestPlaceholdersSurviveJSONRendering(t *testing.T) {
	// JSON escapes nothing inside a placeholder, but this pins the assumption: the redacted
	// bytes must still be valid JSON, because a machine reader is one of the two audiences.
	doc := map[string]string{"endpoint": "93.184.216.34:443", "path": `C:\Users\alex.smith\x`}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	r := NewRedactor(DefaultPolicy())
	out := r.String(string(raw))
	var back map[string]string
	if err := json.Unmarshal([]byte(out), &back); err != nil {
		t.Fatalf("redacted JSON is no longer valid JSON: %v\n%s", err, out)
	}
	if strings.Contains(back["endpoint"], "93.184.216.34") {
		t.Errorf("value survived: %q", back["endpoint"])
	}
}

func TestWindowsPathsInJSONEscapingAreRedacted(t *testing.T) {
	// The export is redacted as rendered bytes, and JSON doubles backslashes. A path rule that
	// only understood single backslashes would leave the account name in the exported JSON -
	// the one artifact most likely to be shared - while redacting it in the text form.
	raw := `{"stateDir":"C:\\Users\\alex.smith\\AppData\\Local\\net-merge","usb":"USB\\VID_1234&PID_5678\\SERIAL12345"}`
	r := NewRedactor(DefaultPolicy())
	out := r.String(raw)
	if strings.Contains(out, "alex.smith") || strings.Contains(out, "SERIAL12345") {
		t.Fatalf("escaped Windows data survived redaction: %s", out)
	}
	var back map[string]string
	if err := json.Unmarshal([]byte(out), &back); err != nil {
		t.Fatalf("redacted JSON no longer parses: %v\n%s", err, out)
	}
	if !strings.Contains(back["stateDir"], `C:\Users\[user#1]\AppData`) {
		t.Errorf("stateDir lost its shape: %q", back["stateDir"])
	}
	if !strings.Contains(back["usb"], `USB\VID_1234&PID_5678\[serial#1]`) {
		t.Errorf("usb path lost its shape: %q", back["usb"])
	}
}

func TestPolicyOffLeavesTextAlone(t *testing.T) {
	r := NewRedactor(Policy{})
	if out := r.String(sampleText); out != sampleText {
		t.Errorf("with every rule off the text must be unchanged")
	}
}

func TestDescribeCounts(t *testing.T) {
	var c RedactionCounts
	if got := c.Describe(); got != "nothing needed redacting" {
		t.Errorf("Describe(empty) = %q", got)
	}
	c.add("ip")
	c.add("mac")
	c.add("secret")
	got := c.Describe()
	for _, want := range []string{"1 public address", "1 MAC address", "1 credential"} {
		if !strings.Contains(got, want) {
			t.Errorf("Describe() = %q, missing %q", got, want)
		}
	}
}
