package diag

// Tests for the command layer. The outputs below are recorded shapes from Windows PowerShell
// (ConvertTo-Json) and from Linux tools, replayed here as data: this is how the Windows command
// set is verified on a Linux development host, and every test that does so says which platform
// its sample came from.

import (
	"strings"
	"testing"
)

// TestPSJSONHandlesBothShapes covers the two forms ConvertTo-Json really produces: an array for
// several pipeline items and a bare object for one. A parser that only accepts the array form
// fails exactly when a machine has a single adapter, which is common on a laptop.
func TestPSJSONHandlesBothShapes(t *testing.T) {
	t.Run("array", func(t *testing.T) {
		objs, err := psJSON(`[{"Name":"Ethernet"},{"Name":"Wi-Fi"}]`)
		if err != nil {
			t.Fatal(err)
		}
		if len(objs) != 2 || psStr(objs[1], "Name") != "Wi-Fi" {
			t.Fatalf("decoded %+v", objs)
		}
	})
	t.Run("single object", func(t *testing.T) {
		objs, err := psJSON(`{"Name":"Ethernet","DriverProvider":"Intel"}`)
		if err != nil {
			t.Fatal(err)
		}
		if len(objs) != 1 || psStr(objs[0], "DriverProvider") != "Intel" {
			t.Fatalf("decoded %+v", objs)
		}
	})
	t.Run("empty", func(t *testing.T) {
		objs, err := psJSON("   \n")
		if err != nil || len(objs) != 0 {
			t.Fatalf("empty output decoded to %+v, err %v", objs, err)
		}
	})
	t.Run("preamble", func(t *testing.T) {
		// A profile script that prints a banner before the JSON is the usual reason a parse
		// "mysteriously" fails on a real machine.
		objs, err := psJSON("Loading profile...\n{\"Name\":\"Ethernet\"}")
		if err != nil {
			t.Fatal(err)
		}
		if len(objs) != 1 || psStr(objs[0], "Name") != "Ethernet" {
			t.Fatalf("decoded %+v", objs)
		}
	})
	t.Run("not json", func(t *testing.T) {
		if _, err := psJSON("Get-NetAdapter : Access denied"); err == nil {
			t.Fatal("a non-JSON error message was accepted as JSON")
		}
	})
}

// TestPSFieldAccessors covers the type coercions PowerShell's serializer forces on us: numbers
// that arrive as strings, booleans that arrive as 0/1, and nulls that must not read as zero.
func TestPSFieldAccessors(t *testing.T) {
	obj := map[string]any{
		"Enabled":   true,
		"ifIndex":   float64(12),
		"ifMetric":  "45",
		"Interface": nil,
		"Addresses": []any{map[string]any{"IPAddress": "10.0.0.5"}},
		"Gateway":   map[string]any{"NextHop": "10.0.0.1"},
	}
	if got := psStr(obj, "Interface"); got != "" {
		t.Errorf("a null field read as %q", got)
	}
	if v, ok := psInt(obj, "ifIndex"); !ok || v != 12 {
		t.Errorf("ifIndex = %d (ok=%t)", v, ok)
	}
	if v, ok := psInt(obj, "ifMetric"); !ok || v != 45 {
		t.Errorf("a numeric string did not coerce: %d (ok=%t)", v, ok)
	}
	if v, ok := psBool(obj, "Enabled"); !ok || !v {
		t.Errorf("bool = %t (ok=%t)", v, ok)
	}
	if got := addrStrings(obj["Addresses"]); len(got) != 1 || got[0] != "10.0.0.5" {
		t.Errorf("addresses decoded as %v", got)
	}
	if got := gatewayStrings(obj["Gateway"]); len(got) != 1 || got[0] != "10.0.0.1" {
		t.Errorf("gateway decoded as %v", got)
	}
	// Case-insensitive lookup: PowerShell's property casing varies between cmdlets.
	if got := psStr(obj, "ifindex"); got != "12" {
		t.Errorf("case-insensitive lookup returned %q", got)
	}
}

// TestParsePingLossRejectsUnreachable is the point of parsing ping at all: Windows ping exits 0
// for "Destination host unreachable", so the exit code is not a result.
func TestParsePingLossRejectsUnreachable(t *testing.T) {
	cases := []struct {
		name    string
		out     string
		wantOK  bool
		wantPct float64
	}{
		{
			name:    "windows reply",
			out:     "Reply from 10.0.0.1: bytes=32 time=2ms TTL=64\r\n\r\nPing statistics for 10.0.0.1:\r\n    Packets: Sent = 2, Received = 2, Lost = 0 (0% loss),\r\nApproximate round trip times in milli-seconds:\r\n    Minimum = 1ms, Maximum = 2ms, Average = 1ms\r\n",
			wantOK:  true,
			wantPct: 0,
		},
		{
			name:    "windows partial loss",
			out:     "Ping statistics for 10.0.0.1:\r\n    Packets: Sent = 2, Received = 1, Lost = 1 (50% loss),\r\n    Minimum = 1ms, Maximum = 1ms, Average = 1ms\r\n",
			wantOK:  true,
			wantPct: 50,
		},
		{
			name:    "windows unreachable",
			out:     "Reply from 10.0.0.1: Destination host unreachable.\r\n\r\nPing statistics for 10.0.1.1:\r\n    Packets: Sent = 2, Received = 2, Lost = 0 (0% loss),\r\n",
			wantOK:  true,
			wantPct: 100,
		},
		{
			name:    "linux reply",
			out:     "PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.\n64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=9.7 ms\n\n--- 1.1.1.1 ping statistics ---\n2 packets transmitted, 2 received, 0% packet loss, time 1001ms\nrtt min/avg/max/mdev = 9.2/9.4/9.7/0.2 ms\n",
			wantOK:  true,
			wantPct: 0,
		},
		{
			name:    "linux total loss",
			out:     "PING 10.9.9.9 (10.9.9.9) 56(84) bytes of data.\n\n--- 10.9.9.9 ping statistics ---\n2 packets transmitted, 0 received, 100% packet loss, time 1000ms\n",
			wantOK:  true,
			wantPct: 100,
		},
		{
			name:   "garbage",
			out:    "ping: usage error",
			wantOK: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pct, _, ok := parsePingLoss(c.out)
			if ok != c.wantOK {
				t.Fatalf("ok = %t, want %t (from %q)", ok, c.wantOK, c.out)
			}
			if ok && pct != c.wantPct {
				t.Fatalf("loss = %v, want %v", pct, c.wantPct)
			}
		})
	}
}

func TestParsePingAverage(t *testing.T) {
	win := "Packets: Sent = 2, Received = 2, Lost = 0 (0% loss),\r\nApproximate round trip times in milli-seconds:\r\n    Minimum = 1ms, Maximum = 9ms, Average = 4ms"
	if _, avg, ok := parsePingLoss(win); !ok || avg != 4 {
		t.Errorf("windows average = %v (ok=%t), want 4", avg, ok)
	}
	lin := "2 packets transmitted, 2 received, 0% packet loss, time 1001ms\nrtt min/avg/max/mdev = 9.200/9.432/9.700/0.200 ms"
	if _, avg, ok := parsePingLoss(lin); !ok || avg < 9.4 || avg > 9.5 {
		t.Errorf("linux average = %v (ok=%t), want about 9.43", avg, ok)
	}
}

// TestParseTraceroute covers both tools' line shapes and the key distinction the check reports:
// a trace that stops with "* * *" is not proof of a fault.
func TestParseTraceroute(t *testing.T) {
	win := "\r\nTracing route to one.one.one.one [1.1.1.1]\r\nover a maximum of 15 hops:\r\n\r\n  1     1 ms     1 ms     1 ms  192.168.1.1\r\n  2     *        *        *     Request timed out.\r\n  3    10 ms     9 ms    11 ms  1.1.1.1\r\n\r\nTrace complete.\r\n"
	hops, reached := parseTracerouteHops(win)
	if hops != 3 {
		t.Errorf("windows hops = %d, want 3", hops)
	}
	if !reached {
		t.Error("windows trace with addressed hops was reported as never reached")
	}

	lin := "traceroute to 1.1.1.1 (1.1.1.1), 15 hops max, 60 byte packets\n 1  192.168.1.1  0.512 ms  0.487 ms  0.471 ms\n 2  * * *\n 3  * * *\n"
	hops, reached = parseTracerouteHops(lin)
	if hops != 3 {
		t.Errorf("linux hops = %d, want 3", hops)
	}
	if !reached {
		t.Error("linux trace with an addressed first hop was reported as never reached")
	}

	none := "traceroute to 10.255.255.1 (10.255.255.1), 15 hops max\n 1  * * *\n 2  * * *\n"
	hops, reached = parseTracerouteHops(none)
	if hops != 2 || reached {
		t.Errorf("all-silent trace reported hops=%d reached=%t", hops, reached)
	}
}

// TestParseEngineList checks the parsing of the engine's own adapter listing.
func TestParseEngineList(t *testing.T) {
	out := "net-merge interfaces:\n" +
		"USE   enp130s0  (index 4)  192.168.1.20  2001:db8::5\n" +
		"USE   wlan0     (index 5)  10.0.0.20\n" +
		"skip  docker0: virtual bridge\n" +
		"skip  enp1s0: no carrier (link down)\n"
	use, skip := parseEngineList(out)
	if len(use) != 2 {
		t.Fatalf("use = %v", use)
	}
	if !strings.HasPrefix(use[0], "enp130s0") {
		t.Errorf("first usable adapter parsed as %q", use[0])
	}
	if len(skip) != 2 || !strings.Contains(skip[0], "docker0: virtual bridge") {
		t.Errorf("skip = %v", skip)
	}
}

// TestNTPReplyValidation is the difference between "a UDP packet came back" and "UDP works":
// the reply is checked for length, mode and a transmitted timestamp.
func TestNTPReplyValidation(t *testing.T) {
	valid := make([]byte, 48)
	valid[0] = 0x24 // LI 0, VN 4, mode 4 (server)
	valid[1] = 2    // stratum 2
	valid[40] = 0xE5
	if stratum, ok := parseNTP(valid); !ok || stratum != 2 {
		t.Fatalf("a valid server reply was rejected: stratum=%d ok=%t", stratum, ok)
	}

	short := valid[:24]
	if _, ok := parseNTP(short); ok {
		t.Error("a 24-byte reply was accepted as NTP")
	}
	clientEcho := make([]byte, 48)
	clientEcho[0] = 0x23 // mode 3: a reflection of our own packet
	if _, ok := parseNTP(clientEcho); ok {
		t.Error("a reflected client packet was accepted as a server reply")
	}
	unsynced := make([]byte, 48)
	unsynced[0] = 0xE4 // LI 3: unsynchronised
	if _, ok := parseNTP(unsynced); ok {
		t.Error("an unsynchronised server reply was accepted")
	}
	noStamp := make([]byte, 48)
	noStamp[0] = 0x24
	if _, ok := parseNTP(noStamp); ok {
		t.Error("a reply with a zero transmit timestamp was accepted")
	}
}

// TestSplitEndpoint accepts the address forms a person types and rejects the ambiguous ones.
func TestSplitEndpoint(t *testing.T) {
	cases := []struct {
		in      string
		host    string
		port    string
		wantErr bool
	}{
		{"one.one.one.one:443", "one.one.one.one", "443", false},
		{"1.1.1.1:53", "1.1.1.1", "53", false},
		{"[2606:4700:4700::1111]:443", "2606:4700:4700::1111", "443", false},
		{"2606:4700:4700::1111:443", "", "", true}, // ambiguous without brackets
		{"example.test", "", "", true},             // no port
		{"example.test:", "", "", true},            // empty port
		{"example.test:abc", "", "", true},         // non-numeric port
		{"[2606::1]", "", "", true},                // brackets with no port
	}
	for _, c := range cases {
		host, port, err := splitEndpoint(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("%q was accepted as %s:%s", c.in, host, port)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q rejected: %v", c.in, err)
			continue
		}
		if host != c.host || port != c.port {
			t.Errorf("%q split as %s:%s, want %s:%s", c.in, host, port, c.host, c.port)
		}
	}
}

// TestAddressClassification checks the address ranges the DNS check uses to flag a suspicious
// answer, and that CGNAT (which is normal on a tethered phone) is not called public.
func TestAddressClassification(t *testing.T) {
	pub := []string{"1.1.1.1", "8.8.8.8", "93.184.216.34", "2606:4700:4700::1111"}
	for _, s := range pub {
		if !isPublic(parseIP(t, s)) {
			t.Errorf("%s was not classified as public", s)
		}
	}
	notPub := []string{"10.0.0.1", "192.168.1.1", "172.16.5.4", "100.64.3.9", "127.0.0.1", "fd00::1", "fe80::1"}
	for _, s := range notPub {
		if isPublic(parseIP(t, s)) {
			t.Errorf("%s was classified as public", s)
		}
	}
	for _, s := range []string{"192.0.2.5", "198.51.100.9", "203.0.113.9"} {
		if !isReservedOrDocumentation(parseIP(t, s)) {
			t.Errorf("%s was not classified as reserved/documentation", s)
		}
	}
}

// TestWindowsCommandSetIsReadOnly is the structural guarantee behind "diagnostics never change
// anything": no command in the diagnostic command set may contain a state-changing cmdlet.
func TestWindowsCommandSetIsReadOnly(t *testing.T) {
	// Mutating PowerShell verbs. Get-*, Test-*, Resolve-*, Select-* are the read-only verbs.
	mutating := []string{
		"Set-", "New-", "Remove-", "Add-", "Clear-", "Disable-", "Enable-",
		"Restart-", "Start-", "Stop-", "Rename-", "Reset-", "Update-", "Install-",
		"Uninstall-", "Register-", "Unregister-", "Enable-NetAdapter", "Set-NetFirewallProfile",
	}
	for name, c := range windowsCmds() {
		joined := strings.Join(c.Args2(), " ")
		for _, m := range mutating {
			if strings.Contains(joined, m) {
				t.Errorf("windows command %q contains the mutating token %q: %s", name, m, joined)
			}
		}
	}
	// And the same for the direct tools that take their own flags.
	linuxMutating := []string{"set ", "add ", "del ", "flush ", "down ", "up "}
	for name, c := range linuxCmds() {
		joined := strings.Join(c.Args2(), " ")
		for _, m := range linuxMutating {
			if strings.Contains(" "+joined+" ", m) {
				t.Errorf("linux command %q contains the mutating token %q: %s", name, m, joined)
			}
		}
	}
}

// TestWindowsCommandsUseNoProfile checks the invocation contract: a user's PowerShell profile
// must never be able to change what a diagnostic reports.
func TestWindowsCommandsUseNoProfile(t *testing.T) {
	for name, c := range windowsCmds() {
		if c.Name != "powershell.exe" {
			continue
		}
		joined := strings.Join(c.Args, " ")
		if !strings.Contains(joined, "-NoProfile") || !strings.Contains(joined, "-NonInteractive") {
			t.Errorf("windows command %q is missing -NoProfile/-NonInteractive: %s", name, joined)
		}
	}
}

// TestResolveCommandAvoidsHostsFile checks that the DNS resolution cmdlet is asked not to read
// the hosts file: otherwise a local override would look like a working DNS server.
func TestResolveCommandAvoidsHostsFile(t *testing.T) {
	cmd := psResolve("example.test", "1.1.1.1")
	joined := strings.Join(cmd.Args, " ")
	for _, want := range []string{"-DnsOnly", "-NoHostsFile", "-Server", "Resolve-DnsName"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the resolve command is missing %q: %s", want, joined)
		}
	}
	if !strings.Contains(joined, psQuote("example.test")) {
		t.Errorf("the name was not quoted: %s", joined)
	}
}

// TestPSQuoteEscapesSingleQuotes closes the injection path between a name from settings and the
// PowerShell command line: an embedded quote must be doubled, not passed through.
func TestPSQuoteEscapesSingleQuotes(t *testing.T) {
	got := psQuote("a'; Remove-Item -Recurse C:\\; 'b")
	want := `'a''; Remove-Item -Recurse C:\; ''b'`
	if got != want {
		t.Errorf("quoted literal = %q, want %q", got, want)
	}
}
