package diag

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// This file is the Windows/Linux command layer of the diagnostic centre. Every external
// command a check runs is described here as data, so the Windows command set can be asserted
// by tests that run on Linux (the same approach internal/inventory uses for its probe), and
// so the exact argv of every check is visible in one place.
//
// Rules observed by every spec below:
//
//   - PowerShell always runs with -NoProfile -NonInteractive, so a user's profile script
//     cannot change what a diagnostic reports.
//   - Anything that is parsed is asked for as JSON (-Compress), because parsing a localized
//     table is how Windows diagnostics break on non-English installs.
//   - Nothing here writes. No Set-* cmdlet appears in this file by construction: the check
//     layer has no mechanism to change a setting.
//   - A cmdlet that may not exist on older builds is probed by the caller
//     (Env.hasCommand / the ttlmgr capability probe) before its result is trusted.

// argv is one command: the program plus its arguments.
type argv struct {
	Name string
	Args []string
}

func (a argv) String() string { return strings.Join(a.Args2(), " ") }

// Args2 is the full command including the program, for Evidence.Command.
func (a argv) Args2() []string { return append([]string{a.Name}, a.Args...) }

// psCommand builds a PowerShell invocation of one inline script.
func psCommand(script string) argv {
	return argv{
		Name: "powershell.exe",
		Args: []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script},
	}
}

// ---- Windows command specs -----------------------------------------------------------------

const (
	psIPConfig = "Get-NetIPConfiguration -All | Select-Object InterfaceIndex,InterfaceAlias,InterfaceDescription,NetProfile,IPv4Address,IPv6Address,IPv4DefaultGateway,IPv6DefaultGateway,DNSServer | ConvertTo-Json -Compress -Depth 5"
	psRoutes   = "Get-NetRoute -AddressFamily IPv4,IPv6 | Select-Object AddressFamily,DestinationPrefix,NextHop,InterfaceIndex,InterfaceAlias,RouteMetric,ifMetric,Protocol,Store | ConvertTo-Json -Compress -Depth 4"
	psMetrics  = "Get-NetIPInterface -AddressFamily IPv4,IPv6 | Select-Object ifIndex,InterfaceAlias,AddressFamily,NlMtu,ConnectionState,InterfaceMetric,IgnoreDefaultRoutes,Dhcp,Store | ConvertTo-Json -Compress -Depth 4"
	psDNS      = "Get-DnsClientServerAddress | Select-Object InterfaceIndex,InterfaceAlias,AddressFamily,ServerAddresses | ConvertTo-Json -Compress -Depth 4"
	psAdapters = "Get-NetAdapter -IncludeHidden | Select-Object Name,InterfaceDescription,InterfaceIndex,Status,AdminStatus,MediaConnectionState,MediaType,LinkSpeed,MacAddress,ifIndex,DriverProvider,DriverVersion,DriverDate | ConvertTo-Json -Compress -Depth 4"
	psFirewall = "Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | ConvertTo-Json -Compress -Depth 4"
	psAV       = "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | Select-Object displayName,productState | ConvertTo-Json -Compress -Depth 3"
	psTCPPort  = "Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort,OwningProcess | ConvertTo-Json -Compress -Depth 3"
	psCache    = "Get-DnsClientCache | Select-Object -First 25 Entry,Name,Type,Status,TimeToLive | ConvertTo-Json -Compress -Depth 3"
)

// psResolve builds Resolve-DnsName for one name, optionally at one server. -DnsOnly and
// -NoHostsFile matter: without them a hosts-file entry or a NetBIOS answer would look like a
// working DNS server.
func psResolve(name, server string) argv {
	script := fmt.Sprintf("Resolve-DnsName -Name %s -Type A -DnsOnly -NoHostsFile -ErrorAction Stop | Select-Object Name,Type,IPAddress,NameHost,TTL | ConvertTo-Json -Compress -Depth 3", psQuote(name))
	if server != "" {
		script = fmt.Sprintf("Resolve-DnsName -Name %s -Type A -DnsOnly -NoHostsFile -Server %s -ErrorAction Stop | Select-Object Name,Type,IPAddress,NameHost,TTL | ConvertTo-Json -Compress -Depth 3", psQuote(name), psQuote(server))
	}
	return psCommand(script)
}

// psQuote quotes one PowerShell string literal.
func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// windowsCmds is every Windows command the checks use, in one place for the tests to assert.
func windowsCmds() map[string]argv {
	return map[string]argv{
		"adapters": psCommand(psAdapters),
		"ipconfig": psCommand(psIPConfig),
		"routes":   psCommand(psRoutes),
		"metrics":  psCommand(psMetrics),
		"dns":      psCommand(psDNS),
		"firewall": psCommand(psFirewall),
		"av":       psCommand(psAV),
		"tcpports": psCommand(psTCPPort),
		"dnscache": psCommand(psCache),
		"tracert":  {Name: "tracert", Args: []string{"-d", "-h", "15", "-w", "1000"}},
		"ping":     {Name: "ping", Args: []string{"-n", "2", "-w", "1000"}},
		"pingPath": {Name: "ping", Args: []string{"-n", "1", "-w", "1500", "-f", "-l"}},
		"self":     {Name: "net-merge", Args: []string{}},
	}
}

// ---- Linux command specs -------------------------------------------------------------------

// linuxCmds uses iproute2's JSON output (-j) wherever it exists, because that is stable across
// locales, and falls back to text only for tools without a JSON mode.
func linuxCmds() map[string]argv {
	return map[string]argv{
		"adapters": {Name: "ip", Args: []string{"-j", "-details", "link", "show"}},
		"ipconfig": {Name: "ip", Args: []string{"-j", "addr", "show"}},
		"routes":   {Name: "ip", Args: []string{"-j", "route", "show", "table", "all"}},
		"metrics":  {Name: "ip", Args: []string{"-j", "-details", "link", "show"}},
		"dns":      {Name: "resolvectl", Args: []string{"status"}},
		"tracert":  {Name: "traceroute", Args: []string{"-n", "-m", "15", "-w", "1"}},
		"ping":     {Name: "ping", Args: []string{"-c", "2", "-W", "1"}},
		"pingPath": {Name: "ping", Args: []string{"-c", "1", "-W", "2", "-M", "do", "-s"}},
		"self":     {Name: "net-merge", Args: []string{}},
	}
}

// cmds returns the command set for the environment's platform. An unknown platform gets an
// empty set, and the checks that need commands report a skip rather than inventing one.
func cmds(platform string) map[string]argv {
	switch strings.ToLower(platform) {
	case "windows":
		return windowsCmds()
	case "linux":
		return linuxCmds()
	default:
		return map[string]argv{}
	}
}

// ---- Shared parsing helpers ----------------------------------------------------------------

// psJSON decodes a PowerShell ConvertTo-Json payload into a list of objects. ConvertTo-Json
// emits a bare object (not an array) when the pipeline produced exactly one item, and it
// emits nothing at all for an empty pipeline; both are handled, because both really happen.
func psJSON(s string) ([]map[string]any, error) {
	s = strings.TrimSpace(stripPreamble(s))
	if s == "" {
		return nil, nil
	}
	switch s[0] {
	case '[':
		var arr []map[string]any
		if err := json.Unmarshal([]byte(s), &arr); err != nil {
			return nil, fmt.Errorf("decoding the JSON array: %w", err)
		}
		return arr, nil
	case '{':
		var one map[string]any
		if err := json.Unmarshal([]byte(s), &one); err != nil {
			return nil, fmt.Errorf("decoding the JSON object: %w", err)
		}
		return []map[string]any{one}, nil
	default:
		return nil, fmt.Errorf("output is not JSON: %q", firstChars(s, 120))
	}
}

// stripPreamble removes anything a shell or profile printed before the JSON document, which is
// the usual reason a parse "mysteriously" fails on a real Windows machine.
func stripPreamble(s string) string {
	for i, r := range s {
		if r == '{' || r == '[' {
			return s[i:]
		}
	}
	return s
}

func firstChars(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// psStr reads a string field, tolerating the nulls PowerShell writes for absent values.
func psStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		v, ok := lookupFold(m, k)
		if !ok || v == nil {
			continue
		}
		switch t := v.(type) {
		case string:
			if t != "" {
				return t
			}
		case float64:
			return strconv.FormatFloat(t, 'f', -1, 64)
		case json.Number:
			return t.String()
		case bool:
			if t {
				return "true"
			}
			return "false"
		}
	}
	return ""
}

// psInt reads an integer field, including the string form PowerShell sometimes uses.
func psInt(m map[string]any, keys ...string) (int, bool) {
	for _, k := range keys {
		v, ok := lookupFold(m, k)
		if !ok || v == nil {
			continue
		}
		switch t := v.(type) {
		case float64:
			return int(t), true
		case json.Number:
			if i, err := t.Int64(); err == nil {
				return int(i), true
			}
		case string:
			if i, err := strconv.Atoi(strings.TrimSpace(t)); err == nil {
				return i, true
			}
		case bool:
			if t {
				return 1, true
			}
			return 0, true
		}
	}
	return 0, false
}

// psBool reads a boolean field, accepting the string and numeric forms the serializer uses.
func psBool(m map[string]any, keys ...string) (bool, bool) {
	for _, k := range keys {
		v, ok := lookupFold(m, k)
		if !ok || v == nil {
			continue
		}
		switch t := v.(type) {
		case bool:
			return t, true
		case float64:
			return t != 0, true
		case string:
			switch strings.ToLower(strings.TrimSpace(t)) {
			case "true", "yes", "1":
				return true, true
			case "false", "no", "0":
				return false, true
			}
		}
	}
	return false, false
}

// psList reads an array field that may be a single value, a nested object, or absent.
func psList(m map[string]any, keys ...string) []any {
	for _, k := range keys {
		v, ok := lookupFold(m, k)
		if !ok || v == nil {
			continue
		}
		switch t := v.(type) {
		case []any:
			return t
		case map[string]any:
			return []any{t}
		default:
			return []any{t}
		}
	}
	return nil
}

func lookupFold(m map[string]any, key string) (any, bool) {
	if v, ok := m[key]; ok {
		return v, true
	}
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return nil, false
}

// wait: helpers that turn a parsed object into the flat strings the checks use.

// objStr returns the value of a nested object's field as a string, used for the PowerShell
// shapes like IPv4DefaultGateway = @{ NextHop = '192.168.1.1' }.
func objStr(v any, keys ...string) string {
	if m, ok := v.(map[string]any); ok {
		return psStr(m, keys...)
	}
	return ""
}

// addrStrings pulls IP addresses out of a PowerShell IPv4Address/IPv6Address field, which is
// a list of objects with an IPAddress property.
func addrStrings(v any) []string {
	var out []string
	switch t := v.(type) {
	case []any:
		for _, e := range t {
			if s := objStr(e, "IPAddress", "Address"); s != "" {
				out = append(out, s)
			}
		}
	case map[string]any:
		if s := psStr(t, "IPAddress", "Address"); s != "" {
			out = append(out, s)
		}
	case string:
		out = append(out, t)
	}
	return out
}

// gatewayStrings pulls gateway addresses out, tolerating the single-object form.
func gatewayStrings(v any) []string {
	var out []string
	switch t := v.(type) {
	case []any:
		for _, e := range t {
			if s := objStr(e, "NextHop", "IPAddress", "Address"); s != "" {
				out = append(out, s)
			}
		}
	case map[string]any:
		if s := psStr(t, "NextHop", "IPAddress", "Address"); s != "" {
			out = append(out, s)
		}
	case string:
		out = append(out, t)
	}
	return out
}

// parsePingLoss reads a ping tool's summary and reports the packet loss percentage and the
// average RTT it printed. Windows ping prints "Lost = 1 (50% loss)" and "Average = 12ms";
// iputils prints "50% packet loss" and "rtt min/avg/max/mdev = 0.1/0.2/0.3/0.0 ms". Both are
// parsed here so the check can validate what happened instead of trusting the exit code
// (Windows ping exits 0 even for "Destination host unreachable").
func parsePingLoss(out string) (lossPct float64, avgMs float64, ok bool) {
	lower := strings.ToLower(out)
	// Explicit unreachable reports from either tool.
	if strings.Contains(lower, "destination host unreachable") || strings.Contains(lower, "100% packet loss") ||
		strings.Contains(lower, "lost = 2 (100%") || strings.Contains(lower, "request timed out") && !strings.Contains(lower, "0% loss") {
		return 100, 0, true
	}
	// "Lost = 1 (50% loss)" (Windows, localised number formatting aside)
	if i := strings.Index(lower, "% loss"); i > 0 {
		j := strings.LastIndex(lower[:i], "(")
		if j >= 0 {
			if v, err := strconv.ParseFloat(strings.TrimSpace(lower[j+1:i]), 64); err == nil {
				lossPct = v
				ok = true
			}
		}
	}
	// "50% packet loss" (iputils, busybox)
	if !ok {
		if i := strings.Index(lower, "% packet loss"); i > 0 {
			j := i
			for j > 0 && (lower[j-1] == '.' || (lower[j-1] >= '0' && lower[j-1] <= '9')) {
				j--
			}
			if v, err := strconv.ParseFloat(strings.TrimSpace(lower[j:i]), 64); err == nil {
				lossPct = v
				ok = true
			}
		}
	}
	// Average RTT: "Average = 12ms" or "rtt min/avg/max/mdev = 0.12/0.34/..."
	if i := strings.Index(lower, "average = "); i >= 0 {
		s := lower[i+len("average = "):]
		s = strings.TrimSuffix(strings.TrimSuffix(strings.TrimSpace(strings.Fields(s)[0]), "ms"), "ms")
		if v, err := strconv.ParseFloat(strings.Trim(s, "ms"), 64); err == nil {
			avgMs = v
		}
	} else if i := strings.Index(lower, "rtt min/avg/max"); i >= 0 {
		if eq := strings.Index(lower[i:], "="); eq >= 0 {
			fields := strings.Fields(strings.ReplaceAll(lower[i+eq+1:], "/", " "))
			if len(fields) >= 2 {
				if v, err := strconv.ParseFloat(fields[1], 64); err == nil {
					avgMs = v
				}
			}
		}
	}
	return lossPct, avgMs, ok
}

// parseTracerouteHops counts the hops a traceroute printed and reports whether the last hop
// answered. A traceroute that stops early with "* * *" is not a failure of this host: many
// routers do not answer ICMP, which the check says out loud.
func parseTracerouteHops(out string) (hops int, reached bool) {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.Contains(line, "Tracing route") || strings.Contains(line, "over a maximum") ||
			strings.Contains(line, "traceroute to") || strings.Contains(line, "Route trace") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if _, err := strconv.Atoi(fields[0]); err != nil {
			continue
		}
		hops++
		rest := strings.Join(fields[1:], " ")
		if strings.Contains(rest, "* * *") || strings.Contains(rest, "*  *  *") {
			continue
		}
		// An IPv4/IPv6 literal or a hostname on the hop line means it answered.
		if ipInLine(rest) {
			reached = true
		}
	}
	return hops, reached
}

func ipInLine(s string) bool {
	for _, f := range strings.Fields(s) {
		f = strings.Trim(f, "[]()")
		if net.ParseIP(f) != nil {
			return true
		}
		if i := strings.IndexByte(f, ':'); i > 0 {
			if net.ParseIP(f[:i]) != nil {
				return true
			}
		}
	}
	return false
}
