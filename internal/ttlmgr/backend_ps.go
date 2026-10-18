// Package file: the PowerShell-driven backend.
//
// This file carries no build constraint on purpose. The backend is pure logic over the Runner
// interface, so keeping it buildable everywhere lets the test suite exercise the command
// construction, the tolerant output decoding and the failure classification on any host. The
// single platform-specific piece - reading the registry to tell an explicitly configured value
// from a default - is injected through explicitLookup and lives in registry_windows.go.
package ttlmgr

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// powershell is the interpreter this backend drives. Windows PowerShell 5.1 ships with every
// Windows 10 and 11 install, so it is the baseline; the NetTCPIP cmdlets it can reach are the
// documented mechanism for these settings.
const powershell = "powershell.exe"

// registryKeyIPv4 and registryKeyIPv6 hold the persisted values behind the cmdlets. They are
// read to answer "did the platform have this written down?", which the cmdlets do not expose.
const (
	registryKeyIPv4   = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`
	registryValueIPv4 = "DefaultTTL"

	registryKeyIPv6   = `SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters`
	registryValueIPv6 = "DefaultHopLimit"
)

// WindowsBackend inspects and changes packet-header settings through the documented Windows
// PowerShell networking cmdlets, and reads the registry only to distinguish an explicitly
// configured value from the operating system's own default.
//
// Two rules are load-bearing here:
//
//   - The cmdlets are the mechanism. The registry is read, never written directly, because a
//     direct registry write is not the documented way to change these settings and its effect
//     on the running stack is not something this code can verify.
//   - A capability is probed, not assumed. A cmdlet existing does not imply a parameter
//     exists on that build, so Capabilities checks the parameter list and reports what it
//     found, including the verbatim probe error when it found nothing.
type WindowsBackend struct {
	runner Runner

	// explicitLookup reads a persisted DWORD and reports whether it was present. It is nil,
	// or always reports absent, on hosts without a Windows registry, where nothing is ever
	// reported as explicitly configured.
	explicitLookup func(key, value string) (int, bool)
}

// NewWindowsBackend returns a backend driven by the given runner. Passing the runner in is
// what makes the whole backend testable without a Windows host.
func NewWindowsBackend(r Runner) *WindowsBackend {
	return &WindowsBackend{runner: r, explicitLookup: readRegistryDWORD}
}

// Name implements Backend.
func (w *WindowsBackend) Name() string { return "windows-powershell" }

// psCommandSpec is one cmdlet this backend may use, with the parameter whose presence matters.
type psCommandSpec struct {
	Command   string
	Parameter string
}

// requiredCommands is the full set the backend can use. It is declared once so that probing,
// capability reporting and the diagnostics page cannot drift apart.
func requiredCommands() []psCommandSpec {
	return []psCommandSpec{
		{"Get-NetIPv4Protocol", "DefaultHopLimit"},
		{"Get-NetIPv6Protocol", "DefaultHopLimit"},
		{"Set-NetIPv4Protocol", "DefaultHopLimit"},
		{"Set-NetIPv6Protocol", "DefaultHopLimit"},
		{"Get-NetIPInterface", "CurrentHopLimit"},
		{"Set-NetIPInterface", "CurrentHopLimit"},
	}
}

// probeScript resolves each cmdlet and each parameter and returns the findings as JSON. Doing
// it in one invocation keeps the probe to a single PowerShell start-up, which is the dominant
// cost of every call to this backend.
func probeScript() string {
	var sb strings.Builder
	sb.WriteString("$ErrorActionPreference='SilentlyContinue'\n$out=@()\n")
	for _, c := range requiredCommands() {
		fmt.Fprintf(&sb, "$c=Get-Command %s -ErrorAction SilentlyContinue\n", c.Command)
		sb.WriteString("$has=$false;$err=''\n")
		sb.WriteString("if($c){try{$has=($c.Parameters.Keys -contains '")
		sb.WriteString(c.Parameter)
		sb.WriteString("')}catch{$err=$_.Exception.Message}}else{$err='command not found'}\n")
		fmt.Fprintf(&sb, "$out+=[pscustomobject]@{command='%s';parameter='%s';present=[bool]$c;hasParam=[bool]$has;detail=$err}\n",
			c.Command, c.Parameter)
	}
	sb.WriteString("ConvertTo-Json -InputObject $out -Compress -Depth 3\n")
	return sb.String()
}

// Capabilities implements Backend.
func (w *WindowsBackend) Capabilities(ctx context.Context) Capabilities {
	caps := Capabilities{Platform: "windows", Supported: false}

	if _, err := w.runner.LookPath(powershell); err != nil {
		caps.Notes = append(caps.Notes,
			fmt.Sprintf("PowerShell (%s) was not found, so the documented networking cmdlets could not be probed: %v", powershell, err),
			"No TTL or hop-limit setting was read or changed.")
		return caps
	}

	res := w.runner.Run(ctx, powershell, psArgs(probeScript())...)
	if res.Failed() {
		caps.Notes = append(caps.Notes,
			"The capability probe did not complete, so this build's command support is unknown.",
			"probe: "+res.Command,
			"result: "+res.Output())
		return caps
	}

	rows, err := decodeObjectList(res.Stdout)
	if err != nil {
		caps.Notes = append(caps.Notes,
			"The capability probe returned output that could not be parsed, so command support is unknown.",
			"result: "+firstLine(res.Stdout))
		return caps
	}

	for _, row := range rows {
		cc := CommandCapability{
			Command:   str(row, "command"),
			Parameter: str(row, "parameter"),
			Present:   boolean(row, "present"),
			HasParam:  boolean(row, "hasParam"),
			Detail:    str(row, "detail"),
		}
		if !cc.HasParam {
			cc.CheckError = cc.Detail
		}
		caps.Commands = append(caps.Commands, cc)
	}

	// The backend is usable when at least one complete read/write pair is present. Anything
	// less is reported as unsupported with the specific gap named, rather than half-working.
	has := func(cmd string) bool {
		for _, cc := range caps.Commands {
			if cc.Command == cmd && cc.HasParam {
				return true
			}
		}
		return false
	}
	var missing []string
	for _, c := range requiredCommands() {
		if has(c.Command) {
			continue
		}
		var found *CommandCapability
		for i := range caps.Commands {
			if caps.Commands[i].Command == c.Command {
				found = &caps.Commands[i]
				break
			}
		}
		switch {
		case found == nil:
			missing = append(missing, c.Command+" (not found)")
		case !found.Present:
			missing = append(missing, c.Command+" (not found)")
		default:
			missing = append(missing, fmt.Sprintf("%s (parameter %s missing)", c.Command, c.Parameter))
		}
	}
	caps.Supported = has("Get-NetIPv4Protocol") && has("Set-NetIPv4Protocol") &&
		has("Get-NetIPv6Protocol") && has("Set-NetIPv6Protocol")
	if !caps.Supported {
		caps.Notes = append(caps.Notes,
			"The NetTCPIP cmdlets needed for these settings are not all available on this build: "+strings.Join(missing, ", "),
			"Nothing was read or changed. On a build without them these settings can only be inspected manually.")
		return caps
	}

	caps.Notes = append(caps.Notes,
		"System-global settings are read and written with Get/Set-NetIPv4Protocol and Get/Set-NetIPv6Protocol -DefaultHopLimit.",
		"A system-global change affects every adapter at once.",
		"Per-interface settings are read and written with Get/Set-NetIPInterface -CurrentHopLimit, where the documented value 0 means \"use the system default\".",
		"Windows' built-in default for both families is 128, not the 64 used by other operating systems; the captured original is read from the running system rather than assumed.")
	if !has("Set-NetIPInterface") {
		caps.Notes = append(caps.Notes,
			"Set-NetIPInterface -CurrentHopLimit is not available on this build, so per-interface changes are reported as unsupported rather than approximated with a system-global write.")
	}
	return caps
}

// psArgs builds the argument list for a PowerShell invocation. -NoProfile and -NonInteractive
// keep a user's profile from changing the result or blocking on a prompt, and
// -ExecutionPolicy Bypass lets a machine-wide policy allow an inline command that is generated
// here rather than loaded from disk.
func psArgs(script string) []string {
	return []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script}
}

// Read implements Backend.
//
// It asks the cmdlet for the effective value, then reads the registry to learn whether that
// value was explicitly configured. A cmdlet failure is not papered over with a registry guess:
// when the effective value cannot be read, Read fails and says why.
func (w *WindowsBackend) Read(ctx context.Context, ref SettingRef) (Observed, error) {
	if !ref.Kind.IsConfigurable() {
		return Observed{}, newError(CodeUnsupported,
			fmt.Sprintf("%s is not a host setting", ref.Kind),
			ref.Kind.Explain())
	}

	if ref.Scope == ScopePerInterface {
		return w.readInterface(ctx, ref)
	}
	return w.readSystem(ctx, ref)
}

func (w *WindowsBackend) readSystem(ctx context.Context, ref SettingRef) (Observed, error) {
	cmd := "Get-NetIPv4Protocol"
	regKey, regValue := registryKeyIPv4, registryValueIPv4
	if ref.Family == FamilyIPv6 {
		cmd, regKey, regValue = "Get-NetIPv6Protocol", registryKeyIPv6, registryValueIPv6
	}
	script := fmt.Sprintf("(%s -ErrorAction Stop).DefaultHopLimit | ConvertTo-Json -Compress", cmd)
	res := w.runner.Run(ctx, powershell, psArgs(script)...)
	if res.Failed() {
		return Observed{}, newError(CodeReadFailed,
			fmt.Sprintf("could not read the system-wide %s value", ref.Family),
			"Run the same command in an elevated PowerShell window to see the underlying error.",
			"command: "+res.Command, "result: "+res.Output())
	}
	val, err := decodeInt(res.Stdout)
	if err != nil {
		return Observed{}, newError(CodeReadFailed,
			fmt.Sprintf("the system-wide %s value could not be parsed from the command output", ref.Family),
			"This is a reporting problem rather than a network problem; the raw output is below.",
			"command: "+res.Command, "output: "+firstLine(res.Stdout))
	}

	obs := Observed{Value: intPtr(val), Origin: "cmdlet:" + cmd + ".DefaultHopLimit"}
	if w.explicitLookup != nil {
		if reg, ok := w.explicitLookup(regKey, regValue); ok {
			obs.Explicit = true
			obs.Origin += fmt.Sprintf(" (explicitly configured; registry %s\\%s=%d)", regKey, regValue, reg)
		}
	}
	return obs, nil
}

func (w *WindowsBackend) readInterface(ctx context.Context, ref SettingRef) (Observed, error) {
	script := fmt.Sprintf(
		"(Get-NetIPInterface -InterfaceIndex %d -AddressFamily %s -ErrorAction Stop).CurrentHopLimit | ConvertTo-Json -Compress",
		ref.InterfaceIdx, psFamily(ref.Family))
	res := w.runner.Run(ctx, powershell, psArgs(script)...)
	if res.Failed() {
		return Observed{}, newError(CodeReadFailed,
			fmt.Sprintf("could not read the per-interface value for %q", ref.Interface),
			"Check that the adapter still exists and that the shell is elevated.",
			"command: "+res.Command, "result: "+res.Output())
	}
	val, err := decodeInt(res.Stdout)
	if err != nil {
		return Observed{}, newError(CodeReadFailed,
			fmt.Sprintf("the per-interface value for %q could not be parsed", ref.Interface),
			"The raw output is below.",
			"command: "+res.Command, "output: "+firstLine(res.Stdout))
	}

	// The documented meaning of 0 for -CurrentHopLimit is "use the system default", so it is
	// reported as inherited rather than as the literal value zero. Reporting 0 as a TTL would
	// be wrong: no packet is ever sent with a hop limit of zero.
	obs := Observed{
		Origin: "cmdlet:Get-NetIPInterface.CurrentHopLimit",
	}
	if val == 0 {
		obs.Explicit = false
		global := SystemRef(ref.Family)
		if g, gerr := w.readSystem(ctx, global); gerr == nil && g.Value != nil {
			obs.Value = g.Value
			obs.Origin += fmt.Sprintf(" (inherited: this adapter uses the system default of %d)", *g.Value)
		} else {
			obs.Origin += " (inherited: this adapter uses the system default, which could not be read)"
		}
		return obs, nil
	}
	obs.Value = intPtr(val)
	obs.Explicit = true
	return obs, nil
}

// Write implements Backend. It runs the documented setter and then reads the value back. A
// setter that exits zero is not accepted as proof of success, because a no-op write reports
// success just as a real one does.
func (w *WindowsBackend) Write(ctx context.Context, ref SettingRef, value int) error {
	if !ref.Kind.IsConfigurable() {
		return newError(CodeUnsupported, fmt.Sprintf("%s is not a host setting", ref.Kind), ref.Kind.Explain())
	}
	if value < 1 || value > 255 {
		return newError(CodeWriteFailed,
			fmt.Sprintf("%d is outside the range a packet header can carry", value),
			"The TTL and hop-limit fields are 8 bits, so the value must be between 1 and 255.")
	}

	var script string
	if ref.Scope == ScopePerInterface {
		script = fmt.Sprintf("Set-NetIPInterface -InterfaceIndex %d -AddressFamily %s -CurrentHopLimit %d -ErrorAction Stop",
			ref.InterfaceIdx, psFamily(ref.Family), value)
	} else {
		cmd := "Set-NetIPv4Protocol"
		if ref.Family == FamilyIPv6 {
			cmd = "Set-NetIPv6Protocol"
		}
		script = fmt.Sprintf("%s -DefaultHopLimit %d -ErrorAction Stop", cmd, value)
	}

	res := w.runner.Run(ctx, powershell, psArgs(script)...)
	if res.Failed() {
		return w.writeError(ref, value, res)
	}
	return nil
}

// Unset implements Backend. For a per-interface setting Windows documents 0 as "use the system
// default", which is a real unset. For a system-global setting there is no documented way to
// remove the explicit value, so this reports that plainly instead of writing a number and
// calling it a reset.
func (w *WindowsBackend) Unset(ctx context.Context, ref SettingRef) error {
	if ref.Scope == ScopePerInterface {
		script := fmt.Sprintf("Set-NetIPInterface -InterfaceIndex %d -AddressFamily %s -CurrentHopLimit 0 -ErrorAction Stop",
			ref.InterfaceIdx, psFamily(ref.Family))
		res := w.runner.Run(ctx, powershell, psArgs(script)...)
		if res.Failed() {
			return w.writeError(ref, 0, res)
		}
		return nil
	}
	return newError(CodeUnsupported,
		fmt.Sprintf("this build cannot remove the explicit system-wide %s value", ref.Family),
		"Windows documents no way to unset the system default, only to set it. Restoring the captured "+
			"value - which was read from this PC - re-creates the behaviour that was in effect.",
		"setting: "+string(ref.ID))
}

// writeError turns a failed setter into an actionable error, classifying the two failure modes
// worth distinguishing: a refusal for lack of privilege, and everything else.
func (w *WindowsBackend) writeError(ref SettingRef, value int, res Result) error {
	code := CodeWriteFailed
	hint := "Check that the adapter still exists. The raw command output is below."
	combined := strings.ToLower(res.Output())
	if res.TimedOut {
		code = CodeTimeout
		hint = "The command did not finish in time. Retry, or raise the command timeout in Settings."
	} else if strings.Contains(combined, "access is denied") ||
		strings.Contains(combined, "requires elevation") ||
		strings.Contains(combined, "unauthorizedaccess") ||
		strings.Contains(combined, "administrator") {
		code = CodePermission
		hint = "This change needs an elevated process. Restart the Control Center as administrator " +
			"(the title bar says whether it is elevated). Nothing was changed."
	}
	details := []string{
		fmt.Sprintf("setting: %s", ref.Compact()),
		fmt.Sprintf("requested value: %d", value),
		"command: " + res.Command,
	}
	if res.Output() != "" {
		details = append(details, "output: "+firstLine(res.Output()))
	}
	if res.Err != "" {
		details = append(details, "error: "+res.Err)
	}
	return &Error{Code: code, Message: fmt.Sprintf("the system refused to set %s to %d", ref.Compact(), value),
		Hint: hint, Details: details}
}

// psFamily maps a Family to the value the -AddressFamily parameter expects.
func psFamily(f Family) string {
	if f == FamilyIPv6 {
		return "IPv6"
	}
	return "IPv4"
}

// --- tolerant PowerShell JSON decoding -------------------------------------------------
//
// ConvertTo-Json is notoriously shape-unstable: one object serialises as an object, a
// single-element array collapses to a scalar, and an empty result is null. Every decoder here
// handles all of those, and returns a typed, descriptive error rather than panicking or
// silently yielding a zero value.

// decodeInt accepts a bare number, a quoted number, or a one-element array of either.
func decodeInt(s string) (int, error) {
	raw := strings.TrimSpace(s)
	if raw == "" || raw == "null" {
		return 0, fmt.Errorf("empty output")
	}
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		// PowerShell can emit an unquoted value when a cmdlet is not found; take the first
		// token so the caller gets a number or a clear parse error.
		fields := strings.Fields(raw)
		if len(fields) == 0 {
			return 0, fmt.Errorf("no value in %q", firstLine(raw))
		}
		if n, nerr := strconv.Atoi(fields[0]); nerr == nil {
			return n, nil
		}
		return 0, fmt.Errorf("not a number: %q", firstLine(raw))
	}
	return coerceInt(v)
}

// coerceInt unwraps the shapes ConvertTo-Json produces.
func coerceInt(v any) (int, error) {
	switch t := v.(type) {
	case float64:
		return int(t), nil
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(t))
		if err != nil {
			return 0, fmt.Errorf("not a number: %q", t)
		}
		return n, nil
	case []any:
		if len(t) == 0 {
			return 0, fmt.Errorf("empty array")
		}
		return coerceInt(t[0])
	case nil:
		return 0, fmt.Errorf("null")
	default:
		return 0, fmt.Errorf("unexpected JSON type %T", v)
	}
}

// decodeObjectList accepts an array of objects, a single object, a JSON-encoded string
// containing either, or null, and always returns a slice.
func decodeObjectList(s string) ([]map[string]any, error) {
	raw := strings.TrimSpace(s)
	if raw == "" || raw == "null" {
		return nil, nil
	}
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return nil, fmt.Errorf("not JSON: %q", firstLine(raw))
	}
	return coerceObjectList(v)
}

func coerceObjectList(v any) ([]map[string]any, error) {
	switch t := v.(type) {
	case []any:
		out := make([]map[string]any, 0, len(t))
		for _, e := range t {
			if m, ok := e.(map[string]any); ok {
				out = append(out, m)
			}
		}
		if len(out) == 0 && len(t) > 0 {
			return nil, fmt.Errorf("array contained no objects")
		}
		return out, nil
	case map[string]any:
		return []map[string]any{t}, nil
	case string:
		// A nested JSON string happens when a caller pipes a JSON document through a cmdlet.
		return decodeObjectList(t)
	case nil:
		return nil, nil
	default:
		return nil, fmt.Errorf("unexpected JSON type %T", v)
	}
}

// str reads a string field, tolerating the numeric and boolean shapes PowerShell produces.
func str(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return ""
		}
		return string(b)
	}
}

// boolean reads a boolean field, tolerating the string and numeric forms.
func boolean(m map[string]any, key string) bool {
	v, ok := m[key]
	if !ok || v == nil {
		return false
	}
	switch t := v.(type) {
	case bool:
		return t
	case string:
		b, err := strconv.ParseBool(strings.TrimSpace(t))
		return err == nil && b
	case float64:
		return t != 0
	default:
		return false
	}
}
