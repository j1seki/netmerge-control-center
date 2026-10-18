package ttlmgr

// These tests exercise the PowerShell backend's own logic through a fake Runner: command
// construction, tolerant parsing of the several shapes ConvertTo-Json produces, capability
// probing, and failure classification. The Runner is a SIMULATION; no PowerShell process is
// started and no Windows setting is read or touched.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
)

type fakeRunner struct {
	mu      sync.Mutex
	calls   []string
	runFn   func(ctx context.Context, name string, args ...string) Result
	lookErr error
}

func (f *fakeRunner) Run(ctx context.Context, name string, args ...string) Result {
	f.mu.Lock()
	f.calls = append(f.calls, formatCommand(name, args))
	f.mu.Unlock()
	if f.runFn != nil {
		return f.runFn(ctx, name, args...)
	}
	return Result{Command: formatCommand(name, args), Started: true}
}

func (f *fakeRunner) LookPath(name string) (string, error) {
	if f.lookErr != nil {
		return "", f.lookErr
	}
	return "/fake/" + name, nil
}

func (f *fakeRunner) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// scriptArg returns the -Command script from a PowerShell argument list.
func scriptArg(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[len(args)-1]
}

func okResult(stdout string) Result { return Result{Started: true, Stdout: stdout} }

// probeJSON renders a probe result, letting a test remove the parameter from one command.
func probeJSON(t *testing.T, hasParam map[string]bool) string {
	t.Helper()
	rows := make([]map[string]any, 0, len(requiredCommands()))
	for _, c := range requiredCommands() {
		hp := true
		if v, ok := hasParam[c.Command]; ok {
			hp = v
		}
		rows = append(rows, map[string]any{
			"command": c.Command, "parameter": c.Parameter, "present": true, "hasParam": hp,
			"detail": "",
		})
	}
	b, err := json.Marshal(rows)
	if err != nil {
		t.Fatalf("marshal probe rows: %v", err)
	}
	return string(b)
}

// --- capability probing ----------------------------------------------------------------

func TestCapabilitiesReportsFullSupport(t *testing.T) {
	fr := &fakeRunner{runFn: func(context.Context, string, ...string) Result {
		return okResult(probeJSON(t, nil))
	}}
	caps := NewWindowsBackend(fr).Capabilities(context.Background())

	if !caps.Supported {
		t.Fatalf("supported = false with every cmdlet present; notes: %v", caps.Notes)
	}
	if len(caps.Commands) != len(requiredCommands()) {
		t.Fatalf("capabilities list %d commands, want %d", len(caps.Commands), len(requiredCommands()))
	}
	if !capabilitiesAllowPerInterface(caps) {
		t.Error("per-interface setter was probed as present but is not allowed")
	}
	joined := strings.Join(caps.Notes, " ")
	if !strings.Contains(joined, "-DefaultHopLimit") {
		t.Error("notes do not name the documented mechanism")
	}
	if !strings.Contains(joined, "affects every adapter") {
		t.Error("notes do not warn that a system-global change affects every adapter")
	}
	if !strings.Contains(joined, "128") {
		t.Error("notes do not state the Windows built-in default")
	}
}

func TestCapabilitiesWithoutPowerShell(t *testing.T) {
	fr := &fakeRunner{lookErr: errors.New("executable file not found in $PATH")}
	caps := NewWindowsBackend(fr).Capabilities(context.Background())

	if caps.Supported {
		t.Fatal("a host without PowerShell must not report support")
	}
	if joined := strings.Join(caps.Notes, " "); !strings.Contains(joined, "was not found") {
		t.Errorf("notes = %v, want the missing interpreter named", caps.Notes)
	}
	if fr.callCount() != 0 {
		t.Error("the probe ran even though the interpreter could not be resolved")
	}
}

func TestCapabilitiesReportsMissingParameter(t *testing.T) {
	fr := &fakeRunner{runFn: func(context.Context, string, ...string) Result {
		return okResult(probeJSON(t, map[string]bool{"Set-NetIPInterface": false}))
	}}
	caps := NewWindowsBackend(fr).Capabilities(context.Background())

	if !caps.Supported {
		t.Fatal("the system-wide read/write pair is complete, so the backend is usable")
	}
	if capabilitiesAllowPerInterface(caps) {
		t.Error("a missing Set-NetIPInterface parameter was reported as usable")
	}
	joined := strings.Join(caps.Notes, " ")
	if !strings.Contains(joined, "per-interface changes are reported as unsupported") {
		t.Errorf("notes = %v, want the per-interface limitation stated", caps.Notes)
	}
}

func TestCapabilitiesProbeOutputUnparsable(t *testing.T) {
	fr := &fakeRunner{runFn: func(context.Context, string, ...string) Result {
		return okResult("this is not json")
	}}
	caps := NewWindowsBackend(fr).Capabilities(context.Background())

	if caps.Supported {
		t.Fatal("unparsable probe output must not be treated as support")
	}
	if joined := strings.Join(caps.Notes, " "); !strings.Contains(joined, "could not be parsed") {
		t.Errorf("notes = %v, want the parse failure reported", caps.Notes)
	}
}

func TestCapabilitiesProbeCommandFailed(t *testing.T) {
	fr := &fakeRunner{runFn: func(context.Context, string, ...string) Result {
		return Result{Started: true, ExitCode: 1, Stderr: "module failed to load"}
	}}
	caps := NewWindowsBackend(fr).Capabilities(context.Background())

	if caps.Supported {
		t.Fatal("a failed probe must not be treated as support")
	}
	if joined := strings.Join(caps.Notes, " "); !strings.Contains(joined, "did not complete") {
		t.Errorf("notes = %v, want the incomplete probe reported", caps.Notes)
	}
}

// --- reading ---------------------------------------------------------------------------

func TestReadSystemUsesCmdletValueAndRegistryFlag(t *testing.T) {
	fr := &fakeRunner{runFn: func(_ context.Context, _ string, args ...string) Result {
		script := scriptArg(args)
		if !strings.Contains(script, "Get-NetIPv4Protocol -ErrorAction Stop") {
			t.Fatalf("unexpected script: %s", script)
		}
		return okResult("128")
	}}
	b := NewWindowsBackend(fr)

	var gotKey, gotValue string
	b.explicitLookup = func(key, value string) (int, bool) {
		gotKey, gotValue = key, value
		return 128, true
	}

	obs, err := b.Read(context.Background(), SystemRef(FamilyIPv4))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if obs.Value == nil || *obs.Value != 128 {
		t.Fatalf("value = %s, want 128", FormatIntPtr(obs.Value))
	}
	if !obs.Explicit {
		t.Error("a present registry value must be reported as explicitly configured")
	}
	if !strings.Contains(obs.Origin, "explicitly configured") {
		t.Errorf("origin = %q, want the explicit-configuration fact stated", obs.Origin)
	}
	if gotKey != registryKeyIPv4 || gotValue != registryValueIPv4 {
		t.Errorf("registry lookup = %q/%q, want %q/%q", gotKey, gotValue, registryKeyIPv4, registryValueIPv4)
	}
}

func TestReadSystemAbsentRegistryValueIsNotExplicit(t *testing.T) {
	fr := &fakeRunner{runFn: func(context.Context, string, ...string) Result { return okResult("128") }}
	b := NewWindowsBackend(fr)
	b.explicitLookup = func(string, string) (int, bool) { return 0, false }

	obs, err := b.Read(context.Background(), SystemRef(FamilyIPv4))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if obs.Explicit {
		t.Error("an absent registry value was reported as explicitly configured")
	}
	if strings.Contains(obs.Origin, "explicitly configured") {
		t.Errorf("origin = %q, want no explicit claim", obs.Origin)
	}
}

func TestReadSystemMalformedOutput(t *testing.T) {
	fr := &fakeRunner{runFn: func(context.Context, string, ...string) Result {
		return okResult("PowerShell error text")
	}}
	_, err := NewWindowsBackend(fr).Read(context.Background(), SystemRef(FamilyIPv4))
	if !IsCode(err, CodeReadFailed) {
		t.Fatalf("error = %v, want %s for unparsable output", err, CodeReadFailed)
	}
}

func TestReadSystemCommandFailure(t *testing.T) {
	fr := &fakeRunner{runFn: func(context.Context, string, ...string) Result {
		return Result{Started: true, ExitCode: 1, Stderr: "Access is denied"}
	}}
	_, err := NewWindowsBackend(fr).Read(context.Background(), SystemRef(FamilyIPv4))
	if !IsCode(err, CodeReadFailed) {
		t.Fatalf("error = %v, want %s", err, CodeReadFailed)
	}
	var e *Error
	if errors.As(err, &e) && !strings.Contains(e.Hint, "elevated PowerShell") {
		t.Errorf("hint = %q, want a concrete next step", e.Hint)
	}
}

func TestReadInterfaceZeroMeansInherit(t *testing.T) {
	fr := &fakeRunner{runFn: func(_ context.Context, _ string, args ...string) Result {
		switch script := scriptArg(args); {
		case strings.Contains(script, "Get-NetIPInterface"):
			return okResult("0")
		case strings.Contains(script, "Get-NetIPv6Protocol"):
			return okResult("128")
		default:
			t.Fatalf("unexpected script: %s", script)
			return Result{}
		}
	}}
	b := NewWindowsBackend(fr)
	b.explicitLookup = func(string, string) (int, bool) { return 0, false }

	obs, err := b.Read(context.Background(), IfaceRef(FamilyIPv6, 7, "Wi-Fi"))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	// 0 is the documented "use the system default": it must never be shown as a hop limit.
	if obs.Value == nil || *obs.Value != 128 {
		t.Fatalf("value = %s, want the inherited system value 128", FormatIntPtr(obs.Value))
	}
	if obs.Explicit {
		t.Error("an inherited value was reported as explicitly configured")
	}
	if !strings.Contains(obs.Origin, "inherited") || !strings.Contains(obs.Origin, "128") {
		t.Errorf("origin = %q, want the inheritance explained", obs.Origin)
	}
}

func TestReadInterfaceExplicitValue(t *testing.T) {
	fr := &fakeRunner{runFn: func(context.Context, string, ...string) Result { return okResult("64") }}
	obs, err := NewWindowsBackend(fr).Read(context.Background(), IfaceRef(FamilyIPv4, 7, "Wi-Fi"))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if obs.Value == nil || *obs.Value != 64 || !obs.Explicit {
		t.Fatalf("observed = %+v, want an explicit 64", obs)
	}
}

func TestReadRejectsNonConfigurableKinds(t *testing.T) {
	ref := SettingRef{ID: "descriptive.dns-record-ttl", Kind: KindDNSRecordTTL, Scope: ScopeNotApplicable}
	_, err := NewWindowsBackend(&fakeRunner{}).Read(context.Background(), ref)
	if !IsCode(err, CodeUnsupported) {
		t.Fatalf("error = %v, want %s: DNS record TTL is not a host setting", err, CodeUnsupported)
	}
}

// --- writing ---------------------------------------------------------------------------

func TestWriteUsesDocumentedSetters(t *testing.T) {
	var scripts []string
	fr := &fakeRunner{runFn: func(_ context.Context, _ string, args ...string) Result {
		scripts = append(scripts, scriptArg(args))
		return Result{Started: true}
	}}
	b := NewWindowsBackend(fr)

	cases := []struct {
		ref  SettingRef
		want string
	}{
		{SystemRef(FamilyIPv4), "Set-NetIPv4Protocol -DefaultHopLimit 65 -ErrorAction Stop"},
		{SystemRef(FamilyIPv6), "Set-NetIPv6Protocol -DefaultHopLimit 65 -ErrorAction Stop"},
		{IfaceRef(FamilyIPv4, 7, "Wi-Fi"), "Set-NetIPInterface -InterfaceIndex 7 -AddressFamily IPv4 -CurrentHopLimit 65 -ErrorAction Stop"},
		{IfaceRef(FamilyIPv6, 7, "Wi-Fi"), "Set-NetIPInterface -InterfaceIndex 7 -AddressFamily IPv6 -CurrentHopLimit 65 -ErrorAction Stop"},
	}
	for _, tc := range cases {
		if err := b.Write(context.Background(), tc.ref, 65); err != nil {
			t.Fatalf("Write(%s): %v", tc.ref.ID, err)
		}
	}
	if len(scripts) != len(cases) {
		t.Fatalf("ran %d setters, want %d", len(scripts), len(cases))
	}
	for i, tc := range cases {
		if !strings.Contains(scripts[i], tc.want) {
			t.Errorf("setter %d = %q, want it to contain %q", i, scripts[i], tc.want)
		}
	}
}

func TestWriteRejectsValuesOutsideHeaderRange(t *testing.T) {
	fr := &fakeRunner{}
	b := NewWindowsBackend(fr)
	for _, v := range []int{0, -1, 256, 999} {
		err := b.Write(context.Background(), SystemRef(FamilyIPv4), v)
		if !IsCode(err, CodeWriteFailed) {
			t.Errorf("Write(%d) error = %v, want %s", v, err, CodeWriteFailed)
		}
	}
	if fr.callCount() != 0 {
		t.Error("an impossible value was sent to the platform")
	}
}

func TestWriteClassifiesPermissionDenial(t *testing.T) {
	for _, output := range []string{
		"Set-NetIPv4Protocol : Access is denied",
		"This command requires elevation",
		"System.UnauthorizedAccessException: no permission",
	} {
		fr := &fakeRunner{runFn: func(context.Context, string, ...string) Result {
			return Result{Started: true, ExitCode: 1, Stderr: output, Command: "powershell.exe -Command Set-NetIPv4Protocol"}
		}}
		err := NewWindowsBackend(fr).Write(context.Background(), SystemRef(FamilyIPv4), 65)
		if !IsCode(err, CodePermission) {
			t.Fatalf("output %q classified as %v, want %s", output, err, CodePermission)
		}
		var e *Error
		if errors.As(err, &e) && !strings.Contains(e.Hint, "administrator") {
			t.Errorf("hint = %q, want the elevation requirement explained", e.Hint)
		}
	}
}

func TestWriteClassifiesTimeout(t *testing.T) {
	fr := &fakeRunner{runFn: func(context.Context, string, ...string) Result {
		return Result{Started: true, TimedOut: true, Err: "timed out after 30s"}
	}}
	err := NewWindowsBackend(fr).Write(context.Background(), SystemRef(FamilyIPv4), 65)
	if !IsCode(err, CodeTimeout) {
		t.Fatalf("error = %v, want %s", err, CodeTimeout)
	}
}

func TestWriteReportsGenericFailure(t *testing.T) {
	fr := &fakeRunner{runFn: func(context.Context, string, ...string) Result {
		return Result{Started: true, ExitCode: 1, Stderr: "The system cannot find the file specified."}
	}}
	err := NewWindowsBackend(fr).Write(context.Background(), SystemRef(FamilyIPv4), 65)
	if !IsCode(err, CodeWriteFailed) {
		t.Fatalf("error = %v, want %s", err, CodeWriteFailed)
	}
}

func TestUnsetInterfaceWritesZeroAndSystemIsUnsupported(t *testing.T) {
	var scripts []string
	fr := &fakeRunner{runFn: func(_ context.Context, _ string, args ...string) Result {
		scripts = append(scripts, scriptArg(args))
		return Result{Started: true}
	}}
	b := NewWindowsBackend(fr)

	if err := b.Unset(context.Background(), IfaceRef(FamilyIPv4, 7, "Wi-Fi")); err != nil {
		t.Fatalf("Unset per-interface: %v", err)
	}
	if len(scripts) != 1 || !strings.Contains(scripts[0], "-CurrentHopLimit 0") {
		t.Fatalf("unset script = %v, want the documented 0 value", scripts)
	}

	err := b.Unset(context.Background(), SystemRef(FamilyIPv4))
	if !IsCode(err, CodeUnsupported) {
		t.Fatalf("system unset error = %v, want %s rather than a fabricated default", err, CodeUnsupported)
	}
}

// --- tolerant decoding -----------------------------------------------------------------

func TestDecodeIntShapes(t *testing.T) {
	cases := []struct {
		in      string
		want    int
		wantErr bool
	}{
		{"128", 128, false},
		{" 128 \n", 128, false},
		{`"128"`, 128, false},
		{"[128]", 128, false},
		{"[65,66]", 65, false},
		{"128 extra", 128, false}, // non-JSON fallback takes the first token
		{"", 0, true},
		{"null", 0, true},
		{"[]", 0, true},
		{"not-a-number", 0, true},
	}
	for _, tc := range cases {
		got, err := decodeInt(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("decodeInt(%q) = %d, want an error", tc.in, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("decodeInt(%q) = %d, %v; want %d, nil", tc.in, got, err, tc.want)
		}
	}
}

func TestDecodeObjectListShapes(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    int
		wantErr bool
	}{
		{"array", `[{"a":1},{"b":2}]`, 2, false},
		{"single object", `{"a":1}`, 1, false},
		{"json inside a string", `"{\"a\":1}"`, 1, false},
		{"empty", "", 0, false},
		{"null", "null", 0, false},
		{"array without objects", `[1,2]`, 0, true},
		{"garbage", "garbage", 0, true},
	}
	for _, tc := range cases {
		got, err := decodeObjectList(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("%s: decodeObjectList(%q) = %d rows, want an error", tc.name, tc.in, len(got))
			}
			continue
		}
		if err != nil || len(got) != tc.want {
			t.Errorf("%s: decodeObjectList(%q) = %d rows, %v; want %d, nil", tc.name, tc.in, len(got), err, tc.want)
		}
	}
}

func TestStrAndBooleanCoercion(t *testing.T) {
	m := map[string]any{"n": float64(5), "b": true, "bs": "true", "z": float64(0), "nil": nil}
	if got := str(m, "n"); got != "5" {
		t.Errorf("str(number) = %q, want \"5\"", got)
	}
	if got := str(m, "b"); got != "true" {
		t.Errorf("str(bool) = %q, want \"true\"", got)
	}
	if got := str(m, "missing"); got != "" {
		t.Errorf("str(missing) = %q, want empty", got)
	}
	if !boolean(m, "b") || !boolean(m, "bs") {
		t.Error("boolean(true) and boolean(\"true\") must both be true")
	}
	if boolean(m, "z") || boolean(m, "missing") {
		t.Error("boolean(0) and boolean(missing) must be false")
	}
}
