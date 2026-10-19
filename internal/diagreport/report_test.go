package diagreport

// Tests for the document and the rendered artifacts.
//
// The document under test is assembled from synthetic values - a simulated inventory, a
// simulated diagnostic run - so the assertions are about the report's own behaviour (what it
// claims, what it withholds, whether the two renderings agree) rather than about this machine.

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"net-merge/internal/diag"
	"net-merge/internal/engine"
	"net-merge/internal/inventory"
	"net-merge/internal/logx"
	"net-merge/internal/ttlmgr"
)

var testNow = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

func intPtr(v int) *int { return &v }

// testRun is a small diagnostic run covering the cases the report has to distinguish: a check
// that established something, an informational result, a skipped check and an errored one.
func testRun() diag.RunResult {
	return diag.RunResult{
		Started:    testNow,
		Duration:   3 * time.Second,
		Platform:   "windows",
		AppVersion: "test-build",
		Results: []diag.Result{
			{
				ID: "platform.info", Title: "Platform", Category: diag.CatPlatform, Status: diag.StatusInfo,
				Summary:     "Windows 11, 22631",
				Established: []string{"this line belongs to platform description, not to a fault"},
			},
			{
				ID: "ipv4.connect", Title: "IPv4 TCP connect", Category: diag.CatPath, Status: diag.StatusPass,
				Summary: "connected to 93.184.216.34:443 in 41ms",
				Established: []string{
					"a TCP handshake to 93.184.216.34:443 completed in 41ms",
				},
				Items: []diag.Item{{Code: "connected", Detail: "93.184.216.34:443"}},
				Evidence: []diag.Evidence{{
					Label:    "TCP connect",
					Command:  []string{"Test-NetConnection", "-ComputerName", "93.184.216.34", "-Port", "443"},
					ExitCode: intPtr(0), Started: true, Duration: 41 * time.Millisecond,
					Output: []string{"TcpTestSucceeded : True", "line 2", "line 3", "line 4"},
				}},
			},
			{
				ID: "security.firewall", Title: "Firewall profiles", Category: diag.CatSecurity, Status: diag.StatusInfo,
				Summary:     "3 profile(s) enabled",
				Established: []string{"Domain profile: enabled (inbound Block, outbound Allow)"},
				Items:       []diag.Item{{Scope: "Domain", Code: "firewall_enabled", Detail: "inbound Block, outbound Allow"}},
			},
			{
				ID: "ipv6.connect", Title: "IPv6 TCP connect", Category: diag.CatPath, Status: diag.StatusSkipped,
				Summary:     "no IPv6 address",
				Established: []string{"this must not count as an observation"},
			},
			{
				ID: "routing.trace", Title: "Traceroute", Category: diag.CatRouting, Status: diag.StatusError,
				Summary:     "tracert could not be started",
				Established: []string{"this must not count either"},
				ErrorCodes:  []string{"diag_tool_missing"},
			},
			{
				ID: "adapters.connect", Title: "Per-adapter connectivity", Category: diag.CatPath, Status: diag.StatusWarn,
				Summary: "Ethernet: reachable; Wi-Fi: timed out",
				Established: []string{
					"Ethernet: reachable (connected in 41ms)",
					"Wi-Fi: 93.184.216.34:443 did not answer",
				},
				Items: []diag.Item{
					{Scope: "Ethernet", Code: "connected", Detail: "93.184.216.34:443"},
					{Scope: "Wi-Fi", Code: "timeout", Detail: "93.184.216.34:443"},
				},
			},
		},
		Skipped: map[string]string{"dns.resolve": "no DNS name configured"},
	}
}

func testSnapshot() *inventory.Snapshot {
	return &inventory.Snapshot{
		Taken:             testNow,
		Source:            "simulated inventory (unit test)",
		LinkSpeedTotalBps: 2_500_000_000,
		Adapters: []inventory.Adapter{
			{
				Name: "Ethernet", Description: "Intel(R) Ethernet Controller I225-V", Index: 12,
				Kind: inventory.KindEthernet, Status: inventory.StateEligible, Link: inventory.LinkUp,
				Hardware: true, SpeedBps: 1_000_000_000, MTU: 1500,
				MAC:       "a4:5e:60:1a:2b:3c",
				IPv4:      []inventory.Address{{Address: "192.168.1.20", Prefix: 24}},
				Gateways4: []string{"192.168.1.1"},
				DNS4:      []string{"1.1.1.1", "9.9.9.9"},
				Metric4:   intPtr(25),
				Counters:  &inventory.Counters{In: 1 << 20, Out: 1 << 19},
				Rates:     &inventory.Rates{InPerSec: 1024, OutPerSec: 512, Span: 2, At: testNow},
				Health:    &inventory.Health{Checked: true, OK: true, RTTms: 12.4, Endpoint: "1.1.1.1:443"},
				Engine:    true, EngineAssigned: intPtr(4),
			},
			{
				Name: "Wi-Fi", Index: 7, Kind: inventory.KindWiFi, Status: inventory.StateExcluded,
				Link: inventory.LinkUp, Hardware: true, MTU: 1500,
				MAC:           "9c:2e:a1:44:55:66",
				Exclusion:     "no usable address",
				ExclusionCode: "no_address",
				Gaps:          []string{"DHCP state is not reported on this platform"},
			},
		},
		Routes: []inventory.Route{
			{Family: "ipv4", Destination: "0.0.0.0/0", NextHop: "192.168.1.1", Index: 12, Name: "Ethernet", Metric: 25, Protocol: "dhcp", Default: true},
		},
		Gaps: []string{"this platform exposes no DHCP lease time"},
	}
}

func testTTL() *ttlmgr.Report {
	v4 := 128
	return &ttlmgr.Report{
		Schema: "netmerge.ttlmgr/1",
		At:     testNow,
		Capabilities: ttlmgr.Capabilities{
			Platform: "windows", Supported: true,
			Notes: []string{"packet-header values only; DNS record TTLs are a different concept"},
		},
		Settings: []ttlmgr.Setting{
			{
				SettingRef: ttlmgr.SettingRef{
					ID: ttlmgr.IDv4Default, Kind: ttlmgr.KindPacketTTL,
					Family: ttlmgr.FamilyIPv4, Scope: ttlmgr.ScopeSystemGlobal,
				},
				Value: &v4, ValueOrigin: "cmdlet", Writable: true,
			},
			{
				SettingRef: ttlmgr.SettingRef{
					ID:   ttlmgr.InterfaceSettingID(ttlmgr.FamilyIPv6, 7, "Wi-Fi"),
					Kind: ttlmgr.KindPacketHopLimit, Family: ttlmgr.FamilyIPv6,
					Scope: ttlmgr.ScopePerInterface, Interface: "Wi-Fi", InterfaceIdx: 7,
				},
				// Not configured: on Windows an unwritten value means the built-in default is
				// in effect, which is not zero and must never render as one.
				Value: nil, ValueOrigin: "os-default", Writable: false, WritableReason: "the adapter is not present",
			},
		},
		NotSettings: []ttlmgr.Setting{
			{
				SettingRef: ttlmgr.SettingRef{ID: "dns.record-ttl", Kind: ttlmgr.KindDNSRecordTTL, Scope: ttlmgr.ScopeNotApplicable},
			},
		},
		Captured: map[ttlmgr.SettingID]ttlmgr.Original{
			ttlmgr.IDv4Default: {
				ID: ttlmgr.IDv4Default, Family: ttlmgr.FamilyIPv4, Scope: ttlmgr.ScopeSystemGlobal,
				Value: intPtr(128), Explicit: false, Origin: "cmdlet", CapturedAt: testNow.Add(-time.Hour),
			},
		},
		Config:   ttlmgr.Config{Schema: "netmerge.ttlmgr.config/1", Version: 1, Enabled: false, Policy: ttlmgr.PolicyInterfaceNone},
		Elevated: true, Elevation: "administrator (elevated)",
	}
}

func testDoc(t *testing.T) *Document {
	t.Helper()
	return Build(Options{
		Now:      testNow,
		Version:  "test-build",
		Platform: "windows",
		Arch:     "amd64",
		Elevated: true,
		StateDir: `C:\Users\alex.smith\AppData\Local\net-merge`,
		Snapshot: testSnapshot(),
		Run:      testRun(),
		Engine: &EngineView{
			Running: false,
			Problem: "the status file exists but no process holds the instance lock",
		},
		TTL: testTTL(),
		Logs: []logx.Event{
			{Seq: 1, At: testNow, Level: logx.LevelInfo, LevelID: "info", Code: "engine_start", Message: "engine started", Detail: "mode=bond"},
			{Seq: 2, At: testNow.Add(time.Second), Level: logx.LevelWarn, LevelID: "warn", Message: "adapter skipped", Detail: "Wi-Fi: no usable address"},
		},
	})
}

func TestFactsExcludeChecksThatEstablishedNothing(t *testing.T) {
	doc := testDoc(t)
	var have []string
	for _, f := range doc.Facts {
		have = append(have, f.Check+": "+f.Statement)
	}
	joined := strings.Join(have, "\n")
	for _, want := range []string{
		"ipv4.connect: a TCP handshake",
		"security.firewall: Domain profile",
		"adapters.connect: Ethernet: reachable",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("facts are missing %q; got:\n%s", want, joined)
		}
	}
	for _, unwanted := range []string{
		"this must not count as an observation",
		"this must not count either",
		"this line belongs to platform description",
	} {
		if strings.Contains(joined, unwanted) {
			t.Errorf("a skipped/errored/descriptive result leaked into the facts: %q", unwanted)
		}
	}
}

func TestItemsSurviveTrimming(t *testing.T) {
	doc := Build(Options{
		Now: testNow, Platform: "windows",
		Run: diag.RunResult{Results: []diag.Result{{
			ID: "ipv4.connect", Category: diag.CatPath, Status: diag.StatusPass, Summary: "ok",
			Items: []diag.Item{{Code: "connected", Detail: "93.184.216.34:443"}},
			Evidence: []diag.Evidence{{
				Label: "TCP connect", Started: true,
				Output: []string{"one", "two", "three", "four", "five"},
			}},
		}}},
		Limits: Limits{EvidenceLines: 2, Routes: 10, Logs: 10},
	})
	res := doc.Diagnostics[0]
	if len(res.Items) != 1 || res.Items[0].Code != "connected" {
		t.Errorf("machine-readable items must survive the export trim, got %+v", res.Items)
	}
	if len(res.Evidence) != 1 {
		t.Fatalf("evidence block lost, got %+v", res.Evidence)
	}
	ev := res.Evidence[0]
	if len(ev.Output) != 3 { // two kept lines plus the marker
		t.Errorf("output should be trimmed to two lines plus a marker, got %d: %v", len(ev.Output), ev.Output)
	}
	if !ev.Truncated {
		t.Errorf("a trimmed evidence block must say it was trimmed")
	}
	if !strings.Contains(ev.Output[len(ev.Output)-1], "more line(s)") {
		t.Errorf("the marker should say how much was left out, got %q", ev.Output[len(ev.Output)-1])
	}
}

func TestSummaryAndCaveats(t *testing.T) {
	doc := testDoc(t)
	if doc.Schema != Schema {
		t.Errorf("schema = %q, want %q", doc.Schema, Schema)
	}
	if doc.Summary.ChecksRan != len(doc.Diagnostics) {
		t.Errorf("ChecksRan = %d, want %d", doc.Summary.ChecksRan, len(doc.Diagnostics))
	}
	if doc.Summary.ChecksNotRun != 1 {
		t.Errorf("ChecksNotRun = %d, want 1", doc.Summary.ChecksNotRun)
	}
	if doc.Summary.WorstStatus != string(diag.StatusError) {
		t.Errorf("worst status = %q, want %q", doc.Summary.WorstStatus, diag.StatusError)
	}
	joined := strings.Join(doc.Caveats, "\n")
	if !strings.Contains(joined, "redaction removes values by pattern") {
		t.Errorf("the report must state the limit of redaction, got: %s", joined)
	}
	if !strings.Contains(joined, "failed to run to completion") {
		t.Errorf("an errored check must be named in the caveats, got: %s", joined)
	}
}

func TestTextCarriesTheSectionsAndTheDistinctions(t *testing.T) {
	text := testDoc(t).Text()
	for _, want := range []string{
		"schema: " + Schema,
		"== Summary ==",
		"== How to read this report ==",
		"== Caveats for this report ==",
		"== Verified observations ==",
		"== Hypotheses (candidates to test, not conclusions) ==",
		"== Interfaces ==",
		"== Bonding engine ==",
		"== IPv4 TTL and IPv6 hop limit ==",
		"== Diagnostics ==",
		"== Checks not run ==",
		"== Recent events ==",
		"end of report",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the rendered report is missing the %q section", want)
		}
	}
	// The distinction the whole TTL feature depends on has to be visible to a reader.
	if !strings.Contains(text, "DNS record TTLs and traceroute hop counts are different things") {
		t.Errorf("the TTL section must separate the four look-alike concepts")
	}
	if !strings.Contains(text, "a rate, not a measurement") {
		t.Errorf("the link-speed figure must be labelled as a negotiated rate, not throughput")
	}
	// An absent value is never rendered as zero.
	if !strings.Contains(text, "not configured (the system's own default is in effect)") {
		t.Errorf("an unconfigured TTL value must render as absent, not as 0")
	}
	if !strings.Contains(text, "the platform's own default was in effect") {
		t.Errorf("the captured original should record whether the platform had it written down")
	}
}

func TestBundleRedactsAllArtifacts(t *testing.T) {
	doc := testDoc(t)
	b, err := doc.Bundle(DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	js, txt, md := string(b.JSON), string(b.Text), string(b.Markdown)

	if len(md) == 0 {
		t.Fatalf("the Markdown rendering is empty")
	}
	if !strings.Contains(js, "[ip#1]") {
		t.Errorf("the JSON should carry a placeholder for the public address, got:\n%s", firstLines(js, 40))
	}
	if !strings.Contains(md, "[ip#1]") {
		t.Errorf("the Markdown should carry the same placeholder as the text, got:\n%s", firstLines(md, 40))
	}
	for _, leak := range []string{"93.184.216.34", "1a:2b:3c", "alex.smith"} {
		if strings.Contains(js, leak) {
			t.Errorf("the JSON still contains %q", leak)
		}
		if strings.Contains(txt, leak) {
			t.Errorf("the text still contains %q", leak)
		}
		if strings.Contains(md, leak) {
			t.Errorf("the Markdown still contains %q", leak)
		}
	}
	// The MAC keeps its vendor part, so the report stays diagnostically useful.
	if !strings.Contains(js, "a4:5e:60:xx:xx:xx") {
		t.Errorf("the MAC's vendor part should survive")
	}
	// The counts written into the file must describe the file that was written, and the text
	// pass must not discover anything the JSON pass missed (the two-pass property).
	if b.Counts.Total == 0 {
		t.Fatalf("nothing was counted, yet values were replaced")
	}
	if b.Counts != doc.Redaction {
		t.Errorf("counts written into the JSON (%+v) differ from the counts measured for the bundle (%+v)", doc.Redaction, b.Counts)
	}
	if doc.Redaction.PublicAddresses != 1 {
		t.Errorf("PublicAddresses = %d, want 1", doc.Redaction.PublicAddresses)
	}
	if doc.Redaction.MACAddresses != 2 {
		t.Errorf("MACAddresses = %d, want 2 (both adapters)", doc.Redaction.MACAddresses)
	}
	// The mapping that names the values is for the generating user's terminal, never for a file.
	for _, e := range b.Entries {
		if e.Value == "" {
			continue
		}
		if strings.Contains(js, e.Value) || strings.Contains(txt, e.Value) || strings.Contains(md, e.Value) {
			t.Errorf("the exported artifacts contain the original %s %q that redaction was supposed to hold back", e.Category, e.Value)
		}
	}
}

func TestBundleIsDeterministic(t *testing.T) {
	doc := testDoc(t)
	b1, err := doc.Bundle(DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	b2, err := doc.Bundle(DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b1.JSON, b2.JSON) {
		t.Errorf("two renders of the same document produced different JSON")
	}
	if !bytes.Equal(b1.Text, b2.Text) {
		t.Errorf("two renders of the same document produced different text")
	}
	if !bytes.Equal(b1.Markdown, b2.Markdown) {
		t.Errorf("two renders of the same document produced different Markdown")
	}
	if b1.BaseName != b2.BaseName {
		t.Errorf("base name changed between renders: %q vs %q", b1.BaseName, b2.BaseName)
	}
}

func TestBundleJSONIsValidJSONWithTheCountsInside(t *testing.T) {
	doc := testDoc(t)
	b, err := doc.Bundle(DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(b.JSON, &back); err != nil {
		t.Fatalf("the redacted JSON does not parse: %v", err)
	}
	red, ok := back["redaction"].(map[string]any)
	if !ok {
		t.Fatalf("no redaction block in the exported JSON")
	}
	if n, _ := red["total"].(float64); n == 0 {
		t.Errorf("the redaction block should state what was removed, got %v", red)
	}
	if _, ok := back["hypotheses"]; !ok {
		t.Errorf("the JSON export must carry the hypotheses section")
	}
}

func TestWriteName(t *testing.T) {
	doc := testDoc(t)
	b, err := doc.Bundle(DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	txt, md, js := b.WriteName("/tmp/exports")
	if filepath.Base(txt) != b.BaseName+".txt" {
		t.Errorf("text name = %q", txt)
	}
	if filepath.Base(md) != b.BaseName+".md" {
		t.Errorf("markdown name = %q", md)
	}
	if filepath.Base(js) != b.BaseName+".json" {
		t.Errorf("json name = %q", js)
	}
	if !strings.Contains(b.BaseName, "net-merge-diagnostics-") {
		t.Errorf("base name = %q", b.BaseName)
	}
}

// TestMarkdownMirrorsTheTextReport keeps the two renderings honest about the same facts: every
// section the plain-text report has must exist in the Markdown one, with the same wording, and
// the Markdown must be structurally valid (title, headings, no leftover "==" markers, and prose
// separated from lists so nothing is swallowed as a bullet's continuation).
func TestMarkdownMirrorsTheTextReport(t *testing.T) {
	doc := testDoc(t)
	b, err := doc.Bundle(DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	text, md := string(b.Text), string(b.Markdown)

	if md == "" {
		t.Fatalf("Markdown rendering is empty")
	}
	if !strings.HasPrefix(md, "# net-merge diagnostic report\n") {
		t.Errorf("the report should open with a level-1 title, got:\n%s", firstLines(md, 3))
	}
	if strings.Contains(md, "== ") {
		t.Errorf("plain-text section markers leaked into the Markdown:\n%s", firstLines(md, 40))
	}

	// Section parity: every "== X ==" in the text must be a "## X" heading in the Markdown.
	var sections []string
	for _, line := range strings.Split(text, "\n") {
		if title, ok := strings.CutPrefix(strings.TrimSpace(line), "== "); ok {
			if title, ok := strings.CutSuffix(title, " =="); ok {
				sections = append(sections, title)
			}
		}
	}
	if len(sections) == 0 {
		t.Fatalf("the plain-text report has no sections, so parity is untestable")
	}
	for _, s := range sections {
		if !strings.Contains(md, "## "+s+"\n") {
			t.Errorf("section %q is in the text report but missing as a Markdown heading", s)
		}
	}

	// No line that is prose may sit directly under a bullet, and no bullet under a paragraph
	// without the blank line CommonMark needs to tell them apart.
	lines := strings.Split(md, "\n")
	for i := 1; i < len(lines); i++ {
		prev, cur := lines[i-1], lines[i]
		if prev == "" || cur == "" {
			continue
		}
		prevItem, curItem := strings.HasPrefix(prev, "- "), strings.HasPrefix(cur, "- ")
		if prevItem && !curItem && !strings.HasPrefix(cur, "#") {
			t.Errorf("line %d (%q) follows a bullet with no blank line; it would be read as the bullet's continuation", i+1, cur)
		}
		if !prevItem && !strings.HasPrefix(prev, "#") && curItem {
			t.Errorf("line %d (%q) starts a list directly under prose with no blank line", i+1, cur)
		}
	}

	// A heading must never be glued to the line above it.
	for i, line := range lines {
		if strings.HasPrefix(line, "#") && i > 0 && lines[i-1] != "" {
			t.Errorf("heading %q is not preceded by a blank line", line)
		}
	}
}

func TestDocumentJSONRoundTrip(t *testing.T) {
	doc := testDoc(t)
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var back Document
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back.Schema != doc.Schema || back.Summary.ChecksRan != doc.Summary.ChecksRan {
		t.Errorf("round trip lost summary data: %+v", back.Summary)
	}
	if len(back.Hypotheses) != len(doc.Hypotheses) {
		t.Errorf("round trip lost hypotheses: %d vs %d", len(back.Hypotheses), len(doc.Hypotheses))
	}
	items := 0
	for _, r := range back.Diagnostics {
		items += len(r.Items)
	}
	if items == 0 {
		t.Errorf("round trip lost the machine-readable items")
	}
}

func TestNoInventoryAndNoTTLAreStatedNotHidden(t *testing.T) {
	doc := Build(Options{Now: testNow, Platform: "linux", Run: diag.RunResult{}})
	joined := strings.Join(doc.Caveats, "\n")
	if !strings.Contains(joined, "no adapter inventory was attached") {
		t.Errorf("a report without an inventory must say so, got: %s", joined)
	}
	if !strings.Contains(joined, "no TTL/hop-limit inspection was attached") {
		t.Errorf("a report without a TTL inspection must say so, got: %s", joined)
	}
}

func TestEngineProblemIsStated(t *testing.T) {
	text := testDoc(t).Text()
	if !strings.Contains(text, "the status file exists but no process holds the instance lock") {
		t.Errorf("the engine section must carry the contradiction between the file and the process")
	}
}

func TestEngineStatusRendersNICs(t *testing.T) {
	doc := Build(Options{
		Now: testNow, Platform: "linux",
		Engine: &EngineView{
			Running: true, Mode: "bond", V6: "native", Since: testNow,
			NICs: []engine.SlotStats{{Name: "Ethernet", State: "up", Weight: 1.5, Active: 12, Total: 40, RateIn: 1024, RateOut: 512}},
		},
		Run: diag.RunResult{},
	})
	text := doc.Text()
	for _, want := range []string{"running: yes, mode bond", "IPv6 handling: native", "Ethernet: state up", "12 active / 40 total"} {
		if !strings.Contains(text, want) {
			t.Errorf("engine section missing %q", want)
		}
	}
}

func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
