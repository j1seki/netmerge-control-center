package diagreport

// Tests for the analysis layer.
//
// The diagnostic results here are constructed by hand - a simulated run, never a recorded one -
// so each rule can be exercised against exactly the observations it is meant to reason over.
// The two things these tests hold are the honesty properties: a conclusion drawn from comparing
// two observations is marked verified, a candidate explanation is marked as a hypothesis with a
// confidence, and an absence of observation produces no hypothesis at all.

import (
	"strings"
	"testing"
	"time"

	"net-merge/internal/diag"
	"net-merge/internal/ttlmgr"
)

func hypRes(id string, cat diag.Category, st diag.Status, codes []string, items ...diag.Item) diag.Result {
	return diag.Result{
		ID:         id,
		Category:   cat,
		Status:     st,
		Summary:    "simulated result: " + id,
		ErrorCodes: codes,
		Items:      items,
	}
}

func hypDoc(t *testing.T, results ...diag.Result) *Document {
	t.Helper()
	return Build(Options{
		Now:      time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC),
		Version:  "test-build",
		Platform: "windows",
		Arch:     "amd64",
		Run:      diag.RunResult{Results: results},
	})
}

func TestLinkSpecificFailureIsVerified(t *testing.T) {
	doc := hypDoc(t,
		hypRes("adapters.connect", diag.CatPath, diag.StatusWarn, nil,
			diag.Item{Scope: "Ethernet", Code: "connected", Detail: "93.184.216.34:443"},
			diag.Item{Scope: "Wi-Fi", Code: "timeout", Detail: "93.184.216.34:443"},
		),
	)
	hs := doc.Hypotheses
	if len(hs) == 0 {
		t.Fatal("one link reaching and another failing produced no hypothesis")
	}
	first := hs[0]
	if first.Kind != KindVerified {
		t.Errorf("a conclusion drawn from two differing observations must be verified, got %q", first.Kind)
	}
	if first.Rank != 1 {
		t.Errorf("rank = %d, want 1", first.Rank)
	}
	if !strings.Contains(first.Statement, "Wi-Fi") || !strings.Contains(first.Statement, "Ethernet") {
		t.Errorf("the statement must name both the failing and the working link, got %q", first.Statement)
	}
	if len(first.Supports) == 0 || first.Supports[0] != "adapters.connect" {
		t.Errorf("the hypothesis must cite the check it came from, got %v", first.Supports)
	}
}

func TestEveryLinkFailingIsAHypothesisWithACandidateCause(t *testing.T) {
	doc := hypDoc(t,
		hypRes("adapters.connect", diag.CatPath, diag.StatusFail, nil,
			diag.Item{Scope: "Ethernet", Code: "timeout"},
			diag.Item{Scope: "Wi-Fi", Code: "no_route"},
		),
		hypRes("gateway.reach", diag.CatGateway, diag.StatusPass, nil,
			diag.Item{Scope: "Ethernet", Code: "gateway_answered", Detail: "192.168.1.1"},
		),
		hypRes("ipv4.connect", diag.CatPath, diag.StatusFail, []string{"diag_tcp_timeout"}),
		hypRes("security.firewall", diag.CatSecurity, diag.StatusInfo,
			nil, diag.Item{Scope: "Domain", Code: "firewall_enabled", Detail: "inbound Block, outbound Allow"}),
	)
	hs := doc.Hypotheses
	if len(hs) < 3 {
		t.Fatalf("want at least three hypotheses (all links, filtered path, firewall candidate), got %d: %+v", len(hs), hs)
	}
	byKind := map[string]Hypothesis{}
	for _, h := range hs {
		if h.Rank < 1 {
			t.Errorf("every hypothesis must be ranked, got %+v", h)
		}
		byKind[h.Statement[:20]] = h
	}
	// The firewall pairing must never be more than a candidate, and must say so in words.
	var low *Hypothesis
	for i := range hs {
		if strings.Contains(hs[i].Statement, "firewall") {
			low = &hs[i]
		}
	}
	if low == nil {
		t.Fatalf("no firewall hypothesis was produced: %+v", hs)
	}
	if low.Kind != KindHypothesis || low.Confidence != "low" {
		t.Errorf("the firewall pairing must stay a low-confidence hypothesis, got kind=%q confidence=%q", low.Kind, low.Confidence)
	}
	if !strings.Contains(low.Statement, "cannot prove") {
		t.Errorf("the firewall statement must say it cannot prove the firewall dropped anything, got %q", low.Statement)
	}
	// Ranking: verified first, then high, medium, low.
	lastRank := 0
	for _, h := range hs {
		if h.Rank <= lastRank {
			t.Errorf("ranks must be strictly increasing, got %+v", hs)
		}
		lastRank = h.Rank
	}
	if hs[len(hs)-1].Confidence != "low" {
		t.Errorf("the low-confidence candidate should sort last, got %+v", hs[len(hs)-1])
	}
}

func TestAllLinksFailingWithoutCorroborationStaysMedium(t *testing.T) {
	doc := hypDoc(t,
		hypRes("adapters.connect", diag.CatPath, diag.StatusFail, nil,
			diag.Item{Scope: "Ethernet", Code: "timeout"},
			diag.Item{Scope: "Wi-Fi", Code: "timeout"},
		),
	)
	var found *Hypothesis
	for i := range doc.Hypotheses {
		if strings.Contains(doc.Hypotheses[i].Statement, "shared") {
			found = &doc.Hypotheses[i]
		}
	}
	if found == nil {
		t.Fatalf("no shared-cause hypothesis: %+v", doc.Hypotheses)
	}
	if found.Confidence != "medium" {
		t.Errorf("without DNS failing too, confidence should stay medium, got %q", found.Confidence)
	}
}

func TestAllLinksFailingWithDNSFailureIsHighConfidence(t *testing.T) {
	doc := hypDoc(t,
		hypRes("adapters.connect", diag.CatPath, diag.StatusFail, nil,
			diag.Item{Scope: "Ethernet", Code: "timeout"},
			diag.Item{Scope: "Wi-Fi", Code: "timeout"},
		),
		hypRes("dns.resolve", diag.CatDNS, diag.StatusFail, []string{"diag_dns_timeout"}),
	)
	var found *Hypothesis
	for i := range doc.Hypotheses {
		if strings.Contains(doc.Hypotheses[i].Statement, "shared") {
			found = &doc.Hypotheses[i]
		}
	}
	if found == nil {
		t.Fatalf("no shared-cause hypothesis: %+v", doc.Hypotheses)
	}
	if found.Confidence != "high" {
		t.Errorf("resolution failing in the same run corroborates the shared cause, got %q", found.Confidence)
	}
	if !strings.Contains(found.Statement, "resolution") {
		t.Errorf("the corroboration must be stated, got %q", found.Statement)
	}
}

func TestRefusedConnectionIsNotALinkFailure(t *testing.T) {
	doc := hypDoc(t,
		hypRes("adapters.connect", diag.CatPath, diag.StatusWarn, nil,
			diag.Item{Scope: "Ethernet", Code: "refused", Detail: "example.com:443"},
		),
		hypRes("ipv4.connect", diag.CatPath, diag.StatusWarn, []string{"diag_tcp_refused"},
			diag.Item{Code: "refused", Detail: "example.com:443"},
		),
	)
	for _, h := range doc.Hypotheses {
		if strings.Contains(h.Statement, "shared") || strings.Contains(h.Statement, "specific to") {
			t.Errorf("a refusal means the path works; it must not read as a link failure: %q", h.Statement)
		}
	}
	var found *Hypothesis
	for i := range doc.Hypotheses {
		if strings.Contains(doc.Hypotheses[i].Statement, "closed") {
			found = &doc.Hypotheses[i]
		}
	}
	if found == nil {
		t.Fatalf("no refusal explanation was produced: %+v", doc.Hypotheses)
	}
	if found.Kind != KindVerified {
		t.Errorf("a refusal provably arrived, so this is verified, got %q", found.Kind)
	}
}

func TestDNSServerDeadWhenAskedDirectly(t *testing.T) {
	doc := hypDoc(t,
		hypRes("dns.resolve", diag.CatDNS, diag.StatusPass, nil),
		hypRes("dns.server", diag.CatDNS, diag.StatusFail, []string{"diag_dns_server_unresponsive"},
			diag.Item{Scope: "1.1.1.1", Code: "dns_unresponsive", Detail: "example.com"}),
	)
	var found *Hypothesis
	for i := range doc.Hypotheses {
		if strings.Contains(doc.Hypotheses[i].Statement, "did not answer a direct query") {
			found = &doc.Hypotheses[i]
		}
	}
	if found == nil {
		t.Fatalf("a directly unresponsive DNS server produced no hypothesis: %+v", doc.Hypotheses)
	}
	if found.Kind != KindVerified {
		t.Errorf("the server was asked directly; that is verified, got %q", found.Kind)
	}
	if !strings.Contains(found.Statement, "1.1.1.1") {
		t.Errorf("the statement must name the server, got %q", found.Statement)
	}
}

func TestDNSFailurePairing(t *testing.T) {
	doc := hypDoc(t,
		hypRes("dns.resolve", diag.CatDNS, diag.StatusFail, []string{"diag_dns_timeout"}),
		hypRes("dns.server", diag.CatDNS, diag.StatusFail, []string{"diag_dns_server_unresponsive"},
			diag.Item{Scope: "10.0.0.1", Code: "dns_unresponsive"}),
	)
	var found *Hypothesis
	for i := range doc.Hypotheses {
		if strings.Contains(doc.Hypotheses[i].Statement, "explained by that server") {
			found = &doc.Hypotheses[i]
		}
	}
	if found == nil {
		t.Fatalf("resolve + direct server failure produced no pairing hypothesis: %+v", doc.Hypotheses)
	}
	if found.Confidence != "high" {
		t.Errorf("two agreeing observations should be high confidence, got %q", found.Confidence)
	}
}

func TestReservedDNSAnswerIsFlagged(t *testing.T) {
	doc := hypDoc(t,
		hypRes("dns.resolve", diag.CatDNS, diag.StatusWarn, []string{"diag_dns_reserved_answer"},
			diag.Item{Code: "reserved_answer", Detail: "203.0.113.10"}),
	)
	var found *Hypothesis
	for i := range doc.Hypotheses {
		if strings.Contains(doc.Hypotheses[i].Statement, "reserved") {
			found = &doc.Hypotheses[i]
		}
	}
	if found == nil {
		t.Fatalf("a reserved-range answer produced no hypothesis: %+v", doc.Hypotheses)
	}
	if !strings.Contains(found.Statement, "203.0.113.10") {
		t.Errorf("the statement must name the address, got %q", found.Statement)
	}
	joined := strings.Join(found.NextSteps, " ")
	if !strings.Contains(joined, "captive portal") {
		t.Errorf("the candidate causes (portal, filter, hosts file) belong in the next steps, got %q", joined)
	}
}

func TestMTUBelowStandardIsReportedWithTheFigure(t *testing.T) {
	doc := hypDoc(t,
		hypRes("mtu.path", diag.CatPath, diag.StatusWarn, nil,
			diag.Item{Code: "mtu_below_standard", Detail: "1400"}),
	)
	var found *Hypothesis
	for i := range doc.Hypotheses {
		if strings.Contains(doc.Hypotheses[i].Statement, "1400") {
			found = &doc.Hypotheses[i]
		}
	}
	if found == nil {
		t.Fatalf("a reduced path MTU produced no hypothesis: %+v", doc.Hypotheses)
	}
	joined := strings.Join(found.NextSteps, " ")
	if !strings.Contains(joined, "net-merge -mtu") {
		t.Errorf("the next step should name the concrete action, got %q", joined)
	}
}

func TestVerifiedConclusionsSortBeforeHypotheses(t *testing.T) {
	doc := hypDoc(t,
		hypRes("adapters.connect", diag.CatPath, diag.StatusFail, nil,
			diag.Item{Scope: "Ethernet", Code: "timeout"},
			diag.Item{Scope: "Wi-Fi", Code: "timeout"},
		),
		hypRes("gateway.reach", diag.CatGateway, diag.StatusPass, nil,
			diag.Item{Scope: "Ethernet", Code: "gateway_answered"}),
		hypRes("ipv4.connect", diag.CatPath, diag.StatusFail, []string{"diag_tcp_timeout"}),
		hypRes("engine.stale", diag.CatEngine, diag.StatusWarn, []string{"engine_stale_adapter"},
			diag.Item{Scope: "net-merge", Code: "stale_adapter"}),
	)
	hs := doc.Hypotheses
	if len(hs) < 2 {
		t.Fatalf("want both a verified conclusion and a hypothesis, got %+v", hs)
	}
	if hs[0].Kind != KindVerified {
		t.Errorf("verified conclusions must come first, got kind=%q (%s)", hs[0].Kind, hs[0].Statement)
	}
	for i := 1; i < len(hs); i++ {
		if hs[i-1].Rank >= hs[i].Rank {
			t.Errorf("ranks must ascend: %+v", hs)
		}
	}
}

func TestStaleAdapterAndSkippedEngineAreDistinct(t *testing.T) {
	doc := hypDoc(t,
		hypRes("engine.stale", diag.CatEngine, diag.StatusWarn, []string{"engine_stale_adapter"},
			diag.Item{Scope: "net-merge", Code: "stale_adapter"}),
		hypRes("engine.eligibility", diag.CatEngine, diag.StatusPass, nil,
			diag.Item{Scope: "Ethernet", Code: "engine_uses"},
			diag.Item{Scope: "Wi-Fi", Code: "usable_not_listed"},
		),
	)
	var stale, notListed *Hypothesis
	for i := range doc.Hypotheses {
		switch {
		case strings.Contains(doc.Hypotheses[i].Statement, "no engine is running"):
			stale = &doc.Hypotheses[i]
		case strings.Contains(doc.Hypotheses[i].Statement, "not in the engine's adapter list"):
			notListed = &doc.Hypotheses[i]
		}
	}
	if stale == nil {
		t.Fatalf("stale adapter not reported: %+v", doc.Hypotheses)
	}
	if stale.Kind != KindVerified {
		t.Errorf("a present adapter with no running engine is a verified state, got %q", stale.Kind)
	}
	if !strings.Contains(strings.Join(stale.NextSteps, " "), "net-merge cleanup") {
		t.Errorf("the next step must name the command, got %v", stale.NextSteps)
	}
	if notListed == nil {
		t.Fatalf("usable-but-unlisted adapter not reported: %+v", doc.Hypotheses)
	}
	if notListed.Kind != KindHypothesis {
		t.Errorf("the engine's reason is not visible to this report, so this is a hypothesis, got %q", notListed.Kind)
	}
	if !strings.Contains(notListed.Statement, "Wi-Fi") {
		t.Errorf("the statement must name the adapter, got %q", notListed.Statement)
	}
}

func TestAssignedNoTrafficIsLowConfidence(t *testing.T) {
	doc := hypDoc(t,
		hypRes("counters.assigned-idle", diag.CatAdapters, diag.StatusWarn, nil,
			diag.Item{Scope: "Wi-Fi", Code: "assigned_no_traffic", Detail: "3"}),
	)
	var found *Hypothesis
	for i := range doc.Hypotheses {
		if strings.Contains(doc.Hypotheses[i].Statement, "counters did not move") {
			found = &doc.Hypotheses[i]
		}
	}
	if found == nil {
		t.Fatalf("assigned-but-idle produced no hypothesis: %+v", doc.Hypotheses)
	}
	if found.Confidence != "low" {
		t.Errorf("idle connections look like this, so the confidence must be low, got %q", found.Confidence)
	}
	if !strings.Contains(strings.Join(found.NextSteps, " "), "Generate traffic") {
		t.Errorf("the next step must say to generate traffic first, got %v", found.NextSteps)
	}
}

func TestNoObservationNoHypothesis(t *testing.T) {
	// A run that established nothing must not result in an invented explanation. A skipped
	// check is exactly the case that must stay silent.
	doc := hypDoc(t,
		hypRes("adapters.connect", diag.CatPath, diag.StatusSkipped, nil),
		hypRes("dns.resolve", diag.CatDNS, diag.StatusSkipped, nil),
	)
	if len(doc.Hypotheses) != 0 {
		t.Errorf("skipped checks must produce no hypotheses, got %+v", doc.Hypotheses)
	}
}

func TestTTLPartialReadIsReported(t *testing.T) {
	doc := Build(Options{
		Now:      time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC),
		Platform: "windows",
		Run:      diag.RunResult{},
		TTL: &ttlmgr.Report{
			Capabilities: ttlmgr.Capabilities{Platform: "windows", Supported: true},
			ReadErrors: []ttlmgr.ReadFailure{{
				Setting: ttlmgr.SettingRef{ID: ttlmgr.IDv4Default, Kind: ttlmgr.KindPacketTTL, Family: ttlmgr.FamilyIPv4, Scope: ttlmgr.ScopeSystemGlobal},
				Code:    "ttl_permission_denied",
				Message: "access is denied",
			}},
		},
	})
	var found *Hypothesis
	for i := range doc.Hypotheses {
		if strings.Contains(doc.Hypotheses[i].Statement, "partial") {
			found = &doc.Hypotheses[i]
		}
	}
	if found == nil {
		t.Fatalf("an unreadable TTL setting produced no hypothesis: %+v", doc.Hypotheses)
	}
	if !strings.Contains(found.Statement, string(ttlmgr.IDv4Default)) {
		t.Errorf("the statement must name the setting that failed, got %q", found.Statement)
	}
	if found.Kind != KindVerified {
		t.Errorf("a read that failed is an observed fact, got %q", found.Kind)
	}
}

func TestPortInUseIsVerified(t *testing.T) {
	doc := hypDoc(t,
		hypRes("ports.conflict", diag.CatEngine, diag.StatusWarn, []string{"port_in_use"},
			diag.Item{Code: "port_in_use", Detail: "127.0.0.1:1080"}),
	)
	var found *Hypothesis
	for i := range doc.Hypotheses {
		if strings.Contains(doc.Hypotheses[i].Statement, "already bound") {
			found = &doc.Hypotheses[i]
		}
	}
	if found == nil {
		t.Fatalf("a bound port produced no hypothesis: %+v", doc.Hypotheses)
	}
	if found.Kind != KindVerified {
		t.Errorf("the bind test proves the port is taken, got %q", found.Kind)
	}
	if !strings.Contains(found.Statement, "127.0.0.1:1080") {
		t.Errorf("the statement must name the address, got %q", found.Statement)
	}
}

func TestAnalyzeIsDeterministic(t *testing.T) {
	results := []diag.Result{
		hypRes("adapters.connect", diag.CatPath, diag.StatusWarn, nil,
			diag.Item{Scope: "Ethernet", Code: "connected"},
			diag.Item{Scope: "Wi-Fi", Code: "timeout"}),
		hypRes("gateway.reach", diag.CatGateway, diag.StatusPass, nil,
			diag.Item{Scope: "Ethernet", Code: "gateway_answered"}),
		hypRes("ipv4.connect", diag.CatPath, diag.StatusFail, []string{"diag_tcp_timeout"}),
	}
	doc := hypDoc(t, results...)
	a := doc.Hypotheses
	b := Analyze(doc)
	if len(a) != len(b) {
		t.Fatalf("two analyses disagree on the count: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].Rank != b[i].Rank || a[i].Kind != b[i].Kind || a[i].Statement != b[i].Statement || a[i].Confidence != b[i].Confidence {
			t.Errorf("analysis is not deterministic at %d: %+v vs %+v", i, a[i], b[i])
		}
	}
}
