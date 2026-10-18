package nics

import "testing"

// selectName is the explicit include/exclude decision, separated from interface enumeration so
// the decision can be tested without a live interface table. These tests are pure logic: no
// adapter on this machine is read, and nothing here is a measurement of a real network.
func TestSelectNameDecision(t *testing.T) {
	cases := []struct {
		name    string
		include []string
		exclude []string
		iface   string
		wantOK  bool
		wantWhy bool // a skip reason is expected
	}{
		{"no lists", nil, nil, "Ethernet", true, false},
		{"include hit", []string{"Ethernet", "Wi-Fi"}, nil, "Wi-Fi", true, false},
		{"include miss is silent", []string{"Ethernet"}, nil, "Wi-Fi", false, false},
		{"exclude hit", nil, []string{"Wi-Fi"}, "Wi-Fi", false, true},
		{"exclude applies in include mode too", []string{"Ethernet", "Wi-Fi"}, []string{"Wi-Fi"}, "Wi-Fi", false, true},
		{"exclusion wins over inclusion", []string{"Ethernet"}, []string{"Ethernet"}, "Ethernet", false, true},
		{"case-insensitive include", []string{"ethernet"}, nil, "Ethernet", true, false},
		{"case-insensitive exclude", nil, []string{"WI-FI"}, "Wi-Fi", false, true},
		{"unrelated exclusion", nil, []string{"Wi-Fi"}, "Ethernet", true, false},
	}
	for _, tc := range cases {
		ok, why := selectName(tc.include, tc.exclude, tc.iface)
		if ok != tc.wantOK {
			t.Errorf("%s: ok = %v, want %v", tc.name, ok, tc.wantOK)
		}
		if (why != "") != tc.wantWhy {
			t.Errorf("%s: reason = %q, want reason present = %v", tc.name, why, tc.wantWhy)
		}
	}
}

// An include list that matches nothing yields no adapters, whatever the host has.
func TestDiscoverNicsWithImpossibleInclude(t *testing.T) {
	got, skipped, err := DiscoverNicsDetailed([]string{"definitely-not-an-interface-xyz"}, nil, nil)
	if err != nil {
		t.Fatalf("discovery failed: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("matched %d adapters for an impossible name: %v", len(got), got)
	}
	// The include miss is silent by design: an adapter that is not on the list was never a
	// candidate, and listing every adapter on the machine as "skipped" would be noise.
	for _, s := range skipped {
		if s.Name != "" {
			t.Errorf("an include miss produced a skip entry: %+v", s)
		}
	}
}
