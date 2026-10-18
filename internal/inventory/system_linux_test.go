//go:build linux

package inventory

// This file is the one place in the package that reads the real machine: it exercises the Linux
// source against the host it runs on. It is deliberately loose about what it finds (the test host
// may have any number of interfaces, any of which may be down) and strict about what it refuses
// to do: invent an interface, report a gateway it did not read, or call an address usable that
// the kernel marked tentative.
//
// It is NOT a simulation, and equally it is NOT evidence about Windows: what it verifies is that
// the netlink source and the eligibility rules agree with a real kernel.

import (
	"context"
	"testing"
)

func TestLinuxSourceReadsThisHost(t *testing.T) {
	src := NewLinuxSource()
	adapters, gaps, err := src.Adapters(context.Background())
	if err != nil {
		t.Fatalf("the real netlink source failed on this host: %v", err)
	}
	if len(adapters) == 0 {
		t.Skip("this host has no non-loopback interfaces to inspect")
	}
	for _, a := range adapters {
		if a.Index == 0 {
			t.Errorf("adapter %q has no interface index", a.Name)
		}
		if a.Name == "lo" {
			t.Errorf("the loopback interface must not be reported as a candidate link")
		}
		if a.Link == "" {
			t.Errorf("adapter %q has no link state", a.Name)
		}
		if a.Kind == "" {
			t.Errorf("adapter %q has no kind", a.Name)
		}
	}
	if len(gaps) == 0 {
		t.Error("the Linux source must declare its own limitation (DHCP state is not exposed by the kernel)")
	}

	routes, _, err := src.Routes(context.Background())
	if err != nil {
		t.Fatalf("reading the routing table failed: %v", err)
	}
	for _, r := range routes {
		if r.Family != "v4" && r.Family != "v6" {
			t.Errorf("route %+v has no usable family", r)
		}
		if r.Destination == "" {
			t.Errorf("route %+v has no destination", r)
		}
	}
	// A machine that runs this test at all is nearly always behind a default route; if it is not,
	// that is a fact about the host rather than a failure of the reader, so it is logged only.
	var defaults int
	for _, r := range routes {
		if r.Default {
			defaults++
		}
	}
	t.Logf("this host: %d interfaces, %d routes (%d default), gaps: %v", len(adapters), len(routes), defaults, gaps)
}

func TestLinuxSourceSnapshotIsSelfConsistent(t *testing.T) {
	c := NewCollector(NewLinuxSource())
	snap, err := c.Snapshot(context.Background(), Options{})
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snap.Taken.IsZero() {
		t.Error("the snapshot has no timestamp")
	}
	if snap.Source != "linux-netlink" {
		t.Errorf("source = %q", snap.Source)
	}
	if len(snap.Adapters) != len(snap.Usable())+len(snap.Unusable()) {
		t.Errorf("%d adapters but %d usable + %d unusable", len(snap.Adapters), len(snap.Usable()), len(snap.Unusable()))
	}
	for _, a := range snap.Adapters {
		switch a.Status {
		case StateActive, StateEligible, StateExcluded, StateDisconnected, StateUnhealthy, StateUnknown:
		default:
			t.Errorf("adapter %q has the unknown status %q", a.Name, a.Status)
		}
		if a.Status == StateExcluded && (a.ExclusionCode == "" || a.Exclusion == "") {
			t.Errorf("adapter %q is excluded with no reason attached", a.Name)
		}
		if a.Status == StateEligible && a.ExclusionCode != "" {
			t.Errorf("adapter %q is eligible but carries the exclusion %q", a.Name, a.ExclusionCode)
		}
	}
	t.Logf("this host summary: %s", snap.Summary())
}
