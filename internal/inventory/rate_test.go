package inventory

// Tests for the byte-rate tracker. Rate maths is where a dashboard becomes dishonest quietly: a
// counter reset reported as a spike, or a rate divided by a 4 ms interval, both look plausible.
// These tests pin the behaviour that stops that.

import (
	"testing"
	"time"
)

func TestRateIsDerivedOverTheWholeWindow(t *testing.T) {
	tr := NewRateTracker(10 * time.Second)
	base := time.Unix(1_700_000_000, 0)

	if _, ok := tr.ObserveAt("eth0", Counters{In: 1000, Out: 500}, base); ok {
		t.Fatal("the first sample produced a rate; there is nothing to divide by")
	}
	rate, ok := tr.ObserveAt("eth0", Counters{In: 5000, Out: 2500}, base.Add(2*time.Second))
	if !ok {
		t.Fatal("two samples two seconds apart produced no rate")
	}
	if rate.InPerSec != 2000 || rate.OutPerSec != 1000 {
		t.Errorf("rate = %+v, want 2000/1000 bytes per second", rate)
	}
	if rate.Span != 2 {
		t.Errorf("span = %v, want the full two-second window", rate.Span)
	}
	if !rate.At.Equal(base.Add(2 * time.Second)) {
		t.Errorf("rate timestamp = %v, want the newest sample", rate.At)
	}
}

func TestRateIsNotTakenOverAnImpossiblyShortInterval(t *testing.T) {
	tr := NewRateTracker(time.Minute)
	base := time.Unix(1_700_000_000, 0)
	tr.ObserveAt("eth0", Counters{}, base)
	// Two samples in the same instant carry no information about a rate; reporting one would be
	// a division by zero dressed up as a measurement.
	if _, ok := tr.ObserveAt("eth0", Counters{In: 100}, base); ok {
		t.Error("two samples at the same instant produced a rate")
	}
}

func TestCounterResetIsNotReportedAsASpike(t *testing.T) {
	tr := NewRateTracker(time.Minute)
	base := time.Unix(1_700_000_000, 0)

	tr.ObserveAt("eth0", Counters{In: 900_000, Out: 900_000}, base)
	tr.ObserveAt("eth0", Counters{In: 900_100, Out: 900_100}, base.Add(time.Second))
	// The driver reloaded: the counter went back to a small value. The interval that spans the
	// reset carries no information, so the honest answer is that there is no rate yet - what must
	// never happen is a negative rate or a spike.
	if rate, ok := tr.ObserveAt("eth0", Counters{In: 500, Out: 500}, base.Add(2*time.Second)); ok {
		t.Errorf("the first post-reset sample produced a rate %+v: there is no interval yet", rate)
	}
	// A second post-reset sample one second later measures that second, which really did carry no
	// bytes, so zero is the truthful rate here - the point is that it is not the spike the naive
	// subtraction would produce.
	if rate, ok := tr.ObserveAt("eth0", Counters{In: 500, Out: 500}, base.Add(3*time.Second)); !ok {
		t.Error("two post-reset samples one second apart produced no rate")
	} else if rate.InPerSec < 0 || rate.InPerSec > 1000 {
		t.Errorf("rate = %+v, want the reset interval discarded rather than reported as a spike", rate)
	}
	// Two seconds of growth after the reset is a real interval, and it measures only the
	// post-reset bytes.
	rate, ok := tr.ObserveAt("eth0", Counters{In: 2500, Out: 1500}, base.Add(4*time.Second))
	if !ok {
		t.Fatal("two post-reset samples produced no rate")
	}
	if rate.InPerSec != 1000 || rate.OutPerSec != 500 {
		t.Errorf("rate = %+v, want 1000/500 bytes per second measured after the reset", rate)
	}
	if rate.Span != 2 {
		t.Errorf("span = %v, want the post-reset interval only", rate.Span)
	}
}

func TestTwoResetsInARowProduceNoRate(t *testing.T) {
	tr := NewRateTracker(time.Minute)
	base := time.Unix(1_700_000_000, 0)
	tr.ObserveAt("eth0", Counters{In: 5000}, base)
	tr.ObserveAt("eth0", Counters{In: 100}, base.Add(time.Second))
	if _, ok := tr.ObserveAt("eth0", Counters{In: 50}, base.Add(2*time.Second)); ok {
		t.Error("with two resets in the window there is no interval to divide by, so no rate is right")
	}
}

func TestRateHistoryIsPrunedToTheWindow(t *testing.T) {
	tr := NewRateTracker(2 * time.Second)
	base := time.Unix(1_700_000_000, 0)
	for i := 0; i < 10; i++ {
		tr.ObserveAt("eth0", Counters{In: uint64(i * 100)}, base.Add(time.Duration(i)*time.Second))
	}
	rate, ok := tr.Rates("eth0")
	if !ok {
		t.Fatal("no rate after ten samples")
	}
	if rate.Span > 3 {
		t.Errorf("span = %v, want the window respected so a stalled sample is not averaged in", rate.Span)
	}
}

func TestIdleNeedsEnoughHistoryToBeAClaim(t *testing.T) {
	tr := NewRateTracker(time.Minute)
	base := time.Unix(1_700_000_000, 0)

	if idle, known := tr.Idle("eth0", 5*time.Second); known || idle {
		t.Error("an unobserved interface cannot be reported as idle")
	}
	tr.ObserveAt("eth0", Counters{In: 10, Out: 20}, base)
	tr.ObserveAt("eth0", Counters{In: 10, Out: 20}, base.Add(2*time.Second))
	if _, known := tr.Idle("eth0", 5*time.Second); known {
		t.Error("two seconds of history cannot support a five-second idle claim")
	}
	tr.ObserveAt("eth0", Counters{In: 10, Out: 20}, base.Add(9*time.Second))
	idle, known := tr.Idle("eth0", 5*time.Second)
	if !known || !idle {
		t.Errorf("idle = %v known = %v, want an idle verdict with nine seconds of unchanged counters", idle, known)
	}
	tr.ObserveAt("eth0", Counters{In: 11, Out: 20}, base.Add(10*time.Second))
	if idle, known := tr.Idle("eth0", 5*time.Second); !known || idle {
		t.Errorf("idle = %v known = %v, want traffic detected", idle, known)
	}
}

func TestCollectorPublishesRatesOnTheSnapshot(t *testing.T) {
	src := &fakeSource{
		adapters: []Adapter{ethernet("Ethernet", 7)},
		counters: map[int]Counters{7: {In: 1000, Out: 2000}},
	}
	c := NewCollector(src)
	base := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return base }

	snap, err := c.Snapshot(t.Context(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if snap.Adapters[0].Rates != nil {
		t.Error("the first snapshot must not invent a rate")
	}

	c.now = func() time.Time { return base.Add(2 * time.Second) }
	src.counters[7] = Counters{In: 5000, Out: 6000}
	snap, err = c.Snapshot(t.Context(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	r := snap.Adapters[0].Rates
	if r == nil {
		t.Fatal("the second snapshot produced no rate")
	}
	if r.InPerSec != 2000 || r.OutPerSec != 2000 {
		t.Errorf("rate = %+v, want 2000/2000 bytes per second", r)
	}
	if snap.InPerSecTotal != 2000 || snap.OutPerSecTotal != 2000 {
		t.Errorf("totals = %v/%v, want the adapters summed", snap.InPerSecTotal, snap.OutPerSecTotal)
	}
}

func TestForgetDropsHistory(t *testing.T) {
	tr := NewRateTracker(time.Minute)
	base := time.Unix(1_700_000_000, 0)
	tr.ObserveAt("eth0", Counters{In: 1}, base)
	tr.ObserveAt("eth0", Counters{In: 2}, base.Add(time.Second))
	tr.Forget("eth0")
	if _, ok := tr.Rates("eth0"); ok {
		t.Error("a forgotten key still reports a rate")
	}
}
