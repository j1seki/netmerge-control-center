package inventory

import (
	"sync"
	"time"
)

// RateTracker derives per-second byte rates from repeated counter readings.
//
// It keeps a short history rather than only the last two samples, and it is explicit about the
// window it used, because two things go wrong with naive rate maths and both produce numbers a
// user would believe:
//
//   - A counter that resets (adapter replugged, driver reloaded, the 32-bit counters on some
//     devices wrapping) makes the delta negative. That interval is discarded rather than
//     reported as a huge spike.
//   - A rate divided by a very short interval multiplies any sampling jitter. The rate is
//     always the delta over the full span of samples the tracker holds, and the span is carried
//     with it.
type RateTracker struct {
	mu      sync.Mutex
	window  time.Duration
	samples map[string][]counterSample
}

type counterSample struct {
	at time.Time
	c  Counters
}

// DefaultRateWindow is how much history a per-second rate is averaged over. Two seconds is short
// enough to feel live on a dashboard and long enough that one late sample does not distort it.
const DefaultRateWindow = 2 * time.Second

// NewRateTracker returns a tracker keeping window worth of samples. Zero or negative uses
// DefaultRateWindow.
func NewRateTracker(window time.Duration) *RateTracker {
	if window <= 0 {
		window = DefaultRateWindow
	}
	return &RateTracker{window: window, samples: map[string][]counterSample{}}
}

// Observe records a reading for a key and returns the derived rate when two readings more than
// a moment apart are available. It returns false for the first reading, for a reading too close
// to the previous one to divide by, and across a counter reset.
func (t *RateTracker) Observe(key string, c Counters) (Rates, bool) {
	return t.ObserveAt(key, c, time.Now())
}

// ObserveAt is Observe with an explicit timestamp, which is what makes the rate maths testable.
func (t *RateTracker) ObserveAt(key string, c Counters, at time.Time) (Rates, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	hist := t.samples[key]
	// Keep every sample inside the window, and always at least the two newest: a poll slower
	// than the window still deserves a rate over consecutive readings rather than none at all.
	start := len(hist)
	for start > 0 && at.Sub(hist[start-1].at) <= t.window {
		start--
	}
	if start == len(hist) && len(hist) > 2 {
		start = len(hist) - 2
	}
	hist = append(append([]counterSample{}, hist[start:]...), counterSample{at: at, c: c})
	if len(hist) > 8 {
		hist = hist[len(hist)-8:]
	}
	t.samples[key] = hist

	if len(hist) < 2 {
		return Rates{}, false
	}
	return t.ratesAt(hist)
}

// Rates returns the most recent rate for a key without recording a new reading.
func (t *RateTracker) Rates(key string) (Rates, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	hist := t.samples[key]
	if len(hist) < 2 {
		return Rates{}, false
	}
	return t.ratesAt(hist)
}

// ratesAt is the shared derivation. It must be called with the tracker's lock held.
//
// The rate comes from the newest run of samples whose counters only ever increased. A counter
// reset - an adapter replugged, a driver reloaded, a 32-bit counter wrapping - ends that run, and
// the interval that spans it is discarded rather than divided into a spike. If the reset was the
// most recent thing that happened, there is no post-reset interval yet and the honest answer is
// "no rate", not "zero".
func (t *RateTracker) ratesAt(hist []counterSample) (Rates, bool) {
	i := len(hist) - 1
	for i > 0 && hist[i].c.In >= hist[i-1].c.In && hist[i].c.Out >= hist[i-1].c.Out {
		i--
	}
	seg := hist[i:]
	if len(seg) < 2 {
		return Rates{}, false
	}
	first, last := seg[0], seg[len(seg)-1]
	span := last.at.Sub(first.at)
	if span <= 0 {
		return Rates{}, false
	}
	seconds := span.Seconds()
	return Rates{
		InPerSec:  float64(last.c.In-first.c.In) / seconds,
		OutPerSec: float64(last.c.Out-first.c.Out) / seconds,
		Span:      seconds,
		At:        last.at,
	}, true
}

// Idle reports whether a key's counters have not moved for at least window. known is false when
// the tracker has not been observing for long enough to make that claim: "no traffic seen yet"
// and "no traffic for a minute" are different statements and the dashboard must not conflate
// them.
func (t *RateTracker) Idle(key string, window time.Duration) (idle, known bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	hist := t.samples[key]
	if len(hist) < 2 {
		return false, false
	}
	first, last := hist[0], hist[len(hist)-1]
	if last.at.Sub(first.at) < window {
		return false, false
	}
	return last.c.In == first.c.In && last.c.Out == first.c.Out, true

}

// Forget drops the history for a key, used when an adapter disappears so a future adapter that
// reuses the name does not inherit an impossible rate.
func (t *RateTracker) Forget(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.samples, key)
}
