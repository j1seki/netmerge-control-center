package inventory

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Source is where a platform's facts come from. One implementation per platform, plus the fake
// used in tests. A Source reports what it cannot read as gaps instead of guessing, which is what
// lets one dashboard run on Windows (PowerShell cmdlets), Linux (netlink) and anywhere else
// (an honest "not supported here") without the calling code branching on the operating system.
type Source interface {
	// Name identifies the mechanism for the report, e.g. "windows-powershell".
	Name() string
	// Adapters returns every interface the host knows about, including the ones that cannot be
	// used, plus host-wide gaps. Every adapter it returns must carry enough to be judged: a
	// source that cannot read gateways must say so in its gaps.
	Adapters(ctx context.Context) (adapters []Adapter, gaps []string, err error)
	// Routes returns the routing table. Failing to read it degrades the dashboard, it does not
	// stop it: the caller records the error and carries on.
	Routes(ctx context.Context) (routes []Route, gaps []string, err error)
	// Counters returns the platform's byte totals for one interface, and false when this host
	// cannot provide them.
	Counters(ctx context.Context, index int) (Counters, bool)
}

// Collector turns a Source into a Snapshot: it attributes routes to interfaces, samples the
// counters, derives rates, evaluates eligibility and records the host-wide observations. It owns
// the rate history, so one Collector per application is what makes per-second rates meaningful.
type Collector struct {
	src   Source
	rates *RateTracker
	now   func() time.Time
}

// NewCollector returns a Collector over the given source. The rate tracker is created here
// because rates are a property of repeated observation, not of a single read.
func NewCollector(src Source) *Collector {
	return &Collector{src: src, rates: NewRateTracker(0), now: time.Now}
}

// Router is implemented by sources that keep the routing table and the interface list separate.
// It exists so the Collector can attribute routes without knowing how they were read.
type routedSource interface {
	Routes(ctx context.Context) ([]Route, []string, error)
}

// Snapshot collects everything at one instant. An error is returned only when the interface list
// itself could not be read; every lesser failure is recorded in the snapshot so a dashboard can
// show a partial, honest picture rather than an error page.
func (c *Collector) Snapshot(ctx context.Context, opts Options) (*Snapshot, error) {
	snap := &Snapshot{Taken: c.now(), Source: c.src.Name()}

	adapters, gaps, err := c.src.Adapters(ctx)
	if err != nil {
		return nil, fmt.Errorf("read adapter list: %w", err)
	}
	snap.Gaps = append(snap.Gaps, gaps...)

	if rs, ok := c.src.(routedSource); ok {
		routes, rgaps, rerr := rs.Routes(ctx)
		switch {
		case rerr != nil:
			snap.Errors = append(snap.Errors, "routing table could not be read: "+rerr.Error())
		default:
			snap.Gaps = append(snap.Gaps, rgaps...)
			snap.Routes = routes
		}
	}

	attributeRoutes(adapters, snap.Routes)

	for i := range adapters {
		if counters, ok := c.src.Counters(ctx, adapters[i].Index); ok {
			adapters[i].Counters = &counters
		} else {
			adapters[i].Gaps = append(adapters[i].Gaps, "byte counters unavailable")
		}
	}

	adapters = Evaluate(adapters, opts)

	for i := range adapters {
		if adapters[i].Counters != nil {
			if rates, ok := c.rates.ObserveAt(adapters[i].Name, *adapters[i].Counters, snap.Taken); ok {
				adapters[i].Rates = &rates
			}
		}
	}

	snap.Adapters = adapters
	snap.Warnings = append(snap.Warnings, CrossChecks(adapters)...)
	snap.Sort()
	summarize(snap)
	if len(adapters) == 0 {
		snap.Warnings = append(snap.Warnings,
			"no network adapters were found; if this machine does have a wired, Wi-Fi or tethered link, the adapter list itself could not be read")
	}
	return snap, nil
}

// Rates returns the current per-second rate for an adapter name without taking a new snapshot.
func (c *Collector) Rates(name string) (Rates, bool) { return c.rates.Rates(name) }

// Idle reports whether an interface's counters have not moved for at least window. known=false
// means the collector has not been running long enough to say.
func (c *Collector) Idle(name string, window time.Duration) (idle, known bool) {
	return c.rates.Idle(name, window)
}

// attributeRoutes gives each route to its interface (by index, falling back to name) and each
// interface its routes. A route whose interface is not in the list is dropped from the
// per-adapter view but stays in the snapshot's table, which is how a stale route for a removed
// adapter remains visible instead of vanishing.
func attributeRoutes(adapters []Adapter, routes []Route) {
	byIndex := map[int]int{}
	byName := map[string]int{}
	for i := range adapters {
		byIndex[adapters[i].Index] = i
		byName[strings.ToLower(adapters[i].Name)] = i
	}
	for _, r := range routes {
		i, ok := byIndex[r.Index]
		if !ok {
			i, ok = byName[strings.ToLower(r.Name)]
			if !ok {
				continue
			}
		}
		if r.Name == "" {
			r.Name = adapters[i].Name
		}
		if r.Index == 0 {
			r.Index = adapters[i].Index
		}
		r.Default = isDefaultRoute(r.Destination)
		adapters[i].Routes = append(adapters[i].Routes, r)
		adapters[i].RouteCount++
		if r.Default {
			adapters[i].DefaultRoutes = append(adapters[i].DefaultRoutes, r)
			// A default route is also the adapter's gateway for that family. Sources that read
			// the routing table and sources that read gateways directly must produce the same
			// adapter here, or eligibility would depend on which mechanism was available.
			if r.Family == "v6" {
				adapters[i].DefaultRoute6 = true
				if r.NextHop != "" && !isOnLink(r.NextHop) && !containsFold(adapters[i].Gateways6, r.NextHop) {
					adapters[i].Gateways6 = append(adapters[i].Gateways6, r.NextHop)
				}
			} else {
				adapters[i].DefaultRoute4 = true
				if r.NextHop != "" && !isOnLink(r.NextHop) && !containsFold(adapters[i].Gateways4, r.NextHop) {
					adapters[i].Gateways4 = append(adapters[i].Gateways4, r.NextHop)
				}
			}
		}
	}
}

// isDefaultRoute reports whether a destination is the default route for its family.
func isDefaultRoute(dst string) bool {
	switch strings.TrimSpace(dst) {
	case "0.0.0.0/0", "::/0", "0.0.0.0", "::":
		return true
	}
	return false
}

// summarize fills in the totals. The link-speed total is the sum of what the adapters report,
// which is a property of the hardware, and it is labelled as such wherever it is shown: it is
// not a promise that the machine can move that many bits per second, because a single TCP
// connection still follows one route.
func summarize(snap *Snapshot) {
	for _, a := range snap.Adapters {
		if a.Status == StateActive || a.Status == StateEligible {
			snap.LinkSpeedTotalBps += a.SpeedBps
		}
		if a.Rates != nil {
			snap.InPerSecTotal += a.Rates.InPerSec
			snap.OutPerSecTotal += a.Rates.OutPerSec
		}
	}
}

// WithEngineUsage returns opts with the engine's current view attached. It exists so the app
// layer has one place to merge the engine's status file into the inventory's options.
func (o Options) WithEngineUsage(used map[string]bool, assigned map[string]int) Options {
	o.EngineUsed = used
	o.EngineAssigned = assigned
	return o
}

// WithHealth returns opts with the last reachability results attached.
func (o Options) WithHealth(health map[string]Health) Options {
	o.Health = health
	return o
}
