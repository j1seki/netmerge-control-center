package diag

// The TTL/hop-limit check reads the TTLL manager's own inspection rather than repeating its
// logic: the manager owns the values, the capture log and the configuration, and the diagnostic
// centre only reports what it finds. Nothing in this file can write: the inspector is a read
// API, and this check never calls Apply, Restore or any backend.

import (
	"context"
	"fmt"

	"net-merge/internal/ttlmgr"
)

func checkTTLInspect() Check {
	return funcCheck{
		meta: Meta{
			ID:       "ttl.inspect",
			Title:    "IPv4 TTL and IPv6 hop limit",
			Category: CatSecurity,
			Purpose:  "Report the packet-header TTL and hop-limit values this host has, what is captured for rollback, and whether the platform supports managing them at all. Nothing is changed by this check.",
			Establishes: []string{
				"the effective IPv4 TTL and IPv6 hop limit for the system and, where supported, per interface, with where each value came from",
				"whether an original value has been captured for a setting, which is what a restore would put back",
				"whether this platform can manage the values at all, and any setting that could not be read",
				"that these are packet-header values, distinct from DNS record TTLs and traceroute hop counts (both also reported here, labelled NotSettings)",
			},
			DoesNotEstablish: []string{
				"that a value is correct or incorrect: TTL is a normal protocol field with a platform default, and this application never treats a value as a fault",
				"that any change has been made: this check is read-only, and changing values is a separate, explicit, confirmed action in the TTL section",
			},
		},
		run: func(ctx context.Context, env *Env) Result {
			if env.InspectTTL == nil {
				return Result{
					Status:       StatusSkipped,
					Summary:      "no TTL inspector is wired into this run, so the packet-header values were not read",
					Inconclusive: []string{"the IPv4 TTL and IPv6 hop limit on this host"},
				}
			}
			ifaces := ttlInterfaces(ctx, env)
			rep, err := env.InspectTTL(ctx, ifaces)
			if err != nil {
				return Result{
					Status:       StatusError,
					Summary:      "the TTL inspection could not be completed: " + err.Error(),
					Inconclusive: []string{"every TTL and hop-limit value: the inspection is the source for all of them"},
					ErrorCodes:   []string{"diag_ttl_inspect_failed"},
				}
			}
			res := Result{}
			res.Established = append(res.Established,
				fmt.Sprintf("the platform %s a mechanism for these settings", supportedWord(rep.Capabilities.Supported)))
			for _, note := range rep.Capabilities.Notes {
				res.Established = append(res.Established, "capability note: "+note)
			}
			if rep.Capabilities.Supported {
				res.Items = append(res.Items, Item{Code: "ttl_supported"})
			} else {
				res.Items = append(res.Items, Item{Code: "ttl_unsupported"})
			}

			for _, s := range rep.Settings {
				line := fmt.Sprintf("%s: %s", s.ID, ttlValueText(s))
				if s.ValueOrigin != "" {
					line += " (read from " + s.ValueOrigin + ")"
				}
				if !s.Writable {
					line += " [not changeable: " + nonEmpty(s.WritableReason, "reason not reported") + "]"
				}
				res.Established = append(res.Established, line)
				if _, ok := rep.Captured[s.ID]; ok {
					res.Items = append(res.Items, Item{Scope: string(s.ID), Code: "ttl_captured"})
				}
			}
			for _, s := range rep.NotSettings {
				res.Established = append(res.Established,
					fmt.Sprintf("reported separately, and not a settable value here: %s: %s", s.ID, ttlValueText(s)))
			}
			for id, o := range rep.Captured {
				if o.Value == nil {
					res.Established = append(res.Established, fmt.Sprintf("%s: an original was captured but its value could not be read, so a restore would have nothing to put back", id))
					continue
				}
				explicit := "the platform's own default was in effect"
				if o.Explicit {
					explicit = "the value was explicitly set on the platform"
				}
				res.Established = append(res.Established,
					fmt.Sprintf("%s: an original value of %d is captured (captured %s; %s)", id, *o.Value, o.CapturedAt.Format("2006-01-02 15:04:05"), explicit))
			}

			if rep.Config.Enabled {
				res.Established = append(res.Established,
					"the stored configuration records TTL management as enabled by the user; that record by itself changes nothing, and this check did not act on it")
			}

			if len(rep.ReadErrors) > 0 {
				res.Status = Worse(res.Status, StatusWarn)
				for _, e := range rep.ReadErrors {
					res.Inconclusive = append(res.Inconclusive, fmt.Sprintf(
						"%s could not be read: %s (code %s)", e.Setting.ID, e.Message, nonEmpty(e.Code, "unspecified")))
				}
				res.ErrorCodes = append(res.ErrorCodes, "diag_ttl_read_partial")
			}
			for _, w := range rep.Warnings {
				res.Status = Worse(res.Status, StatusWarn)
				res.Inconclusive = append(res.Inconclusive, w)
			}
			if rep.Capabilities.Supported && !rep.Elevated && len(rep.ReadErrors) > 0 {
				res.NextSteps = append(res.NextSteps,
					"Reading the packet-header values usually requires administrator/root rights on Windows; re-running elevated may turn these read failures into values.")
			}
			if !rep.Elevated {
				res.Established = append(res.Established, "elevation: "+nonEmpty(rep.Elevation, "not elevated"))
			}

			switch {
			case !rep.Capabilities.Supported:
				res.Status = StatusInfo
				res.Summary = "this platform has no supported mechanism for the packet-header values; nothing is read and nothing is changed"
			case res.Status == StatusWarn:
				res.Summary = "the packet-header values were partly read; the settings that failed are listed"
			default:
				res.Status = StatusPass
				res.Summary = fmt.Sprintf("IPv4 TTL and IPv6 hop limit read for %d setting(s), %d original value(s) held for rollback", len(rep.Settings), len(rep.Captured))
			}
			return res
		},
	}
}

// ttlInterfaces builds the interface list the manager inspects, from the shared inventory, so the
// per-interface view uses the same adapter names as everything else in the report.
func ttlInterfaces(ctx context.Context, env *Env) []ttlmgr.IfaceInfo {
	snap, err := env.snapshot(ctx)
	if err != nil || snap == nil {
		return nil
	}
	out := make([]ttlmgr.IfaceInfo, 0, len(snap.Adapters))
	for _, a := range snap.Adapters {
		out = append(out, ttlmgr.IfaceInfo{Index: a.Index, Name: a.Name})
	}
	return out
}

func supportedWord(supported bool) string {
	if supported {
		return "provides"
	}
	return "does not provide"
}

// ttlValueText renders a value that may legitimately be absent: on Windows an unwritten registry
// value means the built-in default is in effect, which is not zero and must not be shown as one.
func ttlValueText(s ttlmgr.Setting) string {
	if s.Value == nil {
		return "not configured (the system's own default applies)"
	}
	return fmt.Sprint(*s.Value)
}
