// Package errcodes is the application's catalogue of error and event codes.
//
// Every code the user can meet is listed here with a plain-language meaning and, for errors, a
// suggested next step. The registry exists so that the three places a code surfaces - the
// dashboard, the log, and the exported report - cannot each invent their own wording, and so a
// code is never shown to a person as a bare identifier with no explanation.
//
// The kinds are deliberately separated:
//
//   - KindError: something did not happen and the caller was told. These always carry a fix.
//   - KindSafety: a refusal or a safeguard fired. These are not defects; the fix says how to
//     proceed deliberately (or that nothing is wrong).
//   - KindEvent: a record of something that did happen, kept for the event log's explanations.
package errcodes

import "sort"

// Kind separates errors from refusals from ordinary records.
type Kind string

const (
	KindError  Kind = "error"
	KindSafety Kind = "safety"
	KindEvent  Kind = "event"
)

// Entry is one code's explanation.
type Entry struct {
	Code    string `json:"code"`
	Kind    Kind   `json:"kind"`
	Meaning string `json:"meaning"`
	Fix     string `json:"fix,omitempty"`
}

var registry = map[string]Entry{}

func add(kind Kind, code, meaning, fix string) {
	registry[code] = Entry{Code: code, Kind: kind, Meaning: meaning, Fix: fix}
}

// Lookup returns the entry for a code. The second result is false when the code is not
// registered, which callers must treat as "no explanation available" rather than inventing one.
func Lookup(code string) (Entry, bool) {
	e, ok := registry[code]
	return e, ok
}

// All returns every entry, sorted by code.
func All() []Entry {
	out := make([]Entry, 0, len(registry))
	for _, e := range registry {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}

// Codes returns every registered code, sorted. It exists for the tests that keep the docs and
// the registry in step.
func Codes() []string {
	out := make([]string, 0, len(registry))
	for c := range registry {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

func init() {
	// --- dashboard: request handling -------------------------------------------------------

	add(KindError, "dashboard_bad_request",
		"the request body was not JSON this endpoint understands",
		"reload the page; if you are calling the API yourself, send a JSON object in the documented shape")
	add(KindError, "dashboard_bad_action",
		"an engine action was requested that is not one of on, off or toggle",
		"use on, off or toggle")
	add(KindError, "dashboard_bad_level",
		"an unknown log level was requested",
		"use one of debug, info, warn, error")
	add(KindError, "dashboard_encode_failed",
		"a response could not be encoded, so the dashboard refused to send a partial one",
		"report this with the exported diagnostics; it has never been observed in testing")
	add(KindSafety, "dashboard_unauthorized",
		"the request carried no dashboard access token",
		"open the address printed when the dashboard started; it contains the one-time token that starts a session")
	add(KindSafety, "dashboard_bad_token",
		"the dashboard access token was wrong",
		"the token belongs to a different run of the dashboard; restart the dashboard and use the address it prints")
	add(KindSafety, "dashboard_unauthorized_write",
		"a state-changing request did not carry the token in its header",
		"the page sends the header itself; a refusal here means the request did not come from the dashboard page")
	add(KindSafety, "dashboard_host_rejected",
		"the request's Host header did not name the local machine, which is how the dashboard defends against DNS rebinding",
		"use the 127.0.0.1 address the dashboard printed, not a hostname")
	add(KindSafety, "dashboard_remote_rejected",
		"the request did not arrive over loopback, and the dashboard only ever serves the local machine",
		"open the dashboard on the machine it runs on; it is not reachable from other devices by design")
	add(KindError, "dashboard_state_dir",
		"the engine's state directory could not be prepared or read",
		"check that the user account can write to the state directory reported in Diagnostics; on Windows it lives under the local application data folder")
	add(KindError, "dashboard_marker_failed",
		"the request to turn the engine on or off could not be written to the engine's marker file",
		"check the free space and permissions of the state directory, then try again; the engine is untouched until the marker lands")
	add(KindError, "dashboard_job_unknown",
		"a background job with that id does not exist in this run of the dashboard",
		"job ids are per-run; start the work again from the page")
	add(KindError, "dashboard_job_not_done",
		"the result was asked for while the job was still running",
		"poll the job until its status is done, then ask again")

	// --- dashboard: settings ----------------------------------------------------------------

	add(KindError, "dashboard_settings_invalid",
		"the settings that were submitted failed validation",
		"the message names each problem; fix them in the Settings section and save again")
	add(KindError, "dashboard_settings_save_failed",
		"the settings file could not be written",
		"check that the settings directory is writable and has free space; the previous file is left untouched when a save fails")
	add(KindEvent, "dashboard_settings_saved",
		"the settings file was written",
		"")

	// --- dashboard: diagnostics -------------------------------------------------------------

	add(KindError, "dashboard_diag_unavailable",
		"the diagnostics engine is not available in this context",
		"start the dashboard from the net-merge binary; the diagnostics need its process environment")
	add(KindEvent, "dashboard.diag_run",
		"a diagnostics run was started as a background job",
		"")

	// --- dashboard: TTL ----------------------------------------------------------------------

	add(KindError, "dashboard_ttl_unavailable",
		"the TTL/hop-limit manager is not available in this context",
		"the manager needs the platform backend; start the dashboard from the net-merge binary on Windows")
	add(KindError, "dashboard_ttl_inspect_failed",
		"the TTL/hop-limit settings could not be read",
		"the details carry the platform's own error; read the Diagnostics section's TTL check for the same information with a full explanation")
	add(KindError, "dashboard_ttl_history_failed",
		"the change history could not be read",
		"the history file may be corrupt; it is only append-only, so the current values are unaffected. Inspect the state directory's ttl folder")
	add(KindError, "dashboard_ttl_config_invalid",
		"the TTL configuration failed validation before anything was written",
		"the details list each invalid field: the IPv4 TTL and IPv6 hop limit are 1..255, and the policy is one of none, list, all-except")
	add(KindError, "dashboard_ttl_config_save_failed",
		"the TTL configuration file could not be written",
		"check the state directory's permissions and free space; no system setting was touched")
	add(KindSafety, "dashboard_confirm_required",
		"a change that writes to system settings was requested without explicit confirmation",
		"preview first, then confirm; the dashboard never writes system settings from a request that did not ask for it knowingly")
	add(KindError, "dashboard_ttl_op_failed",
		"the TTL apply or restore did not complete",
		"the details carry the manager's own outcome, which names each setting that failed and whether a rollback was complete")

	// --- dashboard: export -------------------------------------------------------------------

	add(KindError, "dashboard_export_dir",
		"the export directory could not be created",
		"check that the output directory is writable; the export is written nowhere else")
	add(KindError, "dashboard_export_write",
		"the export could not be written to disk",
		"check free space and permissions on the output directory; nothing was uploaded anywhere")
	add(KindEvent, "dashboard.export_saved",
		"a redacted export was written as text and JSON",
		"")

	// --- dashboard: logs -----------------------------------------------------------------------

	add(KindError, "dashboard_logs_unavailable",
		"the event log could not be read",
		"the in-memory event ring is not available in this context; start the dashboard from the net-merge binary")

	// --- TTL manager ---------------------------------------------------------------------------

	add(KindSafety, "ttl_unsupported",
		"this host has no supported mechanism for changing the packet-header value",
		"nothing was changed. Per-interface TTL and hop limit are Windows settings; on other platforms the manager reports the values it cannot change instead of inventing a mechanism")
	add(KindSafety, "ttl_unsupported_platform",
		"the TTL manager's write path only exists on Windows",
		"inspection still works and reports the current values; changes are refused rather than attempted with an unsupported mechanism")
	add(KindSafety, "ttl_permission_denied",
		"the change needs administrator rights and this process does not have them",
		"start the operation with elevation; the tray and the Control Center request it for that operation only. Nothing was changed")
	add(KindSafety, "ttl_read_failed",
		"the value in place before the change could not be read, so the change was not attempted",
		"without the original value there is no honest way to put it back. Fix the read failure first (the details name the setting) and try again")
	add(KindError, "ttl_write_failed",
		"the platform rejected the write",
		"the details carry the platform's own error. The original value is unchanged unless the detail says otherwise")
	add(KindError, "ttl_verify_failed",
		"the write ran but the value read back did not match, so it is reported as unconfirmed rather than as success",
		"treat the setting as unknown; the history and the captured originals still allow a restore. This usually means something else on the system is managing the same value")
	add(KindError, "ttl_rollback_incomplete",
		"a change failed and the automatic rollback could not put every value back",
		"the outcome lists exactly which settings are still changed. Restore from the captured originals, or set the values by hand using the originals shown in TTL > Captured originals")
	add(KindError, "ttl_already_at_value",
		"the requested value is already in place",
		"nothing to do; this is reported as a change that was not needed rather than as a failure")
	add(KindError, "ttl_no_captured_originals",
		"there is nothing to restore because no original values have been captured yet",
		"capture happens automatically before the first change to a setting; this message means no change has been made yet")
	add(KindError, "ttl_config_invalid",
		"the stored TTL configuration failed validation",
		"open TTL > Configuration and fix the named fields; the defaults are shown meanwhile and no system setting was touched")
	add(KindError, "ttl_config_unreadable",
		"the stored TTL configuration could not be read and was quarantined rather than deleted",
		"the previous file is kept beside the new one with a .corrupt- suffix; re-save the configuration from the TTL section")
	add(KindSafety, "ttl_busy",
		"another change is in progress, or a previous run left its lock behind",
		"wait for it to finish. A stale lock from a crashed process is reclaimed automatically; the details say whether that happened")
	add(KindError, "ttl_timeout",
		"the operation did not finish inside its time budget",
		"check the history for a partially applied change; a lock left by a crashed process is reclaimed automatically on the next attempt")
	add(KindError, "ttl_cancelled",
		"the operation was cancelled before it began or while it was in progress",
		"nothing to do; re-run when you are ready")
	add(KindError, "ttl_error",
		"the TTL manager returned an error that has no more specific code",
		"the message carries the platform's own text; include it in an exported report when asking for help")
	add(KindEvent, "ttl_captured",
		"the value in place was recorded before a change, so a restore can put it back exactly",
		"")
	add(KindEvent, "ttl_supported",
		"the platform probe found a mechanism for these settings",
		"")

	// --- diagnostics ---------------------------------------------------------------------------

	add(KindError, "diag_tool_missing",
		"a command the check needs is not installed or not on the search path",
		"the evidence names the command. On Windows the networking checks use PowerShell's NetTCPIP cmdlets; make sure they are available, or run the check on a machine that has them")
	add(KindError, "diag_cmd_failed",
		"the command ran and reported failure",
		"the evidence keeps the command, its exit code and its output; the check's summary says what that failure does and does not establish")
	add(KindError, "diag_parse_failed",
		"a command produced output this build could not parse",
		"this is a defect in the parser, not in the machine; the raw output is kept in the evidence so it can be reported. Other checks still ran")
	add(KindError, "diag_cmd_unavailable",
		"the platform cannot run this command at all",
		"the check reports what it would have established instead of pretending it ran")
	add(KindError, "diag_check_panic",
		"a check panicked and was contained, so it produced no result",
		"the stack trace is in the log. One contained check never stops the others; report the exported diagnostics with this code")
	add(KindError, "diag_inventory_failed",
		"the adapter inventory could not be read for this check",
		"the inventory error is carried in the evidence; run the adapter checks first, they usually name the cause")
	add(KindError, "diag_dns_timeout",
		"the DNS lookup did not answer within its budget",
		"try a second server; a single unresponsive resolver does not prove DNS is broken, and the check says which server it asked")
	add(KindError, "diag_dns_error",
		"the resolver answered with an error",
		"the name itself may not exist; the check distinguishes a resolvable-name problem from a resolver problem in its summary")
	add(KindError, "diag_dns_reserved_answer",
		"the resolver answered with an address reserved for documentation or internal use",
		"this is usually a captive portal or a filtering resolver answering in place of the real record; open a browser or ask the network's operator")
	add(KindError, "diag_dns_server_unresponsive",
		"a configured DNS server did not answer a direct query",
		"the machine may still resolve through another server; the check tests each configured server separately so the failing one is visible")
	add(KindError, "diag_dns_unconfigured",
		"no adapter reported a configured DNS server",
		"resolution can still work through a system-wide or fallback configuration; the check states that it cannot establish otherwise")
	add(KindError, "diag_metric_unavailable",
		"the interface metric could not be read on this platform",
		"the route table still shows the metrics; on platforms that do not expose the setting, the check says so instead of showing a zero")
	add(KindError, "diag_no_route",
		"no route to the destination exists",
		"this is a routing problem, not a connectivity problem: the packet never left the machine. Compare the default routes in the Routing section")
	add(KindError, "diag_endpoint_unresolved",
		"the check's own test endpoint could not be resolved",
		"the endpoint's name is fixed and public; if it will not resolve, that is itself a DNS finding and the check reports it as one")
	add(KindError, "diag_endpoint_invalid",
		"a configured test endpoint is not a usable host name or address",
		"fix the endpoint in Settings > Diagnostics; the default is a well-known public name")
	add(KindError, "diag_tcp_timeout",
		"the TCP connection attempt got no answer before its deadline",
		"a silent drop rather than a refusal. Firewalls and filtering middleboxes look exactly like this; the gateway and DNS checks say whether the path works at all")
	add(KindError, "diag_tcp_refused",
		"the destination answered and refused the connection",
		"the path works: a reset or refusal is a reply. The port or service is the likely cause, not the network")
	add(KindError, "diag_tcp_error",
		"the TCP connection attempt failed for a reason other than a timeout or a refusal",
		"the evidence carries the socket error verbatim; it usually names the adapter or route involved")
	add(KindError, "diag_udp_no_reply",
		"the UDP probe got no reply",
		"UDP has no handshake, so silence proves very little. The check only claims a reply where the destination is one that answers by design, such as NTP")
	add(KindError, "diag_udp_unexpected_reply",
		"the UDP probe got a reply that did not match the request",
		"a reply did arrive, which is what the check needed to establish; the mismatch is recorded rather than dropped")
	add(KindError, "diag_counters_unavailable",
		"the per-adapter byte counters could not be read",
		"the platform may not expose them to this process; without counters the dashboard refuses to show a rate rather than showing zero")
	add(KindError, "diag_engine_cli_unavailable",
		"the net-merge command line could not be run for this check",
		"the check reports the path it tried. This usually means the binary was moved while running; restart the application")
	add(KindError, "diag_ttl_inspect_failed",
		"the TTL/hop-limit check could not read the settings",
		"the TTL section reports the same failure with more detail; on a host with no supported mechanism this is expected and the check says so")
	add(KindError, "diag_ttl_read_partial",
		"some TTL/hop-limit settings were read and some were not",
		"the check lists which ones; a partial read is reported as partial rather than as a clean result")

	// --- engine correlation ----------------------------------------------------------------------

	add(KindError, "engine_stale_adapter",
		"a route names an interface that no longer exists, usually left behind by a phone or adapter removed while the engine was running",
		"run net-merge cleanup to remove the engine's own leftover routes; operating-system routes clear by themselves when the adapter returns or after a restart")
	add(KindEvent, "engine_start",
		"the engine was asked to start",
		"")
	add(KindEvent, "engine_uses",
		"the engine's own status file says which adapters it is using",
		"")

	// --- ports / instance -----------------------------------------------------------------------

	add(KindError, "port_in_use",
		"the port the proxy needs is already taken by another process",
		"the check names the holder when the platform allows it; close that program or configure a different port")
	add(KindError, "tun_driver_missing",
		"the virtual network driver the bonding engine needs is not present or not loadable",
		"on Windows, run the repository's scripts/fetch-wintun.ps1 once to place the driver, then start the engine again; the driver is required only by the engine, not by the dashboard")
}
