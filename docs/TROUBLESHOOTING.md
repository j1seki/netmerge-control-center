# Troubleshooting

Written for the person at the machine. Every entry says what the message means, what it does not
mean, and what to try next. Error and event codes are explained in
[ERROR-CODES.md](ERROR-CODES.md); this file is organised by symptom instead of by code.

## Where things live

| What | Where |
|---|---|
| Engine state and settings | `%LocalAppData%\net-merge` on Windows, `~/.cache/net-merge` on Linux, `/var/run/net-merge` on macOS when the tray runs as root |
| Settings file | `control-center.json` in that directory; versions and defaults are documented in [CONTROL-CENTER.md](CONTROL-CENTER.md) |
| TTL manager's files | `ttl/` under that directory: `ttl-config.json`, `ttl-originals.json`, `ttl-history.jsonl`, `backups/`, `ttl-operation.lock` |
| Logs | `logs/` under that directory; the dashboard's Logs section reads the same events from memory |
| Exports | where you asked for them (dashboard: the output directory shown in the Diagnostics section; CLI: `-export DIR`) |

The dashboard's Diagnostics section prints the exact paths for this machine, so prefer its answer
over this table if they disagree.

## First move for anything unclear

1. Open the dashboard's **Diagnostics** section and run everything.
2. Use **Export** and read the generated text file. It contains the same findings, with the
   addresses, MACs, host names and paths redacted so you can paste it somewhere.
3. The export is written locally, in full, before anything else happens to it; nothing is uploaded
   by this application, ever.

## The dashboard

### The page will not open

- The dashboard prints its address when it starts, including a one-time token. Open **that**
  address; opening `127.0.0.1:port` without the token gets a 401 by design.
- If the browser shows a blank error page, the process is not running any more. The command that
  started it prints why on exit; check the console it was started from.
- The dashboard listens on loopback only, by construction. "Not reachable from another device" is
  not a fault: it is the design. Start it on the machine you want to look at it from.

### "The access token ..." (dashboard_unauthorized / dashboard_bad_token)

The token is per-run. Restarting the dashboard invalidates the old link; use the new one it
prints. After the first request with `?token=` the token is stored in a cookie for the session, so
bookmarking the bare address works only while that run lasts.

### An action button was refused (dashboard_confirm_required)

The dashboard never writes a system setting from a request that did not ask for it knowingly.
In the TTL section, use **Preview** first, read what would change, then **Apply** with the
confirmation. This gate is deliberate and cannot be turned off.

### "This settings file was written by a different build" (stale)

The file on disk records a format version this build does not match. Nothing is broken and your
values still load; saving rewrites the file in the current format. If the file was written by a
*newer* build, copy anything you care about from it before saving, because saving drops fields
this build does not understand.

### "The settings file could not be read"

The defaults are being used for this run and the file on disk has not been changed. The message
names the problem (a missing brace, an out-of-range value, an unreadable file). Fix the file with
a text editor or reset it by deleting it, then reload the page. Deleting `control-center.json`
loses only your preferences, never a captured TTL original and never a change history.

### A job says it is still running

Diagnostics runs and exports are background jobs so the page stays responsive. A diagnostics run
is bounded by the checks' own timeouts; the slowest checks are the traceroute and MTU ladder. You
can cancel from the page; a cancelled run keeps whatever it had already established and shows the
partial result rather than pretending it completed.

### Connections says a link is "not answering" (or "not tested")

First, which one it says - they mean different things:

- **"not answering"** - the probe opened a connection from that adapter to the test endpoint and
  nothing came back within the timeout. Check, in this order: the adapter has a default gateway
  and an address (both are shown in the same card); the tether's phone screen is not asleep
  (some phones stop USB tethering data when they idle); the cable is seated; DNS is irrelevant
  here, because the default endpoint is an address. If a browser works but this fails, the
  network in front of you may be dropping the endpoint - change the diagnostics endpoint in
  Settings to something you trust.
- **"not tested"** - nothing was probed, and that is not a claim of failure. Either the adapter
  is not a traffic candidate (excluded, disconnected - the card gives the reason), the probe is
  switched off (`dashboard.healthIntervalMs` is negative), or no round has run yet.
- **No loss percentage** - loss is only shown once at least two attempts are in the window: one
  sample is not a rate.

The probe is a single TCP connection, once per adapter per round. It answers "can this adapter
reach the internet at all, and how steadily", not "is the bonding engine using it, and how
fast". The engine's own per-adapter state (shown in Overview/status, `State`/`State6`) stays
authoritative for what carries traffic; when the two disagree, the engine is deciding where
traffic goes and the probe is reporting what that adapter can still do. A change here is also an
event (`link.reachability`) in the Logs section, with the adapter and the reason.

## The bonding engine

### The engine is "on" but only one adapter carries traffic

This is normal for a single TCP connection unless the application uses multiple connections: most
TCP flows are pinned to one path, which is what keeps them working. Look at two things instead:

- **Connections**: are several adapters eligible and carrying traffic? Bytes moving on more than
  one adapter is the evidence to look for.
- **Diagnostics**: the per-adapter checks name each adapter's state, and the counters check shows
  whether bytes moved on each during the sample window. "No rate yet" means the counters have not
  provided two comparable readings since the process started - it is not zero.

### An adapter is not being used

The Connections section lists every adapter with a state and, for anything excluded, the specific
reason. Read the reason rather than guessing:

| Reason | Meaning |
|---|---|
| not eligible / excluded (virtual) | The adapter is a virtual device (VPN, bridge, docker, tailscale). Bonding it would bond a tunnel, not a link. |
| excluded (disconnected) | The OS reports no carrier or no address. |
| excluded by profile | The active quality profile's include/exclude list excludes it. |
| excluded by user | The `-exclude` flag or the engine's own filter. |
| assigned connections: — | The engine is not running, so there is no assignment to show. `—` means unknown, not zero. |

### The phone's USB tether does not appear

- On the phone, USB tethering must be switched on *after* the USB connection is made; some phones
  reset the setting when the cable is re-plugged.
- On Windows the adapter appears as a new network adapter ("Remote NDIS ..."). If it appears
  without an address, it is reported as disconnected and will not be used.
- When it disappears while the engine is running, a route naming it can be left behind. The
  Diagnostics section reports those as `engine_stale_adapter`; `net-merge cleanup` removes the
  engine's own leftovers. Operating-system routes clear themselves.

### The engine will not start

- **tun_driver_missing**: the virtual network driver is not present. On Windows, run
  `scripts/fetch-wintun.ps1` once from the repository, then start again. The dashboard and the
  diagnostics do not need the driver.
- **Elevation**: system-wide mode needs administrator rights. The tray and the Control Center ask
  for elevation for that operation only; if the request is refused, the engine stays off and the
  message says so. Nothing is started halfway.
- **port_in_use**: the local proxy port is taken. The check names the holder when the platform
  allows it; close that program or change the port.
- If the window closes immediately, run `net-merge run` from a console to keep the output.

### "Engine on" disagrees between the tray and the dashboard

They cannot disagree by construction: both write and read the same marker and status files. What
you are seeing is the status file going stale - the engine writes it every second, and a file
older than three seconds is reported as not running. A stopped engine therefore always looks
"off", which is the safe reading.

## TTL / hop limit

### "This host has no supported mechanism for these values"

Per-interface TTL and IPv6 hop limit are Windows settings (`Set-NetIPv4Protocol`,
`Set-NetIPv6Protocol`, `Set-NetIPInterface`). On other platforms the manager reports what it can
read and marks the rest not writable. Nothing was changed, and this is not an error.

### A write was refused

| Code | What it means |
|---|---|
| `ttl_permission_denied` | Administrator rights are missing. Start the operation with elevation; it is requested per operation. |
| `ttl_read_failed` | The value in place could not be read, so the change was not attempted. Without the original there is no honest way back. The details name the setting. |
| `ttl_write_failed` | The platform rejected the write; its own error is in the details. The original value is unchanged unless the details say otherwise. |
| `ttl_verify_failed` | The write ran but the value read back did not match, so it is reported as unconfirmed rather than as success. Something else may be managing the same value. |
| `ttl_busy` | Another change is running, or a crashed run left its lock. Stale locks are reclaimed automatically; the details say what happened. |
| `ttl_rollback_incomplete` | A change failed partway and the automatic rollback could not put everything back. The outcome lists exactly which settings are still changed. |

### How to put things back

**Restore** (dashboard TTL section, or `net-merge ttl restore`) writes back the values captured
before the first change. The captured originals live in `ttl/ttl-originals.json`, are never
overwritten by later changes, and are shown in the interface with the time they were taken. If a
restore is ever refused, the originals file is still there: the values can be set by hand from
what it shows.

### A setting says "not configured (the platform default applies)"

That is the honest reading of an absent registry value, not zero and not 128. Windows applies its
built-in default (128) to packets when nothing is configured. The manager will not write a value
to "make it show up".

## Diagnostics

### A check says skipped, or not run

- **skipped**: the check cannot apply on this platform or configuration - for example the Windows
  firewall check on Linux. The summary says why.
- **not run**: the check is disabled in Settings, or it was not selected for this run.
- Neither is a pass. A skipped check has proved nothing.

### "It says the connection failed but my browser works"

Read the check's *establishes* / *cannot establish* lines before the summary. The most common
false alarms:

- **diag_tcp_timeout**: a silent drop. Filtering middleboxes and captive portals look exactly like
  this. Try the same check to the endpoint your browser actually uses.
- **diag_dns_reserved_answer**: a resolver answered with a documentation-range address - usually a
  captive portal answering in place of the real record. Open a browser and log in to the portal.
- **diag_udp_no_reply**: UDP has no handshake, so silence proves very little. Only destinations
  that answer by design (such as NTP servers) claim anything when they reply.
- **counters idle**: an idle host looks exactly like a broken one. Generate traffic (a large
  download) and run the counters check again.

### A check panicked (diag_check_panic)

One contained check never stops the others, and its stack trace is in the log. The other results
from the same run are still valid. Please include the exported report when reporting this.

## Export

### What exactly gets redacted

The export shows you every value it replaced before you share it: a table of placeholders
(`[ip#1]`, `[mac#2]`, `[user#1]`, ...) beside the values they stand for, on screen only. Written
files contain the placeholders, not the values. Redacted: public addresses, MAC addresses (the
vendor half is kept so an adapter can still be told apart), serial numbers, user names and paths,
account and host names, and anything that looks like a credential. Private addresses are kept
because they do not identify you and they are usually needed to understand a routing problem.

### Nothing is uploaded

There is no upload path in this application and no telemetry. The export is written to disk where
you asked for it and that is the end of it.

## Windows notes

- The diagnostics run PowerShell's real networking cmdlets. If a cmdlet is unavailable on the
  machine, the affected check reports `diag_tool_missing` with the command it tried rather than
  failing the whole run.
- Elevation is requested per operation (engine start, TTL write). The dashboard and diagnostics
  run unelevated, and the diagnostics report says which checks needed more.
- The first time the Wintun driver is placed, Windows may show a driver-install prompt; that is
  the signed driver package from the repository's script, not a download performed by this
  application at runtime.
