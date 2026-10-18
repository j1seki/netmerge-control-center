# NetMerge Control Center

NetMerge bonds the internet connections a Windows machine already has - wired Ethernet, Wi-Fi, a
phone over USB tethering - into one logical path, and adds three things around the engine: a live
dashboard, a diagnostics centre, and an IPv4 TTL / IPv6 hop-limit manager. Everything shares one
state directory and one control path, so the dashboard, the tray and the command line cannot
disagree about what is on.

The bonding engine is [net-merge](https://github.com/rohit267/net-merge) as published: the
Control Center drives it and reports on it, and does not replace any of it. The TTL manager is
new code for Windows (the concept - an opt-in, captured-first, restorable hop-limit change -
follows [hotspot-ttl](https://github.com/pratikbin/hotspot-ttl), whose actual mechanisms are
macOS-only and were not reused).

Read along with:

- [ERROR-CODES.md](ERROR-CODES.md) - every error and event code with a plain-language meaning.
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - organised by symptom.
- [THIRD-PARTY.md](THIRD-PARTY.md) - dependency licences.

## Platform support

| Capability | Windows 11 | Windows 10 | Linux / macOS |
|---|---|---|---|
| Bonding engine (net-merge) | yes | yes (best effort) | yes, as the upstream project shipped it |
| Control Center dashboard, diagnostics, export | yes | yes | yes - used for development and testing, so it is genuinely cross-platform |
| TTL / hop-limit manager: inspect | yes | yes | reports values, marks changes unsupported |
| TTL / hop-limit manager: write | yes (needs administrator) | yes (needs administrator) | refused honestly, nothing attempted |

The TTL manager's value comes from a per-interface mechanism that only Windows has. On other
platforms it reports what it can read and refuses to write, rather than inventing a mechanism.

## Quick start (Windows)

1. Get the release binary (`net-merge.exe`) or build it - see the release notes that ship with
   the build for exact instructions.
2. Run the tray as usual (`net-merge tray`) for every-day on/off control, or start the Control
   Center:

   ```
   net-merge dashboard
   ```

   It prints a `http://127.0.0.1:<port>/?token=...` address and opens it in your browser. The
   token is per-run; restarting the dashboard prints a new one.

3. Turn the engine on from the Overview section. That requests administrator rights for the
   engine only, exactly as the tray does.
4. Run the Diagnostics once. It is read-only and safe to run at any time.
5. If you want the TTL / hop-limit manager, use its section: inspect first, configure, preview,
   then apply. All four steps are separate and each says what it did.

Nothing here needs the machine to be online beyond your own connections; there is no account, no
telemetry and no upload.

## The command line

```
net-merge dashboard [-listen addr] [-port n] [-interval d] [-open] [-no-open]
net-merge diag [-only ids] [-category cats] [-json] [-export DIR] [-timeout d]
net-merge ttl inspect [-json]
net-merge ttl config [-enabled] [-v4 n] [-v6 n] [-policy p] [-include a,b] [-exclude a,b]
net-merge ttl preview [-json]
net-merge ttl apply -confirm [-json]
net-merge ttl restore [-confirm] [-only ids] [-json]
net-merge ttl history [-json]
```

`diag` and `ttl` are the scriptable mirrors of the dashboard: same state, same manager, same
gates. A `ttl apply` from the command line without `-confirm` is refused, exactly as the
dashboard refuses an apply without confirmation.

The original engine commands (`tray`, `run`, `on`, `off`, `status`, `list`, `cleanup`, ...) are
unchanged and still work; see `net-merge` with no arguments.

## The dashboard

It is a local web page served by the same binary (`net/http` and an embedded asset bundle, no
extra runtime dependencies).

### Why it is safe to leave running

- It binds to loopback only; `New` refuses any other address, and requests must arrive over
  loopback.
- Every request needs the per-run token. Opening the printed `?token=` address exchanges the
  token for an `HttpOnly`, `SameSite=Strict` cookie and redirects to a clean URL, so the token
  does not stay in the address bar or the history.
- State-changing requests must carry the token in a header, never a cookie, so a page from
  another site cannot drive the dashboard even if a browser sends the cookie along.
- The `Host` header must be a loopback name, which defends against DNS rebinding.
- Responses are marked `no-store`.

It has no listening port on your network, no external fetch path, and no upload code.

### The seven sections

1. **Overview** - is the engine on, which adapters are in use, what the current rates are, and
   the headline diagnostics. Rates appear only when two comparable counter readings exist; "no
   rate yet" is not zero.
2. **Connections** - every adapter with its state and, when excluded, the specific reason.
   Assigned connections come from the engine's own status file, so a dash means "the engine is
   not running", never "zero".
3. **Routing and profile** - default routes and their metrics, the leftover-route check, and the
   active quality profile. The profile is edited in Settings: changing it saves the choice and
   reports what the engine will get; the running engine is not restarted behind your back.
4. **TTL / Hop limit** - the manager described below.
5. **Diagnostics** - every check with what it establishes and what it cannot, plus per-adapter
   probes, DNS, MTU, counters and net-merge-specific correlation. Runs are background jobs.
6. **Logs** - the structured event log (level, code, message, detail) with search and an
   incremental cursor. Codes carry their explanation from the shared registry.
7. **Settings** - the settings file, editable with validation, plus the diagnostics endpoints
   and privacy-redaction preferences. A file written by a different build is flagged as stale
   rather than silently rewritten.

Long operations (diagnostics runs, exports) are background jobs: they return immediately, report
progress, can be cancelled, and are bounded in number. A cancelled diagnostics run keeps what it
had already established.

### Engine control

On/off writes the same marker files the tray writes, and the status shown comes from the engine's
own status file. There is deliberately no second control path. If the status file is older than
three seconds it is reported as not running - a stale file is never read as "on".

## Quality profiles

Profiles set the engine's include/exclude lists, weights and auto-weighting. They do not change
anything by themselves: switching a profile saves it and reports what the engine will get; the
running engine is not restarted behind your back.

| Profile | What it does |
|---|---|
| Maximum Throughput | Uses every eligible path and lets the engine weight adapters by measured throughput. Balancing is per connection: separate connections spread across links, one TCP connection still uses one link. |
| Gaming / Low Latency | Favours the healthy lower-latency path for interactive traffic. Established connections are not broken; pin the weight to the link you want preferred. |
| Fiber Preferred | Prefers the wired home fiber for ordinary traffic; other adapters stay excluded unless included. |
| Connection Reliability | Watches link health and reports transitions. The engine already removes an adapter from new assignments when its probes fail and restores it after recovery; auto-weighting lets a degraded link contribute less. |
| Custom | Your own include list, exclusions and weights - nothing is assumed. |

## TTL / hop limit manager

**Opt-in, always.** Nothing in this manager runs unless you configure and confirm it. Saving a
configuration never touches a system setting, and the `Enabled` flag is a record of intent - every
write still needs an explicit apply.

### What it manages, and what it deliberately does not

It manages **two packet-header values**:

- the IPv4 time-to-live, system-wide default and per adapter;
- the IPv6 hop limit, system-wide default and per adapter.

It reports but never touches the look-alikes: DNS record TTL, traceroute hop counts, per-route
values. They appear under "not these" in `ttl inspect` so they are not mistaken for the packet
header values. It never enables or disables IPv6, never changes routes, and never changes DNS.

### How a change happens

1. **Capture first.** The value in place is read and stored before any write. If it cannot be
   read, the change is not attempted - there is no honest way back without it. The first capture
   wins and is never overwritten by later changes, so "restore" always means the state before
   this application ever touched the setting.
2. **Write.** On Windows this is `Set-NetIPv4Protocol` / `Set-NetIPv6Protocol` (system default)
   and `Set-NetIPInterface` (per adapter), with `Get-*` for every read.
3. **Verify by reading back.** A write that cannot be confirmed is reported as unverified. It is
   never reported as success.
4. **On failure, roll back.** The changes made in this operation are reverted in reverse order.
   If any revert fails, the outcome is marked rollback-incomplete and lists exactly which
   settings are still changed - it is never hidden.
5. **Record.** Every attempt and outcome lands in an append-only history with the reason you gave.

Two guards are worth knowing about, because they are the reason a change can be refused:

- a write is refused when the pre-change value could not be captured;
- a restore falls back to an earlier capture when the most recent one is missing.

### Restoring

`net-merge ttl restore` (or the dashboard's Restore) writes the captured originals back. The
originals live in `ttl-originals.json` and are shown in the interface with when they were taken.
Restoring is also a change: it captures first (so the current value is not lost), verifies, and
reports per setting. It needs the same confirmation as an apply.

### Single-operation guarantee

One change runs at a time, held by a lock file. A lock left by a crashed process is detected
(its owner is gone) and reclaimed; a live one is respected and reported as busy. A corrupt
configuration file is quarantined, not deleted, and the defaults are offered instead.

## Diagnostics

Every check is an individually executable probe that runs real commands - on Windows the real
networking cmdlets (`Get-NetAdapter`, `Get-NetIPConfiguration`, `Get-NetRoute`, `Get-NetIPInterface`,
`Get-DnsClientServerAddress`, `Resolve-DnsName`, `Test-NetConnection`), plus `tracert`, the local
socket stack and the engine's own status. Nothing is simulated and nothing is read from a canned
answer.

Each result says three things:

- **what it establishes** - the fact the evidence supports;
- **what it cannot establish** - the limit of that evidence, in the same voice;
- **a status** - pass, warn, fail, skipped, error or info. Skipped checks have proved nothing by
  definition, and the run summary counts them separately.

The checks write down the exact command and its output where a command was run, so a result can be
reproduced by hand. Checks that only apply to one platform say so and skip rather than fail
(`adapters.driver`, `dns.cache` and the firewall/AV checks are Windows-only).

## Export, and what is redacted

The export produces a timestamped text file and JSON file. The JSON is the machine-readable
version of the same run - suitable for attaching to an issue or feeding to a tool that helps you
read it. **You see every replacement before you share anything**: the page lists each placeholder
and the value it stands for, on screen only.

Redacted: public IPv4/IPv6 addresses, MAC addresses (the vendor half is kept so adapters can
still be told apart), serial numbers and hardware ids, user names and file paths, account and
host names, and credential-looking values. Private addresses are kept - they do not identify you
and are usually needed to understand a routing problem.

There is no automatic upload and no telemetry. The export is written where you asked for it.

## Files this application keeps

All under `%LocalAppData%\net-merge` on Windows (see [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for
other platforms):

| File | What it is |
|---|---|
| `control-center.json` | your settings: listening address, logging, diagnostics endpoints, privacy preferences, quality profiles. Versioned; a file from a different build is flagged, not silently rewritten. |
| `ttl/ttl-config.json` | the TTL manager's opt-in configuration |
| `ttl/ttl-originals.json` | captured pre-change values; the basis of every restore |
| `ttl/ttl-history.jsonl` | append-only history of every attempt and outcome |
| `ttl/backups/` | quarantined corrupt files |
| `logs/` | rotating text log; the same events appear in the dashboard's Logs section |
| engine state | the engine's own status and marker files, unchanged from net-merge |

## Removing it

- Stop the engine (`net-merge off`), then stop the dashboard (Ctrl+C) and the tray.
- If you changed TTL or hop-limit values, run `net-merge ttl restore` first: it puts the
  captured originals back. The captured values are in `ttl-originals.json` if you prefer to check
  by hand.
- Uninstall the tray's sign-in entry with `net-merge autostart off`, and remove any leftover
  engine routes with `net-merge cleanup`.
- Delete the installation directory. Delete `%LocalAppData%\net-merge` if you also want the
  settings, history and captured originals gone - they are plain files and are not registered
  anywhere else.

Nothing is installed as a service, and no registry keys are created by this application beyond
the ones Windows makes for any program the user runs.
