# NetMerge Control Center — Implementation Report

This report covers what was built, how it was verified, and — with equal weight — what was
**not** verifiable on the machine available for this work. It distinguishes five claims throughout:

| Tag | Meaning |
|---|---|
| **Implemented** | the code exists and is wired into the running application |
| **Build verified** | it compiles for the target (`GOOS=windows`) and the binary launches |
| **Automated-test verified** | a test exercises the behaviour and passes in `go test` |
| **Physically tested** | run against real hardware / a real OS on this machine, with observed output |
| **Not verified** | could not be exercised here; the exact blocker is named, and a manual procedure is given |

**The single most important sentence in this report:** the machine available for this work runs
**Linux (CachyOS, x86_64)**. Windows-native behaviour — PowerShell networking cmdlets, Wintun, UAC
elevation, the Inno Setup installer, per-interface hop-limit writes — **could not be executed here**.
Everything Windows-specific is *implemented*, *build-verified* (the `windows/amd64` binary compiles
and, under `wine`, launches and enumerates the host's real adapters) and *automated-test verified*
against recorded cmdlet output and injected fakes. It is **not** "physically tested on Windows."
Where a real USB-tethered Android phone *was* physically available, it was attached to this Linux
host and tested with real byte-counter evidence; those results are in §7 and §8 and are labelled
**physically tested (Linux)**.

Nothing in this report claims a test that was not run. No Windows success is asserted on the basis
that the code compiles.

---

## 1. What was implemented

A single Windows-first application, **NetMerge Control Center**, built as an extension of the
`net-merge` repository (branch `netmerge-control-center`, off `main` @ `6093879`; `main` is
untouched). It keeps net-merge's bonding engine as the authoritative connection-distribution engine
and adds, around it:

- **A Windows-native TTL / hop-limit manager** (`internal/ttlmgr`). Distinguishes IPv4 packet TTL,
  IPv6 hop limit, DNS-record TTL, traceroute hop count, and per-route / per-interface / system
  scope. Opt-in only; captures originals before the first write; verifies each write by reading it
  back; rolls back from the captured values (never an assumed default); keeps an append-only audit
  history; persists a versioned config; recovers from partial transactions; reports unsupported
  per-interface settings honestly. It never changes anything merely because an adapter appeared,
  and implements **no** carrier-evasion/stealth behaviour.
- **A shared network inventory** (`internal/inventory`) that collects live adapter, address,
  gateway, DNS, DHCP, metric, route and byte-counter data on Windows (PowerShell `NetTCPIP`
  cmdlets with an IP-Helper-API fallback) and Linux (netlink), and evaluates eligibility with a
  specific exclusion reason per adapter.
- **A diagnostics centre** (`internal/diag`) — 30+ individually runnable checks plus a combined
  procedure — using real Windows cmdlets/tools (`Get-NetAdapter`, `Get-NetIPConfiguration`,
  `Get-NetRoute`, `Get-NetIPInterface`, `Get-DnsClientServerAddress`, `Resolve-DnsName`,
  `Test-NetConnection`, `tracert`, ping, the net-merge CLI) and validating **what each result
  establishes**, not merely the exit code. Per-adapter connectivity probes are pinned to each
  adapter's own interface.
- **An AI-ready redacted export** (`internal/diagreport`): timestamped text + JSON, redacting public
  IPs, MACs, serials, personal paths, phone identifiers and credentials; human-inspectable before
  sharing; no upload, no telemetry.
- **A local dashboard** (`internal/dashboard`) — seven sections (Overview, Connections, Routing,
  TTL/Hop Limit, Diagnostics, Logs, Settings) served by the same binary on loopback with a per-run
  access token. Long operations run as background jobs so the UI never freezes.
- **Quality profiles** (Maximum Throughput, Gaming/Low Latency, Fiber Preferred, Connection
  Reliability, Custom) applied at the next engine start, plus a per-link reachability monitor
  (`internal/monitor`) that logs real state transitions.
- **Observability**: a 76-code error registry with plain-language explanations
  (`internal/errcodes`), rotating logs with an in-memory ring the dashboard reads, stale-settings
  detection, config backups, dry-run/preview, and a confirmation gate before any system write.

**Explicitly not implemented** (by requirement): stealth/carrier-evasion, disabling
firewall/security/IPv6, hidden services, silent route/DNS rewrites, auto-TTL changes on adapter
appearance, unreviewed third-party downloads, bundled secrets, fake success messages.

---

## 2. Final application architecture

One Go binary (`net-merge`) exposes every surface. There is no second networking service and no
large runtime.

```
cmd/net-merge/            CLI: tray, run, dashboard, diag, ttl, list, status, on/off/quit, …
  controlcenter.go        one construction path: collector + ttlmgr + diag registry + log ring
internal/
  engine/   (unchanged)   the authoritative bonding engine: scheduler, balancer, probes, SOCKS
  nics/                   adapter discovery, counters, egress pinning (ForceEgress), classification
  tun/      (unchanged)   TUN/Wintun front-end
  tray/     (unchanged)   notification-area icon
  platform/ (unchanged)   privileges, single-instance, autostart
  inventory/              shared adapter model + eligibility evaluation (Windows/Linux)
  ttlmgr/                 Windows TTL/hop-limit manager (store, manager, PS backend)
  diag/                   diagnostic checks + pinned probes + host-command table
  diagreport/             redaction policy + report builder + hypothesis rules
  dashboard/              HTTP server (loopback+token), REST API, job store, embedded web assets
  monitor/                per-link reachability probe (TCP connect per adapter per round)
  appcfg/                 versioned control-center.json (profiles, engine prefs, health interval)
  execx/                  one shared windowless subprocess runner
  errcodes/               the 76-code registry + docgen
  logx/                   rotating logs + in-memory ring
```

Data flow: `inventory.Collector` → `dashboard` snapshot loop → `app.js` (DOM built with
`createElement`, no `innerHTML`). The engine is controlled **only** via marker files
(`state.SendMarker`) — the dashboard never opens a second control path. TTL writes are gated:
without `-confirm`/the dashboard confirmation the request is refused
(`dashboard_confirm_required`). The privacy→redaction mapping lives in one place
(`diagreport.PolicyFromPrivacy`) so the CLI and dashboard cannot drift.

---

## 3. Existing components reused vs changed

**Reused as-is (the engine, preserved):** `internal/engine`, `internal/tun`, `internal/tray`,
`internal/platform`, and the bulk of `internal/nics`. The core bonding engine was **not** rewritten;
net-merge remains the authoritative connection-distribution implementation.

**Changed (narrow, each with a test):**
- `internal/nics/nics.go`, `info_windows.go` — added `-exclude` support to discovery
  (`DiscoverNicsDetailed(include, exclude, weights)`; exclusion wins over inclusion) and shared the
  virtual-adapter classification so inventory and engine cannot disagree.
- `internal/logx/logx.go` — added the in-memory ring the dashboard's Logs section reads.
- `cmd/net-merge/main.go` — wired `dashboard`/`diag`/`ttl` subcommands, `-exclude`/`-no-profile`
  flags, and `resolveProfile`.
- `cmd/net-merge/tray.go` — one line (profile resolution at start).
- `CHANGELOG.md`, `README.md`, `THIRD-PARTY-NOTICES.md`, `docs/DEVELOPING.md` — release notes,
  doc links, hotspot-ttl attribution, packaging pointer.

**Integrated by concept, not code:** `hotspot-ttl` (macOS/Swift) contributed only its *safety
model* — opt-in, capture-original, restore-original, nothing silent. No macOS mechanism is reused;
the Windows implementation uses documented `Get/Set-NetIPv4Protocol`,
`Get/Set-NetIPv6Protocol -DefaultHopLimit`, `Get/Set-NetIPInterface -CurrentHopLimit`. net-merge's
MIT licence is untouched; hotspot-ttl is attributed in the shipped notices.

---

## 4. Source files added/modified

Branch `netmerge-control-center` vs `main`: **97 files changed, +27,836 / −47.** 87 files added,
9 modified, plus new docs. By package (added lines):

| Package | Added | Purpose |
|---|---|---|
| `internal/diag` | +5,971 | diagnostics centre, pinned probes, host commands |
| `internal/dashboard` | +4,846 | HTTP server, REST API, jobs, web assets |
| `internal/ttlmgr` | +4,268 | TTL/hop-limit manager |
| `internal/inventory` | +3,877 | shared adapter model, Windows/Linux sources |
| `internal/diagreport` | +3,331 | redaction, report builder, hypotheses |
| `internal/appcfg` | +1,037 | versioned settings |
| `internal/monitor` | +812 | per-link reachability probe |
| `internal/errcodes` | +447 | 76-code registry + docgen |
| `internal/execx` | +356 | shared subprocess runner |
| `cmd/net-merge/controlcenter.go` | +775 | shared construction + CLI wiring |

Full list: `git diff --name-status main..netmerge-control-center`. `main` is untouched
(`git log main` → `6093879`).

---

## 5. Exact build commands and results

**Baseline (before any change):** `go build ./...` → exit 0; `go test ./...` → engine, nics, tray
all pass; `GOOS=windows GOARCH=amd64 go build ./...` → exit 0, real PE32+.

**Full suite after all work:**

```
gofmt -l .                 → (empty)          # clean
go build ./...             → exit 0
go vet ./...               → exit 0           # clean (fyne.io/systray noise excluded)
go test ./... -count=1 -race  → all 14 test packages ok
GOOS=windows GOARCH=amd64 go build ./...  → exit 0
```

**Windows release exes** (exact flags from `scripts/build.ps1`):

```
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.version=0.1.0" \
  -o dist/net-merge.exe ./cmd/net-merge
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w -H=windowsgui -X main.defaultCmd=tray -X main.version=0.1.0" \
  -o dist/net-merge-tray.exe ./cmd/net-merge
```

Result (via `file`): `net-merge.exe` = **PE32+ executable for MS Windows 10.00 (console), x86-64**;
`net-merge-tray.exe` = **PE32+ executable for MS Windows 10.00 (GUI), x86-64**. `-trimpath` verified:
a `strings` scan of both exes finds **0** occurrences of the build host's `/home/j1` path (module
paths like `net-merge/internal/…` are present, as expected).

**wintun.dll** (not in the repo) — downloaded and integrity-checked on this host:
`wintun-0.14.1.zip` SHA-256 = `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`,
which **matches the repo's pinned value**. Extracted `bin/amd64/wintun.dll` + `LICENSE.txt`.
The WireGuard LLC **Authenticode signature check was NOT re-verified here** (needs Windows tooling).

**Launch under wine (build-verified, not a Windows runtime):**
- `wine dist/net-merge.exe version` → `net-merge 0.1.0` (version injection works; exit 0).
- `wine dist/net-merge.exe list` → enumerated the host's **real** adapters through the full
  inventory path: 3 eligible (`enp130s0` fiber, `wlan0`, `enp128s20f0u5i1` USB-tether) with correct
  exclusion reasons (`thunderbolt0: no default gateway`, `tailscale0`/`docker0`/`br-*`: virtual).
- `wine dist/net-merge.exe _icon dist/net-merge.ico` → valid `.ico` produced.

**Packaged:** `dist/net-merge-0.1.0-portable.zip` (12 files, 10 MB): both exes, `wintun.dll` +
license, icon, `LICENSE`, `THIRD-PARTY-NOTICES.md`, `README.md`, and the four Control Center docs.
`dist/` is gitignored.

**Not built here:** the Inno Setup installer (`net-merge-setup-*.exe`). Inno Setup is Windows-only;
the official installer is produced on `windows-latest` by `.github/workflows/release.yml`. This is
the one packaging limitation, documented in `docs/RELEASING.md`.

---

## 6. Exact test commands and pass/fail counts

```
go test ./... -count=1 -race
```

**322 top-level test functions + 36 subtests = 358 test runs, 0 failed, 0 skipped**, across 14
packages (4 packages have no test files). Per package (top-level + subtests):

| Package | Tests | | Package | Tests |
|---|---|---|---|---|
| `internal/diag` | 93 | | `internal/errcodes` | 4 |
| `internal/ttlmgr` | 51 | | `cmd/net-merge` | 4 |
| `internal/diagreport` | 46 | | `internal/execx` | 7 |
| `internal/inventory` | 45 | | `internal/nics` | 7 |
| `internal/dashboard` | 31 | | `internal/monitor` | 8 |
| `internal/engine` | 21 | | `internal/logx` | 13 |
| `internal/appcfg` | 14 | | `internal/tray` | 14 |

**Race-clean:** `-race` found real data races in the diag test fakes (checks run concurrently by
design); fixed with a mutex in `fakeRunner`/`fakeProber`, and the full suite then passed under
`-race`. A **regression test** (`TestAdapterConnectBindsEveryEligibleAddress`) asserts every
per-adapter probe carries a non-zero interface index.

**Pre-existing vs new:** baseline `main` had 3 test packages (engine, nics, tray), all passing. The
other 11 test packages are new. No existing test was deleted or weakened; engine/nics/tray tests
still pass unchanged. (`GOOS=darwin` cross-build fails in `fyne.io/systray` — needs cgo — and
`GOOS=freebsd` fails for `internal/inventory`; both pre-existing, not regressions.)

---

## 7. Physical USB-tethering results (separated from simulations)

**Physically tested — real Android phone over USB tether, attached to this Linux host.**
The phone appeared as `enp128s20f0u5i1`, IPv4 `10.149.224.107/24`, gateway `10.149.224.198`,
interface index 10. The engine/dashboard/diag were run against this **real** adapter. These are
**not** simulations.

**Not verified — Windows USB-tether.** The Windows path (Wintun, `Get-NetAdapter`, per-interface
hop-limit writes, UAC elevation) could not be run: there is no Windows OS on this machine. A manual
procedure is in §13.

**Simulations (clearly labelled):** the automated tests use injected fakes (`fakeProber`,
`fakeRunner`, recorded PowerShell JSON fixtures). They are labelled simulations in the test files
and are never reported as physical-network tests.

---

## 8. Per-adapter counter evidence (physically tested, Linux)

Real byte-counter deltas measured on the live host, proving each link carries its **own** traffic in
isolation (no false aggregate-bandwidth claim — the dashboard's aggregate is the honest sum):

- **Phone isolated:** `curl --interface enp128s20f0u5i1` of 1 MB → phone RX delta **1,044,876 B**;
  fiber noise only **702 B**.
- **Fiber isolated:** 1 MB bound to fiber → fiber RX delta **1,074,001 B**; phone noise only
  **156 B**.
- **Concurrent load:** 4×256 KB connections on the phone → phone RX **1,117,591 B**.
- **Dashboard live rates** during a 700 KB/s-limited phone transfer: phone `rateIn` **689 KB/s**,
  fiber noise only, aggregate = honest sum.
- **Per-adapter reachability (diag, after the egress-pinning fix):** all 3 adapters reachable with
  the probe pinned to each adapter's own interface — fiber 4 ms (if 2), wifi 6 ms (if 3),
  USB-tether 15 ms (if 10); the evidence names each pinned interface.

**Two real bugs found live and fixed** (committed `1e21e51`), each re-verified live:
1. `healthLoop` raced the first snapshot → the page's first health reading lagged a whole interval.
   Fixed with a short 2 s retry until a snapshot exists; verified live (links reachable within ~5 s
   of start at the default 30 s interval).
2. The diag per-adapter probe bound only the source address, which does **not** choose egress on a
   multi-homed host → false timeouts on fiber/wifi to 1.1.1.1:443. Fixed by pinning egress with
   `nics.ForceEgress(ifIndex)` (the same mechanism the engine and monitor use); all 3 adapters now
   report reachable.

**Failure detection (live):** a black-hole endpoint (203.0.113.1:9, RFC 5737) marked all 3 adapters
unreachable with a reason ("no answer within 4 s"), logged one `link.reachability` warning each,
with no churn over multiple rounds.

---

## 9. Known limitations and unimplemented features

- **Windows-native runtime is unverified here** (the big one): PowerShell cmdlet execution, Wintun
  adapter creation, UAC elevation, real per-interface hop-limit writes, the Inno Setup installer.
  All implemented + build-verified + test-verified against recorded output, **not** physically run
  on Windows.
- **Inno Setup installer not built on this host** (Windows-only tool). Portable zip is the
  supported alternative.
- **Nothing is code-signed** — no Authenticode certificate is configured. SmartScreen will warn.
- **wintun.dll Authenticode signature not re-checked on Linux** (only SHA-256 was verified here).
- **Tray has no "Open Control Center" menu item** — the dashboard is reached via `net-merge
  dashboard` (or the `-open` flag). The two surfaces share control files and cannot disagree, but
  the tray does not yet link to the page.
- **App-specific (per-application) routing** is not implemented — the engine balances per
  connection, and the UI does not claim an app is pinned to one interface.
- **Single-connection aggregation is not claimed** — per-connection load balancing improves
  multi-connection workloads; one TCP connection does not aggregate multiple links.
- Pre-existing, not regressions: `GOOS=darwin` build fails (systray needs cgo); `GOOS=freebsd`
  build fails for `inventory`.

---

## 10. Installation and launch instructions

**From the portable package** (what this work produced):

1. Unzip `net-merge-<v>-portable.zip` to a folder (e.g. `C:\Tools\net-merge`).
2. Every-day use: run `net-merge-tray.exe` (windowless; it requests admin once for the engine and
   shows a tray icon). Or `net-merge.exe tray` from an elevated console.
3. Control Center: `net-merge.exe dashboard` — it prints a `http://127.0.0.1:<port>/?token=…`
   address and can open it in the browser (`-open`). The token is per-run.
4. Optional start-at-sign-in: `net-merge.exe autostart on`.

**Build the installer yourself** (needs Windows + Inno Setup 6): `pwsh scripts/build.ps1 -Version
0.1.0`. Full detail in `docs/RELEASING.md`.

**Config location:** `%LocalAppData%\net-merge` (settings, TTL originals/history, logs, engine
state). No private build-host paths are baked in; no global environment changes; no hard-coded
interface names.

---

## 11. Diagnostics and the AI-ready export

**Run diagnostics** — either the CLI:
```
net-merge.exe diag                       # every supported check
net-merge.exe diag -only adapters.connect,dns.resolve
net-merge.exe diag -json                 # machine-readable
net-merge.exe diag -export C:\reports    # writes redacted .txt + .json
```
or the dashboard's **Diagnostics** section (each check individually, or the combined procedure).
Every check states what it **does** and **does not** establish (e.g. "a connected adapter does not
prove its internet route is usable").

**Export for AI analysis** — dashboard **Diagnostics → Export**, or `diag -export DIR`. The report
is timestamped text + JSON and **redacts**: public IPs, MAC addresses, serial numbers, personal
filesystem paths, phone identifiers and credentials (private LAN addresses are kept). Before any
file is written the dashboard shows exactly what was redacted. **Nothing is uploaded; there is no
telemetry;** collection stays local unless the user acts. The report separates verified facts from
hypotheses and lists ranked next actions.

---

## 12. Restoring original settings and uninstalling cleanly

**Restore TTL/hop-limit** (if you changed any):
```
net-merge.exe ttl restore -confirm       # restores the captured originals, not a default
net-merge.exe ttl history                # the audit trail of every change and outcome
```
The captured values are in `%LocalAppData%\net-merge\ttl\ttl-originals.json` if you prefer to check
by hand.

**Stop and remove:**
1. `net-merge.exe off` (engine off), then Ctrl+C the dashboard and quit the tray.
2. `net-merge.exe ttl restore -confirm` (if TTL was changed).
3. `net-merge.exe autostart off` (remove sign-in entry).
4. `net-merge.exe cleanup` (remove any leftover engine routes after a crash).
5. Delete the install folder. Delete `%LocalAppData%\net-merge` to also remove settings, history
   and captured originals (plain files, registered nowhere else).

Nothing is installed as a service; no registry keys are created beyond what Windows makes for any
user-run program. The engine's safe fallback is unchanged from net-merge: the TUN adapter and its
routes disappear with the process, so a crash cannot leave the machine offline.

---

## 13. Remaining steps requiring a person at the physical Windows PC

These cannot be done from this Linux machine and need someone at a real Windows 11 (or 10) box:

1. **Build/run on Windows.** `pwsh scripts/build.ps1 -Version 0.1.0` (needs Go + Inno Setup 6) to
   produce and launch the installer; or unzip the portable package and run `net-merge-tray.exe`.
2. **Verify Windows-native diagnostics.** Run `net-merge.exe diag` and confirm the PowerShell-backed
   checks (adapter discovery, routes, DNS, `Test-NetConnection`, `tracert`) return real Windows data
   — the code paths are test-verified against recorded output but have never run on a live Windows
   host here.
3. **Verify the TTL manager end-to-end on Windows.** Inspect → configure → preview → apply (expect a
   UAC prompt; confirm read-back verification) → restore. On Windows the settings report
   `supported: true`; confirm the captured originals match `Get-NetIPv4Protocol` /
   `Get-NetIPInterface` and that restore returns them exactly. (On this Linux host the manager
   honestly reports `supported: false`.)
4. **Test USB-tethering on Windows.** Plug an Android phone in, enable USB tethering, and confirm
   `Get-NetAdapter`/the dashboard show it as eligible with correct addressing, gateway and routes;
   run a bounded transfer and compare per-adapter counters (mirror of the Linux procedure in §8).
5. **Launch the dashboard on Windows.** `net-merge.exe dashboard -open`, confirm the token flow
   (401 → `?token=` → cookie → page), and check all seven sections show real Windows state.
6. **Optional: code-sign** the exes and installer if a certificate becomes available (currently
   unsigned; SmartScreen will warn).

**State of this machine after testing (audited):** engine **OFF**, no net-merge processes running,
no net-merge TUN interface, normal route table (9 IPv4 routes), and the state directory restored to
`ctl/ logs/ ttl/` only (smoke-test artifacts removed). No test-only changes were left behind.

---

*Report generated for branch `netmerge-control-center` (9 commits, `6093879`…`b72e924`), 97 files,
+27,836/−47, 322 tests passing race-clean, Windows release build verified, physical USB-tether
tested on Linux.*
