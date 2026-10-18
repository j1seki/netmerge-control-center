# Changelog

What changed in each release. Each version's section becomes its GitHub release notes, so add the
entry here before pushing a version tag.

## [Unreleased]

### Added
- **NetMerge Control Center.** The tray and engine now also serve a local dashboard
  (`net-merge dashboard`): live per-adapter state and throughput, routing, a Windows-native
  TTL / hop-limit manager, a diagnostics centre, searchable logs and settings — one binary, no
  extra runtime, loopback-only with a per-run access token. See
  [docs/CONTROL-CENTER.md](docs/CONTROL-CENTER.md).
  - **TTL / hop-limit manager** (Windows): inspects IPv4 TTL and IPv6 hop limit with their scope,
    captures the original values before the first change, applies only after an explicit
    confirmation, verifies each write by reading it back, and restores the captured originals
    (`net-merge ttl restore`) — never an assumed default. Opt-in only; it never changes anything
    because an adapter appeared. See
    [docs/CONTROL-CENTER.md#ttl--hop-limit-manager](docs/CONTROL-CENTER.md#ttl--hop-limit-manager).
  - **Diagnostics centre** (`net-merge diag`, or the dashboard's Diagnostics section): adapter
    discovery, routes, DNS, IPv4/IPv6 connectivity, per-adapter reachability pinned to each
    adapter's own interface, gateway, MTU, traceroute, UDP and more. Each check states what it
    does *and does not* establish, rather than trusting an exit code. Export a redacted,
    human-inspectable report for AI analysis — public IPs, MACs, serials and personal paths are
    replaced, nothing is uploaded, no telemetry. See
    [docs/ERROR-CODES.md](docs/ERROR-CODES.md).
  - **Quality profiles** (`maximum-throughput`, `gaming-low-latency`, `fiber-preferred`,
    `connection-reliability`, `custom`), applied at the next engine start, plus a per-link
    reachability monitor that logs real state transitions.
- **One-line install.** `curl -fsSL https://raw.githubusercontent.com/rohit267/net-merge/main/install.sh | sh` on
  macOS and Linux (it uses Homebrew, apt, dnf, zypper, apk or pacman when it can, the release tarball
  otherwise, and starts the tray), and `irm https://raw.githubusercontent.com/rohit267/net-merge/main/install.ps1 | iex`
  in PowerShell on Windows.
- Releases also carry the downloads under names without the version (`net-merge-setup.exe`,
  `net-merge-macos-universal.tar.gz`, `net-merge-linux-$(uname -m).tar.gz`), so
  `releases/latest/download/...` links always give the newest one.

### Fixed
- `sudo net-merge install` refused on Macs where `/usr/local/bin` is writable by your user (Intel Macs
  with Homebrew). It now puts its root-owned copy in `/opt/net-merge/bin` there, and links `net-merge` into
  `/usr/local/bin`.

## [0.3.0] - 2026-10-17

### Added
- **net-merge as a normal package on every Linux distribution.** Releases now include a `.deb`, `.rpm`,
  `.apk` (Alpine) and Arch package for every CPU: x86-64, ARM64, ARMv7, ARMv6 (Raspberry Pi), x86 32-bit,
  RISC-V, PowerPC (ppc64le), s390x and LoongArch, plus a tarball for each. They are also published as signed
  repositories on GitHub Pages, so `sudo apt install net-merge`, `sudo dnf install net-merge`,
  `sudo zypper install net-merge`, `sudo apk add net-merge` and `sudo pacman -S net-merge` work after a
  one-time setup. The packages give net-merge its network rights themselves, and add an app-menu entry,
  icons and AppStream information.
- **Pauses by itself when only one connection works, and resumes when two do.** With fewer than two
  connections that reach the internet there is nothing to merge, so the tray pauses merging ("Paused: one
  connection") and starts it again when a second connection works. Pausing or starting by hand always wins,
  and it waits for things to settle first: 10 seconds with nothing moving (2 minutes if a download or
  upload is still going) before pausing, 3 seconds before resuming, and at least 30 seconds between
  automatic switches.
  Untick *Pause when there is only one connection* in the tray menu, or run `net-merge tray -auto-pause=false`.

### Changed
- On macOS, pausing and resuming no longer removes and recreates the virtual adapter, so it no longer
  drops a TetherKit (Android) link. Starting and quitting still do.
- New connections no longer wait while the once-a-second adapter speed reading runs (thanks @b0r1ssh).

## [0.2.0] - 2026-10-16

### Added
- **Downloads for macOS and Linux.** Each release now also has `net-merge-X.Y.Z-macos-universal.tar.gz`
  (Apple Silicon and Intel) and `net-merge-X.Y.Z-linux-x86_64.tar.gz` / `-linux-aarch64.tar.gz`. The steps
  to run them are in the README.
- **macOS support** (Apple Silicon and Intel). System-wide mode, the menu-bar tray, the SOCKS5 proxy, live
  per-adapter speeds and start at login (a LaunchAgent) all work. The TUN is a utun, flows are pinned with
  `IP_BOUND_IF` plus a scoped default route per adapter, and adapters come from the routing table. iPhone
  hotspot over USB works as is; Android USB tethering needs the TetherKit app. `sudo net-merge install`
  sets up a passwordless rule for `net-merge tray`.
- **Linux support**, including NixOS. System-wide mode, the tray icon (any desktop with
  StatusNotifierItem support: KDE, GNOME with the AppIndicator extension, XFCE, Cinnamon, ...), the
  SOCKS5 proxy, live per-adapter speeds and autostart (XDG autostart entry) all work. The TUN and
  its routes are set up over netlink, flows are pinned with `SO_BINDTOIFINDEX`, and adapters are
  detected from sysfs and the routing tables. Needs root or `CAP_NET_ADMIN` (`setcap`).
- **Nix flake** with a package and a NixOS module: `programs.net-merge.enable` installs a capability
  wrapper so the tray runs without root, and `programs.net-merge.autostart` starts it in every
  graphical session.

### Changed
- Clicking the tray icon no longer turns merging on or off (it was easy to hit by accident). Open the
  menu (right-click) and choose *Pause merging* / *Start merging*.
- The source is split into packages: `cmd/net-merge` (the command) and `internal/...` (engine, nics,
  tun, tray, platform, state, icon, logx). Build with `go build ./cmd/net-merge`.

## [0.1.1] - 2026-10-14

### Added
- **Speeds on hover.** Hovering the tray icon shows each adapter's download/upload speed and a Total
  line. The numbers come from Windows' own adapter counters, so every app counts, including apps that
  bypass net-merge (qBittorrent binds to adapters directly), and they show while paused too.
- **Real speeds in the menu.** The right-click menu shows each adapter's speed, how many connections
  net-merge put on it, and whether it has IPv6.
- `net-merge status` shows each adapter's total traffic ("link") next to the part net-merge relayed.
- `-mtu` flag to change the virtual adapter's MTU (default 9000).
- `-pprof` flag to serve Go's profiler on a localhost address, for diagnosing CPU use.
- README: screenshots, features and how to use.

### Changed
- **About 3x less CPU.** The virtual adapter now runs at MTU 9000 instead of 1500, so about 5x fewer
  packets go through the userland network stack. Measured on the same machine and links: 0.54 → 0.18
  CPU cores per 100 Mbit/s.
- Tray wording: **Merging** / **Paused**, and *Pause merging* / *Start merging* in the menu (was ON/OFF
  and *Turn on* / *Turn off*).
- Idle UDP sessions end after 30 seconds instead of 60, which means fewer sockets and less memory with
  torrent clients.
- Quieter log: torrent traffic no longer writes a warning for every dropped packet.

### Fixed
- **Tray icon missing after sign-in.** With "start at sign-in" on, the tray could start before the
  taskbar existed and stay invisible and inactive. It now waits for the taskbar, and the sign-in task
  retries if the tray fails to start. If you enabled autostart in 0.1.0, install 0.1.1 with the option
  ticked to update it.
- UDP datagrams larger than 1500 bytes going through the virtual adapter were silently dropped.
- Tooltip cut off after "Ethernet 4 ↓": Windows 11 shows only 64 characters of a tray tooltip, so the
  text now fits that limit.
- A garbled "…" appeared when long tooltip text was shortened.
- Errors from the tray library were not written to the log in the windowless build.

## [0.1.0] - 2026-10-13

First release.

### Added
- System-wide per-connection balancing: every new TCP and UDP connection, IPv4 and IPv6, is pinned to
  one adapter, so parallel connections use Wi-Fi, Ethernet and phone/USB tethers at the same time.
- Tray app: left-click turns it on or off, right-click shows per-adapter speeds, optional start at
  sign-in without a UAC prompt.
- Automatic adapter detection: real hardware with a default gateway is used, while VPN and virtual adapters
  (Tailscale, WireGuard, Hyper-V, WSL) are skipped; `net-merge list` shows why.
- Per-adapter internet checks: a link without internet gets no connections until it recovers.
- Connections are spread by each adapter's measured speed, separately for IPv4 and IPv6.
- IPv6 policy (`-ipv6 auto|on|off`): when only some adapters have IPv6, apps are steered to IPv4 so
  every adapter stays in use.
- Crash-safe: the virtual adapter and its routes disappear with the process.
- Command line: `on`, `off`, `quit`, `status`, `list`, `autostart`, `cleanup`, plus a SOCKS5 mode
  that needs no admin.
- Installer and portable zip.
