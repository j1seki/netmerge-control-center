# Third-party notices

NetMerge Control Center is built inside the net-merge repository and keeps that project's MIT
licence and copyright notice intact (`LICENSE`, Copyright (c) 2026 Rohit Mahto). Nothing in the
existing licence is changed, and no dependency notice is removed.

## Projects whose work is integrated

### net-merge (https://github.com/rohit267/net-merge)

MIT, Copyright (c) 2026 Rohit Mahto.

Used as-is for the bonding engine: TUN/Wintun integration, adapter discovery, the per-connection
scheduler, reachability probes, the tray application and the existing command-line surface. The
Control Center adds packages around it (`internal/execx`, `internal/inventory`, `internal/ttlmgr`
and the application layer). Where the engine had to change, the change is narrow, is listed in
`IMPLEMENTATION_REPORT.md`, and carries a regression test.

### hotspot-ttl (https://github.com/pratikbin/hotspot-ttl)

MIT, Copyright (c) 2026 pratikbin.

This project is **not** linked, copied or vendored. It is a macOS tool (Swift, launchd,
`SCDynamicStore`, `sysctl net.inet.ip.ttl` / `net.inet6.ip6.hlim`), and none of those mechanisms
exist on Windows. What was taken from it is the *concept* and the safety reasoning: an opt-in
packet-header setting, a captured original value that rollback restores, an allow-list of
gateways the change is relevant to, and the rule that nothing changes silently.

The Windows implementation of that concept is original code in `internal/ttlmgr`, and it uses
documented Windows mechanisms (`Get/Set-NetIPv4Protocol -DefaultHopLimit`,
`Get/Set-NetIPv6Protocol -DefaultHopLimit`, `Get/Set-NetIPInterface -CurrentHopLimit`) rather than
any macOS API. Windows' default is 128, not macOS's 64, which is one reason the original value is
captured instead of assumed.

### Hop limit prior art in the workspace (`Hotspot/`)

Not part of the build and not copied. The batch file in that folder
(`netsh int ipv4 set glob defaultcurhoplimit=65`) was read as prior art for what a Windows
hop-limit change looks like. The Control Center deliberately does **not** reproduce the
carrier-evasion purpose of that script: the TTL component here is opt-in configuration with
captured originals and rollback, for transparent troubleshooting and administered environments.

## Go module dependencies

All are declared in `go.mod` and fetched from their upstream sources; no binaries are bundled and
no third-party executable is downloaded at runtime by the Control Center:

| Module | Licence |
| --- | --- |
| fyne.io/systray | MIT |
| github.com/vishvananda/netlink | Apache-2.0 |
| github.com/xjasonlyu/tun2socks/v2 | MIT |
| golang.org/x/net, golang.org/x/sys | BSD-3-Clause |
| golang.zx2c4.com/wireguard | MIT |
| gvisor.dev/gvisor | Apache-2.0 |

`Wintun` (the Windows TUN driver used by the engine's Windows path) is downloaded by the
repository's existing `scripts/fetch-wintun.ps1` from its upstream release during packaging, which
is the behaviour that was already there; the Control Center adds no new download.
