# Third-party notices

net-merge is MIT licensed (see `LICENSE`). It links the following libraries, all under permissive
licenses (license texts are in each project's repository and in the Go module cache):

| Component | License | Use |
|---|---|---|
| [tun2socks](https://github.com/xjasonlyu/tun2socks) | MIT | TUN device + userland TCP/IP stack glue |
| [gVisor](https://github.com/google/gvisor) (netstack) | Apache-2.0 | userland TCP/IP stack |
| [wireguard-go](https://git.zx2c4.com/wireguard-go) / [wintun Go bindings](https://git.zx2c4.com/wintun-go) | MIT | Windows TUN device access |
| [fyne.io/systray](https://github.com/fyne-io/systray) | Apache-2.0 | system tray icon |
| [vishvananda/netlink](https://github.com/vishvananda/netlink) | Apache-2.0 | Linux TUN addresses and routes, default-route discovery |
| golang.org/x/sys, golang.org/x/net, golang.org/x/time, golang.org/x/crypto | BSD-3-Clause | Windows and Linux system APIs, support code |
| Other transitive modules (see `go.mod` / `go.sum`) | MIT / Apache-2.0 / BSD | |

## hotspot-ttl

The TTL / hop-limit manager in this build is a Windows reimplementation of the *concept* behind
[hotspot-ttl](https://github.com/pratikbin/hotspot-ttl) (MIT, Copyright (c) 2026 pratikbin). No
hotspot-ttl code is linked, copied or vendored: that project is a macOS tool built on Swift,
launchd, `SCDynamicStore` and `sysctl`, none of which exist on Windows. What was taken is the
safety reasoning — an opt-in packet-header setting, a captured original value that rollback
restores, and the rule that nothing changes silently. The Windows implementation
(`internal/ttlmgr`) is original and uses documented Windows mechanisms
(`Get/Set-NetIPv4Protocol`, `Get/Set-NetIPv6Protocol -DefaultHopLimit`,
`Get/Set-NetIPInterface -CurrentHopLimit`). It deliberately does not reproduce that project's or
the workspace's carrier-evasion purpose: it is transparent configuration for troubleshooting and
administered environments, never a way to conceal tethering from a carrier.

## Wintun

The installer and portable zip include `wintun.dll`, the prebuilt, signed driver from
<https://www.wintun.net/>, unmodified, under the Prebuilt Binaries License. Copyright (C) 2018-2021
WireGuard LLC. The license text is shipped next to it as `wintun-LICENSE.txt`. The DLL is not stored
in this repository: `scripts/fetch-wintun.ps1` downloads it and verifies its SHA-256 and its
WireGuard LLC code signature.
