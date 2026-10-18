<p align="center">
  <img src="docs/icon.png" width="128" alt="net-merge icon">
</p>

<h1 align="center">net-merge</h1>

<p align="center">
  <strong>Use all your internet connections at the same time.</strong><br>
  Combine Wi-Fi, Ethernet and phone hotspots, so downloads, games and browsers get the speed of every connection added up.
</p>

<p align="center">
  <a href="https://github.com/rohit267/net-merge/releases/latest">Download</a> ·
  <a href="#install">Install</a> ·
  <a href="#add-a-second-connection">Add a second connection</a> ·
  <a href="#troubleshooting">Troubleshooting</a> ·
  <a href="docs/DEVELOPING.md">How it works</a>
</p>

<p align="center">
  <a href="https://github.com/rohit267/net-merge/actions/workflows/ci.yml"><img src="https://github.com/rohit267/net-merge/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/rohit267/net-merge/releases"><img src="https://img.shields.io/github/v/release/rohit267/net-merge" alt="Latest release"></a>
  <a href="https://github.com/rohit267/net-merge/releases"><img src="https://img.shields.io/github/downloads/rohit267/net-merge/total" alt="Downloads"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/rohit267/net-merge" alt="MIT license"></a>
  <img src="https://img.shields.io/badge/platforms-Windows%20%7C%20macOS%20%7C%20Linux-blue" alt="Windows, macOS and Linux">
  <a href="https://buymeacoffee.com/rohit267"><img src="https://img.shields.io/badge/Buy%20me%20a%20coffee-rohit267-FFDD00?logo=buymeacoffee&logoColor=black" alt="Buy me a coffee"></a>
  <a href="https://paypal.me/champdev"><img src="https://img.shields.io/badge/Donate-PayPal-00457C?logo=paypal&logoColor=white" alt="Donate with PayPal"></a>
</p>

<p align="center">
  <img src="docs/demo.gif" width="600" alt="Speed test on a Mac with Wi-Fi and an Android phone: the net-merge menu shows both connections carrying traffic, and the download reaches about 326 Mbit/s">
  <br>
  <sub>A Mac with Wi-Fi + an Android phone. The menu shows both connections working at once. <a href="docs/demo.mp4">Watch the full 45-second video.</a></sub>
</p>

net-merge uses all your network adapters together. It works on **Windows, macOS and Linux**. It is free.
There is no account, no server and no VPN.

A real test with Wi-Fi + an Android USB tether + an iPhone hotspot, 9 downloads at once:
**232-303 Mbit/s**. The fastest connection alone gave about 121 Mbit/s.

| Windows: hover the icon | Windows: the menu | macOS: the menu bar |
|---|---|---|
| ![Tooltip: Merging, speed of each adapter and the total](docs/tray-tooltip.png) | ![Menu: total, each adapter's speed and flows, IPv6 option, Pause merging, Quit](docs/tray-menu.png) | ![macOS menu: total 399 Mbit/s, en0 and feth0 each with their flows, Pause merging, Quit](docs/tray-menu-macos.png) |

## How it helps

net-merge gives every new connection to one of your links. When an app opens many connections, they
spread over all your links.

- **Good for:** Steam and game downloads, browsers, system updates, cloud uploads (Google Drive),
  download managers like IDM, torrents.
- **Not for:** one single connection. One connection always uses one link, so one big file from one
  connection does not get faster.
- **Works for every app**, TCP and UDP, IPv4 and IPv6. You do not set up a proxy.
- **Smart:** faster links get more connections. A link with no internet gets none until it works again.
- **Safe:** if net-merge crashes, your internet keeps working.
- **Light:** about 0.18 CPU cores per 100 Mbit/s.

## Install

**macOS and Linux**: paste this into a terminal.

```
curl -fsSL https://raw.githubusercontent.com/rohit267/net-merge/main/install.sh | sh
```

**Windows**: paste this into PowerShell.

```
irm https://raw.githubusercontent.com/rohit267/net-merge/main/install.ps1 | iex
```

That's it: net-merge is installed and its icon appears in the menu bar or tray. On Linux the script
uses your package manager (apt, dnf, zypper, apk or pacman) and on macOS Homebrew when you have it, so
net-merge updates with the rest of your system. To start it at sign-in: `net-merge autostart on`.

<details>
<summary><strong>Rather type the commands yourself?</strong> One block per system, each ready to paste.</summary>
<br>

**Homebrew** (macOS):

```
brew install rohit267/tap/net-merge && sudo "$(brew --prefix)/bin/net-merge" install && net-merge tray
```

**macOS without Homebrew**:

```
curl -fsSL https://github.com/rohit267/net-merge/releases/latest/download/net-merge-macos-universal.tar.gz | tar -xz -C /tmp net-merge && sudo /tmp/net-merge install && net-merge tray
```

**Debian, Ubuntu, Linux Mint, Pop!_OS, Raspberry Pi OS** (apt):

```
curl -fsSL https://rohit267.github.io/net-merge/apt/key.gpg | sudo tee /usr/share/keyrings/net-merge.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/net-merge.gpg] https://rohit267.github.io/net-merge/apt stable main" | sudo tee /etc/apt/sources.list.d/net-merge.list
sudo apt update && sudo apt install -y net-merge
```

**Fedora, RHEL, Rocky, Alma** (dnf):

```
sudo curl -fsSL -o /etc/yum.repos.d/net-merge.repo https://rohit267.github.io/net-merge/rpm/net-merge.repo && sudo dnf install -y net-merge
```

**openSUSE** (zypper):

```
sudo zypper addrepo https://rohit267.github.io/net-merge/rpm/net-merge.repo && sudo zypper --gpg-auto-import-keys install -y net-merge
```

**Arch, Manjaro, EndeavourOS** (pacman):

```
curl -fsSL https://rohit267.github.io/net-merge/apt/key.asc | sudo pacman-key --add - && sudo pacman-key --lsign-key 0168C7AB77721656904811AE904F61E7F4F1C2A1
printf '\n[net-merge]\nSigLevel = Required\nServer = https://rohit267.github.io/net-merge/arch/$arch\n' | sudo tee -a /etc/pacman.conf
sudo pacman -Sy --noconfirm net-merge
```

**Alpine** (apk):

```
sudo wget -O /etc/apk/keys/net-merge.rsa.pub https://rohit267.github.io/net-merge/apk/net-merge.rsa.pub
echo https://rohit267.github.io/net-merge/apk | sudo tee -a /etc/apk/repositories && sudo apk add net-merge
```

**Homebrew** (Linux):

```
brew install rohit267/tap/net-merge && sudo setcap cap_net_admin,cap_net_raw+ep "$(readlink -f "$(brew --prefix)/bin/net-merge")"
```

**Any other Linux** (any CPU):

```
curl -fsSL https://github.com/rohit267/net-merge/releases/latest/download/net-merge-linux-$(uname -m).tar.gz | tar -xz -C /tmp net-merge && sudo install -m 755 /tmp/net-merge /usr/local/bin/ && sudo setcap cap_net_admin,cap_net_raw+ep /usr/local/bin/net-merge
```

**Windows by hand**: download [net-merge-setup.exe](https://github.com/rohit267/net-merge/releases/latest/download/net-merge-setup.exe)
and run it. Windows may warn because the app is not signed yet: click *More info*, then *Run anyway*.
There is also a [portable zip](https://github.com/rohit267/net-merge/releases/latest/download/net-merge-portable.zip).

Then start it with `net-merge tray` (Linux, macOS) or from the Start menu (Windows).
</details>

<details>
<summary><strong>Good to know</strong></summary>
<br>

- **Which CPUs:** x86-64, ARM64 and Apple Silicon, ARMv7, ARMv6 (Raspberry Pi), x86 32-bit, RISC-V,
  PowerPC (ppc64le), s390x and LoongArch.
- **No password prompts:** the Linux packages give net-merge the network rights it needs (`setcap`), and on
  macOS `net-merge install` adds one rule so that only `net-merge tray` can run as root without a password.
- **Linux tray icon:** needs a desktop with StatusNotifierItem support: KDE, XFCE, Cinnamon, LXQt, Budgie,
  or GNOME with the *AppIndicator and KStatusNotifierItem Support* extension (Ubuntu already has it).
- **Firewall:** if it blocks unknown traffic, trust the `net-merge` interface
  (for example `firewall-cmd --zone=trusted --add-interface=net-merge`).
- **Signed repositories:** apt, dnf, zypper and pacman use the key in
  [`packaging/apt-signing-key.asc`](packaging/apt-signing-key.asc), fingerprint
  `0168 C7AB 7772 1656 9048 11AE 904F 61E7 F4F1 C2A1`.
- **Uninstall:** your package manager (`sudo apt remove net-merge`, `brew uninstall net-merge`, ...) or
  Windows' *Installed apps*. On macOS also `net-merge autostart off` and `sudo net-merge uninstall`.
</details>

### NixOS

```nix
# flake.nix
inputs.net-merge.url = "github:rohit267/net-merge";

# configuration.nix (with `inputs` passed via specialArgs)
imports = [ inputs.net-merge.nixosModules.default ];
programs.net-merge = {
  enable = true;
  autostart = true;   # optional: start the tray in every graphical session
};
```

To try it without installing: `sudo nix run github:rohit267/net-merge -- run`.

## Add a second connection

net-merge needs **two or more** real connections. Use Wi-Fi plus one of these: a phone (USB tethering or
hotspot), an Ethernet cable, or a second Wi-Fi. Plug it in and net-merge adds it within a few seconds.
When you unplug it, its connections move to the others.

**Windows and Linux:** plug the phone in and turn on *USB tethering* (Android) or *Personal Hotspot*
(iPhone). That is all.

**Mac with an iPhone** (nothing extra to install)
1. Plug the iPhone in with a cable. Tap *Trust* on the iPhone if it asks.
2. On the iPhone, open *Settings > Personal Hotspot* and turn on *Allow Others to Join*.
3. An **iPhone USB** network appears on the Mac. net-merge adds it in a few seconds.

**Mac with an Android phone** (needs the app **TetherKit**)

macOS cannot use Android USB tethering by itself. The app **TetherKit** adds that support.
1. Install and open TetherKit.
2. Plug the phone in and turn on *USB tethering* in the phone's settings.
3. Click **Apply** in TetherKit. net-merge adds the new network in a few seconds.

> **Start net-merge first, then connect the Android phone.** macOS drops the TetherKit connection each
> time net-merge starts or quits. Pausing and resuming is safe: net-merge keeps its virtual adapter while
> paused. If the phone link disappears, click **Apply** in TetherKit again. The iPhone is not affected.

A phone uses its mobile data, so part of your traffic goes through it while net-merge runs. Quit
net-merge when you do not want that.

## Use it

1. Start net-merge. A tray icon appears (menu bar on Mac).
2. The icon is **green** when it is merging and **grey** when it is paused.
3. **It pauses by itself** when fewer than two connections have internet, because there is nothing to
   merge, and the menu says *Paused: one connection*. It **starts again by itself** when a second
   connection works. If you pause or start it yourself, that choice wins: it will not start again after
   you paused it. Untick *Pause when there is only one connection* in the menu to switch this off, or run
   `net-merge tray -auto-pause=false`.
4. **Hover** the icon to see the speed of each connection and the total.
5. **Right-click** the icon (on Mac, click it) to open the menu. It shows each connection's speed, how
   many connections net-merge gave it, and the buttons *Pause merging* / *Start merging* and *Quit*.
6. To start it at sign-in: tick the box in the Windows installer, or run `net-merge autostart on`.

Tips:
- Torrent clients already use every connection. Leave qBittorrent's network interface on *Any interface*.
- Leave *Use all adapters (IPv6 only if every adapter has it)* ticked. Untick it only if you must reach a
  site that only has IPv6.
- `net-merge list` shows which connections are used and why others are skipped. `net-merge status`
  shows live numbers.

## Troubleshooting

<details>
<summary><strong>A second connection does not make things faster</strong></summary>
<br>

You only gain speed when each connection reaches the internet by its own path. Wi-Fi from your home
router plus a phone on mobile data works. Wi-Fi and Ethernet plugged into the **same router** do not: they
share one internet line, so the total stays the same.

Also remember that one connection always uses one link. Many parallel connections (Steam, browsers,
download managers) are what speed up. Run `net-merge status` to see how many connections each link carries.
</details>

<details>
<summary><strong>A connection does not show up</strong></summary>
<br>

Run `net-merge list`. It shows which connections are used and why the others are skipped, for example
"no default gateway" (the link has no internet yet).

- **iPhone on a Mac:** plug it in, tap *Trust*, and turn on *Settings > Personal Hotspot > Allow Others to
  Join*. If the **iPhone USB** network in *System Settings > Network* stays inactive, turn off its
  **Disable unless needed** switch.
- **Android on a Mac:** install **TetherKit** and click **Apply** (see above).
- **Phone on Windows:** if the phone does not appear in *Network Settings*, install your phone maker's USB
  driver.
</details>

<details>
<summary><strong>The Android connection disappears on a Mac</strong></summary>
<br>

macOS drops the TetherKit connection each time net-merge starts or quits (pausing and resuming is safe).
Start net-merge first, then connect the phone. If it vanishes, click **Apply** in TetherKit again.
</details>

<details>
<summary><strong>Windows uses only one network</strong></summary>
<br>

Windows can switch Wi-Fi off when Ethernet is plugged in. Open the Group Policy Editor (`gpedit.msc`),
go to *Computer Configuration > Administrative Templates > Network > Windows Connection Manager*, and set
**Minimize the number of simultaneous connections to the Internet or a Windows domain** to **Disabled**.
</details>

<details>
<summary><strong>macOS says it cannot open net-merge, or Windows says "protected your PC"</strong></summary>
<br>

The apps are not code-signed yet. On macOS run `xattr -d com.apple.quarantine net-merge`. On Windows click
*More info*, then *Run anyway*.
</details>

<details>
<summary><strong>The menu says "Paused: one connection"</strong></summary>
<br>

net-merge only has something to do with two or more connections that have internet, so it waits. Plug
in or connect the second one (see *Add a second connection*) and it starts by itself after a few seconds.
To merge anyway, choose *Start merging* (it then stays on until a second connection has come and gone), or
untick *Pause when there is only one connection*.

Switching merging on or off cuts the connections that are open at that moment, which is why it waits 10
seconds with nothing moving before pausing (2 minutes if a download or upload is still going) and
3 seconds before resuming,
and never switches by itself more than once every 30 seconds.
</details>

<details>
<summary><strong>I cannot find the tray icon</strong></summary>
<br>

On Windows it may be behind the `^` arrow next to the clock. On macOS it is in the menu bar. On Linux the
desktop needs StatusNotifierItem support (KDE, XFCE, Cinnamon, LXQt, Budgie, or GNOME with the *AppIndicator
and KStatusNotifierItem Support* extension).
</details>

<details>
<summary><strong>A site asks me to log in again</strong></summary>
<br>

net-merge may use a different IP for each connection, and some sites tie your login to one IP. That is a
limit of splitting connections over several links.
</details>

## Commands

```
net-merge tray            tray icon (the normal way to run it)
net-merge on | off        start / pause merging in the running tray
net-merge quit            pause and close the tray
net-merge status | list   live numbers / which connections are used
net-merge autostart on|off|status
net-merge socks           plain SOCKS5 proxy on 127.0.0.1:1080 (no admin, per app)
net-merge cleanup         remove leftover routes after a crash
net-merge install         macOS only: `sudo net-merge install` (see above)
```

More flags and details are in [docs/DEVELOPING.md](docs/DEVELOPING.md).

## Good to know

- Needs admin (Windows), `CAP_NET_ADMIN` (Linux) or `sudo net-merge install` once (macOS).
- Some sites tie your login to one IP. net-merge may use a different IP for each connection, so such a
  site can ask you to log in again.
- If your connections differ in IPv6 support, sites that only have IPv6 are not reachable while the box
  above is ticked.

## More

- What changed in each version: [CHANGELOG.md](CHANGELOG.md)
- How it works, building from source, tests: [docs/DEVELOPING.md](docs/DEVELOPING.md)
- **The Control Center** — dashboard, TTL / hop-limit manager, diagnostics, quality profiles,
  AI-ready export: [docs/CONTROL-CENTER.md](docs/CONTROL-CENTER.md)
- Something not working: [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md). Every error code is
  explained in [docs/ERROR-CODES.md](docs/ERROR-CODES.md).
- Packaging a Windows build (installer or portable, native or cross-compile): [docs/RELEASING.md](docs/RELEASING.md)
- Want to help? [CONTRIBUTING.md](CONTRIBUTING.md). Found a security problem? [SECURITY.md](SECURITY.md)
- License: MIT, see `LICENSE`. Third-party parts: `THIRD-PARTY-NOTICES.md` and
  [docs/THIRD-PARTY.md](docs/THIRD-PARTY.md).

## Support

net-merge is free. If it saves you time, you can [buy me a coffee](https://buymeacoffee.com/rohit267) or [donate with PayPal](https://paypal.me/champdev). Thank you!
