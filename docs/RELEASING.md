# Building and packaging

How to produce a Windows release of net-merge + the Control Center, what each artifact is, and
what was actually verified on which machine. Read this before shipping a build.

There are two supported paths:

| Path | Produces | Needs |
|---|---|---|
| **Native Windows** (`scripts/build.ps1`) | installer **and** portable zip | Windows, Go, [Inno Setup 6](https://jrsoftware.org/isinfo.php) |
| **Cross-compile** (any host with Go) | the two `.exe`s, the icon, and a portable zip | Go; `wintun.dll` fetched separately (below) |

Both produce the *same two executables* from the same source with the same flags. Only the native
path can build the Inno Setup installer, because Inno Setup is a Windows-only tool.

## The artifacts

| File | What it is | Subsystem |
|---|---|---|
| `net-merge.exe` | the command line (`tray`, `run`, `dashboard`, `diag`, `ttl`, `list`, ...) | console |
| `net-merge-tray.exe` | the windowless tray app; launched with no arguments it defaults to `tray` | GUI (`-H=windowsgui`) |
| `wintun.dll` | the Windows TUN driver the engine loads at runtime; **not** in the repo | — |
| `net-merge.ico` | the tray/installer icon, generated from the binary (`net-merge.exe _icon`) | — |
| `net-merge-setup-<v>.exe` | the Inno Setup installer (native path only) | — |
| `net-merge-<v>-portable.zip` | the files above + licence + docs, for a manual install | — |

One source tree builds both exes. The only differences are the linker flags: the tray build sets
`-H=windowsgui` (no console window) and `-X main.defaultCmd=tray` (double-clicking it starts the
tray), plus `-X main.version=<v>` on both so `net-merge version` reports the real number.

## Native Windows build (installer + portable)

```
pwsh scripts/build.ps1 -Version 0.1.0 [-RepoUrl https://github.com/you/net-merge]
```

The script vets, tests, builds both exes, generates the icon, runs `scripts/fetch-wintun.ps1`
(downloads `wintun.dll` and verifies its SHA-256 **and** its WireGuard LLC code signature), builds
the Inno Setup installer, and zips the portable package — all into `dist\`. It fails early if the
version string is not `X.Y.Z` or if Inno Setup is missing.

## Cross-compile build (portable, no installer)

This is the path used to produce the packaged build in this repository's working tree, and the one
that works on a non-Windows host. Go cross-compiles cleanly to `windows/amd64` (the engine is pure
Go; the Windows-specific code is behind `_windows.go` build tags).

```
VER=0.1.0
GOOS=windows GOARCH=amd64 go build -trimpath \
  -ldflags "-s -w -X main.version=$VER" \
  -o dist/net-merge.exe ./cmd/net-merge
GOOS=windows GOARCH=amd64 go build -trimpath \
  -ldflags "-s -w -H=windowsgui -X main.defaultCmd=tray -X main.version=$VER" \
  -o dist/net-merge-tray.exe ./cmd/net-merge
```

Generate the icon from the freshly built console exe (this is the same command `build.ps1` runs):

```
# on Windows:  dist\net-merge.exe _icon dist\net-merge.ico
# on Linux/macOS with wine:
wine dist/net-merge.exe _icon dist/net-merge.ico
```

`wintun.dll` is not in the repo. On Windows, `scripts/fetch-wintun.ps1 -OutDir dist` downloads and
verifies it. On a non-Windows host you can fetch and check the digest by hand (the signature check
itself needs Windows tooling):

```
curl -fsSL https://www.wintun.net/builds/wintun-0.14.1.zip -o wintun.zip
# expected sha256: 07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51
sha256sum wintun.zip
unzip -j wintun.zip 'wintun/bin/amd64/wintun.dll' 'wintun/LICENSE.txt' -d dist/
```

Then assemble the portable zip (the same file set `build.ps1` compresses, plus the Control Center
docs):

```
cd dist && zip -j ../net-merge-$VER-portable.zip \
  net-merge.exe net-merge-tray.exe wintun.dll wintun-LICENSE.txt net-merge.ico \
  LICENSE THIRD-PARTY-NOTICES.md README.md \
  CONTROL-CENTER.md TROUBLESHOOTING.md ERROR-CODES.md THIRD-PARTY.md && cd ..
```

### Determinism and private paths

Both exes are built with `-trimpath`, so the build host's filesystem layout is stripped out of the
binary: a `strings` scan of the shipped exes finds **zero** occurrences of the build host's home
directory (verified on the build used for this report). `-s -w` drops the symbol table and DWARF.
The remaining paths inside the binary are the Go module paths (`net-merge/internal/...`), which are
expected. There are no hard-coded interface names, gateways or phone-adapter assumptions: adapter
detection is entirely runtime (`GetAdaptersAddresses` on Windows), and the quality profiles and
diagnostic endpoints live in a versioned settings file, not the binary.

## What is verified, and where

| Check | Native Windows | Cross-compile (this build) |
|---|---|---|
| `go vet ./...` clean | yes | yes |
| `go test ./...` green | yes | yes (on the build host) |
| Both exes produced, correct subsystem (console / GUI) | yes | yes (`file` reports PE32+ console and GUI) |
| `wintun.dll` fetched, **SHA-256 verified** | yes | yes (digest matched the pinned value) |
| `wintun.dll` **WireGuard LLC signature verified** | yes (PowerShell `Get-AuthenticodeSignature`) | **no** — needs Windows; only the digest was checked here |
| Binary launches and reports its version | yes | yes (ran `net-merge.exe version` and `list` under wine: printed `net-merge 0.1.0` and enumerated the host's real adapters) |
| Inno Setup installer built | yes | **no** — Inno Setup is Windows-only |
| Code-signed (Authenticode) | **no** — no signing certificate is configured in this project | **no** |

**Signing:** this project does not configure an Authenticode signing certificate, so neither the
exes nor the installer are code-signed. Windows SmartScreen will show its usual "unrecognized app"
warning on first run from a downloaded file. This is reported honestly rather than glossed over;
signing would need a certificate the project does not have.

**The installer** is the one artifact that cannot be produced off Windows. The portable zip is the
supported alternative: unzip it anywhere and run `net-merge-tray.exe` (or `net-merge.exe
dashboard`). Everything the installer would do by hand — Start-menu shortcut, optional start-at-
sign-in, the `%LocalAppData%\net-merge` state folder — is described in
[CONTROL-CENTER.md](CONTROL-CENTER.md#removing-it) so a portable install can be set up and removed
cleanly.

## Versioning and release flow

Releases are cut by pushing a `vX.Y.Z` tag; `.github/workflows/release.yml` builds on
`windows-latest` with `build.ps1` and publishes the installer + portable zip (plus the Linux
packages in a second job). The release notes are that version's section of `CHANGELOG.md` — add it
before tagging, or the workflow fails early. `scripts/release-notes.ps1 -Version X.Y.Z` previews the
notes.
