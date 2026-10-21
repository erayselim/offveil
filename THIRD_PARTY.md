# Third-party components

offveil (Apache-2.0) redistributes the following sidecar binaries in the
Windows and Mac installers. They run as separate processes (or a signed DLL loaded
via the Permitted API). This is aggregation, not a combined work.

The sing-box source archive is included in each shared release. Its upstream
source is unchanged; `offveil-core/tools/singbox` contains the dependency lock
and build recipe used for both platforms. Source and dependency checksums are
verified before building, and a source vulnerability scan must pass.

Darwin sidecars are **not** in the Windows installer. Same tags, different
builds: sing-box from the same pinned source and ByeDPI `v0.17.3` with `make`
(`build-byedpi-darwin.sh`). The Linux `*-aarch64.tar.gz` ByeDPI release is
not used. The Darwin ByeDPI build applies the Apple-only outbound interface
binding patch in `offveil-core/patches/byedpi-darwin-bind-interface.patch`.
Its source and rationale are in `docs/mac-reliability.md`; upstream MIT notices
are preserved. The Windows binary is unmodified.

## sing-box (GPL-3.0-or-later)

| | |
|---|---|
| Upstream | https://github.com/SagerNet/sing-box |
| Tag | `v1.13.14` |
| Release source asset | `sing-box-1.13.14-source.zip` |
| Source module checksum | `h1:p9/eqwilCgzyR/DpKM8hq7ppvzPIq1QMLgZWT3Cbg10=` |
| Binary | `sing-box.exe` / `sing-box` (general network tunnel) |
| Build | Go 1.26.10; security-updated dependency lock in `offveil-core/tools/singbox` |
| License files | `offveil-core/third_party/sing-box/LICENSE`, `COPYING` (GNU GPL-3.0) |
| Source | https://github.com/SagerNet/sing-box/tree/v1.13.14 |

## ByeDPI / ciadpi (MIT)

| | |
|---|---|
| Upstream | https://github.com/hufrea/byedpi |
| Tag | `v0.17.3` |
| Asset | `byedpi-17.3-x86_64-w64.zip` |
| ZIP SHA-256 | `70d2c94147193cb915f9c6eb5144b8d404dacbcfa90bda2383b6b211afafa456` |
| Binary | `ciadpi.exe` (local SOCKS desync) |
| License file | `offveil-core/third_party/byedpi/LICENSE` |

## Wintun (Prebuilt Binaries License, WireGuard LLC)

| | |
|---|---|
| Upstream | https://www.wintun.net/builds |
| Version | `0.14.1` |
| ZIP SHA-256 | `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51` |
| Binary | `wintun.dll` (amd64) |
| License file | `offveil-core/third_party/wintun/LICENSE.txt` |

Redistribution is allowed only alongside software that uses Wintun via the
Permitted API (`wintun.h`). offveil loads the official DLL that way; the DLL
is not modified.

## Instrument Sans (SIL Open Font License 1.1)

Bundled in the UI as a self-hosted variable font (`@fontsource-variable/instrument-sans`).

| | |
|---|---|
| Upstream | https://github.com/Instrument/instrument-sans |
| License | SIL OFL 1.1 |
| Notice | Copyright 2022 The Instrument Sans Project Authors |

The OFL text is included in the app as `licenses/instrument-sans-LICENSE.txt`
and in source under `offveil-ui/src-tauri/bundle-bin/`. The font is not sold
by itself.

## Other (not redistributed as sidecar binaries)

The isolated packet regression module in `offveil-core/tests/tunudp` uses
`sing-tun v0.8.11` and `sing v0.8.11` (GPL-3.0-or-later), plus SagerNet's
gVisor fork (Apache-2.0), pinned to the bundled sing-box's stack versions.
These are test dependencies in a separate Go module; they are not linked
into offveil-core or included as test executables in the installer. Go module
downloads retain upstream license files. The Windows test runner stages a
private source copy and replaces only the automatic firewall-rule installer
with an inert fixture. Packet processing and reassembly use upstream code.

Go, Rust, Tauri, React, and other build/runtime libraries follow their own
licenses (typically MIT / Apache-2.0 / BSD). See `go.mod`, `Cargo.lock`, and
`package-lock.json`.
