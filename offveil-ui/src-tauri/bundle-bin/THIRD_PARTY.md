# Third-party components

offveil (Apache-2.0) redistributes the following sidecar binaries in the
Windows installer. They run as separate processes (or a signed DLL loaded
via the Permitted API). This is aggregation, not a combined work.

Corresponding source for GPL components is the pinned upstream tag, not a
fork. Hashes below are fail-closed in `offveil-core/scripts/fetch-*.ps1`.

## sing-box (GPL-3.0-or-later)

| | |
|---|---|
| Upstream | https://github.com/SagerNet/sing-box |
| Tag | `v1.13.14` |
| Asset | `sing-box-1.13.14-windows-amd64.zip` |
| ZIP SHA-256 | `f580782c6dd10f7691c66cea1d7c421813c5fbf7e305d1ee7ce0c3a40d196341` |
| Binary | `sing-box.exe` (SOCKS selective tunnel) |
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

## Other (not redistributed as sidecar binaries)

Go, Rust, Tauri, React, and other build/runtime libraries follow their own
licenses (typically MIT / Apache-2.0 / BSD). See `go.mod`, `Cargo.lock`, and
`package-lock.json`.
