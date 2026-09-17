# Core contracts

UI and core follow these schemas. Bump `contracts_version` on a breaking
IPC change.

Go orchestrator + sing-box + ByeDPI sidecar. UI is Tauri 2.

## 1. Process model

```text
[offveil-ui]  --IPC-->  [offveil-core service]
                              |
                              |- manages sing-box
                              `- manages ciadpi (ByeDPI child)
```

Windows: named pipe `\\.\pipe\offveil-core` → `offveil-core` Windows Service.
Darwin: unix socket `/var/run/offveil/core.sock` → root LaunchDaemon
(`KeepAlive` false, `RunAtLoad` false).

- The UI does not touch TUN, DNS, or routes.
- Core runs as `LOCAL SYSTEM` (Windows) or root (Darwin), or an equivalently privileged service account.
- IPC is localhost only. No remote clients.
- Per-machine NSIS registers `offveil-core` (StartType=manual). The UI runs
  `asInvoker`. After install the UI starts the service with `StartService`
  (no UAC; Authenticated Users are granted `SERVICE_START`). Elevated
  `offveil-core setup` is only a fallback if the SCM entry is missing or
  its DACL rejects start. After that the UI talks over the pipe.
- Darwin: `offveil-core setup` is one-time admin (`osascript` with
  administrator privileges; not a Network Extension, not a `.pkg` for this
  phase). It installs `/Library/LaunchDaemons/offveil-core.plist`, copies
  the binary under `/Library/Application Support/offveil`, creates group
  `offveil`, and writes `/etc/sudoers.d/offveil` so `%admin` may
  `start`/`stop` without a password (SERVICE_START analogue). UI open:
  `launchctl load` + `start`. UI `shutdown`: launchd `unload`. Boot does
  not start the daemon.

## 2. IPC (UI <-> core)

Transport:
- Windows: named pipe `\\.\pipe\offveil-core`. Protected DACL: LocalSystem + Authenticated Users. Remote clients rejected (`FILE_PIPE_REJECT_REMOTE_CLIENTS`).
- Darwin: pathname unix socket `/var/run/offveil/core.sock` when running as root; interactive/CI uses `$TMPDIR/offveil-<uid>/core.sock`. Non-root clients dial the root socket when it exists. Override: `OFFVEIL_IPC_SOCK`. Mode `0600` (same-user) or `0660` owned by the setup user / group `offveil`. No abstract sockets; no remote.

Encoding: request/response JSON. Envelope and methods are the same on both OS.

### 2.1 Envelope

```json
{
  "id": "uuid-or-monotonic",
  "method": "status",
  "params": {}
}
```

```json
{
  "id": "uuid-or-monotonic",
  "ok": true,
  "result": {}
}
```

Error:

```json
{
  "id": "uuid-or-monotonic",
  "ok": false,
  "error": {
    "code": "not_running",
    "message": "Core protection is stopped"
  }
}
```

### 2.2 Methods

| Method | Params | Result | Notes |
|--------|--------|--------|-------|
| `ping` | | `{ "version", "contracts_version", "service" }` | Liveness |
| `health` | | same as `ping` | Alias |
| `start` | `{ "mode"?: "auto" }` | `Status` | Start cascade |
| `stop` | | `Status` | Clean shutdown |
| `restart` | | `Status` | Stop then start (UI "Yenile"; no `already_running`) |
| `status` | | `Status` | Snapshot (includes `health`) |
| `test` | `{ "targets"?: string[] }` | `TestReport` | Connection test |
| `diagnostics` | | `DiagnosticsBundle` | PII-safe zip path (`path`, `sha256`, `created_at`) |
| `repair` | | `{ "status": Status, "steps": [...] }` | UI "Revert changes": stop protection, restore leftover DNS/NRPT/adapter, flush DNS cache, clear learned DPI policy. Best-effort; does not reset Winsock or other apps. |
| `shutdown` | | `{ "ok": true }` | Stop protection and the demand-start service (UI exit; Windows SCM / Darwin launchd unload, no admin prompt) |

Pipe (Windows): `\\.\pipe\offveil-core`. Protected DACL: LocalSystem + Authenticated
Users. Remote clients rejected (`FILE_PIPE_REJECT_REMOTE_CLIENTS`).

Socket (Darwin): see Transport above. JSON methods are unchanged.

`mode` is `"auto"` only. No other modes are exposed.

### 2.3 `Status`

```json
{
  "state": "stopped | starting | active | degraded | stopping",
  "protection": false,
  "summary": "Açık",
  "outbound_hint": "desync",
  "since": "2026-07-20T20:00:00Z",
  "targets": [
    {
      "id": "discord",
      "label": "Discord",
      "outcome": "ok | probing | failed | unknown",
      "path": "direct | desync | tunnel | none"
    }
  ],
  "last_error": null
}
```

The UI shows `state`, `protection`, `summary`, `targets[].outcome`. `path`
is for diagnostics.

Optional fields (UI may ignore; diagnostics uses them):

- `capture`: TUN (`adapter_name`, `routes_applied`, `egress`, ...)
- `desync`: ByeDPI SOCKS
- `tunnel`: selective WARP/Reality SOCKS (`retry_hint` maps to UI "Yenile")
- `ruleset`: signed package (`version`, `source`, `sha256`)
- `expand`: DNS-observed domain expand (half-loaded CDN)
- `udp`: `voice_path` (`direct|desync|tunnel`) + `quic` (`drop`)
- `heal`: network change / sleep-resume self-heal

`start` runs a curated probe at session begin. `outbound_hint` and
`targets[].path` come from cache. `test` returns `TestReport` (ASN + rows).

Main screen is `protection` + `summary` (plus tunnel `retry_hint`). Copy is
`Açık` / `Kapalı` / `Bozuldu`. Broken state has one action, "Yenile"
(`restart`). Close / Exit sends IPC `shutdown` (demand-start service).

### 2.4 Error codes

| Code | Meaning |
|------|---------|
| `not_running` | `stop` / `test` while stopped |
| `already_running` | `start` again |
| `privilege` | Missing service/TUN rights |
| `tun_failed` | TUN did not come up (Wintun / utun) |
| `engine_failed` | sing-box or ByeDPI crashed |
| `internal` | Unexpected |

## 3. Policy model

### 3.1 Outbound

```text
direct | desync | tunnel
```

| Value | Where it runs |
|-------|----------------|
| `direct` | sing-box `direct` outbound |
| `desync` | sing-box -> `socks://127.0.0.1:<byedpi>` |
| `tunnel` | sing-box selective WG / Reality (allowlist only) |

### 3.2 Cascade

```text
start
  -> DoH always (system DNS → local stub; not ISP)
  -> ByeDPI + TUN always (TCP/443 → desync; UDP → direct; exclude/LAN excepted)
  -> curated probe applies to special packages only (Discord/IMVU)
       open?        -> that package UDP direct (HTTPS still desync)
       sni/dpi?     -> that package UDP desync
       ip/desync fail? -> that package suffix → selective tunnel
  -> canary probe (background; youtube/instagram/x/tiktok/telegram)
       throttle_suspect / ip_drop → those suffixes → selective tunnel
       else stay on default HTTPS desync (no special UDP)
  -> default HTTPS never follows Discord's path
```

While protection is on, system DNS queries go to `127.0.0.1:53`. Windows:
catch-all NRPT namespace `.`. Darwin: `networksetup -setdnsservers <service>
127.0.0.1` on Wi-Fi / Ethernet / Thunderbolt (not utun / VPN;
`networksetup` does not list utun). `/etc/resolver/` is not used. The stub
answers over DoH. TUN installs split-default (`0.0.0.0/1` + `128.0.0.0/1`)
so unlisted TCP/443 hits local ByeDPI; this is not `0.0.0.0/0` WARP.
Leak-guard (NIC `SetDNS`) is off. Stop, crash-cleanup, `repair`, and
uninstall must undo that rewrite — leftover `127.0.0.1` blackholes DNS.
Windows removes the NRPT rule. Darwin restores the snapshot or `empty`, then
`killall -HUP mDNSResponder`. iCloud Private Relay / Limit IP tracking
override manual DNS; diagnostics records them; core does not disable them.
Split-default routes go away with the TUN.

### 3.3 Cache record

```json
{
  "key": "asn:9121|discord.com",
  "path": "desync",
  "class": "dpi_reset",
  "strategy_id": "byedpi:default-safe",
  "updated_at": "2026-07-20T20:00:00Z",
  "ttl_seconds": 86400
}
```

- ISS/ASN change invalidates related cache.
- TTL expiry triggers a silent re-probe.
- TTL by class: `retry` 15 min, `dpi_reset`/`desync` 6 h, `direct`/`open` 24 h.
- Tunnel: primary provider fail falls over to the other (WARP <-> Reality).
  UI shows "Yenile" only after both are exhausted.
- Desync fail goes to tunnel.
- Desync probe fail runs a limited auto-strategy scan (~40s). The winner is
  stored under the ASN in `desync-strategies.json`.

### 3.4 DIRECT (never tunnel/desync)

- Private / LAN
- Steam / Riot / Epic / Faceit store+launcher suffixes (ruleset `path_force: direct`)
- Generic UDP (game servers are not on the domain list; protocol split is the protection)

## 4. Probe protocol

Classify the block and pick an outbound. Raw socket detail does not go to
the UI.

### 4.1 Classes

| Class | Observation | Next path |
|-------|-------------|-----------|
| `open` | DoH IP + TLS handshake OK | `direct` |
| `dns_poison` | Known censor IP / NXDOMAIN / inconsistent A | Force DoH, then try TLS |
| `dpi_reset` | RST / early close after ClientHello | `desync` |
| `ip_drop` | SYN timeout / blackhole | `tunnel` |
| `timeout` | Unclear | desync, then tunnel |
| `throttle_suspect` | Extremely slow TLS | prefer `tunnel` |

### 4.2 Steps (per target)

1. Resolve A/AAAA over DoH. Check poison fingerprints and NXDOMAIN/empty
   (`195.175.254.2` and similar).
2. Short TCP+TLS SNI probe (timeout ~3-5s). Try at most 2 A records.
3. Control-host differential (default `www.microsoft.com`): control open +
   target unclear raises DPI suspicion. If the control is also down, do not
   pick aggressive tunnel.
4. Write class, pick path, cache (`confidence` 0-1).
5. Optional verify after the path is applied (HTTP HEAD / Discord API):
   `VerifyHTTP`.
6. Session `Chosen` is the most expensive path among results
   (`tunnel` > `desync` > `direct`).

### 4.3 `TestReport` (connection test)

```json
{
  "asn": "9121",
  "isp_hint": "Turk Telekom",
  "results": [
    {
      "target": "discord.com",
      "class": "dpi_reset",
      "path": "desync",
      "ok": true
    }
  ]
}
```

## 5. Ruleset format

File: `ruleset/active.json`. Signature: `active.json.sig` (Ed25519, base64).

```json
{
  "version": 6,
  "updated_at": "2026-09-01",
  "packages": [
    {
      "id": "discord",
      "label": "Discord",
      "default_enabled": true,
      "domains": [
        "discord.com",
        "discordapp.com",
        "discord.gg",
        "gateway.discord.gg",
        "cdn.discordapp.com",
        "media.discordapp.net"
      ],
      "domain_suffix": [
        ".discord.com",
        ".discordapp.com",
        ".discord.gg",
        ".discordapp.net",
        ".discord.media"
      ],
      "resolve_hosts": ["discord.com", "gateway.discord.gg", "latency.discord.media"],
      "probe_hosts": ["discord.com"],
      "notes": "Voice: domain_suffix .discord.gg / .discord.media; UDP mirrors cascade; sniffed QUIC drop"
    },
    {
      "id": "imvu",
      "label": "IMVU",
      "default_enabled": true,
      "domains": [
        "secure.imvu.com",
        "api.imvu.com",
        "webasset-akm.imvu.com",
        "userimages-akm.imvu.com"
      ],
      "domain_suffix": [".imvu.com", ".im.vu"],
      "resolve_hosts": [
        "secure.imvu.com",
        "webasset-akm.imvu.com",
        "userimages-akm.imvu.com"
      ],
      "probe_hosts": ["secure.imvu.com"],
      "notes": "legacy-cdn: Classic ignores system proxy; TUN + CDN expand"
    }
  ]
}
```

Package tags: `discord`, `canary`, `legacy-cdn`, `direct-games`, ...
`kind: "canary"` is not a status card; probe is background; only
`throttle_suspect` / `ip_drop` send its suffixes to the selective tunnel.

### 5.1 Update channel

`ruleset/channel.json` plus the embedded copy:

| Field | Meaning |
|-------|---------|
| `base_url` | GitHub Release / CDN prefix |
| `ruleset_file` / `signature_file` | `active.json` + `active.json.sig` |
| `public_key_hex` | Ed25519 public (32-byte hex) |
| `update_interval_hours` | Default 24 |

Load order: cache (`%ProgramData%\offveil\ruleset`) then beside-exe then
embedded then optional remote. Remote is applied only after signature
verify. `OFFVEIL_RULESET_URL` overrides `base_url`.
`OFFVEIL_RULESET_SKIP_UPDATE=1` skips remote.

Core turns enabled packages into capture resolve / probe / sing-box route
lists.

DNS stub query watch -> `MatchPackage` / `ExpandForHost` -> capture
`AddPrefixes` (legacy CDN half-load). Discord voice UDP follows the special
package path (`direct` / ByeDPI SOCKS5 UDP ASSOCIATE / sing-box SOCKS to
tunnel). Generic UDP stays on the ISP path. Sniffed QUIC is rejected in
sing-box so HTTPS falls back to TCP TLS; raw UDP/443 is not dropped.
Network change or sleep triggers silent self-heal (Windows power notifications;
Darwin `kern.waketime` / freeze-gap, no IOKit/CGO).

## 6. Engine wiring

### 6.1 sing-box

- TUN inbound with split-default `route_address` (`0.0.0.0/1` + `128.0.0.0/1`, never `0.0.0.0/0`). `auto_route` on. Windows: Wintun `interface_name` `offveil`. Darwin: omit `interface_name` (sing-box picks `utunN`; `"offveil"` is a bad tun name). Go capture is snapshot-only (`SkipAdapter`).
- DoH / DNS hijack
- Route: TCP/443 → `desync`; UDP → `direct`; Steam/Riot/Epic/Faceit + LAN exclude; special suffixes may `tunnel`
- Sniffed QUIC reject (not port 443) so HTTP/3 falls back to TCP TLS
- Selective tunnel outbound(s) for special IP-drop and canary throttle/IP-drop suffixes
- Sidecar: `sing-box.exe` (Windows) / `sing-box` (Darwin). Same release tag; Darwin asset `sing-box-*-darwin-arm64.tar.gz`.

### 6.2 ByeDPI

- Local SOCKS listener
- Default safe strategy set. Windows: `byedpi:windows-safe` (fake+ttl via `--auto ssl_err`). Darwin: `byedpi:darwin-safe` (`--split 1 --disorder 3+s --mod-http=h,d --auto=torst --tlsrec 1+s`; no `--fake` / `--ttl`)
- Auto-strategy: `ScanCandidates` (Windows) or `ScanCandidatesDarwin` (adds `--oob`; never fake/ttl) + ASN cache; no UI parameters
- Sidecar: `ciadpi.exe` (Windows, official zip) / `ciadpi` (Darwin, `make` from the same tag). Linux aarch64 tarball is not used. Ad-hoc `codesign --force -s -` after every copy on Darwin.

### 6.3 Not used

- sing-box Windows WinDivert bridge / TLS-spoof paths
- Full default-route VPN (`0.0.0.0/0` WARP). Catch-all NRPT is DNS-only.
  TUN split-default feeds local ByeDPI; unlisted sites do not go to WARP.
- Strategy knobs in the UI

## 7. Privacy

- No telemetry.
- Diagnostics zip is a local file (`%ProgramData%\offveil\diagnostics` on
  Windows, `/Library/Application Support/offveil/diagnostics` on Darwin);
  the user shares it if they want.
- Contents: ASN, ISP hint, fingerprint hash, cascade path, probe class,
  scrubbed error_class. No public IP, SSID, MAC, user path, or credentials.
- Anonymous probe sharing, if added, is opt-in.

## 8. Versioning

- This file's `contracts` major: bump on breaking IPC/field changes.
- `contracts_version = 1` (carried in `ping` / `status`).

## 9. Crash cleanup

Protection rewrites system DNS so queries go to the local stub (`127.0.0.1:53`).
If that rewrite survives the core process, every name lookup blackholes.

The same LIFO registry (`internal/cleanup`) runs on:

- IPC `stop` / `shutdown`
- service manager stop (Windows SCM / Darwin launchd unload)
- panic recovery (`crashlog.Guard`)
- `repair` and `uninstall`

Order: sidecars (ByeDPI, sing-box, process group / Job Object), routes,
adapter, DNS restore. Errors are logged, not fatal.

The undo file (`dns-restore.json` under the machine data dir) is written
*before* DNS is rewritten. Stop / crash / repair / uninstall must apply it
(Windows: catch-all NRPT; Darwin: `networksetup` snapshot or `empty`, then
`killall -HUP mDNSResponder`). A leftover `127.0.0.1` resolver is treated
as a defect, not as "protection still on". Darwin repair also drops leftover
split-default routes that still point at `10.87.0.1/30`. Orphan `utun` without
an owning FD cannot be destroyed (no Wintun `CloseOrphanAdapter`). Uninstall
unlinks an idle `/var/run/offveil/core.sock`.
