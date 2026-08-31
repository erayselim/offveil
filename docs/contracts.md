# Core contracts

UI and core follow these schemas. Bump `contracts_version` on a breaking
IPC change.

Go orchestrator + sing-box + ByeDPI sidecar. UI is Tauri 2.

## 1. Process model

```text
[offveil-ui.exe]  --named pipe-->  [offveil-core Windows Service]
                                         |
                                         |- manages sing-box (in-process or child)
                                         `- manages ciadpi.exe (ByeDPI child)
```

- The UI does not touch TUN, DNS, or routes.
- Core runs as `LOCAL SYSTEM` or an equivalently privileged service account.
- IPC is localhost named pipe only. No remote clients.
- Per-machine NSIS registers `offveil-core` (StartType=manual). The UI runs
  `asInvoker`. After install the UI starts the service with `StartService`
  (no UAC; Authenticated Users are granted `SERVICE_START`). Elevated
  `offveil-core setup` is only a fallback if the SCM entry is missing or
  its DACL rejects start. After that the UI talks over the pipe.

## 2. IPC (UI <-> core)

Transport: Windows named pipe `\\.\pipe\offveil-core`.
Encoding: request/response JSON.

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
| `shutdown` | | `{ "ok": true }` | Stop protection and the Windows service (UI exit, no UAC) |

Pipe: `\\.\pipe\offveil-core`. Protected DACL: LocalSystem + Authenticated
Users. Remote clients rejected (`FILE_PIPE_REJECT_REMOTE_CLIENTS`).

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
| `tun_failed` | Wintun did not come up |
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
  -> DoH always (system DNS → local stub via catch-all NRPT; not ISP)
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

While protection is on, Windows DNS Client queries go to `127.0.0.1:53` (NRPT
namespace `.`). The stub answers over DoH. TUN installs split-default
(`0.0.0.0/1` + `128.0.0.0/1`) so unlisted TCP/443 hits local ByeDPI; this is
not `0.0.0.0/0` WARP. Leak-guard (NIC `SetDNS`) is off. Stop, crash-cleanup,
`repair`, and uninstall must remove the catch-all NRPT rule — a leftover
would blackhole all DNS. Split-default routes go away with the TUN.

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
Network change or sleep triggers silent self-heal.

## 6. Engine wiring

### 6.1 sing-box

- TUN (Wintun) inbound with split-default `route_address` (never `0.0.0.0/0`)
- DoH / DNS hijack
- Route: TCP/443 → `desync`; UDP → `direct`; Steam/Riot/Epic/Faceit + LAN exclude; special suffixes may `tunnel`
- Sniffed QUIC reject (not port 443) so HTTP/3 falls back to TCP TLS
- Selective tunnel outbound(s) for special IP-drop and canary throttle/IP-drop suffixes

### 6.2 ByeDPI

- Local SOCKS listener
- Default safe strategy set
- Auto-strategy: `ScanCandidates` + ASN cache; no UI parameters

### 6.3 Not used

- sing-box Windows WinDivert bridge / TLS-spoof paths
- Full default-route VPN (`0.0.0.0/0` WARP). Catch-all NRPT is DNS-only.
  TUN split-default feeds local ByeDPI; unlisted sites do not go to WARP.
- Strategy knobs in the UI

## 7. Privacy

- No telemetry.
- Diagnostics zip is a local file (`%ProgramData%\offveil\diagnostics`);
  the user shares it if they want.
- Contents: ASN, ISP hint, fingerprint hash, cascade path, probe class,
  scrubbed error_class. No public IP, SSID, MAC, user path, or credentials.
- Anonymous probe sharing, if added, is opt-in.

## 8. Versioning

- This file's `contracts` major: bump on breaking IPC/field changes.
- `contracts_version = 1` (carried in `ping` / `status`).
