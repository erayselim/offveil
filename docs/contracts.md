# Core contracts

This describes 1.1.0. IPC envelopes remain version 1; network policy files use
schema 3. See [network architecture](network-architecture.md).

## Process and privilege model

The unprivileged Tauri UI talks only to the local core service. Core owns DNS,
capture and child processes. Windows uses `LOCAL SYSTEM` and a demand-start
`offveil-core` service; macOS uses a root LaunchDaemon. Protection is started and
stopped explicitly. The UI does not configure adapters, routes or DNS.

Windows IPC is `\\.\pipe\offveil-core`, with LocalSystem and Authenticated Users
access, no Anonymous/Everyone, and remote pipe clients rejected. On macOS the
root socket is `/var/run/offveil/core.sock`; interactive use is under the temp
directory, overridable with `OFFVEIL_IPC_SOCK`. Permissions are same-user or the
authorized setup group. There is no remote control endpoint.

## IPC

Requests are line-delimited JSON:

```json
{"id":"request-id","method":"status","params":{}}
```

Responses preserve the request ID and return either a result or an RPC error:

```json
{"id":"request-id","ok":true,"result":{}}
```

```json
{"id":"request-id","ok":false,"error":{"code":"not_running","message":"Core protection is stopped"}}
```

| Method | Parameters | Result |
|---|---|---|
| ping / health | none | version, contracts_version, service |
| start | optional mode: auto | Status |
| stop | none | Status |
| restart | none | Status after stop/start |
| status | none | Status |
| test | optional targets: hostname array | endpoint diagnostic report; never changes routes or policy |
| diagnostics | none | DiagnosticsBundle with the redacted report inline |
| repair | none | stopped Status plus best-effort restore steps |
| shutdown | none | stops protection and the demand-start service |

Error codes are `not_running`, `already_running`, `privilege`, `tun_failed`,
`engine_failed`, `internal` and `bad_request`. `mode` accepts only `auto`.
IPC readiness is part of service readiness. Unexpected listener loss cleans up
owned network state and exits unsuccessfully for the supervisor to handle.

### Status

```json
{
  "state":"active",
  "protection":true,
  "summary":"Açık",
  "outbound_hint":"desync",
  "since":"2026-10-27T00:00:00Z",
  "targets":[
    {"id":"tcp","label":"TCP","outcome":"ok","path":"desync"},
    {"id":"udp","label":"UDP","outcome":"ok","path":"direct"}
  ],
  "last_error":null,
  "health":"ok",
  "network":{
    "mode":"selective",
    "coverage":"dns_web_desync",
    "dpi":"present",
    "layers":{"dns":"up","tcp":"up","tunnel":"off"},
    "groups":[
      {"id":"discord","label":"Discord","kind":"persistent","path":"desync","healthy":true,"checked":true}
    ],
    "tcp_path":"desync",
    "udp_path":"direct",
    "ipv4":true,
    "ipv6":false,
    "healthy":true
  }
}
```

States are `stopped`, `starting`, `active`, `degraded`, `stopping`. Only a
broken session is `degraded`: the DNS stub is down, or a required component
used up its restart budget. Everything else is `active` and `network.reason`
explains it:

| `network.reason` | Summary | Meaning |
| --- | --- | --- |
| (none) | Açık | All layers up, persistent canaries open |
| `dns_only_fallback` | Sınırlı koruma | Filtering measured, TCP layer could not start; DNS still on |
| `group_unreachable` | Sınırlı koruma | A persistent group opens on no path |
| `offline` | Bağlantı yok | Neutral controls fail on the physical interface too |
| `recovering` | Yeniden bağlanıyor | A required component is restarting (`transition=transport_recovery`) |
| `dns_unavailable`, `component_unavailable` | Bozuldu | Broken; `last_error` is set |

`network.mode` is `dns_only` (no filtering measured, no TUN), `selective` (TUN
and helper) or `fallback`. `layers.tunnel` is `off`, `ready` (a tunnel exists
in the gateway) or `up` (a group uses it). `groups[].path` is `desync`,
`tunnel` or `direct` (DNS-only modes). Group IDs and labels come from the signed
ruleset. The 1.0.4 beta `remote`/`local` modes and `remote_transport_unavailable`
reason are still understood by the UI for mixed-version installs.

The optional `transition` field identifies automatic `network_heal` or
`transport_recovery`. A full-stack heal can temporarily have `state=stopped`
or `starting` and `protection=false`; the UI shows reconnection while the
operation is pending. Explicit Stop clears it and cancels the pending restart.

Optional diagnostics fields include `capture`, `dns`, `desync`, `tunnel`,
`ruleset`, `expand`, `udp`, `heal` and `network`. New fields remain optional
for older IPC clients.

### Test and support results

IPC `test` reports ASN/ISP metadata and rows with target, class, expected path and
classification completion. `ok=true` does not mean the chosen bypass works.
This request runs outside the lifecycle lock and cannot publish after its
session has stopped or changed. It never changes network identity or routing.

A DiagnosticsBundle has path, created_at, sha256, version, optional note and
`report`: the same redacted document that is written to the ZIP. Unprivileged
collectors use `report` and never read the root-owned diagnostics directory.
The ZIP contains diagnostics.json, summary.md and manifest.json. The digest
covers diagnostics.json. Exports preserve the last active session after Stop,
but always state current protection separately. A new failed startup replaces
an older successful snapshot so its error remains visible.

Durable failure events (last 64) include classification changes, layer start
and fallback, adapter readiness, strategy trials, group escalation and WARP
endpoint results. They survive daemon exits and offline collection.

## Routing and verification

System DNS uses the local stub at `127.0.0.1:53`. Windows steers the resolver
with catch-all NRPT; macOS snapshots and sets eligible physical-service DNS
with `networksetup`. The gateway sends its own DNS to the stub on every
platform. Upstreams are tried Google first (EDNS Client Subnet keeps CDN answers
local), then Quad9, then Cloudflare, with a race after 150 ms and a circuit
breaker to plain DNS. Known poisoned answers are dropped; the signed ruleset can
add fingerprints. While the TCP layer is up the stub answers AAAA with NODATA
and strips IPv6 hints, so protected web traffic stays on IPv4.

At startup core probes neutral controls and the first host of each canary group
over the physical interface. If every canary opens, only the DNS layer runs. If
any canary is reset, dropped, throttled or tampered with, the TCP layer starts.
DNS-only sessions re-measure every five minutes and after a network change.

The TCP layer captures public IPv4 only. IPv4 TCP 80/443 goes to the local
helper, whose first group leaves connections untouched; ByeDPI applies the
strategy only after a reset, timeout or missing ServerHello and caches the
destination. UDP and QUIC stay direct. Exclusions (game stores, OS updates,
banks, government sites) always go direct.

Canary groups are probed through the gateway every 30 s (crisis groups every
fifth round). Two failed rounds start a strategy scan aimed at that canary; a
candidate must open the canary without breaking the controls and is verified on
the real helper and gateway before it is kept. If no strategy works, that group
alone moves to the tunnel. The tunnel is prepared off the lifecycle lock: WARP
registration over the physical interface, then endpoint preflight across
documented hosts and UDP ports. Group paths switch at runtime through sing-box
selectors over a loopback API with a per-process secret; the TUN is not rebuilt.

Failure classes distinguish timeout, EOF, reset, refused, certificate,
configuration and other dial/probe failures. A handshake slower than three
seconds on an otherwise healthy line counts as throttling.

## Network policy format

```json
{
  "schema_version":3,
  "version":8,
  "network":{"control_hosts":["www.cloudflare.com","www.microsoft.com","example.com"],"routes":[]},
  "canaries":[{"id":"discord","label":"Discord","kind":"persistent","probe_hosts":["discord.com"],"domain_suffix":["discord.com"]}],
  "exclude":["steampowered.com"],
  "strategies":[{"id":"byedpi:fake-ttl4","platform":"windows","args":["--disorder","1","--fake","-1","--ttl","4"]}],
  "poison_ips":[]
}
```

See [ruleset/README.md](../ruleset/README.md) for field limits. Schema/version
checks apply to embedded, adjacent, cached and remote content. Remote/cache
content requires a valid Ed25519 signature. Strategy arguments are filtered by a
flag allowlist; listen, bind, daemon and file options are refused.

Strategy evidence is scoped to ASN and physical fingerprint in a new namespace;
entries chosen against neutral controls by older versions are not reused.

## Lifecycle and cleanup

Each protection session has a generation and cancellation context. Stop,
replacement and self-heal invalidate background work. Status and diagnostics
remain available from immutable snapshots during startup/repair. Slow probes,
strategy scans, tunnel preparation and component recovery run outside the
lifecycle lock. Late sessions are closed rather than adopted.

Before a gateway starts, core removes a stale `offveil` Wintun adapter. It then
waits up to 20 s for the adapter while the gateway is alive; a gateway exit ends
the wait at once and its log class is journaled. A network change on the same
physical interface restarts only the helper (new source address) and
re-measures; a different interface rebuilds the stack.

Core uses kill-on-close child ownership and one Wait per process. Cleanup is
best-effort in reverse ownership order: gateway and helper, resolver, capture,
job. No credentials, public IPs, SSID, account data, raw provider responses or
browsing DNS history enter support exports.
