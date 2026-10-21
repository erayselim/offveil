# Core contracts

This describes the application-independent 1.0.4-beta.4 version. Beta.3
artifacts use the previous routing policy. IPC envelopes remain version 1;
network policy files use schema 2. See [network architecture](network-architecture.md).

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
| diagnostics | none | DiagnosticsBundle |
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
  "outbound_hint":"tunnel",
  "since":"2026-10-21T00:00:00Z",
  "targets":[
    {"id":"tcp","label":"TCP","outcome":"ok","path":"tunnel"},
    {"id":"udp","label":"UDP","outcome":"ok","path":"tunnel"}
  ],
  "last_error":null,
  "health":"ok",
  "network":{
    "mode":"remote",
    "coverage":"public_tcp_udp_dual_stack",
    "tcp_path":"tunnel",
    "udp_path":"tunnel",
    "ipv4":true,
    "ipv6":true,
    "healthy":true
  }
}
```

States are `stopped`, `starting`, `active`, `degraded`, `stopping`. Protection
means the owned protection session is enabled; coverage is a separate fact.
Remote mode routes public TCP/UDP through a verified remote transport. Local
fallback is `degraded`, summary `Sınırlı koruma`, coverage `tls_http_only`,
TCP path `desync`, UDP path `direct`. A local provider retry is not itself a
broken local process. A required component loss or repeated failed control
quorum is a connection failure. The UI uses `network.reason` to distinguish it
from limited coverage, and preserves legacy error handling when the field is absent.

Optional diagnostics fields include `capture`, `dns`, `desync`, `tunnel`,
`ruleset`, `expand`, `udp`, `heal` and `network`. The IP family fields describe
capture configuration, not proof that every destination in that family works.
`targets` is an aggregate protocol view; individual failed site diagnostics do
not change it. New fields remain optional for older IPC clients.

### Test and support results

IPC `test` reports ASN/ISP metadata and rows with target, class, expected path and
classification completion. `ok=true` does not mean the chosen bypass works.
This request runs outside the lifecycle lock and cannot publish after its
session has stopped or changed. It never changes network identity or routing.

The support collector also works while the daemon is unavailable. The UI runs
`support -check-network` with a bounded overall timeout. It includes public
IPv4/IPv6 DNS/TCP/TLS/HTTP checks through current OS/TUN routes. Optional
`-check-url` and `-check-tcp` endpoints are explicit; no application endpoint or
download schema is built in. See [network diagnostics](network-diagnostics.md).

A DiagnosticsBundle has path, created_at, sha256, version and optional note.
The ZIP contains diagnostics.json, summary.md and manifest.json. The digest
covers diagnostics.json. Exports preserve the last active session after Stop,
but always state current protection separately. A new failed startup replaces
an older successful snapshot so its error remains visible.

## Routing and verification

System DNS uses the local stub at `127.0.0.1:53`. Windows steers the resolver
with catch-all NRPT; macOS snapshots and sets eligible physical-service DNS
with `networksetup`. NIC rewrite/leak guard is disabled. The shared sing-box
gateway delegates DNS to core's TCP loopback stub on Windows; standalone/macOS
helpers retain their configured resolver transport. Core races multiple DoH
upstreams and filters known poisoned replies. Stop/repair restores DNS state.

Public IPv4 and IPv6 use split-default capture. Local/private/bootstrap traffic
is excluded; the gateway has explicit owned-subnet loop guards. There are no
built-in game, voice, updater or application exceptions. Exact and suffix DIRECT
exceptions are optional user configuration.

Remote provider attempts happen on a separate SOCKS listener with TUN disabled.
At least two independent control hosts must pass certificate-verified TLS.
Provider-only probes cannot inherit DIRECT exceptions. Runtime remote checks
verify both provider and gateway quorums. A single control failure is tolerated;
two failed rounds are required to degrade an accepted path.

Remote coverage includes opaque TCP, arbitrary ports, literal IPs and UDP/QUIC.
When no provider works, local HTTP/TLS bypass is explicitly limited; other
traffic is direct and sniffed QUIC is rejected for TCP fallback. A working relay
is required to bypass transport/IP restrictions that local desync cannot fix.

`network.bypass_families` is IPv4/IPv6 in remote mode and IPv4 in local mode.
The current physical-source-bound local helper cannot proxy IPv6; these flows
remain direct. Local QUIC fallback is therefore limited to IPv4 as well.

Failure classes distinguish timeout, EOF, reset, refused, certificate,
configuration and other dial/probe failures. Provider facts retain safe stage,
control target and natural-versus-cleanup exit origin. `up` is process liveness;
`healthy` is measured control quorum. Neither is universal endpoint success.

## Network policy format

```json
{
  "schema_version":2,
  "version":7,
  "updated_at":"2026-10-21",
  "network":{
    "control_hosts":["www.cloudflare.com","www.microsoft.com","example.com"],
    "routes":[]
  }
}
```

`network.routes` supports explicit `path: direct` exceptions, using `domains`
for exact names and `domain_suffix` for suffixes. Other paths and nonempty old
packages are rejected. Schema/version checks apply to embedded, adjacent,
cached and remote content. Remote/cache content requires a valid Ed25519
signature. Missing or invalid remote content falls back to a valid local source.
Release CI signs source policy; a stale signature must not accompany changed data.

Local strategy evidence is scoped to network ASN, fingerprint and transport
profile in a new cache namespace. Old global application/ASN-only entries are
not applied to network-wide routing.

## Lifecycle and cleanup

Each protection session has a generation and cancellation context. Stop,
replacement and self-heal invalidate background work. Status and diagnostics
remain available from immutable snapshots during startup/repair. Slow probes,
strategy verification and component/provider recovery run outside the lifecycle
lock. Late sessions are closed rather than adopted.

Core uses kill-on-close child ownership and one Wait per process. Cleanup is
best-effort in reverse ownership order: gateway/provider, helper, resolver,
capture, job. Recovery cleanup targets the current replacement session, not a
captured old instance. Failed restoration prevents an overlapping replacement.

The last 64 redacted failure/recovery events survive daemon exits. No credentials,
public IPs, SSID, account data, raw provider responses or browsing DNS history
enter support exports. DNS observation is bounded, counts demand, never guesses
sibling hosts and never triggers probes for every system lookup.

Native fixtures use SOCKS-only configs; actual TUN/OS traffic and device cleanup
require physical acceptance. See [engine reliability](engine-reliability.md).
