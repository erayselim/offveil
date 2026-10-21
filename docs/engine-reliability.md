# Engine reliability

The beta.4 core owns one protection session. Application names, package
availability and endpoint diagnostic failures are not global routing inputs.
See [network architecture](network-architecture.md) and [contracts](contracts.md).

## Ownership and cancellation

Each accepted session has a generation and cancellation context. Public lifecycle
requests also invalidate pending automatic restarts. Stop, crash cleanup and
self-heal cancel the current session; old probes, trials and provider refreshes
cannot publish into its replacement. Child processes belong to the session's
job/context, while readiness and probe operations use shorter independent deadlines.

Status and diagnostics use immutable published snapshots while startup or repair
owns the lifecycle lock. Endpoint diagnostics, control checks, strategy discovery,
winner verification and component/provider restarts perform network work outside
that lock. A late started session is closed after Stop, not adopted.

Network fingerprint/ASN drift and power resume rebuild owned state after a bounded
settle/cooldown. A network change already observed by the periodic checker is
passed through to self-heal instead of requiring a second observation. Changes
inside the cooldown are delayed rather than discarded. Repair serializes restoration
with Start, and mocks restoration in unit tests to avoid host DNS/route changes.

## Components, transport and coverage

DNS, gateway/provider and local helper have independent process snapshots. DNS
and the gateway are required. The helper is required only for limited local
bypass; its exit cannot hide a required gateway exit or break healthy remote
traffic. Component restart has a bounded per-session budget. Resolver cleanup
always closes the current replacement session and restores its DNS changes.

Provider candidates run on a TUN-free loopback listener. Two of three independent
TLS control hosts are needed. User DIRECT exceptions and bootstrap route bypasses
do not apply to provider-only controls. Remote runtime checks verify both provider
and gateway; site diagnostics are isolated. A control round failure is confirmed
before replacing an accepted transport. Full public TCP/UDP coverage and limited
local HTTP/TLS coverage are reported separately from process liveness.

A failed remote preflight leaves a working local gateway intact. Switching
remote providers reuses the gateway. A verified local-to-remote promotion or
demotion changes the gateway once; failed promotion restores local routing.
Startup and periodic retries have explicit budgets and cooldowns. No repeated
application probes or guessed sibling host expansion run in the background.

The local strategy scanner keeps the accepted helper while isolated candidates
run. It uses a two-control quorum; one inaccessible endpoint cannot veto all
methods. A candidate must also pass on the real helper and gateway. Failure
rolls back. Scan markers belong to one operation/session and are cleared when
their helper is superseded. Accepted strategy evidence uses the network/profile
scope, never an old global application/ASN cache.

## Native dataplane

Windows uses mixed system TCP and gVisor UDP; macOS uses gVisor. Both address
families have TUN addresses, split-default routes and owned-subnet loop guards.
Remote mode passes opaque TCP, UDP and QUIC without domain/process matching.
Local mode sends recognizable HTTP/TLS to the local helper and leaves other
traffic direct. It cannot claim encrypted full-network coverage.

The selected physical interface pins direct and remote relay egress. Loopback
proxy and core-stub DNS dialers remain unpinned. Bootstrap/local exclusions avoid
resolver and transport recursion. The core observes DNS demand only as a bounded
count; it does not export browsing hostnames or prepare per-host capture routes.

Known transient Windows adapter conflicts receive bounded retry after the failed
child is reaped. Missing payload, permission and configuration errors are separate.
Readiness checks cannot replace routed acceptance: inspect actual Windows route
and interface MTU state if the physical TUN path fails.

## Support and verification

The redacted 64-event failure history survives process exits. Facts include build
and session generation, provider stage, target control, error class and exit origin.
EOF, reset, refused, certificate and timeout are distinct. A component `recovered`
event means process recovery; control quorum and coverage remain separate facts.
Failed startup remains visible even after a previous successful session.

Run from `offveil-core`:

```text
go test ./...
go vet ./...
go test -race ./internal/engine ./internal/desync ./internal/tunnel ./internal/dns ./internal/support ./internal/proc ./internal/capture
```

With `OFFVEIL_SINGBOX_TEST` set to the pinned binary, native fixtures check
configuration, core DNS forwarding, opaque TCP and UDP routing over owned
loopback peers. They generate `EnableTUN=false` for `sing-box run`. TUN-bearing
configurations are passed only to `sing-box check`. Fixtures do not install
adapters, change routes, rewrite DNS or contact an external relay.

`scripts/test-tun-udp.ps1` exercises the packet-level module without a physical
TUN; it verifies fragmentation/reassembly around the configured MTU. Its build
configuration must stay aligned with production's stack and MTU. A local TLS
fixture verifies the native desync argument sets; `check-payload` validates them.

Release acceptance still needs disposable Windows/macOS devices and affected
networks: real OS/TUN traffic over IPv4/IPv6, legacy TCP ports, UDP/QUIC, provider
failure/recovery, sleep/wake, reconnect, Stop and repair. Cross-compilation and
SOCKS fixtures do not prove those physical device paths or a particular ISP fix.
