# Engine reliability

The 1.1 core owns one protection session built from layers. Application names
and endpoint diagnostic failures are not routing inputs; signed canary groups
are. See [network architecture](network-architecture.md) and [contracts](contracts.md).

## Ownership and cancellation

Each accepted session has a generation and cancellation context. Public lifecycle
requests also invalidate pending automatic restarts. Stop, crash cleanup and
self-heal cancel the current session; old probes, scans and tunnel preparation
cannot publish into its replacement. Child processes belong to the session's
job/context, while readiness and probe operations use shorter independent deadlines.

Status and diagnostics use immutable published snapshots while startup or repair
owns the lifecycle lock. Classification is bounded to seven seconds. Group
probes, strategy scans, winner verification, WARP registration/preflight and
component restarts run outside that lock. A late started session is closed after
Stop, not adopted. At most one group repair runs at a time.

A physical network change or power resume is settled and debounced. On the same
interface only the helper restarts with the new source address and the network
is re-measured; the TUN stays. A different interface rebuilds owned state. Relay
or ASN drift alone never rebuilds.

## Components and layers

DNS is always required; a stopped stub is reported as broken at once. The helper
and gateway are required only while the TCP layer runs. A required component
that exits is restarted within a per-session budget; until the budget is spent
the status is reconnecting, not broken. Resolver cleanup always closes the
current replacement session and restores its DNS changes.

If the TCP layer cannot start (helper, gateway or adapter), protection stays on
with DNS only and the failure is journaled with stage and class. The layer is
retried three times, two minutes apart. A DNS-only session re-measures every
five minutes and starts the TCP layer when filtering appears.

## Groups, scans and the tunnel

Each canary group has a path (desync or tunnel), a failure count and a retry
time. Two failed rounds trigger a scan aimed at that group's canary: a candidate
must open it and keep two of three neutral controls working, in its deployed
pass-through-first form. The winner is verified on the real helper and gateway;
failure rolls back to the accepted helper. Evidence is cached per ASN and
physical fingerprint in a namespace that ignores older control-only results.

If no strategy opens the group, it moves to the tunnel. Preparation happens off
the lock; the gateway is rebuilt once only if it has no tunnel yet, otherwise a
selector switches the group. A failed tunnel marks the group unreachable for ten
minutes; a group that recovers on its own is marked healthy again.

## Native dataplane

Windows uses mixed system TCP and gVisor UDP; macOS uses gVisor. The TUN has an
IPv4 address only, split-default IPv4 routes and an owned-subnet loop guard. TUN
MTU is 9000 on Windows and 4064 on macOS; WireGuard keeps 1280 inside the tunnel.

The selected physical interface pins direct and tunnel egress. Loopback helper,
selector API and core-stub DNS dialers remain unpinned. Before a gateway starts,
a stale `offveil` adapter is removed; adapter readiness waits up to 20 s and ends
early if the gateway exits, recording the gateway's log class.

## Support and verification

The redacted 64-event failure history survives process exits. Events cover
classification changes, layer start/fallback, adapter readiness, strategy
trials, group escalation, WARP endpoint results and component recovery.

Run from `offveil-core`:

```text
go test ./...
go vet ./...
go test -race ./internal/engine ./internal/desync ./internal/tunnel ./internal/dns ./internal/support ./internal/proc ./internal/capture
```

With `OFFVEIL_SINGBOX_TEST` and `OFFVEIL_BYEDPI_TEST` set to the pinned
binaries, native fixtures check every gateway configuration with `sing-box
check`, switch group selectors on a live TUN-free gateway, and parse every
deployed ByeDPI chain. Fixtures do not install adapters, change routes, rewrite
DNS or contact an external relay.

Release acceptance still needs physical Windows/macOS devices on the affected
networks: real TUN traffic, downloads with protection on and off, sleep/wake,
network changes, Stop and repair.
