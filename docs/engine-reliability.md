# Engine reliability and bounded background work

The core owns protection sessions, background probes and sidecar processes.
This document describes their lifecycle and the checks that guard recovery
on Windows and macOS.

## Session ownership

Each accepted protection session has a generation and a cancellation context.
Stop, crash cleanup and internal self-heal invalidate that session. Canary,
periodic probes and delayed network/power notifications cannot publish into a
later session, even if an injected or slow operation ignores cancellation.
Public lifecycle requests separately invalidate pending automatic restarts.

The periodic network check can pass an already-detected change to self-heal.
It no longer depends on observing the same change a second time after policy
adopted it. Changes arriving during the heal cooldown are delayed within the
same session rather than discarded. The IPv4 fingerprint probe selects a
source through an address already excluded from offveil's TUN routes; UDP
connect does not send a packet. This prevents the TUN's own source address
from masking physical egress changes.

Repair holds the lifecycle lock through network restoration and policy reset,
so a new start cannot install a stack midway through repair. Status and
diagnostics continue to use the published operation snapshot while it runs.

Canary results replace the last result for each host. The retained report
preserves special-package results and remains independent of reports already
returned to an IPC caller. Repeated checks do not accumulate duplicate rows.

## Child processes and Windows power callbacks

The process helper owns exactly one `exec.Cmd.Wait` call per started sidecar.
It reaps natural exits, supports concurrent close, notices startup exits
before the SOCKS timeout, and bounds inherited output-pipe draining with
`WaitDelay`. Sidecar status reflects process completion; status/health reads
mark protection degraded when a live component has stopped. A two-second
watcher retries only the failed component, at most twice per session with a
five-second cooldown. ByeDPI recovery keeps a healthy TUN running. The last
64 failure/recovery events survive daemon restarts; support includes exit
codes, allowlisted adapter reasons, candidate/target/provider outcomes and
build/session generations, never raw sidecar logs. Discord and IMVU are
validated separately before selecting their fallback paths.

After a protected path or secondary endpoint fails, the local dataplane stays
available while a background strategy search runs. Its default network-work
budget is 32 seconds, at most six seconds per trial including startup and
target checks, followed by bounded process teardown. Two isolated helpers run
concurrently; each checks at most four hosts concurrently. A slow first
candidate cannot starve all later methods. Trials use separate loopback ports, the same
physical source/interface binding and the session cancellation context.
They cannot change the live policy or turn a cancelled late result into a
winner. Status, diagnostics and stop remain available during network work.

A winner is verified again on the real helper port and through sing-box's
SOCKS dataplane for all protected probe hosts. Failure restores the previous
strategy; success updates the recovery configuration and ASN cache. A
strategy that passes Discord but fails IMVU is removed from the ASN cache.
Process recovery is suspended during the helper switch to avoid competing
processes on the same port. Stop and replacement sessions invalidate trials,
verification and rollback, including dependencies that return late.

An unavailable protected path is also checked through the running fallback
SOCKS dataplane every 30 seconds. Only successful TLS clears its error and
retry hint; independent canary failures remain degraded. This does not
repeatedly register WARP accounts or rebuild working capture routes. Local
desync probes resolve the destination before SOCKS CONNECT because ByeDPI
rejects domain CONNECT with `--no-domain`; TLS still uses the original SNI
and certificate validation.

While the local desync dataplane is active, background TLS checks also cover
Discord's updater, Gateway and download CDN once per minute. Only hosts owned
by the enabled signed package are contacted. A failure must repeat before
it invalidates the homepage-only ASN cache and starts discovery. The same
endpoints must pass candidate adoption and later path recovery. These are
TLS checks, not manifest/download or WebSocket validation.

If discovery cannot repair a new endpoint failure, a single provider promotion
per session replaces only sing-box, keeping the DNS stub and ByeDPI alive.
All service endpoints must pass before adoption; failure restores the local
dataplane. Cancellation prevents a late provider or rollback from taking over
a replacement session. Each launch owns a distinct temporary configuration,
removed on close, so overlapping canceled starts cannot overwrite each other.

Windows retries only known transient adapter-exists/removing/busy startup
errors, at most three attempts inside one eight-second readiness budget.
Permission, configuration and network failures are not treated as adapter
conflicts. A missing Wintun payload fails explicitly before launch.

Service startup waits for IPC listener readiness. An unexpected listener exit
runs owned network cleanup and terminates unsuccessfully so the supervisor
can apply recovery. Intentional stop cancels IPC before cleanup. Offline
Windows support reads SCM state/PID/exit codes, owned adapter presence and
Wintun file facts; `system.protection_state=unknown` distinguishes unavailable
daemon state from a measured disabled session.

Support retains `sidecars.tunnel_fallback` after a failed provider is replaced
by the local dataplane, including provider/class, bounded HTTP reason codes
and available process exit facts. `sidecars.desync_scan` records candidate
checks and the outcome of real-port verification. Provider response bodies
are not included. `protected_path_unavailable` is separate from `tun_failed`;
the word "tunnel" alone is not evidence of a TUN driver failure.

Go requires `Wait` after a successful `Start` and disallows concurrent `Wait`
calls. See the [Go process contract](https://pkg.go.dev/os/exec#Cmd.Wait) and
[`WaitDelay`](https://pkg.go.dev/os/exec#Cmd).

Windows uses one process-lifetime Go callback and distinct subscription IDs
in `DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS.Context`. Unsubscription removes the
handler without creating another Go callback or allowing an old context ID
to select a newer subscription. Go callback allocations are not released and
their count is limited; the native Windows subscription is still explicitly
unregistered. See [Go callbacks](https://pkg.go.dev/syscall?GOOS=windows#NewCallback),
[Windows subscription parameters](https://learn.microsoft.com/en-us/windows/win32/api/powrprof/ns-powrprof-device_notify_subscribe_parameters)
and [native unregistration](https://learn.microsoft.com/en-us/windows/win32/api/powerbase/nf-powerbase-powerunregistersuspendresumenotification).

## Repeated network work

Windows uses sing-box's `mixed` stack: system TCP and gVisor UDP. The pinned
system UDP parser discarded IPv4 fragments, so the 1280-byte capture MTU
could lose otherwise ordinary UDP datagrams. The mixed path reassembles
fragments before forwarding; macOS retains its existing full gVisor stack.
The selected physical interface now pins the direct outbound, while local
ByeDPI SOCKS remains unpinned. The owned offveil adapter cannot be selected
as egress even if it reports an Ethernet-like interface type. DNS hijacking
precedes a drop guard for the TUN's own subnet; private/direct exceptions
follow it so a packet cannot loop through the same capture interface.

The separate [packet test module](../offveil-core/tests/tunudp/README.md)
exercises the pinned runtime stack without creating a real TUN.

Windows explicitly opts out of seed resolution and host-prefix expansion
when sing-box owns split-default routes. Per-host capture configurations
retain seed resolution and expansion. Darwin already used this behavior.

Identical in-flight plain-DNS fallback questions now share work through the
same client as DoH, with separate transport keys. Each caller keeps its own
response ID, private response copy and cancellation. Plain responses are not
cached; the existing positive DoH cache, poison filtering, circuit timing and
upstream race remain in place. Network reset detaches both transports' old
flights. On Windows, sing-box delegates DNS to the already-running core stub
over literal loopback TCP, sharing its upstream failover and poison filtering.
The local DNS dialer remains unpinned; loopback and every core bootstrap DNS
IP are excluded from TUN capture. Standalone helpers and macOS retain their
existing DoH default. A pinned native sing-box fixture validates DNS hijacking
through the core TCP stub without installing a TUN or changing system DNS.

## Validation

Run from `offveil-core` on each supported platform:

```text
go vet ./...
go test ./...
go test -race ./internal/engine ./internal/dns ./internal/capture ./internal/proc ./internal/power ./internal/ipc ./internal/desync ./internal/tunnel ./internal/support ./internal/appservice
```

Repair unit tests use a fake restore operation to avoid modifying the host's
NRPT, DNS or adapter settings. Regression checks cover stale background
results, cancellation, cooldown changes,
repair/start ordering, bounded canary rows and report ownership, process
exit/close, power subscription ownership, split-default capture and fallback
coalescing/reset. Windows and macOS CI run the selected race checks.

The fallback regressions also cover a working Discord/failed IMVU pair,
multi-host candidate selection, startup/parent deadlines, failed-winner
rollback, cancellation during scan and verification, recovery without a
process restart, retained provider facts and redacted registration errors.

Windows CI also runs `scripts/test-tun-udp.ps1` and native sing-box UDP/config
checks. The packet module follows the config generator's stack/MTU, verifies
both directions and reversed fragments across the MTU boundary, and includes
the old system-stack failure as a controlled reproduction. Only its automatic
Windows firewall installer is stubbed in a private test source copy. Native
SOCKS tests separately check opaque UDP and interface binding with an owned
loopback echo peer. Neither fixture changes system DNS or capture routes.

For sidecar integration checks, start the bundled binaries on private SOCKS
ports and verify `up=false` after terminating each owned test process. Keep
this check separate from routed TUN traffic: a SOCKS-only sing-box session
does not validate system DNS or capture routes.

Cross-compilation checks build compatibility. Use the disposable macOS
runner's real protection smoke test to verify routed TUN HTTPS. Physical
devices are needed for Discord/IMVU voice, sleep/wake recovery and energy
measurements. Changes to the MTU, desynchronization strategies, tunnel
providers or platform-specific TUN stacks need traffic validation as well as
unit tests.

A SOCKS check cannot prove that an application's TUN or UDP path works.
