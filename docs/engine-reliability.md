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
16 failure/recovery events survive daemon restarts; support includes exit
codes and stderr classes, never raw sidecar logs. Discord and IMVU are
validated separately before selecting their fallback paths.

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

Windows explicitly opts out of seed resolution and host-prefix expansion
when sing-box owns split-default routes. Per-host capture configurations
retain seed resolution and expansion. Darwin already used this behavior.

Identical in-flight plain-DNS fallback questions now share work through the
same client as DoH, with separate transport keys. Each caller keeps its own
response ID, private response copy and cancellation. Plain responses are not
cached; the existing positive DoH cache, poison filtering, circuit timing and
upstream race remain in place. Network reset detaches both transports' old
flights. The sing-box DNS configuration is unchanged: rerouting that resolver
requires separate real-traffic validation for bootstrap and DNS loops.

## Validation

Run from `offveil-core` on each supported platform:

```text
go vet ./...
go test ./...
go test -race ./internal/engine ./internal/dns ./internal/capture ./internal/proc ./internal/power ./internal/ipc ./internal/desync ./internal/tunnel
```

Repair unit tests use a fake restore operation to avoid modifying the host's
NRPT, DNS or adapter settings. Regression checks cover stale background
results, cancellation, cooldown changes,
repair/start ordering, bounded canary rows and report ownership, process
exit/close, power subscription ownership, split-default capture and fallback
coalescing/reset. Windows and macOS CI run the selected race checks.

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
