# Windows DPI recovery and Discord endpoint coverage

Historical beta.3 investigation. The development version now uses
[application-independent network routing](network-architecture.md); the package
and endpoint selection below is retained as release history.

The 1.0.4-beta.2 support report contained repeated protected-path failures,
two sing-box exits classified as TUN setup errors and an offline export with
no core IPC listener. It did not contain the underlying Windows error or a
failed Discord HTTP request. These changes address reproducible recovery and
coverage gaps; they do not establish that the customer's line is fixed.

## Changes

- Ten Windows candidates now cover TCP SNI/header splits, middle-of-SNI TLS
  record splits, combined record/TCP splits and existing disorder/fake
  variants. The accepted default is retained until a replacement passes.
- Two isolated trial helpers prevent a slow first strategy from consuming
  the entire search. Per-host checks share the trial deadline concurrently;
  canceled workers are reaped and distinguished from network timeouts.
- Discord updater, Gateway and download CDN TLS checks run in the background
  while using local desync. Repeat failure invalidates the partial ASN cache
  and triggers discovery. Homepage success cannot clear an updater failure.
- If discovery fails, configured providers are tried once for that endpoint
  episode's session. Only sing-box is replaced. Failed promotion restores
  the local dataplane; verified adoption preserves independent failures.
- Windows sing-box DNS uses the core's loopback TCP stub, sharing its DoH
  upstream failover and poison filtering. Literal loopback and explicit
  capture exclusions avoid bootstrap recursion. Standalone/default and
  macOS resolver behavior are preserved.
- Known transient Windows adapter conflicts receive bounded retry after the
  failed child is reaped. Missing DLL, permission and configuration errors
  receive no blind retry. Every launch owns its configuration file.
- The service waits for a bound IPC listener. Unexpected listener loss
  cleans up owned state before failure exit. Offline support retains SCM,
  adapter and Wintun facts plus 64 safe failure events across daemon exits.

The endpoint monitor verifies TLS and certificates. The opt-in support
diagnostic still performs the fuller manifest, bounded download and
WebSocket checks. Native Discord's TLS implementation, process-specific
firewall behavior, complete updates and voice need device testing.

## Research basis

Three focused Exa searches returned 15 results, including duplicate pages.
Primary source reads informed implementation choices:

- [ByeDPI v0.17.3 README](https://github.com/hufrea/byedpi/blob/v0.17.3/README.md):
  SNI-relative/midpoint offsets, repeated split positions, TLS record splitting
  and Windows disorder/fake limitations. New arguments are checked against the
  bundled native executable; no preset is assumed to work for every ISP.
- [Original Superonline packet observations](https://github.com/net4people/bbs/issues/413):
  historical evidence of SNI-dependent loss/throttling, rather than only RST.
  These measurements are not evidence of this device's current failure.
- [Pinned sing-box TCP DNS transport](https://github.com/SagerNet/sing-box/blob/v1.13.14/docs/configuration/dns/server/tcp.md)
  and [HTTPS transport](https://github.com/SagerNet/sing-box/blob/v1.13.14/docs/configuration/dns/server/https.md):
  explicit dialer/bootstrap behavior for the bundled version.
- [Pinned Windows TUN lifecycle](https://github.com/SagerNet/sing-tun/blob/v0.8.11/tun_windows.go):
  local adapter creation, address/DNS configuration and route ownership.
  Upstream issue reports of lingering adapters were treated as hypotheses;
  only narrowly recognized transient conditions are retried.

## Verification and remaining acceptance

Regressions cover candidate starvation, concurrent target verification,
late cancellation, updater-only failure, partial-cache invalidation, provider
adoption/rollback, stop during promotion, independent target failure, IPC
readiness/loss, adapter-specific retry, temporary-config ownership and safe
offline collection. A native sing-box fixture exercises DNS hijacking through
an owned local TCP DNS server with the TUN inbound removed.
The four new Windows candidates also complete certificate-verified TLS and
an HTTP response through the real bundled ByeDPI against an owned local peer.

Run the core suite, vet and lifecycle race checks in
[engine reliability](engine-reliability.md). With `OFFVEIL_SINGBOX_TEST` set,
the suite also runs native configuration, DNS, routing and UDP fixtures.
`offveil-core check-payload` validates production strategy arguments.

Local Windows validation on 2026-10-20 passed: the full core suite with both
native helper fixtures enabled, `go vet ./...`, lifecycle/diagnostic race
checks, all ten native ByeDPI argument sets, and verified TLS/HTTP through
the four new strategies. Windows amd64 and Darwin arm64 core builds passed;
the Darwin result is compile validation only. Both CI YAML files parse, and
the diff passes whitespace checks. CI now includes the new native DNS/TLS
fixtures and service/support race checks.

Physical acceptance remains Windows on the affected Superonline line:
complete Discord updating/login/media and voice; refresh; sleep/wake;
network reconnection; and an offline support export if anything fails.
Compare the same device on a hotspot. A successful SOCKS/TLS fixture is
not proof of native application traffic through the real TUN.
