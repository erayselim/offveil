# macOS service and diagnostics design

The Mac UI is unprivileged. Protection runs in the root LaunchDaemon `system/offveil-core`; its endpoint is `/var/run/offveil/core.sock`. A user process listening under `$TMPDIR` is a development process and must never satisfy production bootstrap checks. Interactive development requires an explicit `OFFVEIL_IPC_SOCK` override.

## Service lifecycle

The free, ad-hoc-signed distribution continues to install a conventional LaunchDaemon with explicit administrator approval. Its plist references the canonical executable through `ProgramArguments`. Service control uses the system domain explicitly: `bootstrap`, `kickstart`, `kill` and `bootout`. It does not depend on the GUI user's default launchctl domain or on a responsive engine RPC.

On stop, launchd receives SIGTERM first. If the job still has a PID after a grace period, SIGKILL targets that launchd job identity. Remaining sidecars are signalled only after matching their complete executable paths to the installed offveil directory. DNS restoration runs after sidecars have stopped. Installation validates the new payload before quiescing the old installation and copying signed executables.

A reachable socket does not replace the installation checks. Setup always recreates the stopped job's plist from the current configuration, so an older registration cannot keep launching a bundle/DMG executable. The configured executable is always the canonical installed core. If demand-start finishes but ping remains unavailable, the UI performs one managed stop/start recovery before sending any protection-start RPC. It does not replay a timed-out protection RPC or start again after failed network cleanup.

The updater preserves Tauri's mandatory signature verification. The first upgrade from a broken legacy daemon may require the DMG: the updater in an already-installed old version cannot acquire behavior from the version it has not installed yet.

References: [Apple launchd design](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html), [SMAppService and its registration model](https://developer.apple.com/documentation/servicemanagement/smappservice), [Tauri updater](https://v2.tauri.app/plugin/updater/).

## Compatible desynchronization

ByeDPI is built from pinned `v0.17.3`. Its `DESYNC_DISORDER` and `DESYNC_DISOOB` cases call `setttl(sfd, 1)` internally. Merely omitting `--ttl` does not remove TTL manipulation. In addition, that version compiles `--timeout` only with `TIMEOUT_SUPPORT`, which its Darwin build lacks: passing the option prevents the process from starting. The Mac strategy uses split, TLS record splitting and OOB; incompatible cached strategies are rejected. Windows strategies are independent. CI invokes the actual sidecar with every native argument set before packaging, in addition to the real protection test.

References: [pinned ByeDPI source](https://github.com/hufrea/byedpi/blob/v0.17.3/desync.c), [upstream macOS discussion](https://github.com/hufrea/byedpi/issues/17), [sing-box TUN and loop-prevention requirements](https://sing-box.sagernet.org/configuration/inbound/tun/).

The Darwin build applies the checked-in `byedpi-darwin-bind-interface.patch` after verifying the upstream commit. It uses `IP_BOUND_IF` / `IPV6_BOUND_IF` on outbound sockets, using the physical egress interface selected before TUN startup. The parent passes that interface through `OFFVEIL_BIND_INTERFACE`. This keeps ciadpi's own traffic out of utun; merely binding its source IPv4 did not pass the real TUN HTTPS test. The patch is Apple-only and leaves the Windows binary and argument contract unchanged.

Darwin uses sing-box's `gvisor` TUN stack. On the macOS 26 runner, both ByeDPI and sing-box SOCKS HTTPS worked with the `system` stack while ordinary routed utun TCP connections timed out. The same real traffic test passes with `gvisor`. Windows retains `system`. Keep both SOCKS tests and the ordinary HTTPS test: a listening proxy port or a successful SOCKS request does not establish that the TUN TCP path works.

## Energy and repeated work

The TUN stack, split-default capture, desynchronization rules, QUIC policy and selective tunnel fallback stay unchanged. Darwin capture does not resolve seed addresses for unused per-host routes. Its session opts out of prefix expansion; the engine still records observed CDN hosts and suggestions. Backends that install per-host routes retain their existing resolution path. Expansion reserves an observed host before starting asynchronous work and does not publish results into a later capture session.

Bootstrap and the live DNS stub share a DoH client and connection pool. Identical in-flight wire questions are combined without combining different DNS flags or EDNS options. Each waiter retains its own response ID, private response copy and cancellation. Once no waiters remain, upstream work is cancelled. The bounded positive-answer cache holds at most 256 entries of at most 4096 bytes for the shortest record TTL, capped at 60 seconds. Cache hits age record TTLs; HTTP Age is also deducted. Empty, negative, truncated, failed and known poisoned answers are not cached. Network-change and resume handling clear cached answers and resolver preference, and old in-flight responses cannot refill the new network's cache. Shutdown closes idle HTTPS connections.

Cold DoH queries race all providers. Once a provider succeeds, it gets a 150 ms head start; failure starts the fallback race immediately, and a slow response also triggers the race. The overall two-second DoH budget, poison checks, circuit breaker and plain-DNS fallback remain in place.

The UI polls every 2.5 seconds while visible and every 30 seconds while hidden. Revealing the window refreshes immediately. Requests never overlap, timers resume only after completion, and cleanup removes native listeners even when their registration completes late. The daemon keeps protection independent of the window. Network and power watchers retain their existing behavior in this optimization pass.

Validation: run `go test ./...` and `go test -race ./internal/dns ./internal/engine ./internal/capture` from offveil-core; `node --test scripts/status-polling.test.cjs` from the repository root; and the UI production build. Cross-compiling the core and test binaries for Darwin arm64 checks build compatibility; battery savings, fan behavior and real TUN/Discord/IMVU traffic still require a physical Mac test.

## Support export

Support export is a local operation independent of daemon setup. A native save dialog selects the destination. The bundled core's `support` command tries diagnostics with a short deadline, then records sanitized installation facts if the daemon is absent or stuck. Only a completed ZIP produces a success response. User paths in errors are redacted. Credentials, raw network configuration, subscription data and general daemon logs are not included.

Mac support exports also inspect the system launchd job with a short deadline. Only its state, PID, run count, last exit code and whether its program is canonical are retained. Raw launchctl output, executable paths and environment variables are excluded.

Subprocess stdout/stderr go to private temporary files while the parent waits with a deadline, avoiding full-pipe deadlocks. Captured responses are bounded. The native dialog temporarily suppresses blur-to-tray so the save panel and result remain visible. Only files chosen and exported in this process gain permission for the UI's Open folder action.

Reference: [Tauri native dialogs](https://v2.tauri.app/plugin/dialog/).

## Validation boundaries

The disposable macOS runner installs the actual signed bundle, exports support before installation, starts real protection, verifies an `utun` route, sends HTTPS through the TUN and ByeDPI SOCKS, stops protection and compares the original DNS configuration. It also suspends the daemon and verifies managed stop/start without IPC. Neither fake sessions nor a successful `--help` invocation establish these results.

Physical-device approval dialogs, ISP-specific filtering, Discord voice and sleep/wake still require device testing. Preserve that distinction in release notes.

The mac.4 device report was an offline snapshot: daemon diagnostics timed out, the system socket and plist existed, but all three canonical executables were absent. It contains no active-session trace or registered executable path, so it does not establish why the first reconnect hung or prove a pending Apple approval. The installation bypass and stale-plist behavior above are independently reproducible code defects. Added runner checks cover repeated managed protection toggles with routed HTTPS and repair from a live legacy job with missing canonical payload; these still require execution on macOS.
