# macOS service and diagnostics design

The Mac UI is unprivileged. Protection runs in the root LaunchDaemon `system/offveil-core`; its endpoint is `/var/run/offveil/core.sock`. A user process listening under `$TMPDIR` is a development process and must never satisfy production bootstrap checks. Interactive development requires an explicit `OFFVEIL_IPC_SOCK` override.

## Service lifecycle

The free, ad-hoc-signed distribution continues to install a conventional LaunchDaemon with explicit administrator approval. Its plist references the canonical executable through `ProgramArguments`. Service control uses the system domain explicitly: `bootstrap`, `kickstart`, `kill` and `bootout`. It does not depend on the GUI user's default launchctl domain or on a responsive engine RPC.

On stop, launchd receives SIGTERM first. If the job still has a PID after a grace period, SIGKILL targets that launchd job identity. Remaining sidecars are signalled only after matching their complete executable paths to the installed offveil directory. DNS restoration runs after sidecars have stopped. Installation validates the new payload before quiescing the old installation and copying signed executables.

The updater preserves Tauri's mandatory signature verification. The first upgrade from a broken legacy daemon may require the DMG: the updater in an already-installed old version cannot acquire behavior from the version it has not installed yet.

References: [Apple launchd design](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html), [SMAppService and its registration model](https://developer.apple.com/documentation/servicemanagement/smappservice), [Tauri updater](https://v2.tauri.app/plugin/updater/).

## Compatible desynchronization

ByeDPI is built from pinned `v0.17.3`. Its `DESYNC_DISORDER` and `DESYNC_DISOOB` cases call `setttl(sfd, 1)` internally. Merely omitting `--ttl` does not remove TTL manipulation. In addition, that version compiles `--timeout` only with `TIMEOUT_SUPPORT`, which its Darwin build lacks: passing the option prevents the process from starting. The Mac strategy uses split, TLS record splitting and OOB; incompatible cached strategies are rejected. Windows strategies are independent. CI invokes the actual sidecar with every native argument set before packaging, in addition to the real protection test.

References: [pinned ByeDPI source](https://github.com/hufrea/byedpi/blob/v0.17.3/desync.c), [upstream macOS discussion](https://github.com/hufrea/byedpi/issues/17), [sing-box TUN and loop-prevention requirements](https://sing-box.sagernet.org/configuration/inbound/tun/).

## Support export

Support export is a local operation independent of daemon setup. A native save dialog selects the destination. The bundled core's `support` command tries diagnostics with a short deadline, then records sanitized installation facts if the daemon is absent or stuck. Only a completed ZIP produces a success response. User paths in errors are redacted. Credentials, raw network configuration, subscription data and general daemon logs are not included.

Subprocess stdout/stderr go to private temporary files while the parent waits with a deadline, avoiding full-pipe deadlocks. Captured responses are bounded. The native dialog temporarily suppresses blur-to-tray so the save panel and result remain visible. Only files chosen and exported in this process gain permission for the UI's Open folder action.

Reference: [Tauri native dialogs](https://v2.tauri.app/plugin/dialog/).

## Validation boundaries

The disposable macOS runner installs the actual signed bundle, exports support before installation, starts real protection, verifies an `utun` route, sends HTTPS through the TUN and ByeDPI SOCKS, stops protection and compares the original DNS configuration. It also suspends the daemon and verifies managed stop/start without IPC. Neither fake sessions nor a successful `--help` invocation establish these results.

Physical-device approval dialogs, ISP-specific filtering, Discord voice and sleep/wake still require device testing. Preserve that distinction in release notes.
