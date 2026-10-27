# ByeDPI / ciadpi (desync SOCKS)

Official Windows build from [hufrea/byedpi](https://github.com/hufrea/byedpi)
(MIT).

| | |
|--|--|
| Version | 0.17.3 |
| Asset | `byedpi-17.3-x86_64-w64.zip` |
| ZIP SHA256 | `70d2c94147193cb915f9c6eb5144b8d404dacbcfa90bda2383b6b211afafa456` |
| Binary | `ciadpi.exe` |

Core starts it as a Job Object child on `127.0.0.1:18080`.

```powershell
.\scripts\fetch-byedpi.ps1
Copy-Item third_party\byedpi\ciadpi.exe .\ciadpi.exe
```

Default strategy (`byedpi:windows-safe`) is the official
`dist/windows/byedpi.bat` plus `--auto=ssl_err` fake fallback. See
`internal/desync/strategies.go`.

If the selected strategy and tunnel providers both fail, a background `Scan`
tries `ScanCandidates()` (split / disorder / fake / ttl / tlsrec) with a
32-second network-work budget, two isolated helpers and six seconds per trial.
A candidate must pass at least two independent connectivity controls,
then pass again through the real helper and the sing-box SOCKS dataplane.
These controls establish path health, not access to every blocked destination.
Only that verified winner is stored under the network identity
in `%ProgramData%\offveil\desync\desync-strategies.json`
(`OFFVEIL_DESYNC_CACHE` override).

Trials preserve the physical egress bind, use separate loopback ports, and
are cancelled on stop. Failed real-port verification restores the previous
strategy. A partial success is not persisted as an ISP-wide winner.

Darwin: do not use `byedpi-*-aarch64.tar.gz` (Linux). Build the same tag:

```bash
./scripts/build-byedpi-darwin.sh
```

`ciadpi` (no `.exe`) is ad-hoc signed after copy. Default strategy is
`byedpi:darwin-safe` excludes `--timeout` (not compiled for Darwin), fake,
disorder/disoob and other TTL-changing operations. It uses TCP/TLS record
splitting and OOB. The build applies the checked-in
`patches/byedpi-darwin-bind-interface.patch` after verifying the upstream commit.
The Apple-only patch pins outbound sockets with `IP_BOUND_IF` / `IPV6_BOUND_IF`
using the physical interface passed by the core in `OFFVEIL_BIND_INTERFACE`.
The Darwin accept patch retries interrupted/aborted accepts and backs off on
file descriptor or memory pressure instead of terminating the proxy.
