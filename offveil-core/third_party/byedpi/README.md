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

On probe fail, `Scan` tries `ScanCandidates()` (split / disorder / fake /
ttl / tlsrec) with a ~40s budget, then stores the winner under the ISS ASN
in `%ProgramData%\offveil\desync\desync-strategies.json`
(`OFFVEIL_DESYNC_CACHE` override).
