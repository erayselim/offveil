# offveil-core

Windows Service. Talks to the UI over a named pipe (`\\.\pipe\offveil-core`).
Schema: [docs/contracts.md](../docs/contracts.md).

## Sidecars

```powershell
.\scripts\fetch-wintun.ps1
.\scripts\fetch-byedpi.ps1
.\scripts\fetch-sing-box.ps1
Copy-Item third_party\wintun\wintun.dll .\wintun.dll
Copy-Item third_party\byedpi\ciadpi.exe .\ciadpi.exe
Copy-Item third_party\sing-box\sing-box.exe .\sing-box.exe
```

If WARP fails in TR, Reality fallback is `data/reality.json` or
`OFFVEIL_REALITY_JSON`.

The UI does not need admin at runtime. `start` is issued over the pipe after
`StartService`. `offveil-core setup` is an elevated fallback when the service
is not registered.

Sidecars must sit next to the exe or under `third_party/`.

## Commands

```text
go build -o offveil-core.exe ./cmd/offveil-core

offveil-core run                 # foreground (dev, admin)
offveil-core install             # admin: register the service
offveil-core setup               # admin: install if needed, then start (one UAC)
offveil-core start|stop|status
offveil-core client -method ping
offveil-core client -method start
offveil-core client -method status
offveil-core client -method test
offveil-core client -method diagnostics
offveil-core client -method repair
offveil-core uninstall
```

## IPC ACL

Protected DACL: LocalSystem (FA) + Authenticated Users (GR/GW). No Everyone,
no Anonymous. `go-winio` sets `FILE_PIPE_REJECT_REMOTE_CLIENTS`.
