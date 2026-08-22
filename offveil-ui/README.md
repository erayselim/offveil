# offveil-ui

Tauri 2 + React. No network work of its own. It talks to `offveil-core`
over `\\.\pipe\offveil-core`. Contract: [docs/contracts.md](../docs/contracts.md).

## Dev

```powershell
cd ..\offveil-core
go build -o offveil-core.exe .\cmd\offveil-core

cd ..\offveil-ui
$env:OFFVEIL_CORE_PATH = (Resolve-Path ..\offveil-core\offveil-core.exe).Path
npm install
npm run tauri dev
```

## Rust commands

| Command | |
|---------|--|
| `probe_bootstrap` | Service / pipe state (`needs_install` only if SCM entry is missing) |
| `ensure_service` | `StartService` if registered; elevated `setup` only if missing/denied |
| `get_status` | Core `status` |
| `set_protection` | Core `start` / `stop` |
