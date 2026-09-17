# offveil-ui

Tauri 2 + React. No network work of its own. It talks to `offveil-core`
over a local IPC transport. Contract: [docs/contracts.md](../docs/contracts.md).

- Windows: named pipe `\\.\pipe\offveil-core`
- Darwin: unix socket `/var/run/offveil/core.sock` (`OFFVEIL_IPC_SOCK` override)

## Dev (Windows)

```powershell
cd ..\offveil-core
go build -o offveil-core.exe .\cmd\offveil-core

cd ..\offveil-ui
$env:OFFVEIL_CORE_PATH = (Resolve-Path ..\offveil-core\offveil-core.exe).Path
npm install
npm run tauri dev
```

## Dev (macOS, Apple Silicon)

```bash
cd ../offveil-core
CGO_ENABLED=0 go build -o offveil-core ./cmd/offveil-core
# optional: OFFVEIL_IPC_SOCK=$TMPDIR/offveil-$UID/core.sock ./offveil-core run

cd ../offveil-ui
export OFFVEIL_CORE_PATH="$(pwd)/../offveil-core/offveil-core"
npm install
npm run tauri dev
```

First protection start runs one-time admin (`osascript`) → `offveil-core setup`
(LaunchDaemon + sudoers). After that the switch is passwordless.

## Rust commands

| Command | |
|---------|--|
| `probe_bootstrap` | Service / IPC state (`needs_install` only if the demand-start entry is missing) |
| `ensure_service` | Windows `StartService` / Darwin `sudo -n … start` if registered; elevated `setup` only if missing/denied |
| `get_status` | Core `status` |
| `set_protection` | Core `start` / `stop` |
