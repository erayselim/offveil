# Contributing

Windows 10/11 amd64. Do not commit secrets, sidecar binaries, or runtime
credentials (`offveil-core/data/*.json`, `.secrets/`).

## Setup

Go 1.25.13, Node 22, and a stable Rust toolchain. Then follow the Build
section in [README.md](README.md).

```powershell
cd offveil-core
go test ./...

cd ..\offveil-ui
npm ci
npm run typecheck
```

IPC and ruleset shapes live in [docs/contracts.md](docs/contracts.md).
Bump `contracts_version` on a breaking change.

## Pull requests

- Keep the UI as one switch. No ISP presets or desync knobs.
- Match the existing tone: short, English in user-facing docs.
- CI runs `go test` and `tsc` on every PR.

## Issues

- Bug: [.github/ISSUE_TEMPLATE/bug.yml](.github/ISSUE_TEMPLATE/bug.yml)
- Beta (Discord within 2 minutes): [.github/ISSUE_TEMPLATE/beta.yml](.github/ISSUE_TEMPLATE/beta.yml)
- Vulnerability: [SECURITY.md](SECURITY.md)
