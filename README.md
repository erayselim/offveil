<img src="https://cdn.gtaup.com/_-GYV5he.svg" alt="offveil" width="360" />

<b>Windows client for services ISPs in Turkiye interfere with.</b><br>
One switch. Local DoH, DPI desync, and a selective tunnel when that is not enough.

<a href="https://github.com/erayselim/offveil/releases"><img src="https://img.shields.io/github/v/release/erayselim/offveil?style=flat-square&color=2CC295" alt="Release" /></a>
<a href="LICENSE"><img src="https://img.shields.io/github/license/erayselim/offveil?style=flat-square&color=2CC295" alt="License" /></a>
<a href="https://github.com/erayselim/offveil/releases"><img src="https://img.shields.io/github/downloads/erayselim/offveil/total?style=flat-square&color=2CC295" alt="Downloads" /></a>

---

| Protected | Not protected |
| --- | --- |
| <img src="https://cdn.gtaup.com/8em0Untu.webp" width="260" alt="Protected" /> | <img src="https://cdn.gtaup.com/ejxN-hWI.webp" width="260" alt="Not protected" /> |

## Download

Only from [GitHub Releases](https://github.com/erayselim/offveil/releases). Check `offveil_*_x64-setup.exe` against `SHA256SUMS.txt` on the same release:

```powershell
Get-FileHash -Algorithm SHA256 .\offveil_*_x64-setup.exe
```

Attestation, if you want it:

```powershell
gh attestation verify .\offveil_*_x64-setup.exe --owner erayselim
```

SmartScreen will show "Windows protected your PC". Use **More info**, then **Run anyway**. Smart App Control blocks unsigned binaries with no bypass. We do not tell you to turn SAC off. See [docs/antivirus.md](docs/antivirus.md).

The NSIS installer is per-machine (`C:\Program Files\offveil`, one UAC). It registers `offveil-core` as a manual-start service. The switch in the UI starts and stops protection.

If something breaks, export a diagnostics zip from the app. There are no ISP presets to pick. Beta reports: [issue form](.github/ISSUE_TEMPLATE/beta.yml).

## Layout

```text
offveil-core/   Windows Service, policy, probe, sidecars
offveil-ui/     Tauri 2 + React client
ruleset/        Ed25519-signed domain packages
docs/           IPC contract, threat model, AV notes
```

IPC: [docs/contracts.md](docs/contracts.md).

## Build

Core needs an admin / service account at runtime:

```powershell
cd offveil-core
.\scripts\fetch-wintun.ps1
.\scripts\fetch-byedpi.ps1
.\scripts\fetch-sing-box.ps1
go build -o offveil-core.exe ./cmd/offveil-core
```

UI:

```powershell
cd offveil-ui
$env:OFFVEIL_CORE_PATH = (Resolve-Path ..\offveil-core\offveil-core.exe).Path
npm install
npm run tauri dev
```

More in [offveil-core/README.md](offveil-core/README.md) and [offveil-ui/README.md](offveil-ui/README.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security reports go through [SECURITY.md](SECURITY.md), not public issues.

## License

Apache-2.0 ([LICENSE](LICENSE)). Sidecars: [THIRD_PARTY.md](THIRD_PARTY.md).
