# SmartScreen, Smart App Control, Defender

offveil Windows binaries are not Authenticode signed. There is no Microsoft
publisher reputation to lean on.

Download only from this repo's GitHub Releases. Third-party mirrors are
not trusted.

## SmartScreen

Unsigned installers often show "Windows protected your PC".

1. **More info**
2. **Run anyway**
3. On a new machine, check the hash first (below)

Buying a certificate does not clear SmartScreen by itself. Reputation
builds on a signed publisher identity over time.

## Smart App Control (SAC)

SAC is not SmartScreen. On some Windows 11 installs it blocks unsigned
exe files with no "Run anyway".

This beta does not cover SAC-on machines. We do not tell you to turn SAC
off: on systems upgraded from Windows 10 it may not be reversible.

If SAC is on, mark that separately on the beta form.

## Defender / AV false positives

VPN/TUN plus desync heuristics often land unsigned tools in Defender
quarantine.

If `offveil.exe`, `offveil-core.exe`, `sing-box.exe`, `ciadpi.exe`, or
`wintun.dll` is quarantined:

1. Restore it from Protection history.
2. Add a folder exclusion for `C:\Program Files\offveil`.
3. Put the ISP, Windows version, and threat name on the issue.

Do not turn Defender off globally.

## Hash check

```powershell
Get-FileHash -Algorithm SHA256 .\offveil_*_x64-setup.exe
```

Compare with `SHA256SUMS.txt` on the same GitHub Release.

Attestation (GitHub CLI):

```powershell
gh attestation verify .\offveil_*_x64-setup.exe --owner erayselim
```

## What is signed

The installer, `offveil-core.exe`, the UI, and the sidecars are not
Authenticode signed. What you get instead:

| | |
|--|--|
| SHA-256 | `SHA256SUMS.txt` on the same release |
| GitHub artifact attestation | `actions/attest-build-provenance` |
| Tauri updater Ed25519 | `latest.json` + `.sig`; pubkey embedded in the UI |
| Ruleset Ed25519 | `channel.json` + `active.json.sig`; pubkey embedded in core |

Ruleset private key lives only in GitHub Actions secret
`OFFVEIL_RULESET_PRIVATE_KEY`. Updater private key is
`TAURI_SIGNING_PRIVATE_KEY`. Key handling:
[docs/maintainer-secrets.md](maintainer-secrets.md).

## Maintainer: each public asset

1. VirusTotal URL of the installer (triage, not a proof).
2. [Microsoft WDSI file submission](https://www.microsoft.com/en-us/wdsi/filesubmission)
   on every release.
