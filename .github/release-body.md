## offveil $TAG, unsigned Windows beta

This build is not Authenticode-signed. Trust comes from GitHub Actions,
hashes, and attestation, not from Microsoft publisher reputation.

### Before you run the installer

1. Download only from this GitHub Release.
2. Verify SHA-256 against `SHA256SUMS.txt`:
   ```powershell
   Get-FileHash -Algorithm SHA256 .\offveil_*_x64-setup.exe
   ```
3. Optional provenance:
   ```powershell
   gh attestation verify .\offveil_*_x64-setup.exe --owner erayselim
   ```
4. SmartScreen: **More info**, then **Run anyway**.
5. Smart App Control (SAC) on Windows 11 may block this with no bypass.
   This beta does not cover SAC-on PCs. We do not recommend turning SAC off.
6. Defender may quarantine TUN/desync binaries. Restore them and exclude
   `C:\Program Files\offveil`. See `docs/antivirus.md`.

### Install

Per-machine NSIS to `C:\Program Files\offveil`. One UAC at install. Service
`offveil-core` is registered (manual start). The switch is in the UI.

### Updates

The in-app updater downloads a new unsigned NSIS. SmartScreen/SAC may
show up again.

### Support

There is no preset to pick. Attach the diagnostics zip from the app
(`%ProgramData%\offveil\diagnostics`). Beta form: Discord opened within
2 minutes? ISP? Windows version? SAC on/off?
