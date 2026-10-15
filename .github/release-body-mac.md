# offveil for Apple Silicon

This preview improves macOS installation and adds in-app updates. Supports M1 and later Macs running macOS 12 or later.

## Changes

- Package the core and sidecars as nested executables and verify signatures before installation.
- Detect outdated core files after an app update and refresh them with administrator approval.
- Discover newer Mac releases and prereleases through **Check for Updates**, verify downloads and restart after installation.
- Update to Go 1.26.9, rustls 0.23.46 and patched networking dependencies.

## Install

Download **`offveil_1.0.0-mac.2_aarch64.dmg`** and compare its SHA-256 with **`SHA256SUMS.txt`** on this release:

```bash
shasum -a 256 offveil_1.0.0-mac.2_aarch64.dmg
```

1. Open the DMG and drag **offveil into Applications**.
2. Open the copy in Applications. If the developer cannot be verified, use **System Settings → Privacy & Security → Open Anyway**, then confirm **Open**.
3. Approve the administrator prompt for core setup. Turn off iCloud Private Relay / Limit IP Address Tracking while testing.

This build is ad-hoc signed and is not notarized by Apple. An unidentified-developer warning is expected. The DMG includes `READ-ME-FIRST.txt`; see the [Mac installation guide](https://github.com/erayselim/offveil/blob/v1.0.0-mac.2/docs/beta-mac.md) for troubleshooting.

## Updates

Older Mac builds need this DMG installed manually once. Future higher-version Mac releases can be installed through **Check for Updates**. Updating the privileged core may request administrator approval after restart.

## Validation and support

Automated checks cover arm64 payloads, signatures, DMG/archive contents, initial service setup, IPC, shutdown, restart and replacing installed core files. Physical-device connectivity and an update between two published versions still require manual testing.

If protection fails, use **Settings → Save a support file** and include the macOS version and exact error in your report.

This is a Mac-only prerelease. The published Windows installer, Windows update manifest and GitHub Latest selection are unchanged.
