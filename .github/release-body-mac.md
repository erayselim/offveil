# offveil for Apple Silicon

This preview fixes startup and diagnostics problems reported in `1.0.0-mac.2`. Supports M1 and later Macs running macOS 12 or later.

## Changes

- Honor each Mac IPC request's timeout instead of cutting startup off after eight seconds. Timeout errors now point to diagnostics.
- Keep DNS query observation from waiting on the engine lock during startup and shutdown.
- Return status and generate support files from a saved snapshot while the engine is busy. Diagnostics include the last startup stage and snapshot time.
- Create distinct, complete diagnostics archives that the desktop user can read. Bound macOS DNS inspection and report Private Relay resolver hints without claiming they prove the setting is disabled.

## Update from 1.0.0-mac.2

Use **Check for Updates** in offveil. The Mac updater includes published prereleases and verifies the download signature. After installation, the app restarts and may request administrator approval to replace the core and sidecars.

If protection is stuck or the update cannot stop the old core, restart the Mac, open offveil and update before turning protection on. If in-app updating still fails, install the DMG below manually.

## Manual installation

Download **`offveil_1.0.0-mac.3_aarch64.dmg`** and compare its SHA-256 with **`SHA256SUMS.txt`** on this release:

```bash
shasum -a 256 offveil_1.0.0-mac.3_aarch64.dmg
```

1. Open the DMG and drag **offveil into Applications**, replacing the previous copy if present.
2. Open the copy in Applications. If the developer cannot be verified, use **System Settings → Privacy & Security → Open Anyway**, then confirm **Open**.
3. Approve the administrator prompt for core setup.

This build is ad-hoc signed and is not notarized by Apple. An unidentified-developer warning is expected. The DMG includes `READ-ME-FIRST.txt`; see the [Mac installation guide](https://github.com/erayselim/offveil/blob/v1.0.0-mac.3/docs/beta-mac.md) for troubleshooting.

## Validation and support

Automated checks cover core and UI tests, delayed socket responses, diagnostics during blocked startup, arm64 payloads, signatures, DMG/archive contents, service setup, readable support archives, shutdown, restart and replacing installed core files. Physical-device connectivity and an update between two published versions still require manual testing.

For the next connection test, turn off **iCloud Private Relay** and the connected network's **Limit IP Address Tracking** setting. Record whether this changes the result. offveil does not change these settings.

If protection fails, use **Settings → Save a support file** and include the macOS version, release version and exact error in your report.

This is a Mac-only prerelease. The published Windows installer, Windows update manifest and GitHub Latest selection are unchanged.
