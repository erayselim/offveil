# macOS preview

offveil for Apple Silicon (M1 and later), macOS 12 or later. Intel Macs are not supported.

## Install

1. Download `offveil_*_aarch64.dmg` from [GitHub Releases](https://github.com/erayselim/offveil/releases).
2. Compare its SHA-256 with `SHA256SUMS.txt` on the same Mac release. Shared Windows/Mac releases use `SHA256SUMS-mac.txt` for Mac files.

   ```bash
   shasum -a 256 ~/Downloads/offveil_*_aarch64.dmg
   ```

3. Open the DMG and drag **offveil into Applications**. Launch the copy in Applications.
4. If macOS cannot verify the developer, open **System Settings → Privacy & Security → Open Anyway**, then confirm **Open**.
5. Approve the administrator prompt to install the core service. Turn off iCloud Private Relay / Limit IP Address Tracking while testing.

The app is ad-hoc signed, without Developer ID or Apple notarization. An unidentified-developer warning is expected. See [Apple's instructions](https://support.apple.com/en-us/102445) and [Tauri's signing guide](https://v2.tauri.app/distribute/sign/macos/). The DMG includes an offline installation guide.

## Updates

Install this preview manually once if upgrading from an older Mac build. After that, **Check for Updates** discovers newer published releases and prereleases that contain a complete Mac update package. Windows-only releases and drafts are skipped.

Downloads are verified with the Tauri updater signature before installation. The app stops protection, shuts down the old daemon, installs the update and restarts. If the bundled core or sidecars changed, the setup screen requests administrator approval to refresh them. Protection cannot start with an outdated payload.

Versions follow SemVer. `1.0.0-mac.9 → 1.0.0-mac.10 → 1.0.0` is an upgrade sequence. After `1.0.0`, use a higher version such as `1.0.1-mac.1` for another preview. An unchanged or lower version is not offered.

## Troubleshooting

Record the exact alert. An unidentified-developer warning, a damaged-app warning and a malware warning are different conditions.

After checking the downloaded DMG's checksum, inspect the installed copy:

```bash
sw_vers
uname -m
codesign --verify --deep --strict --verbose=2 "/Applications/offveil.app"
codesign --display --verbose=4 "/Applications/offveil.app"
xattr -p com.apple.quarantine "/Applications/offveil.app"
```

`uname -m` should report `arm64`. `Signature=adhoc` and no developer team are expected. The last command may report that the quarantine attribute is absent. If signature verification fails, download a fresh copy and report the output; do not re-sign the damaged copy.

If the source and checksum are verified, signature verification passes, and **Open Anyway** still does not work, you can explicitly trust this installed copy by removing only its download quarantine:

```bash
xattr -dr com.apple.quarantine "/Applications/offveil.app"
open "/Applications/offveil.app"
```

This does not provide Apple verification. It changes only offveil's quarantine attribute and does not disable Gatekeeper globally. Do not use this fallback for a malware warning. If access is denied, report the output rather than changing system-wide security settings.

`spctl --assess` may reject an ad-hoc build even when `codesign --verify` passes. Signature integrity and Gatekeeper trust are separate checks.

For a protection failure, use **Settings → Save a support file**. Include the release tag, macOS version, exact error, and whether failure happened during installation, startup, protection, or update.

## Validation

Automated macOS checks cover:

- Core and UI tests, arm64 binaries and nested code signatures.
- Payload startup from the app, updater archive and mounted DMG.
- First service installation, non-root IPC, shutdown and demand-start.
- Replacing an existing installation while preserving binary signatures.

Browser-download approval, physical-device connectivity, DNS restoration, Discord voice, sleep/wake and an update between two published versions require manual testing. Automated packaging checks do not establish these results.

## Release maintenance

`release-darwin` derives the app and core version from the tag. It seals the final bundle, creates and signs the updater archive, then generates `latest-mac.json`. Keep the manifest, archive and archive signature together on the same release.

Update `offveil-ui/src/whats-new.macos.json` for each Mac release. Matching notes are included in both the app and update manifest; Windows notes remain independent.

Mac-only `v*-mac*` tags stage draft prereleases without changing GitHub Latest. Verify the artifacts and publish the draft as a prerelease to make it available to the updater. Shared `v*` tags attach Mac assets to the existing Windows release. Windows `latest.json`, checksums and release status are preserved.

Discovery inspects up to 300 recent GitHub releases. API or rate-limit failures are reported as check failures. Update verification uses the existing `TAURI_SIGNING_PRIVATE_KEY`; it does not require an Apple Developer account.

`ci-darwin` produces the `offveil-mac-install-test` artifact without release keys. To inspect an already built package on macOS:

```bash
bash scripts/darwin-smoke-bundle.sh /path/to/offveil.app /path/to/offveil.app.tar.gz /path/to/offveil.dmg
```

`darwin-smoke-install.sh` installs and removes a system service and is restricted to disposable GitHub-hosted macOS runners.
