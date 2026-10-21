# Releases

Windows and Apple Silicon share a version, tag and GitHub release. The release
workflow builds and tests both platforms before assembling a draft. It verifies
the updater signatures, ruleset signature and version agreement, then publishes
the complete release. One checksum file covers both platforms.

Before tagging, dispatch `release.yml` from the intended branch. This builds
the signed Windows/Mac packages and verifies the combined release metadata
without publishing a GitHub release or changing update pointers. Verified
packages remain in the `verified-release-preflight` workflow artifact. Only
a tag push enables publication steps.

The Windows job verifies the updater signatures before executing installers
on its disposable runner. It checks a clean install, payload/license files,
demand-start service and versioned IPC, then upgrades from the prior beta and
checks again. It does not enable protection or modify a developer's machine.
macOS runs the existing bundle and installation smoke tests.

Update the version in package.json/package-lock.json, Cargo.toml/Cargo.lock,
tauri.conf.json, the core version and both localized whats-new files. Run
`node scripts/release.cjs check vVERSION` before tagging. The short release body
in `.github/release-body.md` gets direct Windows and Mac download links. Update
the README's direct download links to the same release.

## Release candidates and existing Windows clients

GitHub prereleases cannot be Latest. Windows b4/b5 and the RC use the existing
`releases/latest/download/latest.json` endpoint. To offer a shared RC through
that endpoint, the publish job replaces only Latest's update manifest and the
corresponding checksum entry. Its installer and installer signature are retained.
The previous metadata is saved in the workflow's `legacy-update-backup` artifact.
Before changing this pointer, the new signed packages must have passed validation.

The Mac updater discovers the highest newer SemVer release with a complete Mac
manifest, archive and signature. Both mac.3 and mac.4 can discover the shared RC.
A mac.3 installation whose old service cannot stop still needs a manual DMG
upgrade; this limitation is described in the installation guide.

After publication, `scripts/release.cjs verify-published` checks the live legacy
Windows endpoint, Mac discovery from both prior versions, signing-key continuity,
downloaded package signatures, ruleset signature and all published checksums.
It does not simulate interactive installation or physical-device networking.

The same bridge is used for beta releases. The published verification also
checks the current stable client and Beta 1/Beta 2/Beta 3 on both supported platforms.
Windows uses signed NSIS executables; Mac uses signed tar update archives.
The updater's unused Windows ZIP feature is disabled, removing its ZIP
extraction dependency while preserving these two update formats.

For a normal stable release, GitHub Latest moves to the new release and the
standard Windows endpoint follows automatically. For an RC rollback, restore
both saved legacy metadata files. Do not replace a published installer's bytes
or move an existing version tag.
