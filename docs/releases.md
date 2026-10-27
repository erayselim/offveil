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

Both platforms build the pinned sing-box source with the patched Go toolchain
and isolated dependency lock in `offveil-core/tools/singbox`. Its actual tagged
source must pass govulncheck before packaging. The shared release includes the
upstream source archive, covered by the same checksum file as the installers.

The Windows job verifies the updater signatures before executing installers
on its disposable runner. It checks a clean install, payload/license files,
demand-start service and versioned IPC, then upgrades from v1.0.3 and checks
again. It does not enable protection or modify a developer's machine.

Update the version in package.json/package-lock.json, Cargo.toml/Cargo.lock,
tauri.conf.json, the core version and both localized whats-new files. Run
`node scripts/release.cjs check vVERSION` before tagging. The short release body
in `.github/release-body.md` gets direct Windows and Mac download links.

## Channels

| Install | Windows endpoint | Mac discovery |
| --- | --- | --- |
| Stable (no `-` in version) | `releases/latest/download/latest.json` | stable releases with `latest-mac.json` |
| Beta (prerelease version) | `releases/download/updates-beta/latest-beta.json` | stable `latest-mac.json` and beta `latest-mac-beta.json` |

A tag with a hyphen is published as a GitHub prerelease. It never becomes Latest
and never rewrites another release's assets. Its manifests are named
`latest-beta.json` and `latest-mac-beta.json`; installed 1.0.x clients look only
for `latest.json` and `latest-mac.json`, so they are not offered the beta.
Testers install the first beta by hand; after that it updates within the beta
channel.

Every release, beta or stable, uploads its Windows manifest to the fixed
`updates-beta` prerelease as `latest-beta.json`. A stable release therefore
also reaches beta installs, which then return to the stable channel.

`scripts/release.cjs verify-published` checks the published assets, signatures
and checksums. For a beta it also checks that the stable pointer still holds a
stable version and that no supported prior client would be offered the beta.
For a stable release it checks that every supported prior client is offered it.

## Beta acceptance

Before promoting a beta, test on Windows and macOS, on the affected ISPs and a
mobile hotspot:

- Discord app, web and voice; a DNS-blocked site; random HTTPS sites.
- A large download with protection on and off (support file speed sample).
- Game ping; sleep/wake; Wi-Fi change; Stop and repair leave DNS, routes and
  the adapter clean.
- A support file from each device.

Do not replace a published installer's bytes or move an existing version tag.
