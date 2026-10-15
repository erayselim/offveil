# offveil for Apple Silicon

This preview repairs the Mac service lifecycle, removes incompatible desynchronization operations and makes support export independent of a working daemon. Supports M1 and later Macs running macOS 12 or later.

## Changes

- Remove the unsupported `--timeout` argument that prevented the Darwin ByeDPI process from starting, along with disorder/disoob operations that change TTL internally. Mac strategies use split, TLS record splitting and OOB; incompatible cached strategies are rejected.
- Use the gVisor TUN stack on Mac. Real macOS 26 traffic tests exposed TCP failures with the previous system stack even while both SOCKS paths were healthy.
- Pin ByeDPI's outbound sockets to the physical interface to keep them out of utun. The small Darwin-only patch and its source revision are included in the repository.
- Require the privileged system daemon. A core started from Terminal as a normal user no longer makes the app appear installed and ready.
- Stop, recover and refresh the root service through launchd instead of waiting for protection RPC during an update. Restore offveil's network changes after sidecars stop.
- Save support ZIPs through a native file dialog, including offline installation facts when the daemon is missing or unresponsive. Export remains available while protection is starting.
- Bound helper execution without undrained stdout/stderr pipes. Mac auto-connect is off until explicitly enabled in Settings.

## Update from mac.2 or mac.3

Install this release manually if the old updater reports that protection cannot be stopped. The new installer can quiesce an unresponsive old daemon with administrator approval. An already-installed updater cannot acquire this recovery behavior until it has been upgraded.

After this upgrade, **Check for Updates** continues to include published Mac prereleases and verify update signatures. Refreshing the privileged core may request administrator approval after restart.

## Manual installation

Download **`offveil_1.0.0-mac.4_aarch64.dmg`** and compare its SHA-256 with **`SHA256SUMS.txt`** on this release:

```bash
shasum -a 256 offveil_1.0.0-mac.4_aarch64.dmg
```

1. Quit the old app (use Force Quit if it is unresponsive). Open the DMG and drag **offveil into Applications**, replacing the previous copy.
2. Open the copy in Applications. If the developer cannot be verified, use **System Settings → Privacy & Security → Open Anyway**, then confirm **Open**.
3. Approve the administrator prompt for core setup.

This build is ad-hoc signed and is not notarized by Apple. An unidentified-developer warning is expected. The DMG includes `READ-ME-FIRST.txt`; see the [Mac installation guide](https://github.com/erayselim/offveil/blob/v1.0.0-mac.4/docs/beta-mac.md) for troubleshooting.

## Validation and support

The Mac validation workflow exercises the actual signed bundle: offline ZIP export, root service installation, real TUN startup, routed HTTPS, HTTPS through ByeDPI SOCKS, DNS restoration and recovery of a deliberately suspended daemon. It also checks signatures, DMG/archive contents and payload replacement. Hosted-runner success does not establish censorship bypass on a user's ISP; physical-device connectivity, Discord voice and an update between two published versions still require device testing.

For the next connection test, turn off **iCloud Private Relay** and the connected network's **Limit IP Address Tracking** setting. Record whether this changes the result. offveil does not change these settings.

If protection fails, use **Settings → Save a support file**, choose where to save the ZIP and send that file with the exact error. The ZIP includes macOS/release information and records when a live daemon snapshot was unavailable.

This is a Mac-only prerelease. The published Windows installer, Windows update manifest and GitHub Latest selection are unchanged.
