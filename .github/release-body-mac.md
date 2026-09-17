# Apple Silicon prerelease

This tag is **not** GitHub Latest. Windows stays on the current `v*` Windows release. Auto-update still reads `latest.json` from Latest; this build does not replace that file.

**Disk image:** `offveil_*_aarch64.dmg`  
**Checksums:** `SHA256SUMS.txt` on this release.

```bash
shasum -a 256 offveil_*_aarch64.dmg
```

M1 and later only. Intel is not in this build.

## Gatekeeper

Ad-hoc signed, not Developer ID. After a browser download:

1. System Settings → Privacy & Security → **Open Anyway**
2. If macOS still says the app is damaged: `xattr -cr /Applications/offveil.app`

## First run

Administrator password once (core). Turn off iCloud Private Relay / Limit IP tracking.

If protection fails: **Settings → Save a support file**.
