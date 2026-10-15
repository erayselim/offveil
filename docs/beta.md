# Release candidate testing

Windows and Apple Silicon now share the same release candidate. Report results
through the [issue forms](https://github.com/erayselim/offveil/issues/new/choose).

## Before testing

Download from the shared release and verify the file against `SHA256SUMS.txt`.
See the [Windows security notes](antivirus.md) or [Mac installation guide](beta-mac.md)
if the operating system blocks installation. Include the exact warning in a
report; do not disable system-wide security protections.

## What to check

- Install on a clean system and upgrade an existing installation.
- Check for updates from Windows b4/b5 or Mac mac.3/mac.4.
- Turn protection on, off and on again. Confirm normal browsing still works.
- Try Discord text, voice and media, IMVU assets, and the services affected by
  your internet provider.
- Change networks and test sleep/wake, then confirm protection reconnects.
- After stopping or quitting, confirm the original network settings are restored.
- On Mac, compare CPU and battery use while idle and during the same download
  or video with protection on and off. Record the device and workload.

In a report, include the app version, operating system/device, internet provider
when relevant, steps and exact error. Attach a support file from Settings when
possible. A successful hosted-runner test does not establish behavior on every
device or provider.

See [release maintenance](releases.md) for packaging and update verification.
