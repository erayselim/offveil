#!/usr/bin/env bash
# First-run service installation on a disposable GitHub-hosted runner only.
# Never starts protection: no TUN or DNS override is requested.
set -euo pipefail
if [[ "$(uname -s)" != Darwin || "${GITHUB_ACTIONS:-}" != true || "${RUNNER_ENVIRONMENT:-}" != github-hosted ]]; then
  echo "Requires a disposable GitHub-hosted macOS runner" >&2
  exit 1
fi
APP="${1:?usage: darwin-smoke-install.sh <app>}"
CORE="$APP/Contents/MacOS/offveil-core"
INSTALLED="/Library/Application Support/offveil/offveil-core"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/offveil-upgrade.XXXXXX")"
cleanup() {
  sudo "$CORE" uninstall || true
  rm -rf "$WORK"
}
trap cleanup EXIT

sudo "$CORE" setup
# Hosted runners already allow broad passwordless sudo. Check our own policy
# independently so that a missing/invalid offveil sudoers file cannot be masked.
sudo /usr/sbin/visudo -cf /etc/sudoers.d/offveil
for name in offveil-core sing-box ciadpi; do
  dst="$(dirname "$INSTALLED")/$name"
  cmp "$APP/Contents/MacOS/$name" "$dst"
  codesign --verify --strict "$dst"
done

ping_until_ready() {
  local i
  for i in {1..50}; do
    if "$INSTALLED" client -method ping; then return 0; fi
    sleep 0.2
  done
  echo "LaunchDaemon socket not reachable by UI user" >&2
  return 1
}
ping_until_ready
"$INSTALLED" client -method shutdown
for i in {1..50}; do
  [[ -S /var/run/offveil/core.sock ]] || break
  sleep 0.2
done
if [[ -S /var/run/offveil/core.sock ]]; then
  echo "LaunchDaemon did not release its socket after shutdown" >&2
  exit 1
fi
# Exercise the UI's demand-start route after the initial admin installation.
/usr/bin/sudo -n "$INSTALLED" start
ping_until_ready

# Exercise refresh of an existing installation with a valid, different payload.
# Re-sign only a temporary sidecar to model an older build without corrupting it.
for name in offveil-core sing-box ciadpi; do
  cp "$APP/Contents/MacOS/$name" "$WORK/$name"
done
codesign --force --sign - --timestamp=none --identifier com.offveil.smoke.previous "$WORK/ciadpi"
"$INSTALLED" client -method shutdown
sleep 1
sudo "$WORK/offveil-core" setup
ping_until_ready
cmp "$WORK/ciadpi" "$(dirname "$INSTALLED")/ciadpi"
"$INSTALLED" client -method shutdown
sleep 1
sudo "$CORE" setup
ping_until_ready
for name in offveil-core sing-box ciadpi; do
  cmp "$APP/Contents/MacOS/$name" "$(dirname "$INSTALLED")/$name"
done
echo "First install, signature preservation, non-root IPC, demand-start and payload refresh passed."
