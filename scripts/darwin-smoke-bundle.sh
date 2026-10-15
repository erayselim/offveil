#!/usr/bin/env bash
# Read-only payload checks. No Gatekeeper exceptions, DNS changes or elevation.
# codesign integrity passing does not mean an ad-hoc app passes Gatekeeper.
set -euo pipefail

APP="${1:?usage: darwin-smoke-bundle.sh <app> [updater.tar.gz] [image.dmg]}"
TAR="${2:-}"
DMG="${3:-}"
[[ "$(uname -s)" == Darwin ]] || { echo "Darwin only" >&2; exit 1; }
APP="$(cd "$APP" && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/offveil-smoke.XXXXXX")"
MOUNT=""
cleanup() {
  if [[ -n "$MOUNT" ]]; then hdiutil detach "$MOUNT" || true; fi
  rm -rf "$WORK"
}
trap cleanup EXIT

check_app() {
  local app="$1" main name bin status
  main="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$app/Contents/Info.plist")"
  [[ -n "$main" && "$main" != */* ]]
  codesign --verify --deep --strict --verbose=2 "$app"
  for name in "$main" offveil-core sing-box ciadpi; do
    bin="$app/Contents/MacOS/$name"
    [[ -f "$bin" && -x "$bin" ]]
    lipo "$bin" -verify_arch arm64
    codesign --verify --strict --verbose=2 "$bin"
    # Copies into the archive / disk image must keep exactly the sealed bytes.
    cmp "$APP/Contents/MacOS/$name" "$bin"
  done
  "$app/Contents/MacOS/offveil-core" version
  "$app/Contents/MacOS/sing-box" version
  status=0
  "$app/Contents/MacOS/ciadpi" --help > "$WORK/help.txt" 2>&1 || status=$?
  if [[ "$status" -ge 128 ]] || ! grep -Eqi 'help|port|split|disorder' "$WORK/help.txt"; then
    cat "$WORK/help.txt" >&2
    echo "ciadpi failed to start (exit $status)" >&2
    return 1
  fi
}

check_app "$APP"
if [[ -n "$TAR" ]]; then
  mkdir "$WORK/updater"
  tar -xzf "$TAR" -C "$WORK/updater"
  check_app "$WORK/updater/$(basename "$APP")"
fi
if [[ -n "$DMG" ]]; then
  MOUNT="$WORK/mounted"
  mkdir "$MOUNT"
  hdiutil attach -readonly -nobrowse -mountpoint "$MOUNT" "$DMG"
  [[ -L "$MOUNT/Applications" && -s "$MOUNT/READ-ME-FIRST.txt" ]]
  # Simulate Finder drag-install, preserving quarantine if one is present.
  mkdir "$WORK/Applications"
  ditto "$MOUNT/$(basename "$APP")" "$WORK/Applications/$(basename "$APP")"
  check_app "$WORK/Applications/$(basename "$APP")"
  hdiutil detach "$MOUNT"
  MOUNT=""
fi
echo "Bundle, payload startup and requested containers passed. Gatekeeper approval still needs a downloaded-app test."
