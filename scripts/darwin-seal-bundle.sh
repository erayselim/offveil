#!/usr/bin/env bash
# Assemble and ad-hoc sign a Tauri .app for free, manual-approval distribution.
# This verifies integrity; it does NOT establish Developer ID / Gatekeeper trust.
#
# Recreates updater .tar.gz (caller signs it with `tauri signer sign`).
# Optional UDZO dmg with an Applications symlink.
set -euo pipefail

usage() {
  echo "usage: darwin-seal-bundle.sh --app <path.app> [--tar <out.tar.gz>] [--dmg <out.dmg>]" >&2
  exit 2
}

APP=""
TAR=""
DMG=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --app) APP="${2:-}"; shift 2 ;;
    --tar) TAR="${2:-}"; shift 2 ;;
    --dmg) DMG="${2:-}"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "unknown arg: $1" >&2; usage ;;
  esac
done

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "darwin-seal-bundle.sh is Darwin-only" >&2
  exit 1
fi
if [[ -z "$APP" || ! -d "$APP" ]]; then
  echo "missing .app: $APP" >&2
  exit 1
fi

APP="$(cd "$APP" && pwd)"
if [[ "$APP" != *.app ]]; then
  echo "not an .app bundle: $APP" >&2
  exit 1
fi

xattr -cr "$APP"

# Tauri stages these as resources. Mach-O helpers belong in Contents/MacOS;
# keep all three together so setup can copy core + sidecars from the same dir.
for name in offveil-core sing-box ciadpi; do
  src="$APP/Contents/Resources/$name"
  dst="$APP/Contents/MacOS/$name"
  if [[ -f "$src" ]]; then
    mv -f "$src" "$dst"
  fi
  if [[ ! -f "$dst" || ! -x "$dst" ]]; then
    echo "missing executable helper: $dst" >&2
    exit 1
  fi
done

MAIN="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$APP/Contents/Info.plist")"
if [[ -z "$MAIN" || "$MAIN" == */* || ! -x "$APP/Contents/MacOS/$MAIN" ]]; then
  echo "invalid CFBundleExecutable: $MAIN" >&2
  exit 1
fi

# Sign inside-out explicitly. --deep is for verification, not recursive signing.
for name in offveil-core sing-box ciadpi "$MAIN"; do
  bin="$APP/Contents/MacOS/$name"
  lipo -verify_arch arm64 "$bin"
  codesign --force --sign - --timestamp=none "$bin"
  codesign --verify --strict --verbose=2 "$bin"
done

codesign --force --sign - --timestamp=none "$APP"
codesign --verify --deep --strict --verbose=2 "$APP"
echo "sealed $APP"

if [[ -n "$TAR" ]]; then
  mkdir -p "$(dirname "$TAR")"
  TAR="$(cd "$(dirname "$TAR")" && pwd)/$(basename "$TAR")"
  rm -f "$TAR"
  (
    cd "$(dirname "$APP")"
    COPYFILE_DISABLE=1 tar -czf "$TAR" "$(basename "$APP")"
  )
  echo "wrote $TAR"
fi

if [[ -n "$DMG" ]]; then
  mkdir -p "$(dirname "$DMG")"
  DMG="$(cd "$(dirname "$DMG")" && pwd)/$(basename "$DMG")"
  STAGE="$(mktemp -d "${TMPDIR:-/tmp}/offveil-dmg.XXXXXX")"
  cleanup() { rm -rf "$STAGE"; }
  trap cleanup EXIT
  cp -R "$APP" "$STAGE/"
  codesign --verify --deep --strict "$STAGE/$(basename "$APP")"
  ln -s /Applications "$STAGE/Applications"
  ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  cp "$ROOT/docs/install-mac.txt" "$STAGE/READ-ME-FIRST.txt"
  rm -f "$DMG"
  ok=0
  for i in 1 2 3; do
    if hdiutil create -volname offveil -srcfolder "$STAGE" -ov -format UDZO -fs HFS+ "$DMG"; then
      ok=1
      break
    fi
    rm -f "$DMG"
    sleep 3
  done
  if [[ "$ok" -ne 1 ]]; then
    echo "hdiutil create failed" >&2
    exit 1
  fi
  xattr -cr "$DMG" || true
  echo "wrote $DMG"
  trap - EXIT
  cleanup
fi
