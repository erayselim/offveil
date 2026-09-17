#!/usr/bin/env bash
# Ad-hoc re-seal a Tauri .app so Gatekeeper is "unidentified developer",
# not "damaged". Nested sidecars (cp into Resources) lose their signature.
# Does not use --options runtime (ad-hoc + hardenedRuntime false).
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

xattr -cr "$APP" || true

# Inside-out: helpers, then main binary, then the bundle.
while IFS= read -r -d '' f; do
  codesign --force --sign - --timestamp=none "$f"
done < <(find "$APP/Contents" -type f \( -name offveil-core -o -name sing-box -o -name ciadpi \) -print0)

MAIN=""
shopt -s nullglob
mains=("$APP"/Contents/MacOS/*)
shopt -u nullglob
if [[ ${#mains[@]} -eq 0 ]]; then
  echo "no Contents/MacOS binary in $APP" >&2
  exit 1
fi
for MAIN in "${mains[@]}"; do
  if [[ -f "$MAIN" && -x "$MAIN" && "$MAIN" != *.dSYM ]]; then
    codesign --force --sign - --timestamp=none "$MAIN"
  fi
done

codesign --force --deep --sign - --timestamp=none "$APP"
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
  ln -s /Applications "$STAGE/Applications"
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
