#!/usr/bin/env bash
# Stage core + sidecars + licenses for the Darwin Tauri bundle.
# Does not fetch; run fetch-sing-box-darwin-arm64.sh / build-byedpi-darwin.sh first.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CORE="${ROOT}/offveil-core"
DEST="${ROOT}/offveil-ui/src-tauri/bundle-bin"
mkdir -p "$DEST"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "stage-bundle-darwin.sh is Darwin-only" >&2
  exit 1
fi

# shellcheck source=../offveil-core/scripts/darwin-adhoc-sign.sh
source "${CORE}/scripts/darwin-adhoc-sign.sh"

find_core() {
  local c
  for c in "${CORE}/dist/offveil-core" "${CORE}/offveil-core"; do
    if [[ -f "$c" ]]; then
      echo "$c"
      return 0
    fi
  done
  return 1
}

if ! CORE_BIN="$(find_core)"; then
  echo "Building offveil-core (darwin/arm64)"
  (
    cd "$CORE"
    CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o offveil-core ./cmd/offveil-core
  )
  CORE_BIN="${CORE}/offveil-core"
fi
if [[ ! -f "$CORE_BIN" ]]; then
  echo "offveil-core missing; build core first" >&2
  exit 1
fi

find_sidecar() {
  local name="$1"
  local c
  for c in \
    "${CORE}/dist/${name}" \
    "${CORE}/third_party/sing-box/${name}" \
    "${CORE}/third_party/byedpi/${name}"; do
    if [[ -f "$c" ]]; then
      echo "$c"
      return 0
    fi
  done
  return 1
}

SING_BOX="$(find_sidecar sing-box || true)"
CIADPI="$(find_sidecar ciadpi || true)"
if [[ -z "$SING_BOX" ]]; then
  echo "Missing sing-box — run offveil-core/scripts/fetch-sing-box-darwin-arm64.sh" >&2
  exit 1
fi
if [[ -z "$CIADPI" ]]; then
  echo "Missing ciadpi — run offveil-core/scripts/build-byedpi-darwin.sh" >&2
  exit 1
fi

copy_replace_sign "$CORE_BIN" "${DEST}/offveil-core"
copy_replace_sign "$SING_BOX" "${DEST}/sing-box"
copy_replace_sign "$CIADPI" "${DEST}/ciadpi"

cp "${ROOT}/LICENSE" "${DEST}/LICENSE"
cp "${ROOT}/THIRD_PARTY.md" "${DEST}/THIRD_PARTY.md"
if [[ -f "${CORE}/third_party/byedpi/LICENSE" ]]; then
  cp "${CORE}/third_party/byedpi/LICENSE" "${DEST}/byedpi-LICENSE.txt"
fi
if [[ -f "${CORE}/third_party/sing-box/LICENSE" ]]; then
  cp "${CORE}/third_party/sing-box/LICENSE" "${DEST}/sing-box-LICENSE.txt"
fi
if [[ -f "${CORE}/third_party/sing-box/COPYING" ]]; then
  cp "${CORE}/third_party/sing-box/COPYING" "${DEST}/sing-box-COPYING.txt"
fi

echo "Staged Darwin bundle binaries -> $DEST"
ls -l "$DEST"
