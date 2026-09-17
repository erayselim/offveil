#!/usr/bin/env bash
# Build ciadpi from the same ByeDPI tag as Windows (v0.17.3).
# Official *-aarch64.tar.gz is Linux; do not download it (exec format error on M1).
set -euo pipefail

TAG="v0.17.3"
COMMIT="7efde1b1296eaaa187b70e951894dde17527489c"
REPO="https://github.com/hufrea/byedpi.git"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${ROOT}/third_party/byedpi"
STAGE="${1:-}"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "build-byedpi-darwin.sh is Darwin-only (git clone + make; not the Linux aarch64 tarball)" >&2
  exit 1
fi

if [[ -n "$STAGE" ]]; then
  mkdir -p "$STAGE"
  STAGE="$(cd "$STAGE" && pwd)"
fi

mkdir -p "$OUT_DIR"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/offveil-byedpi.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

echo "Cloning $REPO $TAG"
git clone --depth 1 --branch "$TAG" "$REPO" "${TMP}/src"
cd "${TMP}/src"
GOT="$(git rev-parse HEAD)"
if [[ "$GOT" != "$COMMIT" ]]; then
  echo "ByeDPI commit mismatch: got $GOT expected $COMMIT" >&2
  exit 1
fi

# Guard: this script must never curl a release tarball.
if git remote -v | grep -qi 'releases/download'; then
  echo "unexpected releases/download remote" >&2
  exit 1
fi

make
if [[ ! -f ./ciadpi ]]; then
  echo "make did not produce ./ciadpi" >&2
  exit 1
fi

# shellcheck source=darwin-adhoc-sign.sh
source "${ROOT}/scripts/darwin-adhoc-sign.sh"

copy_replace_sign ./ciadpi "${OUT_DIR}/ciadpi"

if [[ -f LICENSE ]]; then
  cp LICENSE "${OUT_DIR}/LICENSE"
fi

echo "OK -> ${OUT_DIR}/ciadpi"

if [[ -n "$STAGE" ]]; then
  copy_replace_sign "${OUT_DIR}/ciadpi" "${STAGE}/ciadpi"
  echo "OK -> ${STAGE}/ciadpi"
fi
