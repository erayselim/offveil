#!/usr/bin/env bash
# Official sing-box darwin/arm64 tarball, SHA-256 fail-closed.
# Same minor as Windows fetch-sing-box.ps1 (1.13.14). Intel / linux tarball rejected.
set -euo pipefail

VERSION="1.13.14"
ASSET="sing-box-${VERSION}-darwin-arm64.tar.gz"
EXPECTED="73e8967b0fc08e17bce4263ca56ebc394822401a16497a1c4e02316c888202ab"
URL="https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/${ASSET}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${ROOT}/third_party/sing-box"
STAGE="${1:-}"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "fetch-sing-box-darwin-arm64.sh is Darwin-only" >&2
  exit 1
fi

if [[ -n "$STAGE" ]]; then
  mkdir -p "$STAGE"
  STAGE="$(cd "$STAGE" && pwd)"
fi

case "$ASSET" in
  *linux*|*amd64*|*x86_64*)
    echo "refusing non-darwin-arm64 asset: $ASSET" >&2
    exit 1
    ;;
esac

mkdir -p "$OUT_DIR"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/offveil-sing-box.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

TAR="${TMP}/${ASSET}"
echo "Downloading $URL"
curl -fsSL "$URL" -o "$TAR"
HASH="$(shasum -a 256 "$TAR" | awk '{print $1}')"
if [[ "$HASH" != "$EXPECTED" ]]; then
  echo "SHA256 mismatch: got $HASH expected $EXPECTED" >&2
  exit 1
fi

mkdir -p "${TMP}/extract"
tar -xzf "$TAR" -C "${TMP}/extract"

SRC=""
while IFS= read -r -d '' f; do
  SRC="$f"
  break
done < <(find "${TMP}/extract" -type f -name 'sing-box' -print0)
if [[ -z "$SRC" ]]; then
  echo "sing-box binary not found in archive" >&2
  exit 1
fi

# shellcheck source=darwin-adhoc-sign.sh
source "$(cd "$(dirname "$0")" && pwd)/darwin-adhoc-sign.sh"

copy_replace_sign "$SRC" "${OUT_DIR}/sing-box"

LIC=""
while IFS= read -r -d '' f; do
  LIC="$f"
  break
done < <(find "${TMP}/extract" -type f \( -name 'LICENSE*' -o -name 'COPYING' \) -print0)
if [[ -n "$LIC" ]]; then
  cp "$LIC" "${OUT_DIR}/$(basename "$LIC")"
fi

cat > "${OUT_DIR}/README.darwin.md" <<EOF
# sing-box ${VERSION} (darwin arm64)

Fetched by \`scripts/fetch-sing-box-darwin-arm64.sh\`.

- Upstream: https://github.com/SagerNet/sing-box
- Release: v${VERSION}
- Asset: ${ASSET}
- TAR SHA256: ${EXPECTED}

Windows zip stays \`scripts/fetch-sing-box.ps1\`. Do not merge this binary into the NSIS bundle.
EOF

echo "OK -> ${OUT_DIR}/sing-box"

if [[ -n "$STAGE" ]]; then
  copy_replace_sign "${OUT_DIR}/sing-box" "${STAGE}/sing-box"
  echo "OK -> ${STAGE}/sing-box"
fi
