#!/usr/bin/env bash
# Retained entry point: native source build with a patched, pinned Go toolchain.
set -euo pipefail
if [[ "$(uname -s)" != Darwin || "$(uname -m)" != arm64 ]]; then
  echo "sing-box build requires darwin/arm64" >&2
  exit 1
fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAGE="${1:-}"
if [[ -n "$STAGE" ]]; then
  mkdir -p "$STAGE"
  STAGE="$(cd "$STAGE" && pwd)"
fi
cd "${ROOT}/tools/singbox"
go run build.go "${ROOT}/third_party/sing-box"
# Preserve replace-copy signing semantics for Mach-O binaries.
source "${ROOT}/scripts/darwin-adhoc-sign.sh"
copy_replace_sign "${ROOT}/third_party/sing-box/sing-box" "${ROOT}/third_party/sing-box/sing-box.signed"
mv -f "${ROOT}/third_party/sing-box/sing-box.signed" "${ROOT}/third_party/sing-box/sing-box"
if [[ -n "$STAGE" ]]; then
  copy_replace_sign "${ROOT}/third_party/sing-box/sing-box" "${STAGE}/sing-box"
fi
