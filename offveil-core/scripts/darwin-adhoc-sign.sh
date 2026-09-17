#!/usr/bin/env bash
# Ad-hoc sign a Mach-O after a replace-copy.
# In-place `cp` keeps the inode and can leave a stale kernel signature cache
# (Killed: 9 / Code Signature Invalid). Write a new file, then:
#   codesign --force -s -
set -euo pipefail

adhoc_sign() {
  local path="$1"
  if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "darwin-adhoc-sign: refusing to codesign on $(uname -s)" >&2
    return 1
  fi
  codesign --force -s - "$path"
}

# copy_replace SRC DST — new inode, then ad-hoc sign DST.
copy_replace_sign() {
  local src="$1"
  local dst="$2"
  local dir tmp
  dir="$(dirname "$dst")"
  mkdir -p "$dir"
  tmp="$(mktemp "${dir}/.offveil-sidecar.XXXXXX")"
  if ! cp "$src" "$tmp"; then
    rm -f "$tmp"
    return 1
  fi
  chmod 755 "$tmp"
  if ! mv -f "$tmp" "$dst"; then
    rm -f "$tmp"
    return 1
  fi
  adhoc_sign "$dst"
}
