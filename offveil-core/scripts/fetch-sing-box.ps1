# Retained entry point: build pinned source with the security-patched Go toolchain.
$ErrorActionPreference = 'Stop'
$Root = Split-Path $PSScriptRoot -Parent
Push-Location (Join-Path $Root 'tools/singbox')
try {
    go run build.go (Join-Path $Root 'third_party/sing-box')
    if ($LASTEXITCODE -ne 0) { throw 'Verified sing-box source build failed' }
} finally { Pop-Location }
