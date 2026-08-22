# Stages core + sidecars + license files next to the Tauri bundle inputs.
# Run from anywhere; paths are relative to this script.
$ErrorActionPreference = "Stop"
$Repo = Split-Path $PSScriptRoot -Parent
$Core = Join-Path $Repo "offveil-core"
$Dest = Join-Path $Repo "offveil-ui\src-tauri\bundle-bin"
New-Item -ItemType Directory -Force -Path $Dest | Out-Null

$coreExe = Join-Path $Core "offveil-core.exe"
if (-not (Test-Path $coreExe)) {
    Write-Host "Building offveil-core.exe"
    Push-Location $Core
    try {
        go build -o offveil-core.exe .\cmd\offveil-core
    } finally {
        Pop-Location
    }
}
if (-not (Test-Path $coreExe)) {
    throw "offveil-core.exe missing; build core first"
}

$required = @{
    (Join-Path $Core "third_party\sing-box\sing-box.exe") = "sing-box.exe"
    (Join-Path $Core "third_party\byedpi\ciadpi.exe")     = "ciadpi.exe"
    (Join-Path $Core "third_party\wintun\wintun.dll")     = "wintun.dll"
}
foreach ($src in $required.Keys) {
    if (-not (Test-Path $src)) {
        throw "Missing sidecar $src — run offveil-core/scripts/fetch-*.ps1"
    }
    Copy-Item $src (Join-Path $Dest $required[$src]) -Force
}

Copy-Item $coreExe (Join-Path $Dest "offveil-core.exe") -Force
Copy-Item (Join-Path $Repo "LICENSE") (Join-Path $Dest "LICENSE") -Force
Copy-Item (Join-Path $Repo "THIRD_PARTY.md") (Join-Path $Dest "THIRD_PARTY.md") -Force
Copy-Item (Join-Path $Core "third_party\wintun\LICENSE.txt") (Join-Path $Dest "wintun-LICENSE.txt") -Force
Copy-Item (Join-Path $Core "third_party\byedpi\LICENSE") (Join-Path $Dest "byedpi-LICENSE.txt") -Force
Copy-Item (Join-Path $Core "third_party\sing-box\LICENSE") (Join-Path $Dest "sing-box-LICENSE.txt") -Force
if (Test-Path (Join-Path $Core "third_party\sing-box\COPYING")) {
    Copy-Item (Join-Path $Core "third_party\sing-box\COPYING") (Join-Path $Dest "sing-box-COPYING.txt") -Force
}

Write-Host "Staged bundle binaries -> $Dest"
Get-ChildItem $Dest | ForEach-Object { Write-Host "  $($_.Name)" }
