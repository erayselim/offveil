# Fetches official sing-box Windows amd64 build and verifies SHA-256.
# Source: https://github.com/SagerNet/sing-box/releases
$ErrorActionPreference = "Stop"
$Version = "1.13.14"
$Asset = "sing-box-$Version-windows-amd64.zip"
$Expected = "f580782c6dd10f7691c66cea1d7c421813c5fbf7e305d1ee7ce0c3a40d196341"
$Url = "https://github.com/SagerNet/sing-box/releases/download/v$Version/$Asset"
$Root = Split-Path $PSScriptRoot -Parent  # offveil-core
$OutDir = Join-Path $Root "third_party\sing-box"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$Zip = Join-Path $env:TEMP $Asset
Write-Host "Downloading $Url"
Invoke-WebRequest -Uri $Url -OutFile $Zip -UseBasicParsing
$hash = (Get-FileHash -Algorithm SHA256 $Zip).Hash.ToLowerInvariant()
if ($hash -ne $Expected) {
    throw "SHA256 mismatch: got $hash expected $Expected"
}

$Extract = Join-Path $env:TEMP "sing-box-extract-$Version"
if (Test-Path $Extract) { Remove-Item -Recurse -Force $Extract }
Expand-Archive -Path $Zip -DestinationPath $Extract -Force

$Src = Get-ChildItem -Recurse $Extract -Filter "sing-box.exe" | Select-Object -First 1
if (-not $Src) { throw "sing-box.exe not found in archive" }
Copy-Item $Src.FullName (Join-Path $OutDir "sing-box.exe") -Force
$Lic = Get-ChildItem -Recurse $Extract -Filter "LICENSE*" | Select-Object -First 1
if ($Lic) { Copy-Item $Lic.FullName (Join-Path $OutDir "LICENSE") -Force }

@"
# sing-box $Version (Windows amd64)

Fetched by ``scripts/fetch-sing-box.ps1``.

- Upstream: https://github.com/SagerNet/sing-box
- Release: v$Version
- ZIP SHA256: $Expected

Used as selective tunnel sidecar (WARP WireGuard endpoint or VLESS Reality).
"@ | Set-Content -Path (Join-Path $OutDir "README.md") -Encoding UTF8

Write-Host "OK -> $(Join-Path $OutDir 'sing-box.exe')"
Write-Host "Place next to offveil-core.exe: Copy-Item third_party\sing-box\sing-box.exe .\sing-box.exe"
