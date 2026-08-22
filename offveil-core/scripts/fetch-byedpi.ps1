# Fetches official ByeDPI (ciadpi) Windows amd64 build and verifies SHA-256.
# Source: https://github.com/hufrea/byedpi/releases
$ErrorActionPreference = "Stop"
$Version = "0.17.3"
$Asset = "byedpi-17.3-x86_64-w64.zip"
$Expected = "70d2c94147193cb915f9c6eb5144b8d404dacbcfa90bda2383b6b211afafa456"
$Url = "https://github.com/hufrea/byedpi/releases/download/v$Version/$Asset"
$Root = Split-Path $PSScriptRoot -Parent  # offveil-core
$OutDir = Join-Path $Root "third_party\byedpi"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$Zip = Join-Path $env:TEMP $Asset
Write-Host "Downloading $Url"
Invoke-WebRequest -Uri $Url -OutFile $Zip -UseBasicParsing
$hash = (Get-FileHash -Algorithm SHA256 $Zip).Hash.ToLowerInvariant()
if ($hash -ne $Expected) {
    throw "SHA256 mismatch: got $hash expected $Expected"
}

$Extract = Join-Path $env:TEMP "byedpi-extract-$Version"
if (Test-Path $Extract) { Remove-Item -Recurse -Force $Extract }
Expand-Archive -Path $Zip -DestinationPath $Extract -Force

$Src = Get-ChildItem -Recurse $Extract -Filter "ciadpi.exe" | Select-Object -First 1
if (-not $Src) { throw "ciadpi.exe not found in archive" }
Copy-Item $Src.FullName (Join-Path $OutDir "ciadpi.exe") -Force
$Lic = Get-ChildItem -Recurse $Extract -Filter "LICENSE*" | Select-Object -First 1
if ($Lic) { Copy-Item $Lic.FullName (Join-Path $OutDir "LICENSE") -Force }
Write-Host "OK -> $(Join-Path $OutDir 'ciadpi.exe')"
Write-Host "Place next to offveil-core.exe: Copy-Item third_party\byedpi\ciadpi.exe .\ciadpi.exe"
