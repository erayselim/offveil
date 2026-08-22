# Fetches official Wintun 0.14.1 and verifies SHA-256.
$ErrorActionPreference = "Stop"
$Version = "0.14.1"
$Expected = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
$Url = "https://www.wintun.net/builds/wintun-$Version.zip"
$Root = Split-Path $PSScriptRoot -Parent  # offveil-core
$OutDir = Join-Path $Root "third_party\wintun"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$Zip = Join-Path $env:TEMP "wintun-$Version.zip"
Write-Host "Downloading $Url"
Invoke-WebRequest -Uri $Url -OutFile $Zip -UseBasicParsing
$hash = (Get-FileHash -Algorithm SHA256 $Zip).Hash.ToLowerInvariant()
if ($hash -ne $Expected) {
    throw "SHA256 mismatch: got $hash expected $Expected"
}

$Extract = Join-Path $env:TEMP "wintun-extract-$Version"
if (Test-Path $Extract) { Remove-Item -Recurse -Force $Extract }
Expand-Archive -Path $Zip -DestinationPath $Extract -Force

$SrcDll = Join-Path $Extract "wintun\bin\amd64\wintun.dll"
Copy-Item $SrcDll (Join-Path $OutDir "wintun.dll") -Force
$License = Join-Path $Extract "wintun\LICENSE.txt"
if (Test-Path $License) {
    Copy-Item $License (Join-Path $OutDir "LICENSE.txt") -Force
}
Write-Host "OK -> $(Join-Path $OutDir 'wintun.dll')"
