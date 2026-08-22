# Generates Tauri updater latest.json from NSIS artifacts.
param(
    [Parameter(Mandatory = $true)][string]$NsisDir,
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$DownloadBase,
    [Parameter(Mandatory = $true)][string]$OutFile
)
$ErrorActionPreference = "Stop"
$setup = Get-ChildItem -Path $NsisDir -Filter "*-setup.exe" | Select-Object -First 1
if (-not $setup) { throw "No *-setup.exe in $NsisDir" }
$sigPath = "$($setup.FullName).sig"
if (-not (Test-Path $sigPath)) { throw "Missing updater signature $sigPath (set TAURI_SIGNING_PRIVATE_KEY)" }
$signature = (Get-Content -Raw $sigPath).Trim()
$url = "$($DownloadBase.TrimEnd('/'))/$($setup.Name)"
$pubDate = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
$doc = [ordered]@{
    version  = $Version
    notes    = "Unsigned NSIS. SmartScreen: More info → Run anyway. SAC-on is unsupported. Verify SHA256SUMS.txt."
    pub_date = $pubDate
    platforms = [ordered]@{
        "windows-x86_64"           = @{ signature = $signature; url = $url }
        "x86_64-pc-windows-msvc"   = @{ signature = $signature; url = $url }
    }
}
$json = $doc | ConvertTo-Json -Depth 6
[System.IO.File]::WriteAllText($OutFile, $json)
Write-Host "Wrote $OutFile -> $url"
