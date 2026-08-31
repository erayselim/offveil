# Generates Tauri updater latest.json from NSIS artifacts.
# Notes come from offveil-ui/src/whats-new.json when its version matches.
param(
    [Parameter(Mandatory = $true)][string]$NsisDir,
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$DownloadBase,
    [Parameter(Mandatory = $true)][string]$OutFile,
    [string]$WhatsNewFile = ""
)
$ErrorActionPreference = "Stop"

function Normalize-Ver([string]$v) {
    return $v.Trim().TrimStart("v", "V")
}

if (-not $WhatsNewFile) {
    $WhatsNewFile = Join-Path $PSScriptRoot "..\offveil-ui\src\whats-new.json"
}

$setup = Get-ChildItem -Path $NsisDir -Filter "*-setup.exe" | Select-Object -First 1
if (-not $setup) { throw "No *-setup.exe in $NsisDir" }
$sigPath = "$($setup.FullName).sig"
if (-not (Test-Path $sigPath)) { throw "Missing updater signature $sigPath (set TAURI_SIGNING_PRIVATE_KEY)" }
$signature = (Get-Content -Raw $sigPath).Trim()
$url = "$($DownloadBase.TrimEnd('/'))/$($setup.Name)"
$pubDate = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")

$notes = ""
if (Test-Path $WhatsNewFile) {
    $whatsNew = Get-Content -Raw -Encoding UTF8 $WhatsNewFile | ConvertFrom-Json
    $wnVer = Normalize-Ver ([string]$whatsNew.version)
    $relVer = Normalize-Ver $Version
    if ($wnVer -eq $relVer -and $whatsNew.notes) {
        $notesObj = [ordered]@{
            tr = [string]$whatsNew.notes.tr
            en = [string]$whatsNew.notes.en
        }
        $notes = ($notesObj | ConvertTo-Json -Compress)
    } else {
        Write-Warning "whats-new.json version '$($whatsNew.version)' != release '$Version'; omitting notes"
    }
} else {
    Write-Warning "whats-new.json not found at $WhatsNewFile; omitting notes"
}

$doc = [ordered]@{
    version  = $Version
    notes    = $notes
    pub_date = $pubDate
    platforms = [ordered]@{
        "windows-x86_64"           = @{ signature = $signature; url = $url }
        "x86_64-pc-windows-msvc"   = @{ signature = $signature; url = $url }
    }
}
$json = $doc | ConvertTo-Json -Depth 6
[System.IO.File]::WriteAllText($OutFile, $json)
Write-Host "Wrote $OutFile -> $url"
