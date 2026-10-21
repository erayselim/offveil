# Clean install + upgrade acceptance, exclusively on a disposable GitHub runner.
param(
    [Parameter(Mandatory = $true)][string]$Installer,
    [Parameter(Mandatory = $true)][string]$ExpectedVersion,
    [string]$PriorTag = 'v1.0.4-beta.3'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'This installer test is restricted to disposable Windows GitHub Actions runners.'
}
$repo = Split-Path $PSScriptRoot -Parent
$installRoot = [IO.Path]::GetFullPath((Join-Path $env:ProgramFiles 'offveil'))
$core = Join-Path $installRoot 'offveil-core.exe'
$uninstaller = Join-Path $installRoot 'uninstall.exe'
$installerPath = (Resolve-Path -LiteralPath $Installer).Path
$script:ownsInstallation = $false
if (Get-Service -Name 'offveil-core' -ErrorAction SilentlyContinue) { throw 'Runner already contains offveil-core' }
if (Test-Path -LiteralPath $installRoot) { throw 'Runner already contains an offveil installation' }

function Invoke-CheckedNative([string]$File, [string[]]$NativeArgs) {
    & $File @NativeArgs
    if ($LASTEXITCODE -ne 0) { throw "Native command failed: $File (exit $LASTEXITCODE)" }
}

function Install-Package([string]$Package) {
    $process = Start-Process -FilePath $Package -ArgumentList '/S' -WindowStyle Hidden -PassThru -Wait
    if ($process.ExitCode -ne 0) { throw "Installer exited with $($process.ExitCode)" }
    $script:ownsInstallation = $true
}

function Assert-Installation([string]$Version, [bool]$Current) {
    if (-not (Test-Path -LiteralPath $core)) { throw 'Installed core missing' }
    $reported = & $core version
    if ($LASTEXITCODE -ne 0 -or -not $reported.StartsWith("offveil-core $Version ")) { throw "Installed core version mismatch: $reported" }
    $required = @('LICENSE', 'THIRD_PARTY.md', 'sing-box.exe', 'ciadpi.exe', 'wintun.dll',
        'licenses\byedpi-LICENSE.txt', 'licenses\sing-box-LICENSE.txt', 'licenses\sing-box-COPYING.txt', 'licenses\wintun-LICENSE.txt')
    if ($Current) { $required += 'licenses\instrument-sans-LICENSE.txt' }
    foreach ($relative in $required) {
        if (-not (Test-Path -LiteralPath (Join-Path $installRoot $relative))) { throw "Installer omitted $relative" }
    }
    if ($Current) {
        foreach ($file in @('offveil-core.exe', 'sing-box.exe', 'ciadpi.exe', 'wintun.dll')) {
            $source = Join-Path $repo "offveil-ui\src-tauri\bundle-bin\$file"
            $installed = Join-Path $installRoot $file
            if ((Get-FileHash -LiteralPath $source).Hash -ne (Get-FileHash -LiteralPath $installed).Hash) { throw "Installed payload differs: $file" }
        }
    }
    $service = Get-Service -Name 'offveil-core'
    try { if ($service.StartType -ne 'Manual') { throw 'Core must remain demand-start' } } finally { $service.Dispose() }
    Invoke-CheckedNative $core @('start')
    $ping = $null
    for ($attempt = 0; $attempt -lt 10; $attempt++) {
        $reply = & $core client -method ping -timeout 2s 2>$null
        if ($LASTEXITCODE -eq 0) { $ping = ($reply | ConvertFrom-Json); break }
        Start-Sleep -Milliseconds 250
    }
    if ($null -eq $ping -or -not $ping.ok -or $ping.result.version -ne $Version) { throw 'Installed service did not answer versioned IPC ping' }
    $status = & $core client -method status
    if ($LASTEXITCODE -ne 0) { throw 'Installed service status failed' }
    $state = $status | ConvertFrom-Json
    if ($state.result.protection -or $state.result.state -ne 'stopped') { throw 'Installer unexpectedly enabled network protection' }
    Invoke-CheckedNative $core @('stop')
    $service = Get-Service -Name 'offveil-core'
    try { $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(15)) } finally { $service.Dispose() }
    Write-Host "Installed payloads, notices, demand-start and IPC verified: $Version"
}

function Uninstall-Package {
    if (-not (Test-Path -LiteralPath $uninstaller)) { throw 'Installed uninstaller missing' }
    # NSIS _?= keeps the uninstaller in-place so -Wait joins the actual process.
    $process = Start-Process -FilePath $uninstaller -ArgumentList @('/S', "_?=$installRoot") -WindowStyle Hidden -PassThru -Wait
    if ($process.ExitCode -ne 0) { throw "Uninstaller exited with $($process.ExitCode)" }
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        $service = Get-Service -Name 'offveil-core' -ErrorAction SilentlyContinue
        if ($null -eq $service) { $script:ownsInstallation = $false; return }
        $service.Dispose()
        Start-Sleep -Milliseconds 300
    }
    throw 'Uninstall left the core service registered'
}

$priorVersion = $PriorTag.TrimStart('v')
$priorName = "offveil_{0}_x64-setup.exe" -f $priorVersion
$priorDir = Join-Path $env:RUNNER_TEMP 'offveil-prior-installer'
New-Item -ItemType Directory -Force -Path $priorDir | Out-Null
Invoke-CheckedNative 'gh' @('release', 'download', $PriorTag, '--repo', $env:GITHUB_REPOSITORY,
    '--pattern', $priorName, '--pattern', "$priorName.sig", '--dir', $priorDir)
$priorPath = Join-Path $priorDir $priorName
Invoke-CheckedNative 'node' @((Join-Path $PSScriptRoot 'release.cjs'), 'verify-updater', $priorPath, "$priorPath.sig")
Invoke-CheckedNative 'node' @((Join-Path $PSScriptRoot 'release.cjs'), 'verify-updater', $installerPath, "$installerPath.sig")
try {
    Install-Package $installerPath
    Assert-Installation $ExpectedVersion $true
    Uninstall-Package
    Install-Package $priorPath
    Assert-Installation $priorVersion $false
    Install-Package $installerPath
    Assert-Installation $ExpectedVersion $true
    Uninstall-Package
    Write-Host "Clean install and $PriorTag -> v$ExpectedVersion upgrade passed."
} finally {
    if ($script:ownsInstallation -and (Test-Path -LiteralPath $uninstaller)) {
        try { Uninstall-Package } catch { Write-Warning "Installer test cleanup: $_" }
    }
}
