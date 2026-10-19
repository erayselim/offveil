param([switch]$Race)
$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path $PSScriptRoot -Parent
$ModuleRoot = Join-Path $RepoRoot "offveil-core\tests\tunudp"
$BuildRoot = Join-Path $RepoRoot "offveil-core\dist"
New-Item -ItemType Directory -Path $BuildRoot -Force | Out-Null
Push-Location $ModuleRoot
try {
    $Dependency = (& go mod download -json github.com/sagernet/sing-tun@v0.8.11) | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or -not $Dependency.Dir) { throw "Pinned sing-tun download failed" }
    # Stage the checksum-verified module privately. Go forbids overlays inside
    # GOMODCACHE; the shared cache and the production sidecar remain untouched.
    $TestRoot = Join-Path $BuildRoot ("tun-udp-test-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $TestRoot | Out-Null
    $SourceRoot = Join-Path $TestRoot "sing-tun"
    Copy-Item -LiteralPath $Dependency.Dir -Destination $SourceRoot -Recurse
    $UpstreamFile = Join-Path $SourceRoot "stack_system_windows.go"
    $ReplacementFile = Join-Path $ModuleRoot "testdata\stack_system_windows.go"
    [System.IO.File]::SetAttributes($UpstreamFile, [System.IO.FileAttributes]::Normal)
    [System.IO.File]::WriteAllText($UpstreamFile, [System.IO.File]::ReadAllText($ReplacementFile), [System.Text.UTF8Encoding]::new($false))
    $ModFile = Join-Path $TestRoot "regression.mod"
    Copy-Item -LiteralPath (Join-Path $ModuleRoot "go.mod") -Destination $ModFile
    Copy-Item -LiteralPath (Join-Path $ModuleRoot "go.sum") -Destination (Join-Path $TestRoot "regression.sum")
    $CoreRoot = Join-Path $RepoRoot "offveil-core"
    & go mod edit "-modfile=$ModFile" "-replace=github.com/sagernet/sing-tun=$SourceRoot" "-replace=github.com/erayselim/offveil/offveil-core=$CoreRoot"
    if ($LASTEXITCODE -ne 0) { throw "Test module staging failed" }
    $TestArgs = @("test", "-modfile=$ModFile", "-tags=with_gvisor", "-timeout=60s", "-v")
    if ($Race) { $TestArgs += "-race" }
    & go @TestArgs ./...
    if ($LASTEXITCODE -ne 0) { throw "Packet-level UDP regression failed" }
} finally {
    Pop-Location
}
