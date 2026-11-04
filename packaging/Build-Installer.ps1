[CmdletBinding()]
param(
    [string]$BinDir,
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Import-Module (Join-Path $root 'tools\ProjectMetadata.psm1') -Force -ErrorAction Stop
$metadata = Get-SupportAssistProjectMetadata -Root $root
if ([string]::IsNullOrWhiteSpace($BinDir)) {
    $BinDir = Join-Path $root 'out\build\windows-msvc-release\Release'
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $root 'out\packages'
}

if (-not (Test-Path $BinDir -PathType Container)) {
    throw "Release binary directory not found: $BinDir"
}

$wix = Get-Command wix.exe -CommandType Application -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($null -eq $wix) {
    throw 'WiX Toolset v4 (wix.exe) is required to build the MSI.'
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$output = (Resolve-Path $OutputDirectory).Path
$wxs = Join-Path $PSScriptRoot 'SupportAssistTool.wxs'
$msi = Join-Path $output ("{0}-x64.msi" -f $metadata.PackageBase)

& $wix.Source build $wxs -arch x64 `
    -d "BinDir=$BinDir" `
    -d "ProductName=$($metadata.productName)" `
    -d "CompanyName=$($metadata.companyName)" `
    -d "ProductVersion=$($metadata.version)" `
    -d "UpgradeCode=$($metadata.upgradeCode)" `
    -d "ExecutableName=$($metadata.executableName)" `
    -o $msi
if ($LASTEXITCODE -ne 0) {
    throw ("WiX build failed with exit code {0}" -f $LASTEXITCODE)
}

Write-Host "Created $msi"
