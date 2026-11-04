[CmdletBinding()]
param(
    [string]$StatusFile,
    [string]$BuildDirectory,
    [string]$OutputFile
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Import-Module (Join-Path $root 'tools\ProjectMetadata.psm1') -Force -ErrorAction Stop
$metadata = Get-SupportAssistProjectMetadata -Root $root

function Resolve-VcpkgStatusFile {
    param([string]$ExplicitStatusFile, [string]$ExplicitBuildDirectory)

    if (-not [string]::IsNullOrWhiteSpace($ExplicitStatusFile)) {
        $resolved = Resolve-Path $ExplicitStatusFile -ErrorAction Stop
        return $resolved.Path
    }

    $roots = @()
    if (-not [string]::IsNullOrWhiteSpace($ExplicitBuildDirectory)) {
        $roots += $ExplicitBuildDirectory
    }
    $roots += @(
        (Join-Path $root 'out\build\windows-msvc-release'),
        (Join-Path $root 'out\build\windows-msvc-debug')
    )

    foreach ($candidateRoot in $roots) {
        if (-not (Test-Path $candidateRoot -PathType Container)) { continue }
        foreach ($candidate in @(
            (Join-Path $candidateRoot 'vcpkg_installed\vcpkg\status'),
            (Join-Path $candidateRoot 'vcpkg_installed\x64-windows-static\vcpkg\status')
        )) {
            if (Test-Path $candidate -PathType Leaf) {
                return (Resolve-Path $candidate).Path
            }
        }
        $found = Get-ChildItem -Path $candidateRoot -Filter status -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '[\\/]vcpkg_installed[\\/].*[\\/]vcpkg[\\/]status$' } |
            Select-Object -First 1
        if ($null -ne $found) { return $found.FullName }
    }

    throw 'Unable to locate the vcpkg installed status file. Pass -StatusFile or -BuildDirectory after configuring/building Windows.'
}

function Parse-VcpkgStatus {
    param([string]$Path)
    $records = @()
    $paragraphs = ((Get-Content -LiteralPath $Path -Raw -Encoding UTF8) -replace "`r`n", "`n") -split "`n`n+"
    foreach ($paragraph in $paragraphs) {
        if ([string]::IsNullOrWhiteSpace($paragraph)) { continue }
        $fields = [ordered]@{}
        foreach ($line in ($paragraph -split "`n")) {
            if ($line -notmatch '^([^:]+):\s*(.*)$') { continue }
            $fields[$matches[1]] = $matches[2]
        }
        if (-not $fields.Contains('Package')) { continue }
        $records += [ordered]@{
            name = [string]$fields['Package']
            version = if ($fields.Contains('Version')) { [string]$fields['Version'] } else { '' }
            architecture = if ($fields.Contains('Architecture')) { [string]$fields['Architecture'] } else { '' }
            feature = if ($fields.Contains('Feature')) { [string]$fields['Feature'] } else { 'core' }
            status = if ($fields.Contains('Status')) { [string]$fields['Status'] } else { '' }
        }
    }
    return @($records | Sort-Object name, feature, architecture)
}

$status = Resolve-VcpkgStatusFile -ExplicitStatusFile $StatusFile -ExplicitBuildDirectory $BuildDirectory
$packages = Parse-VcpkgStatus -Path $status
if ($packages.Count -eq 0) { throw "No package records were parsed from $status" }

if ([string]::IsNullOrWhiteSpace($OutputFile)) {
    $OutputFile = Join-Path (Split-Path $status -Parent) 'SAT-WINDOWS-DEPENDENCY-SBOM.json'
}
$outputParent = Split-Path $OutputFile -Parent
if (-not [string]::IsNullOrWhiteSpace($outputParent)) { New-Item -ItemType Directory -Path $outputParent -Force | Out-Null }

$statusHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $status).Hash.ToLowerInvariant()
$sbom = [ordered]@{
    bomFormat = 'SAT-WINDOWS-DEPENDENCY-SBOM'
    specVersion = '1.0'
    generatedUtc = [DateTimeOffset]::UtcNow.ToString('o')
    productVersion = [string]$metadata.version
    buildRevision = [string]$metadata.buildRevision
    triplet = 'x64-windows-static'
    source = [ordered]@{
        vcpkgStatusFile = $status
        sha256 = $statusHash
    }
    packages = $packages
}

$sbom | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputFile -Encoding UTF8
Write-Host "Windows dependency SBOM: $OutputFile"
Write-Host ("Packages/features recorded: {0}" -f $packages.Count)
