$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-SupportAssistProjectMetadata {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    )

    $metadataPath = Join-Path $Root 'project-metadata.json'
    if (-not (Test-Path $metadataPath -PathType Leaf)) {
        throw "Project metadata file not found: $metadataPath"
    }

    try {
        $metadata = Get-Content -LiteralPath $metadataPath -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    catch {
        throw "Project metadata is not valid JSON: $metadataPath`n$($_.Exception.Message)"
    }

    foreach ($property in @(
        'productName', 'productSlug', 'companyName', 'version', 'cmakeProject',
        'executableName', 'upgradeCode'
    )) {
        if ($metadata.PSObject.Properties.Name -notcontains $property -or
            [string]::IsNullOrWhiteSpace([string]$metadata.$property)) {
            throw "Project metadata is missing required property '$property': $metadataPath"
        }
    }

    if ([string]$metadata.version -notmatch '^\d+\.\d+\.\d+$') {
        throw "Project metadata version must be semantic major.minor.patch: $($metadata.version)"
    }
    if ([string]$metadata.upgradeCode -notmatch '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$') {
        throw "Project metadata upgradeCode is not a GUID: $($metadata.upgradeCode)"
    }

    $metadata | Add-Member -NotePropertyName MetadataPath -NotePropertyValue $metadataPath -Force
    $metadata | Add-Member -NotePropertyName PackageBase -NotePropertyValue ("{0}-{1}" -f $metadata.productSlug, $metadata.version) -Force
    return $metadata
}

Export-ModuleMember -Function Get-SupportAssistProjectMetadata
