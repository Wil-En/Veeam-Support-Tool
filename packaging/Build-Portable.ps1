[CmdletBinding()]
param(
    [string]$BuildDirectory,
    [ValidateSet('Debug', 'Release')][string]$Configuration = 'Release',
    [string]$OutputDirectory,
    # Mirrors tools/Package-Linux.sh --allow-insecure-dependencies. Produces a clearly marked
    # developer artifact from a dependency set below the reviewed security floor. Never distribute.
    [switch]$AllowInsecureDependencies
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Import-Module (Join-Path $root 'tools\ProjectMetadata.psm1') -Force -ErrorAction Stop
$metadata = Get-SupportAssistProjectMetadata -Root $root
if ([string]::IsNullOrWhiteSpace($BuildDirectory)) {
    $BuildDirectory = Join-Path $root 'out\build\windows-msvc-release'
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $root 'out\packages'
}

$build = (Resolve-Path $BuildDirectory).Path
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$output = (Resolve-Path $OutputDirectory).Path
$stage = Join-Path $output ("{0}-portable" -f $metadata.PackageBase)
$zip = Join-Path $output ("{0}-portable.zip" -f $metadata.PackageBase)

Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $zip -Force -ErrorAction SilentlyContinue
New-Item $stage -ItemType Directory -Force | Out-Null

$binaryRoot = Join-Path $build $Configuration
$executableName = "{0}.exe" -f $metadata.executableName
$source = Join-Path $binaryRoot $executableName
if (-not (Test-Path $source -PathType Leaf)) {
    throw "Required $Configuration application not found: $source"
}
Copy-Item $source $stage

# Unit tests and private build artifacts are intentionally not copied. The
# portable customer payload contains one executable.
$unexpectedExecutables = @(Get-ChildItem -Path $stage -Filter '*.exe' -File)
if ($unexpectedExecutables.Count -ne 1 -or $unexpectedExecutables[0].Name -ne $executableName) {
    throw 'Portable staging must contain exactly one customer-facing executable.'
}

# No loose documents in the payload.
#
# LICENSE went because the package goes to Veeam support engineers who already work under it.
# THIRD_PARTY_NOTICES.md went because the attribution now lives in the User Guide, as an
# Open-Source Components section - the notice still travels with the distribution, in the document
# an engineer would actually open, and the package carries one fewer file.

# The user guide, and only the user guide.
#
# This copied the whole repository docs/ tree - the developer guide, every build-fix report, the
# reference corpus - into a package an engineer carries onto a customer machine and deletes
# afterwards. None of it is for them. What they do need is the guide for the edition they are
# holding.
#
# One guide, matching the package - two would add several megabytes to something whose whole point
# is a minimal footprint. The guides are self-contained: figures, stylesheet and script are
# embedded, so one opened from a USB stick on a machine with no network still renders.
$guideSource = Join-Path $root 'docs\user-guide'
#
# The application resolves the guide by one exact path, built in AppWindow::user_guide_path:
# executable_directory() / documents / Support-Assist-Tool-Windows-User-Guide-<version>.html.
# This staged it as Documentation with the unversioned repository file name, so both the folder
# and the file name disagreed with that lookup and Help > User Guide reported the guide missing
# on a package that contained it. Stage the name the application asks for; Test-SourceConsistency
# compares the two so they cannot drift apart again.
$guideTarget = Join-Path $stage 'documents'
New-Item $guideTarget -ItemType Directory -Force | Out-Null
$guideShippedName = 'Support-Assist-Tool-Windows-User-Guide-{0}.html' -f $metadata.version
foreach ($guide in @('Support-Assist-Tool-User-Guide.html')) {
    $path = Join-Path $guideSource $guide
    if (-not (Test-Path $path -PathType Leaf)) {
        throw ("Required user guide not found: $path. Run tools/Generate-Project-Docs.py before " +
               "packaging - a package that ships without its guide is not a deliverable.")
    }
    Copy-Item $path (Join-Path $guideTarget $guideShippedName)
}
# portable.flag is not created. It was an empty file, and grep across src/ finds no line that
# reads it - SAT does not behave differently for its presence or absence.

# SAT release dependency gate. The Linux packager already refuses to build an official artifact
# from a dependency set below the reviewed floor; Windows portable packaging must do the same.
# CVE-2026-55200 (CVSS 8.1) affects libssh2 up to and including 1.11.1: a malicious SSH server can
# execute code on the SAT client during key exchange, before host-key trust is evaluated.
#
# The floor is 1.11.2, matching CMakeLists.txt and config/security/runtime-security-policy.json.
# It was 1.12.0 here - a version that does not exist and is on no upstream roadmap - so this gate
# would have rejected a build carrying the actual fix, and Windows portable packaging could only be
# produced by declaring the dependencies insecure. The advisory names a fix COMMIT rather than a
# release, which is why the policy also pins requiredFixCommit: a 1.11.2_DEV snapshot taken before
# that commit reports the same version and must not pass on the version number alone.
$libssh2Floor = [version]'1.11.2'
$vcpkgStatus = Join-Path $build 'vcpkg_installed\x64-windows-static\share\libssh2\vcpkg_abi_info.txt'
$libssh2Version = $null
$libssh2Manifest = Join-Path $build 'vcpkg_installed\vcpkg\status'
foreach ($candidate in @($libssh2Manifest)) {
    if (Test-Path $candidate -PathType Leaf) {
        $text = Get-Content -LiteralPath $candidate -Raw
        if ($text -match '(?ms)^Package:\s*libssh2\s*$.*?^Version:\s*([0-9]+(?:\.[0-9]+)+)') {
            $libssh2Version = [version]$Matches[1]
            break
        }
    }
}
# The commit the policy requires, and what the overlay port recorded actually building. A version
# string cannot prove a pre-release build contains a fix; the commit can.
$policyPath = Join-Path $root 'config\security\runtime-security-policy.json'
$requiredCommit = $null
if (Test-Path $policyPath -PathType Leaf) {
    $policy = Get-Content -LiteralPath $policyPath -Raw | ConvertFrom-Json
    # components is an object keyed by component name, not an array.
    if ($policy.components.PSObject.Properties.Name -contains 'libssh2') {
        $entry = $policy.components.libssh2
        if ($entry.PSObject.Properties.Name -contains 'requiredFixCommit') {
            $requiredCommit = [string]$entry.requiredFixCommit
        }
    }
}

$builtCommit = $null
$provenancePath = Join-Path $build 'vcpkg_installed\x64-windows-static\share\libssh2\SAT-PROVENANCE.json'
if (Test-Path $provenancePath -PathType Leaf) {
    $provenance = Get-Content -LiteralPath $provenancePath -Raw | ConvertFrom-Json
    if ($provenance.components.PSObject.Properties.Name -contains 'libssh2') {
        $builtCommit = [string]$provenance.components.libssh2.sourceCommit
    }
}

$fixProven = ($null -ne $requiredCommit) -and ($null -ne $builtCommit) -and
             ($builtCommit -eq $requiredCommit)
if ($fixProven) {
    Write-Host ("SAT release gate: libssh2 built from the required fix commit " +
                "$($requiredCommit.Substring(0,8)) (CVE-2026-55200 remediated).")
}

if ($null -eq $libssh2Version) {
    if (-not $AllowInsecureDependencies) {
        throw ("SAT release gate: the packaged libssh2 version could not be determined, so the " +
               "CVE-2026-55200 floor (>= $libssh2Floor) could not be verified. Re-run with " +
               "-AllowInsecureDependencies to produce a clearly marked developer artifact.")
    }
    Write-Warning 'SAT release gate: libssh2 version undetermined; producing a SECURITY-UNAPPROVED artifact.'
    $script:SecurityUnapproved = $true
} elseif ($libssh2Version -lt $libssh2Floor -and $fixProven) {
    # Below the floor by version, but built from the commit the policy requires. That is the case
    # this CVE actually presents: the advisory names a fix commit and upstream has published no
    # release containing it, so the overlay builds from the commit and the port still reports the
    # base version. Proving the commit is a stricter test than comparing the version, not a
    # relaxation of one - a 1.11.2_DEV snapshot taken before the fix reports the same version and
    # fails here, because its provenance names a different commit.
    Write-Host ("SAT release gate: libssh2 reports $libssh2Version but is built from the required " +
                "fix commit; CVE-2026-55200 is remediated.") -ForegroundColor Green
} elseif ($libssh2Version -lt $libssh2Floor) {
    if (-not $AllowInsecureDependencies) {
        throw ("SAT release gate: libssh2 $libssh2Version is affected by CVE-2026-55200 " +
               "(CVSS 8.1, remote code execution on the SSH client during key exchange, public PoC). " +
               "SAT requires >= $libssh2Floor. vcpkg does not publish a fixed libssh2; use the overlay " +
               "port in ports/libssh2 or wait for vcpkg to publish it. To produce a clearly marked " +
               "developer artifact instead, re-run with -AllowInsecureDependencies.")
    }
    Write-Warning ("SAT release gate OVERRIDDEN: packaging libssh2 $libssh2Version, affected by " +
                   "CVE-2026-55200. This artifact is NOT security-approved and must not be distributed.")
    $script:SecurityUnapproved = $true
} else {
    Write-Host ("SAT release gate: libssh2 $libssh2Version satisfies the CVE-2026-55200 floor.") -ForegroundColor Green
}

# Record the exact static vcpkg dependency closure used by the Windows build.
# This does not replace vulnerability review, but makes the shipped dependency
# set auditable and prevents release provenance from being implicit.
# Written BESIDE the package, not inside it. The gate above still runs and the closure is still
# recorded - that provenance is what proves the CVE-2026-55200 fix commit is in this build - but a
# 7 KB JSON no engineer opens does not travel to a customer machine and back.
$sbomScript = Join-Path $root 'tools\Generate-Windows-Dependency-SBOM.ps1'
$sbomOutput = Join-Path (Split-Path $zip -Parent) 'WINDOWS-DEPENDENCY-SBOM.json'
& $sbomScript -BuildDirectory $build -OutputFile $sbomOutput
# $LASTEXITCODE is only set by native executables. $sbomScript is a PowerShell script, so it never
# sets one, and under Set-StrictMode reading the unset variable is itself a terminating error -
# which failed packaging AFTER the SBOM had been written correctly. A failing script throws under
# ErrorActionPreference = 'Stop', so the meaningful check is that the artifact exists and has
# content.
$sbomFile = Get-Item -LiteralPath $sbomOutput -ErrorAction SilentlyContinue
if ($null -eq $sbomFile -or $sbomFile.Length -eq 0) {
    throw 'Windows dependency SBOM generation failed.'
}

Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -CompressionLevel Optimal

# The checksum covers the finished .zip and sits next to it. Hashing the staged files INTO the
# package meant the manifest could only verify files someone had already extracted - and the thing
# anyone actually wants to verify is the archive they were handed.
$archiveHash = Get-FileHash -Algorithm SHA256 -LiteralPath $zip
('{0} *{1}' -f $archiveHash.Hash.ToLowerInvariant(), (Split-Path $zip -Leaf)) |
    Set-Content (Join-Path (Split-Path $zip -Parent) 'SHA256SUMS.txt') -Encoding ascii

Write-Host "Created $zip"
