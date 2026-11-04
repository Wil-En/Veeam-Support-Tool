$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Add-SupportAssistPathEntry {
    param([Parameter(Mandatory = $true)][string]$Directory)

    if ([string]::IsNullOrWhiteSpace($Directory) -or -not (Test-Path $Directory -PathType Container)) {
        return
    }

    $entries = @($env:Path -split ';' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if (-not ($entries | Where-Object { $_.TrimEnd('\\') -ieq $Directory.TrimEnd('\\') })) {
        $env:Path = "$Directory;$env:Path"
    }
}

function Get-SupportAssistExecutablePath {
    param(
        [Parameter(Mandatory = $true)][string]$CommandName,
        [Parameter(Mandatory = $false)][string[]]$Candidates = @()
    )

    $command = Get-Command $CommandName -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -ne $command) {
        return $command.Source
    }

    foreach ($candidate in @($Candidates)) {
        if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path $candidate -PathType Leaf)) {
            return (Resolve-Path $candidate).Path
        }
    }

    return $null
}

function Get-SupportAssistVisualStudioInstallations {
    $installations = New-Object System.Collections.Generic.List[string]

    $vswhereCandidates = @()
    if (-not [string]::IsNullOrWhiteSpace(${env:ProgramFiles(x86)})) {
        $vswhereCandidates += (Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe')
    }
    if (-not [string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
        $vswhereCandidates += (Join-Path $env:ProgramFiles 'Microsoft Visual Studio\Installer\vswhere.exe')
    }

    $vswhere = Get-SupportAssistExecutablePath -CommandName 'vswhere.exe' -Candidates $vswhereCandidates
    if ($null -ne $vswhere) {
        $reported = @(& $vswhere -products '*' -version '[17.0,18.0)' -property installationPath 2>$null)
        foreach ($path in $reported) {
            if (-not [string]::IsNullOrWhiteSpace($path) -and (Test-Path $path -PathType Container)) {
                $installations.Add((Resolve-Path $path).Path)
            }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
        foreach ($edition in @('Community', 'Professional', 'Enterprise', 'BuildTools')) {
            $candidate = Join-Path $env:ProgramFiles "Microsoft Visual Studio\2022\$edition"
            if (Test-Path $candidate -PathType Container) {
                $resolved = (Resolve-Path $candidate).Path
                if (-not ($installations -contains $resolved)) {
                    $installations.Add($resolved)
                }
            }
        }
    }

    return @($installations)
}

function Resolve-SupportAssistBuildEnvironment {
    [CmdletBinding()]
    param([string]$VcpkgRoot = $env:VCPKG_ROOT)

    $cmakeCandidates = New-Object System.Collections.Generic.List[string]

    if (-not [string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
        $cmakeCandidates.Add((Join-Path $env:ProgramFiles 'CMake\bin\cmake.exe'))
    }

    $visualStudioInstallations = @(Get-SupportAssistVisualStudioInstallations)
    foreach ($installation in $visualStudioInstallations) {
        $cmakeCandidates.Add((Join-Path $installation 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'))
    }

    if (-not [string]::IsNullOrWhiteSpace($VcpkgRoot)) {
        $vcpkgTools = Join-Path $VcpkgRoot 'downloads\tools'
        if (Test-Path $vcpkgTools -PathType Container) {
            $downloadedCMake = Get-ChildItem -Path $vcpkgTools -Filter 'cmake.exe' -File -Recurse -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending |
                Select-Object -First 1
            if ($null -ne $downloadedCMake) {
                $cmakeCandidates.Add($downloadedCMake.FullName)
            }
        }
    }

    $cmake = Get-SupportAssistExecutablePath -CommandName 'cmake.exe' -Candidates @($cmakeCandidates)
    if ($null -eq $cmake) {
        throw @'
CMake was not found. Open Visual Studio Installer, modify Visual Studio 2022,
and install "C++ CMake tools for Windows" under the Desktop development with
C++ workload. You may also install CMake separately. After installation,
reopen PowerShell and run this command again.
'@
    }

    $cmakeDirectory = Split-Path $cmake -Parent
    Add-SupportAssistPathEntry -Directory $cmakeDirectory

    $ctestCandidates = @((Join-Path $cmakeDirectory 'ctest.exe'))
    $ctest = Get-SupportAssistExecutablePath -CommandName 'ctest.exe' -Candidates $ctestCandidates
    if ($null -eq $ctest) {
        throw "CTest was not found beside CMake or on PATH. CMake path: $cmake"
    }

    $visualStudio = $null
    foreach ($installation in $visualStudioInstallations) {
        $compiler = Join-Path $installation 'VC\Tools\MSVC'
        if (Test-Path $compiler -PathType Container) {
            $visualStudio = $installation
            break
        }
    }

    [pscustomobject]@{
        CMake = $cmake
        CTest = $ctest
        CMakeDirectory = $cmakeDirectory
        VisualStudio = $visualStudio
        VcpkgRoot = $VcpkgRoot
    }
}

Export-ModuleMember -Function Resolve-SupportAssistBuildEnvironment
