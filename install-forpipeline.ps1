[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true,Position=0)]
    [string]$TargetDir,
    [Parameter(Mandatory=$true,Position=1)]
    [string]$VersionString,
    [Parameter(Mandatory=$true,Position=2)]
    [bool]$IsPrerelease
)

if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }

if (-not (Test-Path $TargetDir))
{
    Write-Host "Creating $TargetDir"
    New-Item -Path $TargetDir -ItemType Container -Force | Out-Null
}
$ModuleName = "safeguard-ps"
$Module = (Join-Path $PSScriptRoot "src\$ModuleName.psd1")
$ModuleCatalog = (Join-Path $PSScriptRoot "src\$ModuleName.cat")

$CodeVersion = "$($VersionString.Split(".")[0..1] -join ".").99999"
$BuildVersion = "$($VersionString)"
Write-Host "Replacing CodeVersion: $CodeVersion with BuildVersion: $BuildVersion"
(Get-Content $Module -Raw).replace($CodeVersion, $BuildVersion) | Set-Content $Module

if (-not $IsPrerelease)
{
    Write-Host "Removing the prerelease tag in the manifest"
    (Get-Content $Module -Raw).replace("Prerelease = 'pre'", "#Prerelease = 'pre'") | Set-Content $Module
}
else
{
    Write-Host "The module will be marked as prerelease"
}

$ModuleDef = (Invoke-Expression -Command (Get-Content $Module -Raw))
if ($ModuleDef["ModuleVersion"] -ne $BuildVersion)
{
    throw "Did not replace code version properly, ModuleVersion is '$($ModuleDef["ModuleVersion"])' BuildVersion is '$BuildVersion'"
}

if ($Env:OS -eq "Windows_NT")
{
    Write-Host "Adding Catalog file for signing"
    New-FileCatalog -CatalogFilePath $ModuleCatalog -CatalogVersion 2.0 -Path (Join-Path $PSScriptRoot "src")
}

Write-Host "Installing '$ModuleName $($ModuleDef["ModuleVersion"])' to '$TargetDir'"
$ModuleDir = (Join-Path $TargetDir $ModuleName)
if (-not (Test-Path $ModuleDir))
{
    New-Item -Path $ModuleDir -ItemType Container -Force | Out-Null
}
$VersionDir = (Join-Path $ModuleDir $ModuleDef["ModuleVersion"])
if (-not (Test-Path $VersionDir))
{
    New-Item -Path $VersionDir -ItemType Container -Force | Out-Null
}
Copy-Item -Recurse -Path (Join-Path $PSScriptRoot "src\*") -Destination $VersionDir
