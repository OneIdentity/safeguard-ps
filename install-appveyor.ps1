$ErrorActionPreference = "Stop"

$TargetDir = (($env:PSModulePath -split ';') | Where-Object { $_.StartsWith($env:UserProfile) })[0]
if (-not $TargetDir)
{
    throw "Unable to find a PSModulePath in your user profile (" + $env:UserProfile + "), PSModulePath: " + $env:PSModulePath
}

if (-not (Test-Path $TargetDir))
{
    Write-Host "Creating $TargetDir"
    New-Item -Path $TargetDir -ItemType Container -Force | Out-Null
}
$ModuleName = "safeguard-ps"
$Module = (Join-Path $PSScriptRoot "src\$ModuleName.psd1")

$CodeVersion = "$($env:APPVEYOR_BUILD_VERSION.Split(".")[0..2] -join ".").99999"
$BuildVersion = "$($env:APPVEYOR_BUILD_VERSION)"
Write-Host "Replacing CodeVersion: $CodeVersion with BuildVersion: $BuildVersion"
(Get-Content $Module -Raw).replace($CodeVersion, $BuildVersion) | Set-Content $Module

$ModuleDef = (Invoke-Expression -Command (Get-Content $Module -Raw))
if ($ModuleDef["ModuleVersion"] -ne $BuildVersion)
{
    throw "Did not replace code version properly, ModuleVersion is '$($ModuleDef["ModuleVersion"])' BuildVersion is '$BuildVersion'"
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
