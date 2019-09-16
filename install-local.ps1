[CmdletBinding()]
Param(
  [string]$TargetDir
)

if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }

if ($PSVersionTable.Platform -ne "Unix")
{
    $UserProf = $env:USERPROFILE
    $Delim = ';'
}
else
{
    $UserProf = $HOME
    $Delim = ':'
}

if (-not $TargetDir)
{
    $TargetDir = [array]($env:PSModulePath -split $Delim) | Where-Object { $_.StartsWith($UserProf) } | Select-Object -First 1
    if (-not $TargetDir)
    {
        throw "Unable to find a PSModulePath in your user profile (" + $UserProf + "), PSModulePath: " + $env:PSModulePath
    }
}

if (-not (Test-Path $TargetDir))
{
    Write-Host "Creating target directory '$TargetDir'"
    New-Item -Path $TargetDir -ItemType Container -Force | Out-Null
}
$ModuleName = "safeguard-ps"
$Module = (Join-Path $PSScriptRoot "src\$ModuleName.psd1")
$ModuleDef = (Invoke-Expression -Command (Get-Content $Module -Raw))

Write-Host "Installing '$ModuleName $($ModuleDef["ModuleVersion"])' to '$TargetDir'"
$ModuleDir = (Join-Path $TargetDir $ModuleName)
if (-not (Test-Path $ModuleDir))
{
    Write-Host "Creating module directory '$ModuleDir'"
    New-Item -Path $ModuleDir -ItemType Container -Force | Out-Null
}
else
{
    Write-Host "Removing module directory '$ModuleDir'"
    Remove-Item -Recurse -Force (Join-Path $ModuleDir "*")
}
$VersionDir = (Join-Path $ModuleDir $ModuleDef["ModuleVersion"])
if (-not (Test-Path $VersionDir))
{
    Write-Host "Creating version directory '$VersionDir'"
    New-Item -Path $VersionDir -ItemType Container -Force | Out-Null
}
$Sources = (Join-Path $PSScriptRoot (Join-Path "src" "*"))
Write-Host "Copying '$Sources' to '$VersionDir'"
Copy-Item -Recurse -Path $Sources -Destination $VersionDir
