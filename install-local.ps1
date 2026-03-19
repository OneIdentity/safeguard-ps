# Copyright (c) 2026 One Identity LLC. All rights reserved.
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false,Position=0)]
    [string]$TargetDir,
    [Parameter(Mandatory=$false)]
    [switch]$WithLinting
)

if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

if ($Env:OS -eq "Windows_NT")
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
    $TargetDirs = [array]($env:PSModulePath -split $Delim)
    $TargetDirs | ForEach-Object {
        Write-Host "Potential target directory = '$_'"
    }
    $TargetDir = $TargetDirs | Where-Object { $_.StartsWith($UserProf) } | Select-Object -First 1
    if (-not $TargetDir)
    {
        throw "Unable to find a PSModulePath in your user profile (" + $UserProf + "), PSModulePath: " + $env:PSModulePath
    }
    Write-Host "Selected target directory = '$TargetDir'"
}

Write-Host "Checking for the existence of '$TargetDir'"
if (-not (Test-Path $TargetDir))
{
    Write-Host "Creating target directory '$TargetDir'"
    New-Item -Path $TargetDir -ItemType Container -Force | Out-Null
}
else
{
    Write-Host "Already exists"
}
$ModuleName = "safeguard-ps"
$Module = (Join-Path $PSScriptRoot "src\$ModuleName.psd1")
$ModuleDef = (Invoke-Expression -Command (Get-Content $Module -Raw))

Write-Host -ForegroundColor Green "Installing '$ModuleName $($ModuleDef["ModuleVersion"])' to '$TargetDir'"
$ModuleDir = (Join-Path $TargetDir $ModuleName)
Write-Host -ForegroundColor Blue "Module directory = '$ModuleDir'"
if (-not (Test-Path $ModuleDir))
{
    Write-Host "Creating module directory '$ModuleDir'"
    New-Item -Path $ModuleDir -ItemType Container -Force | Out-Null
}
else
{
    Write-Host "Removing module directory '$ModuleDir' contents"
    (Get-ChildItem -Recurse $ModuleDir) | Sort-Object -Property FullName -Descending | ForEach-Object {
        Write-Verbose "Removing $_"
        if ($_ -is [System.IO.DirectoryInfo]) { $_.Delete($true) }
        else { $_.Delete() }
    }
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

# --- Run PSScriptAnalyzer lint ---
if ($WithLinting)
{
    $LintScript = (Join-Path $PSScriptRoot "Invoke-PsLint.ps1")
    if (Test-Path $LintScript)
    {
        Write-Host ""
        & $LintScript
        if ($LASTEXITCODE -ne 0)
        {
            Write-Warning "Linting reported errors — see output above."
        }
    }
}
