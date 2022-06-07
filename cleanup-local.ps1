[CmdletBinding()]
Param(
    [string]$TargetDir
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

if (-not (Test-Path $TargetDir))
{
    New-Item -Path $TargetDir -ItemType Container -Force | Out-Null
}
$ModuleName = "safeguard-ps"
$ModuleDir = (Join-Path $TargetDir $ModuleName)
if (-not (Test-Path $ModuleDir))
{
    New-Item -Path $ModuleDir -ItemType Container -Force | Out-Null
}
Remove-Item -Recurse -Force (Join-Path $ModuleDir "*")
Write-Host -ForegroundColor Yellow "$ModuleDir is now clean and you can run:"
Write-Host "`tInstall-Module safeguard-ps -Scope CurrentUser -Verbose"
