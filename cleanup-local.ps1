Param(
    [string]$TargetDir
)

$ErrorActionPreference = "Stop"

if (-not $TargetDir)
{
    $TargetDir = [array]($env:PSModulePath -split ';') | Where-Object { $_.StartsWith($env:UserProfile) }
    if($TargetDir.Count -eq 0)
    {
        throw "Unable to find a PSModulePath in your user profile (" + $env:UserProfile + "), PSModulePath: " + $env:PSModulePath
    }
    $TargetDir = $TargetDir[0]
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
