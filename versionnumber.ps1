[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Version,
    [Parameter(Mandatory=$true, Position=1)]
    [string]$BuildId
)

Write-Host "Version = $Version"
Write-Host "BuildId = $BuildId"

$local:BuildNumber = ($BuildId - 102500) # shrink shared build number appropriately
Write-Host "BuildNumber = $($local:BuildNumber)"

$local:VersionString = "${Version}.$($local:BuildNumber)"
Write-Host "VersionString = $($local:VersionString)"

Write-Output "##vso[task.setvariable variable=VersionString;]$($local:VersionString)"
