# Copyright (c) 2026 One Identity LLC. All rights reserved.
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Version,
    [Parameter(Mandatory=$true, Position=1)]
    [string]$BuildId,
    [Parameter(Mandatory=$false, Position=2)]
    [string]$TagName = "",
    [Parameter(Mandatory=$false, Position=3)]
    [string]$IsTagBuild = "False"
)

Write-Host "Version = $Version"
Write-Host "BuildId = $BuildId"
Write-Host "TagName = $TagName"
Write-Host "IsTagBuild = $IsTagBuild"

if ($IsTagBuild -eq "True") {
    if ($TagName -notmatch '^v\d+\.\d+\.\d+\.\d+$') {
        Write-Error "Tag '$TagName' does not match expected format v<major>.<minor>.<patch>.<build>"
        exit 1
    }
    $local:VersionString = $TagName -replace '^v', ''
    $local:PrereleaseSuffix = ""
    $local:ReleaseTag = $TagName
    Write-Host "Tag build: VersionString = $($local:VersionString), ReleaseTag = $($local:ReleaseTag)"
} else {
    $local:BuildNumber = ($BuildId - 250000) # shrink shared build number appropriately
    Write-Host "BuildNumber = $($local:BuildNumber)"
    $local:VersionString = "${Version}.${local:BuildNumber}"
    $local:PrereleaseSuffix = "pre$($local:BuildNumber)"
    $local:ReleaseTag = "dev/v${Version}.${local:BuildNumber}-$($local:PrereleaseSuffix)"
    Write-Host "Dev build: VersionString = $($local:VersionString), PrereleaseSuffix = $($local:PrereleaseSuffix), ReleaseTag = $($local:ReleaseTag)"
}

Write-Output "##vso[task.setvariable variable=VersionString;]$($local:VersionString)"
Write-Output "##vso[task.setvariable variable=PrereleaseSuffix;]$($local:PrereleaseSuffix)"
Write-Output "##vso[task.setvariable variable=ReleaseTag;]$($local:ReleaseTag)"
