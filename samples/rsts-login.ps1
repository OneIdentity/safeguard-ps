# Copyright (c) 2026 One Identity LLC. All rights reserved.
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$Appliance
)

if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }

# -- Login --
Write-Host -ForegroundColor Yellow  "login"
Connect-Safeguard -Appliance $Appliance -Browser

# GET core/v4/Me
Write-Host -ForegroundColor Yellow  "GET Me"
$me = Invoke-SafeguardMethod Core GET "Me"

# -- Logout --
Disconnect-Safeguard