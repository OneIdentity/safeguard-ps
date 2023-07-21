[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$Appliance
)

if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }

# -- Login --
Write-Host -ForegroundColor Yellow  "login"
Connect-Safeguard -Appliance $Appliance -Browser

# GET core/v3/Me
Write-Host -ForegroundColor Yellow  "GET Me"
$me = Invoke-SafeguardMethod Core GET "Me"

# -- Logout --
Disconnect-Safeguard