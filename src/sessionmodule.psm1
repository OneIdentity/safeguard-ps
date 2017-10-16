<#
.SYNOPSIS
Get status of session module container running in Safeguard.

.DESCRIPTION
Get the execution status of the session module container and whether there
are active sessions or whether debug logging is enabled.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Component
Optionally get only a single component of the status.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardSessionContainerStatus -AccessToken $token -Appliance 10.5.32.54 -Insecure -Component ContainerState

.EXAMPLE
Get-SafeguardSessionContainerStatus
#>
function Get-SafeguardSessionContainerStatus
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false, Position=0)]
        [ValidateSet("ActiveSessions", "ContainerState", "DebugLogging", "ModuleState", IgnoreCase=$true)]
        [string]$Component
    )

    $ErrorActionPreference = "Stop"

    $local:RelativeUrl = "SessionModuleConfig"
    if ($PSBoundParameters.ContainsKey("Component"))
    {
        # Allow case insensitive actions to translate to appropriate case sensitive URL path
        switch ($Component)
        {
            "activesessions" { $Component = "ActiveSessions"; break }
            "containerstate" { $Component = "ContainerState"; break }
            "debuglogging" { $Component = "DebugLogging"; break }
            "modulestate" { $Component = "ModuleState"; break }
        }
        $local:RelativeUrl = "$($local:RelativeUrl)/$Component"
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance GET $local:RelativeUrl
}

<#
.SYNOPSIS
Get status of session module of Safeguard.

.DESCRIPTION
Get the status of the session module including components such as CPU, disk, memory, load,
network adapters, and network switches.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Component
Optionally get only a single component of the status.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardSessionModuleStatus -AccessToken $token -Appliance 10.5.32.54 -Insecure -Component Memory

.EXAMPLE
Get-SafeguardSessionModuleStatus
#>
function Get-SafeguardSessionModuleStatus
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false, Position=0)]
        [ValidateSet("Cpu", "Disk", "Load", "Memory", "NetworkAdapters", "NetworkSwitches", IgnoreCase=$true)]
        [string]$Component
    )

    $ErrorActionPreference = "Stop"

    $local:RelativeUrl = "SessionModuleConfig/Status"
    if ($PSBoundParameters.ContainsKey("Component"))
    {
        # Allow case insensitive actions to translate to appropriate case sensitive URL path
        switch ($Component)
        {
            "cpu" { $Component = "Cpu"; break }
            "disk" { $Component = "Disk"; break }
            "load" { $Component = "Load"; break }
            "memory" { $Component = "Memory"; break }
            "networkadapters" { $Component = "NetworkAdapters"; break }
            "networkswitches" { $Component = "NetworkSwitches"; break }
        }
        $local:RelativeUrl = "$($local:RelativeUrl)/$Component"
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance GET $local:RelativeUrl
}

<#
.SYNOPSIS
Get version of session module of Safeguard.

.DESCRIPTION
Get the version of the session module firmware.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardSessionModuleVersion -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardSessionModuleVersion
#>
function Get-SafeguardSessionModuleVersion
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure
    )

    $ErrorActionPreference = "Stop"

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance GET "SessionModuleConfig/Version"
}

<#
.SYNOPSIS
Reset the session module running inside Safeguard.

.DESCRIPTION
Reboot the session module components to attempt to restore proper functionality.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Reset-SafeguardSessionModule -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Reset-SafeguardSessionModule
#>
function Reset-SafeguardSessionModule
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure
    )

    $ErrorActionPreference = "Stop"
    Import-Module -name "$PSScriptRoot\sg-utilities.psm1" -Scope Local

    Write-Host "Stopping Safeguard Session Module"
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance POST "SessionModuleConfig/ContainerTurnOff" | Out-Null
    Wait-ForSessionModuleState -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure "Off" "" 30

    Write-Host "Starting Safeguard Session Module "
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance POST "SessionModuleConfig/ContainerStart" | Out-Null
    Wait-ForSessionModuleState -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure "Running" "Running" 120

    Write-Host "Safeguard Sessions are available again."
}

<#
.SYNOPSIS
Repair the session module running inside Safeguard.

.DESCRIPTION
Reinstall the session module components to attempt to restore proper functionality.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Repair-SafeguardSessionModule -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Repair-SafeguardSessionModule
#>
function Repair-SafeguardSessionModule
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure
    )

    $ErrorActionPreference = "Stop"
    Import-Module -name "$PSScriptRoot\sg-utilities.psm1" -Scope Local

    Write-Host "Redeploying Safeguard Session Module"
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance POST "SessionModuleConfig/Redeploy" | Out-Null
    Wait-ForSessionModuleState -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure "Running" "Running" 360

    Write-Host "Safeguard Sessions are available again."
}
