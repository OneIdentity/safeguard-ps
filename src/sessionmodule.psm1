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