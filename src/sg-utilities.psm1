# This file contains random Safeguard utilities required by some modules
# Nothing is exported from here
function Wait-SafeguardOnlineStatus
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [int]$Timeout = 600
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:StartTime = (Get-Date)
    $local:Status = "Unreachable"
    $local:TimeElapsed = 10
    do {
        Write-Progress -Activity "Waiting for Online Status" -Status "Current: $($local:Status)" -PercentComplete (($local:TimeElapsed / $Timeout) * 100)
        try
        {
            $local:Status = (Get-SafeguardStatus -Appliance $Appliance -Insecure:$Insecure).ApplianceCurrentState
        }
        catch {}
        Start-Sleep 2
        $local:TimeElapsed = (((Get-Date) - $local:StartTime).TotalSeconds)
        if ($local:TimeElapsed -gt $Timeout)
        {
            throw "Timed out waiting for Online Status, timeout was $Timeout seconds"
        }
    } until ($local:Status -eq "Online")
    Write-Progress -Activity "Waiting for Online Status" -Status "Current: $($local:Status)" -PercentComplete 100
    Write-Host "Safeguard is back online."
}

function Wait-ForSessionModuleState
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [string]$ContainerState,
        [Parameter(Mandatory=$false,Position=1)]
        [string]$ModuleState,
        [Parameter(Mandatory=$false,Position=2)]
        [int]$Timeout = 180
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:StartTime = (Get-Date)
    if ($ContainerState -and $ModuleState)
    {
        $local:DesiredStatus = "$ContainerState, $ModuleState"
    }
    elseif ($ContainerState)
    {
        $local:DesiredStatus = "$ContainerState, Any"
    }
    elseif ($ModuleState)
    {
        $local:DesiredStatus = "Any, $ModuleState"
    }
    else
    {
        $local:DesiredStatus = "Any, Any"
    }
    $local:StatusString = "Unreachable, Unreachable"
    $local:TimeElapsed = 4
    do {
        Write-Progress -Activity "Waiting for Session Module Status: $($local:DesiredStatus)" -Status "Current: $($local:StatusString)" -PercentComplete (($local:TimeElapsed / $Timeout) * 100)
        try
        {
            $local:StateFound = $false
            $local:Status = (Get-SafeguardSessionContainerStatus -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure)
            $local:StatusString = "$($local:Status.SessionContainerState), $($local:Status.SessionModuleState)"
            if ($ContainerState -and $ModuleState)
            {
                $local:StateFound = ($local:Status.SessionContainerState -eq $ContainerState -and $local:Status.SessionModuleState -eq $ModuleState)
            }
            elseif ($ContainerState)
            {
                $local:StateFound = ($local:Status.SessionContainerState -eq $ContainerState)
            }
            elseif ($ModuleState)
            {
                $local:StateFound = ($local:Status.SessionModuleState -eq $ModuleState)
            }
            else
            {
                $local:StateFound = $true
            }
        }
        catch 
        {
            $local:StatusString = "Unreachable, Unreachable"
        }
        Start-Sleep 2
        $local:TimeElapsed = (((Get-Date) - $local:StartTime).TotalSeconds)
        if ($local:TimeElapsed -gt $Timeout)
        {
            throw "Timed out waiting for Session Module Status, timeout was $Timeout seconds"
        }
    } until ($local:StateFound)
    Write-Progress -Activity "Waiting for Session Module Status: $($local:DesiredStatus)" -Status "Current: $($local:StatusString)" -PercentComplete 100
}
