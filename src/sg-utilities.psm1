# This file contains random Safeguard utilities required by some modules
# Nothing is exported from here
function Wait-SafeguardOnlineStatus
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [int]$Timeout
    )

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
        $local:TimeElapsed = (((Get-Date) - $local:StartTime).Seconds)
        if ($local:TimeElapsed -gt $Timeout)
        {
            throw "Timed out waiting for long-running task, timeout was $Timeout seconds"
        }
    } until ($local:Status -eq "Online")
    Write-Progress -Activity "Waiting for Online Status" -Status "Current: $($local:Status)" -PercentComplete 100
    Write-Host "Safeguard is back online."
}