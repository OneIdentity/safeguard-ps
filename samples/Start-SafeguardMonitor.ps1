[CmdletBinding(DefaultParameterSetName="Text")]
Param (
    [Parameter(Mandatory=$true,Position=0)]
    [string]$Appliance,
    [Parameter(Mandatory=$true,Position=1)]
    [string]$IdentityProvider,
    [Parameter(Mandatory=$true,ParameterSetName="Text",Position=2)]
    [string]$Username,
    [Parameter(Mandatory=$false,ParameterSetName="Text")]
    [SecureString]$Password,
    [Parameter(Mandatory=$true,ParameterSetName="Cred",Position=1)]
    [PSCredential]$Credential,
    [Parameter(Mandatory=$false)]
    [switch]$IgnoreSsl,
    [Parameter(Mandatory=$false)]
    [int]$LongIntervalHours = 12,
    [Parameter(Mandatory=$false)]
    [switch]$LongIntervalBackup,
    [Parameter(Mandatory=$false)]
    [switch]$LongIntervalSupportBundle
)

if (-not (Get-Module safeguard-ps)) { Import-Module safeguard-ps }
if (Get-Module safeguard-ps)
{
    if ($PSCmdlet.ParameterSetName -eq "Text")
    {
        Connect-Safeguard -Appliance $Appliance -IdentityProvider $IdentityProvider -Username $Username -Password $Password
    }
    else
    {
        Connect-Safeguard -Appliance $Appliance -IdentityProvider $IdentityProvider -Credential $Credential
    }
    Write-Host -ForegroundColor Green "Connected to Safeguard -- $Appliance"

    $script:CurrentState = (Get-SafeguardApplianceAvailability).ApplianceCurrentState
    $script:LongIntervalTimestamp = (Get-Date)
    Write-Host "Starting state is $($script:CurrentState)"
    while ($true)
    {
        $local:Status = (Get-SafeguardApplianceAvailability)
        $local:State = $local:Status.ApplianceCurrentState
        Write-Verbose "$($local:Status.CurrentTime) state: $($local:State)"
        if ($local:State -ne $script:CurrentState)
        {
            Write-Host "$($local:Status.CurrentTime) state: $($local:State)"
            if ($local:State -eq "Online")
            {
                Write-Host -ForegroundColor Red "Safeguard is back online"
            }
            else
            {
                if ($local:Status.IsMaintenance -and (-not $local:Status.IsQuarantine))
                {
                    Write-Host -ForegroundColor Yellow "Safeguard is going down for maintenance"
                }
                else
                {
                    Write-Host -ForegroundColor Red "Unexpected state: $($local:State)"
                    try { Get-SafeguardSupportBundle } catch { Write-Host -ForegroundColor Red "Failed to download support bundle when unexpected state detected" }

                    # TODO: Send an email or some other form of alert here
                }
            }
            $script:CurrentState = $local:State
        }
        else
        {
            if ((((Get-Date) - $script:LongIntervalTimestamp).TotalHours) -ge $LongIntervalHours)
            {
                Write-Host "Running long interval tasks"
                $local:LongIntervalTaskBlock = {
                    $SafeguardSession
                    if ($args[1])
                    {
                        try
                        {
                            $local:BackupInfo = (New-SafeguardBackup -Appliance $args[0].Appliance -AccessToken $args[0].AccessToken -Insecure:$args[0].Insecure)
                            Export-SafeguardBackup -Appliance $args[0].Appliance -AccessToken $args[0].AccessToken -Insecure:$args[0].Insecure $local:BackupInfo.Id
                        }
                        catch
                        {
                            Write-Output "Failed to create and download backup for long interval"
                            $_
                        }
                    }
                    if ($args[2])
                    {
                        try
                        {
                            Get-SafeguardSupportBundle -Appliance $args[0].Appliance -AccessToken $args[0].AccessToken -Insecure:$args[0].Insecure
                        }
                        catch
                        {
                            Write-Output "Failed to download support bundle for long interval"
                            $_
                        }
                    }
                }
                Start-Job -ScriptBlock $local:LongIntervalTaskBlock -ArgumentList $SafeguardSession,[bool]$LongIntervalBackup,[bool]$LongIntervalSupportBundle
                $script:LongIntervalTimestamp = (Get-Date)
            }
        }
        Start-Sleep -Seconds 10
        $local:Jobs = (Get-Job -State "Completed")
        if ($local:Jobs.Count -gt 0)
        {
            Write-Host "$($local:Jobs.Count) job(s) completed long interval tasks"
            $local:Jobs | Receive-Job
            $local:Jobs | Remove-Job
        }
    }
}
else
{
    throw "safeguard-ps is not installed"
}
