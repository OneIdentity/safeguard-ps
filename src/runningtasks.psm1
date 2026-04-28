<# Copyright (c) 2026 One Identity LLC. All rights reserved. #>

<#
.SYNOPSIS
Get running tasks from Safeguard via the Web API.

.DESCRIPTION
Get a list of currently running or recently completed tasks on the Safeguard
appliance. Tasks include password checks, password changes, account discovery,
asset discovery, SSH key operations, and more.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER TaskName
A string containing the task name to filter by (e.g. TestConnection,
CheckPassword, ChangePassword, DiscoverAccounts, DiscoverAssets).

.PARAMETER TaskId
A string containing the specific task ID to retrieve. Requires TaskName.

.PARAMETER Fields
An array of the property names to return.

.PARAMETER Filter
A string to pass to the -filter query parameter in the Safeguard Web API.

.PARAMETER IncludeSubmitted
Include tasks that have been submitted but not yet started.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardRunningTask

.EXAMPLE
Get-SafeguardRunningTask -TaskName CheckPassword

.EXAMPLE
Get-SafeguardRunningTask -TaskName TestConnection -TaskId "abc-123"
#>
function Get-SafeguardRunningTask
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
        [ValidateSet("Unknown","TestConnection","CheckPassword","ChangePassword",
            "InstallSshKey","ChangeSshKey","UpdateDependentAsset","DiscoverSshHostKey",
            "DiscoverAccounts","DiscoverAssets","Archive","RestoreAccount","SuspendAccount",
            "PasswordSyncAccounts","DiscoverServices","DirectoryAssetSync",
            "DirectoryAssetDeleteSync","DirectoryProviderSync","DirectoryProviderDeleteSync",
            "CheckSshKey","DiscoverSshKeys","SshKeySyncAccounts","LocalIdentityProviderSync",
            "RevokeSshKey","RetrieveSshHostKey","CheckApiKey","ChangeApiKey",
            "ElevateAccount","DemoteAccount","CheckFile","ChangeFile")]
        [string]$TaskName,
        [Parameter(Mandatory=$false)]
        [string]$TaskId,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields,
        [Parameter(Mandatory=$false)]
        [string]$Filter,
        [Parameter(Mandatory=$false)]
        [switch]$IncludeSubmitted
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($TaskId -and -not $TaskName)
    {
        throw "TaskName is required when specifying TaskId"
    }

    $local:RelPath = "RunningTasks"
    if ($TaskName)
    {
        $local:RelPath = "$($local:RelPath)/$TaskName"
        if ($TaskId)
        {
            $local:RelPath = "$($local:RelPath)/$TaskId"
        }
    }

    $local:Parameters = @{}
    if ($Fields)
    {
        $local:Parameters["fields"] = ($Fields -join ",")
    }
    if ($Filter)
    {
        $local:Parameters["filter"] = $Filter
    }
    if ($IncludeSubmitted)
    {
        $local:Parameters["includeSubmitted"] = $true
    }
    if ($local:Parameters.Count -eq 0)
    {
        $local:Parameters = $null
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET $local:RelPath -Parameters $local:Parameters
}

<#
.SYNOPSIS
Cancel a running task in Safeguard via the Web API.

.DESCRIPTION
Cancel a queued or running task on the Safeguard appliance. Both the task
name and task ID are required to identify the task to cancel.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER TaskName
A string containing the task name (e.g. TestConnection, CheckPassword).

.PARAMETER TaskId
A string containing the task ID to cancel.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Stop-SafeguardRunningTask -TaskName CheckPassword -TaskId "abc-123"

.EXAMPLE
Stop-SafeguardRunningTask TestConnection "def-456"
#>
function Stop-SafeguardRunningTask
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [ValidateSet("Unknown","TestConnection","CheckPassword","ChangePassword",
            "InstallSshKey","ChangeSshKey","UpdateDependentAsset","DiscoverSshHostKey",
            "DiscoverAccounts","DiscoverAssets","Archive","RestoreAccount","SuspendAccount",
            "PasswordSyncAccounts","DiscoverServices","DirectoryAssetSync",
            "DirectoryAssetDeleteSync","DirectoryProviderSync","DirectoryProviderDeleteSync",
            "CheckSshKey","DiscoverSshKeys","SshKeySyncAccounts","LocalIdentityProviderSync",
            "RevokeSshKey","RetrieveSshHostKey","CheckApiKey","ChangeApiKey",
            "ElevateAccount","DemoteAccount","CheckFile","ChangeFile")]
        [string]$TaskName,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$TaskId
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "RunningTasks/$TaskName/$TaskId"
}
