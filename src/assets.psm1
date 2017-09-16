# Helper
function Resolve-SafeguardAssetId
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$Asset
    )

    $ErrorActionPreference = "Stop"

    if (-not ($Asset -as [int]))
    {
        $local:Assets = @(Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Assets `
                              -Parameters @{ filter = "Name ieq '$Asset'" })
        if (-not $local:Assets)
        {
            $local:Assets = @(Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Assets `
                                  -Parameters @{ filter = "NetworkAddress ieq '$Asset'" })
        }
        if (-not $local:Assets)
        {
            throw "Unable to find asset matching '$Asset'"
        }
        if ($local:Assets.Count -ne 1)
        {
            throw "Found $($local:Assets.Count) assets matching '$Asset'"
        }
        $local:Assets[0].Id
    }
    else
    {
        $Asset
    }
}

<#
.SYNOPSIS
Get assets managed by Safeguard via the Web API.

.DESCRIPTION
Get the assets managed by Safeguard.  Accounts can be added to these assets,
and Safeguard can be configured to manage their passwords.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Asset
An integer containing ID of the archive server to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardArchiveServer -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardArchiveServer
#>
function Get-SafeguardAsset
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [object]$Asset
    )

    $ErrorActionPreference = "Stop"

    if ($PSBoundParameters.ContainsKey("Asset"))
    {
        $AssetId = Resolve-SafeguardAssetId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Asset
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Assets/$AssetId"
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Assets"
    }
}

<#
.SYNOPSIS
Search for an asset in Safeguard via the Web API.

.DESCRIPTION
Search for an asset in Safeguard for any string fields containing
the SearchString.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER SearchString
A string to search for in the asset (caseless).

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Find-SafeguardAsset -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Find-SafeguardAsset "linux.company.corp"
#>
function Find-SafeguardAsset
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [string]$SearchString
    )

    $ErrorActionPreference = "Stop"

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Assets" `
        -Parameters @{ q = $SearchString }
}


function New-SafeguardAsset
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [string]$DisplayName,
        [Parameter(Mandatory=$false)]
        [string]$Description,
        [Parameter(Mandatory=$true,Position=0)]
        [string]$NetworkAddress,
        [Parameter(Mandatory=$false,Position=1)]
        [object]$Platform,
        [Parameter(Mandatory=$false)]
        [ValidateSet("None","Password","SshKey","DirectoryPassword","LocalHostPassword","AccessKey","AccountPassword",IgnoreCase=$true)]
        [string]$ServiceAccountCredentialType,
        [Parameter(Mandatory=$false)]
        [int]$Port,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = -1
    )

    $ErrorActionPreference = "Stop"
    Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local
    Import-Module -Name "$PSScriptRoot\datatypes.psm1" -Scope Local

    if (-not $PSBoundParameters.ContainsKey("DisplayName"))
    {
        if (Test-IpAddress $NetworkAddress)
        {
            $DisplayName = (Read-Host "DisplayName")
        }
        else
        {
            $DisplayName = $NetworkAddress
        }
    }

    if (-not $PSBoundParameters.ContainsKey("Platform"))
    {
        $Platform = (Read-Host "Enter platform ID or search string")
    }
    $local:PlatformId = Resolve-SafeguardPlatform -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Platform

    if (-not $PSBoundParameters.ContainsKey("ServiceAccountCredentialType"))
    {
        $ServiceAccountCredentialType = (Resolve-SafeguardServiceAccountCredentialType)
    }

    $local:ConnectionProperties = @{
        ServiceAccountCredentialType = $ServiceAccountCredentialType;
    }

    if ($PSBoundParameters.ContainsKey("Port")) { $local:ConnectionProperties["Port"] = $Port }

    $Body = @{
        Name = "$DisplayName";
        Description = "$Description";
        NetworkAddress = "$NetworkAddress";
        PlatformId = $local:PlatformId;
        AssetPartitionId = $AssetPartitionId;
        ConnectionProperties = $local:ConnectionProperties
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
        POST Assets -Body $Body
}


function Remove-SafeguardAsset
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [object]$Asset
    )

    $ErrorActionPreference = "Stop"

    if (-not $PSBoundParameters.ContainsKey("Asset"))
    {
        $Asset = (Read-Host "Asset to delete")
    }

    $AssetId = Resolve-SafeguardAsset -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Asset
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "Assets/$AssetId"
}