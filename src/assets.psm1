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
function Invoke-AssetSshHostKeyDiscovery
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$Asset,
        [Parameter(Mandatory=$false)]
        [object]$AcceptSshHostKey
    )

    $ErrorActionPreference = "Stop"

    Write-Host "Discovering SSH host key..."
    $SshHostKey = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                       POST "Assets/$($Asset.Id)/DiscoverSshHostKey")
    $Asset.SshHostKey = $SshHostKey.SshHostKey
    if ($AcceptSshHostKey)
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            PUT "Assets/$($Asset.Id)" -Body $Asset
    }
    else
    {
        if (Show-SshHostKeyPrompt $SshHostKey.SshHostKey $SshHostKey.Fingerprint)
        {
            Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                PUT "Assets/$($Asset.Id)" -Body $Asset
        }
        else
        {
            throw "SSH host key not accepted"
        }
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

<#
.SYNOPSIS
Get assets from Safeguard via the Web API.

.DESCRIPTION
Get assets from Safeguard that can be used for archiving
backups and session recordings.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER DisplayName
A string containing the display name for this asset. Optional, unless
NetworkAddress is an IP address rather than a DNS name.

.PARAMETER Description
A string containing a description for this asset.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID where this asset should be created.

.PARAMETER NetworkAddress
A string containing the network address for this asset.

.PARAMETER Port
An integer containing the port for this asset.

.PARAMETER Platform
A platform ID for a specific platform type or a string to search for desired platform type.

.PARAMETER ServiceAccountDomainName
A string containing the service account domain name if it has one.

.PARAMETER ServiceAccountName
A string containing the service account name.

.PARAMETER ServiceAccountPassword
A SecureString containing the password to use for the service account.

.PARAMETER ServiceAccountSecretKey
A string containing an API access key for the service account.

.PARAMETER AcceptSshHostKey
Whether or not to auto-accept SSH host key for platforms that support it.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
New-SafeguardAsset -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
New-SafeguardAsset winserver.domain.corp 31 archie
#>
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
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = -1,
        [Parameter(Mandatory=$true,Position=0)]
        [string]$NetworkAddress,
        [Parameter(Mandatory=$false,Position=1)]
        [object]$Platform,
        [Parameter(Mandatory=$false)]
        [int]$Port,
        [Parameter(Mandatory=$false)]
        [ValidateSet("None","Password","SshKey","DirectoryPassword","LocalHostPassword","AccessKey","AccountPassword",IgnoreCase=$true)]
        [string]$ServiceAccountCredentialType,
        [Parameter(Mandatory=$false)]
        [string]$ServiceAccountDomainName,
        [Parameter(Mandatory=$true,Position=2)]
        [string]$ServiceAccountName,
        [Parameter(Mandatory=$false,Position=3)]
        [SecureString]$ServiceAccountPassword,
        [Parameter(Mandatory=$false)]
        [string]$ServiceAccountSecretKey,
        [Parameter(Mandatory=$false)]
        [switch]$AcceptSshHostKey = $false
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
    switch ($ServiceAccountCredentialType.ToLower())
    {
        {$_ -in "password","accountpassword","accesskey"} {
            if (-not $PSBoundParameters.ContainsKey("ServiceAccountName"))
            {
                $ServiceAccountName = (Read-Host "ServiceAccountName")
            }
            $local:ConnectionProperties["ServiceAccountName"] = $ServiceAccountName
            if ($ServiceAccountCredentialType -eq "AccessKey")
            {
                if (-not $PSBoundParameters.ContainsKey("ServiceAccountSecretKey"))
                {
                    $ServiceAccountSecretKey = (Read-Host "ServiceAccountSecretKey")
                }
                $local:ConnectionProperties["SecretKey"] = $ServiceAccountSecretKey
            }
            else
            {
                if (-not $PSBoundParameters.ContainsKey("ServiceAccountPassword"))
                {
                    $ServiceAccountPassword = (Read-Host -AsSecureString "ServiceAccountPassword")
                }
                $local:ConnectionProperties["ServiceAccountPassword"] = $ServiceAccountPassword
            }
        }
        "sshkey" {
            throw "SSH Keys are not supported for asset creation yet"
        }
        default {
            throw "$ServiceAccountCredentialType are not supported yet"
        }
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

    $NewAsset = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                     POST Assets -Body $Body)

    try
    {
        if ($NewAsset.Platform.ConnectionProperties.SupportsSshTransport)
        {
            Invoke-AssetSshHostKeyDiscovery -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $NewAsset -AcceptSshHostKey:$AcceptSshHostKey
        }
        else
        {
            $NewAsset
        }
    }
    catch
    {
        Write-Host -ForegroundColor Yellow "Error setting up SSH host key, removing asset..."
        Remove-SafeguardAsset -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Asset.Id
        throw
    }
}

<#
.SYNOPSIS
Test connection to an asset in Safeguard via the Web API.

.DESCRIPTION
Test the connection to an asset by attempting to determine whether or
not the configured service account can manage passwords for this asset.
This is an asynchronous task in Safeguard.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Asset
An integer containing the ID of the asset to test connection to or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Test-SafeguardAsset -AccessToken $token -Appliance 10.5.32.54 -Insecure 5

.EXAMPLE
Test-SafeguardAsset 5
#>
function Test-SafeguardAsset
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
    $AssetId = Resolve-SafeguardAssetId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Asset

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
        POST "Assets/$AssetId/TestConnection" -LongRunningTask
}

<#
.SYNOPSIS
Remove an asset from Safeguard via the Web API.

.DESCRIPTION
Remove an asset from Safeguard. Make sure it is not in use before
you remove it.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Asset
An integer containing the ID of the asset to remove or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardAsset -AccessToken $token -Appliance 10.5.32.54 -Insecure 5

.EXAMPLE
Remove-SafeguardAsset 5
#>
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

    $AssetId = Resolve-SafeguardAssetId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Asset
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "Assets/$AssetId"
}