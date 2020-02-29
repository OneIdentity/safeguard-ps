# Helper
function Resolve-AssetPartitionIdFromSafeguardSession
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [object]$AssetPartition = $null,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$false)]
        [switch]$UseDefault = $false
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $AssetPartitionId -and $AssetPartition)
    {
        Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
        $AssetPartitionId = (Resolve-SafeguardAssetPartitionId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AssetPartition)
    }

    if (-not $AssetPartitionId)
    {
        if ($SafeguardSession -and $SafeguardSession["AssetPartitionId"])
        {
            $AssetPartitionId = $SafeguardSession["AssetPartitionId"]
        }
        else
        {
            if ($UseDefault)
            {
                # Default behavior is Macrocosm
                $AssetPartitionId = -1
            }
        }
    }

    $AssetPartitionId
}
function Resolve-SafeguardAssetId
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [object]$AssetPartition = $null,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$Asset
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($Asset.Id -as [int])
    {
        $Asset = $Asset.Id
    }

    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                             -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId)
    if ($AssetPartitionId)
    {
        $local:RelPath = "AssetPartitions/$AssetPartitionId/Assets"
        $local:ErrMsgSuffix = " in asset partition (Id=$AssetPartitionId)"
    }
    else
    {
        $local:RelPath = "Assets"
        $local:ErrMsgSuffix = ""
    }

    if (-not ($Asset -as [int]))
    {
        try
        {
            $local:Assets = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" `
                                 -Parameters @{ filter = "Name ieq '$Asset'" })
            if (-not $local:Assets)
            {
                $local:Assets = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" `
                                     -Parameters @{ filter = "NetworkAddress ieq '$Asset'"; fields = "Id" })
            }
        }
        catch
        {
            Write-Verbose $_
            Write-Verbose "Caught exception with ieq filter, trying with q parameter"
            $local:Assets = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" `
                                 -Parameters @{ q = $Asset; fields = "Id" })
        }
        if (-not $local:Assets)
        {
            throw "Unable to find asset matching '$Asset'$($local:ErrMsgSuffix)"
        }
        if ($local:Assets.Count -ne 1)
        {
            throw "Found $($local:Assets.Count) assets matching '$Asset'$($local:ErrMsgSuffix)"
        }
        $local:Assets[0].Id
    }
    else
    {
        if ($AssetPartitionId)
        {
            $local:Assets = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" `
                                 -Parameters @{ filter = "Id eq $Asset and AssetPartitionId eq $AssetPartitionId"; fields = "Id" })
            if (-not $local:Assets)
            {
                throw "Unable to find asset matching '$Asset'$($local:ErrMsgSuffix)"
            }
        }
        $Asset
    }
}
function Resolve-SafeguardAssetAccountId
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [object]$AssetPartition = $null,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$false)]
        [object]$Asset = $null,
        [Parameter(Mandatory=$false)]
        [int]$AssetId,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$Account
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($Account.Id -as [int])
    {
        $Account = $Account.Id
    }

    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                             -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId)
    if ($AssetPartitionId)
    {
        $local:ErrMsgSuffix = " in asset partition (Id=$AssetPartitionId)"
    }
    else
    {
        $local:ErrMsgSuffix = ""
    }

    if (-not $AssetId -and ($Asset))
    {
        $AssetId = (Resolve-SafeguardAssetId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetPartitionId $AssetPartitionId $Asset)
    }
    if ($AssetId)
    {
        $local:RelPath = "Assets/$AssetId/Accounts"
        $local:ErrMsgSuffix = " on asset (Id=$AssetId)$($local:ErrMsgSuffix)"
    }
    elseif ($AssetPartitionId)
    {
        $local:RelPath = "AssetPartitions/$AssetPartitionId/Accounts"
    }
    else
    {
        $local:RelPath = "AssetAccounts"
    }


    if (-not ($Account -as [int]))
    {
        try
        {
            $local:Accounts = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" `
                                   -Parameters @{ filter = "Name ieq '$Account'"; fields = "Id" })
        }
        catch
        {
            Write-Verbose $_
            Write-Verbose "Caught exception with ieq filter, trying with q parameter"
            $local:Accounts = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" `
                                   -Parameters @{ q = $Account; fields = "Id" })
        }
        if (-not $local:Accounts)
        {
            throw "Unable to find account matching '$Account'$local:ErrMsgSuffix"
        }
        if ($local:Accounts.Count -ne 1)
        {
            throw "Found $($local:Accounts.Count) accounts matching '$Account'$local:ErrMsgSuffix"
        }
        $local:Accounts[0].Id
    }
    else
    {
        if ($AssetPartitionId)
        {
            $local:Accounts = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" `
                                 -Parameters @{ filter = "Id eq $Asset and AssetPartitionId eq $AssetPartitionId"; fields = "Id" })
            if (-not $local:Accounts)
            {
                throw "Unable to find account matching '$Account'$($local:ErrMsgSuffix)"
            }
        }
        $Account
    }
}

<#
.SYNOPSIS
Discover SSH host key by connecting to asset managed by Safeguard via the Web API.

.DESCRIPTION
This cmdlet will cause Safeguard to connect to a previously configured asset
to get its SSH host key.  By default, this cmdlet will prompt whether or not you
would like to accept the discovered SSH host key.  This can be overridden to
automatically accept using the AcceptSshHostKey flag.  If the key is accepted
this cmdlet will update Safeguard with the accepted key.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to run SSH host key discovery in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to run SSH host key discovery in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER Asset
An integer containing the ID of the asset or a string containing the name.

.PARAMETER AcceptSshHostKey
Whether or not to automatically accept the SSH host key that is discovered.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Invoke-SafeguardAsset -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Invoke-SafeguardAsset linux123.internal.com
#>
function Invoke-SafeguardAssetSshHostKeyDiscovery
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$Asset,
        [Parameter(Mandatory=$false)]
        [switch]$AcceptSshHostKey
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local

    if (($Asset -as [int]) -or ($Asset -is [string]))
    {
        $local:AssetObj = (Get-SafeguardAsset -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                               -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId $Asset)
    }
    elseif ($Asset -is [array])
    {
        $local:AssetObj = $Asset[0]
    }
    else
    {
        $local:AssetObj = $Asset
    }

    Write-Host "Discovering SSH host key..."
    $local:SshHostKey = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                             POST "Assets/$($local:AssetObj.Id)/DiscoverSshHostKey")
    if (-not $local:SshHostKey)
    {
        throw "SshHostKey not found on asset: $($local:AssetObj.Name)"
    }
    $local:AssetObj.SshHostKey = $local:SshHostKey.SshHostKey
    if ($AcceptSshHostKey)
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            PUT "Assets/$($local:AssetObj.Id)" -Body $local:AssetObj
    }
    else
    {
        if (Show-SshHostKeyPrompt $local:SshHostKey.SshHostKey $local:SshHostKey.Fingerprint)
        {
            Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                PUT "Assets/$($local:AssetObj.Id)" -Body $local:AssetObj
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

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to get assets from.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to get assets from.
(If specified, this will override the AssetPartition parameter)

.PARAMETER AssetToGet
An integer containing the ID of the asset to get or a string containing the name.

.PARAMETER Fields
An array of the asset property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardAsset -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardAsset -Fields Id,Name,NetworkAddress
#>
function Get-SafeguardAsset
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$false,Position=0)]
        [object]$AssetToGet,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Parameters = $null
    if ($Fields)
    {
        $local:Parameters = @{ fields = ($Fields -join ",")}
    }

    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                            -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId)
    if ($AssetPartitionId)
    {
        $local:RelPath = "AssetPartitions/$AssetPartitionId/Assets"
    }
    else
    {
        $local:RelPath = "Assets"
    }

    if ($PSBoundParameters.ContainsKey("AssetToGet"))
    {
        $local:AssetId = (Resolve-SafeguardAssetId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetPartitionId $AssetPartitionId $AssetToGet)
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Assets/$($local:AssetId)" -Parameters $local:Parameters
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" -Parameters $local:Parameters
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

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to find assets in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to find assets in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER SearchString
A string to search for in the asset.

.PARAMETER QueryFilter
A string to pass to the -filter query parameter in the Safeguard Web API.

.PARAMETER Fields
An array of the asset property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Find-SafeguardAsset -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Find-SafeguardAsset "linux.company.corp"

.EXAMPLE
Find-SafeguardAsset -QueryFilter "Platform.PlatformFamily eq 'Windows'"
#>
function Find-SafeguardAsset
{
    [CmdletBinding(DefaultParameterSetName="Search")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=0,ParameterSetName="Search")]
        [string]$SearchString,
        [Parameter(Mandatory=$true,Position=0,ParameterSetName="Query")]
        [string]$QueryFilter,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                            -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId)
    if ($AssetPartitionId)
    {
        $local:RelPath = "AssetPartitions/$AssetPartitionId/Assets"
    }
    else
    {
        $local:RelPath = "Assets"
    }

    if ($PSCmdlet.ParameterSetName -eq "Search")
    {
        $local:Parameters = @{ q = $SearchString }
    }
    else
    {
        $local:Parameters = @{ filter = $QueryFilter }
    }

    if ($Fields)
    {
        $local:Parameters["fields"] = ($Fields -join ",")
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" -Parameters $local:Parameters
}

<#
.SYNOPSIS
Create new asset in Safeguard via the Web API.

.DESCRIPTION
Create a new asset in Safeguard that can be used to manage accounts.

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

.PARAMETER AssetPartition
An integer containing an ID  or a string containing the name of the asset partition
where this asset should be created.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID where this asset should be created.
(If specified, this will override the AssetPartition parameter)

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

.PARAMETER ServiceAccountCredentialType
Type of credential to use to authenticate the asset.

.PARAMETER ServiceAccountSecretKey
A string containing an API access key for the service account.

.PARAMETER NoSshHostKeyDiscovery
Whether or not to skip SSH host key discovery for platforms that support it.

.PARAMETER AcceptSshHostKey
Whether or not to auto-accept SSH host key for platforms that support it.

.PARAMETER ServiceAccountDistinguishedName
A string containing the LDAP distinguished name of a service account.  This is used for
creating LDAP directories.

.PARAMETER NoSslEncryption
Do not use SSL encryption for LDAP directory.

.PARAMETER DoNotVerifyServerSslCertificate
Do not verify Server SSL certificate of LDAP directory.

.PARAMETER PrivilegeElevationCommand
A string containing the privilege elevation command, ex. sudo.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
New-SafeguardAsset -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
New-SafeguardAsset winserver.domain.corp 31 archie

.EXAMPLE
New-SafeguardAsset -Platform 3 -ServiceAccountDomainName "a.b.corp" -ServiceAccountName "foo"
#>
function New-SafeguardAsset
{
    [CmdletBinding(DefaultParameterSetName="Asset")]
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
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=1)]
        [object]$Platform,
        [Parameter(Mandatory=$false)]
        [string]$ServiceAccountSecretKey,
        [Parameter(Mandatory=$false)]
        [switch]$NoSshHostKeyDiscovery = $false,
        [Parameter(Mandatory=$false)]
        [switch]$AcceptSshHostKey = $false,
        [Parameter(Mandatory=$false)]
        [ValidateSet("None","Password","SshKey","DirectoryPassword","LocalHostPassword","AccessKey","AccountPassword","Custom",IgnoreCase=$true)]
        [string]$ServiceAccountCredentialType,
        [Parameter(Mandatory=$true,ParameterSetName="Ldap",Position=0)]
        [string]$ServiceAccountDistinguishedName,
        [Parameter(Mandatory=$false,ParameterSetName="Ldap")]
        [switch]$NoSslEncryption,
        [Parameter(Mandatory=$false,ParameterSetName="Ldap")]
        [switch]$DoNotVerifyServerSslCertificate,
        [Parameter(Mandatory=$false,ParameterSetName="Asset")]
        [Parameter(Mandatory=$true,ParameterSetName="Ad",Position=0)]
        [string]$ServiceAccountDomainName,
        [Parameter(Mandatory=$false,ParameterSetName="Asset",Position=1)]
        [Parameter(Mandatory=$true,ParameterSetName="Ad",Position=1)]
        [string]$ServiceAccountName,
        [Parameter(Mandatory=$false,ParameterSetName="Asset", Position=0)]
        [Parameter(Mandatory=$true,ParameterSetName="Ldap")]
        [string]$NetworkAddress,
        [Parameter(Mandatory=$false,ParameterSetName="Asset")]
        [Parameter(Mandatory=$false,ParameterSetName="Ldap")]
        [int]$Port,
        [Parameter(Mandatory=$false,ParameterSetName="Asset",Position=2)]
        [Parameter(Mandatory=$false,ParameterSetName="Ad",Position=2)]
        [Parameter(Mandatory=$false,ParameterSetName="Ldap",Position=1)]
        [SecureString]$ServiceAccountPassword,
        [Parameter(Mandatory=$false,ParameterSetName="Asset")]
        [string]$PrivilegeElevationCommand
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local
    Import-Module -Name "$PSScriptRoot\datatypes.psm1" -Scope Local

    $local:PlatformId = (Resolve-SafeguardPlatform -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Platform)
    $local:PlatformObject = (Get-SafeguardPlatform -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $local:PlatformId)

    if ($PSCmdlet.ParameterSetName -ne "Ad" -and -not $local:PlatformObject.PlatformType.StartsWith("Other"))
    {
        if (-not $PSBoundParameters.ContainsKey("NetworkAddress"))
        {
            $NetworkAddress = (Read-Host "NetworkAddress")
        }
    }

    if (-not $PSBoundParameters.ContainsKey("DisplayName"))
    {
        if ($PSCmdlet.ParameterSetName -eq "Ad")
        {
            $DisplayName = $ServiceAccountDomainName
        }
        else
        {
            if ([string]::IsNullOrEmpty($NetworkAddress) -or (Test-IpAddress $NetworkAddress))
            {
                $DisplayName = (Read-Host "DisplayName")
            }
            else
            {
                $DisplayName = $NetworkAddress
            }
        }
    }

    if (-not $PSBoundParameters.ContainsKey("ServiceAccountCredentialType"))
    {
        if ($local:PlatformObject.PlatformType -eq "Other")
        {
            $ServiceAccountCredentialType = "None"
        }
        elseif ($local:PlatformObject.PlatformType -eq "OtherManaged")
        {
            $ServiceAccountCredentialType = "Custom"
        }
        else
        {
            $ServiceAccountCredentialType = (Resolve-SafeguardServiceAccountCredentialType)
        }
    }

    $local:ConnectionProperties = @{
        ServiceAccountCredentialType = $ServiceAccountCredentialType;
    }

    if ($PSBoundParameters.ContainsKey("Port")) { $local:ConnectionProperties.Port = $Port }
    if ($PSBoundParameters.ContainsKey("ServiceAccountDomainName")) { $local:ConnectionProperties.ServiceAccountDomainName = $ServiceAccountDomainName }

    if ($ServiceAccountCredentialType -ne "None" -and $ServiceAccountCredentialType -ne "Custom")
    {
        switch ($ServiceAccountCredentialType.ToLower())
        {
            {$_ -in "password","accountpassword","accesskey"} {
                if (-not $PSBoundParameters.ContainsKey("ServiceAccountName") -or -not $ServiceAccountName)
                {
                    if ($PSCmdlet.ParameterSetName -ne "Ldap")
                    {
                        $ServiceAccountName = (Read-Host "ServiceAccountName")
                    }
                }
                $local:ConnectionProperties.ServiceAccountName = $ServiceAccountName
                if ($ServiceAccountCredentialType -eq "AccessKey")
                {
                    if (-not $PSBoundParameters.ContainsKey("ServiceAccountSecretKey"))
                    {
                        $ServiceAccountSecretKey = (Read-Host "ServiceAccountSecretKey")
                    }
                    $local:ConnectionProperties.SecretKey = $ServiceAccountSecretKey
                }
                else
                {
                    if (-not $PSBoundParameters.ContainsKey("ServiceAccountPassword"))
                    {
                        $ServiceAccountPassword = (Read-Host -AsSecureString "ServiceAccountPassword")
                    }
                    $local:ConnectionProperties.ServiceAccountPassword = `
                        [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ServiceAccountPassword))
                }
            }
            {$_ -eq "directorypassword"} {
                if (-not $PSBoundParameters.ContainsKey("ServiceAccountDomainName")) { $ServiceAccountDomainName = (Read-Host "ServiceAccountDomainName") }
                if (-not $PSBoundParameters.ContainsKey("ServiceAccountName")) { $ServiceAccountName = (Read-Host "ServiceAccountName") }
                Import-Module -Name "$PSScriptRoot\directories.psm1" -Scope Local
                $local:DirectoryAccount = (Get-SafeguardDirectoryAccount -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $ServiceAccountDomainName $ServiceAccountName)
                if (-not $local:DirectoryAccount)
                {
                    throw "Unable to find directory account '$ServiceAccountDomainName\$ServiceAccountName'"
                }
                $local:ConnectionProperties.ServiceAccountId = $local:DirectoryAccount.Id
            }
            "sshkey" {
                throw "SSH Keys are not supported for asset creation yet"
            }
            default {
                throw "$ServiceAccountCredentialType are not supported yet"
            }
        }
    }

    if ($PSBoundParameters.ContainsKey("PrivilegeElevationCommand"))
        { $local:ConnectionProperties.PrivilegeElevationCommand = $PrivilegeElevationCommand }

    #Ldap Connection properties
    if ($PSCmdlet.ParameterSetName -eq "Ldap")
    {
        $local:ConnectionProperties.UseSslEncryption = $true;
        $local:ConnectionProperties.VerifySslCertificate = $true;
        $local:ConnectionProperties.ServiceAccountDistinguishedName = $ServiceAccountDistinguishedName;

        if ($NoSslEncryption)
        {
            $local:ConnectionProperties.UseSslEncryption = $false
            $local:ConnectionProperties.VerifySslCertificate = $false
        }
        if ($DoNotVerifyServerSslCertificate)
        {
            $local:ConnectionProperties.VerifySslCertificate = $false
        }
    }

    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                            -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -UseDefault)

    $local:Body = @{
        Name = "$DisplayName";
        Description = "$Description";
        NetworkAddress = "$NetworkAddress";
        PlatformId = $local:PlatformId;
        AssetPartitionId = $AssetPartitionId;
        ConnectionProperties = $local:ConnectionProperties
    }

    $local:NewAsset = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                           POST Assets -Body $local:Body)

    try
    {
        if ($local:NewAsset.Platform.ConnectionProperties.SupportsSshTransport -and -not $NoSshHostKeyDiscovery)
        {
            Invoke-SafeguardAssetSshHostKeyDiscovery -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $local:NewAsset -AcceptSshHostKey:$AcceptSshHostKey
        }
        else
        {
            $local:NewAsset
        }
    }
    catch
    {
        Write-Host -ForegroundColor Yellow "Error setting up SSH host key, removing asset..."
        Remove-SafeguardAsset -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $NewAsset.Id
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

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to test the asset in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to test the asset in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER AssetToTest
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
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$AssetToTest
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:AssetId = (Resolve-SafeguardAssetId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                          -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId $AssetToTest)

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
        POST "Assets/$($local:AssetId)/TestConnection" -LongRunningTask
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

.PARAMETER AssetPartition
An integer containing an ID  or a string containing the name of the asset partition
to delete an asset form.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to delete an asset form.
(If specified, this will override the AssetPartition parameter)

.PARAMETER AssetToDelete
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
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$AssetToDelete
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:AssetId = (Resolve-SafeguardAssetId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                          -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId $AssetToDelete)

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "Assets/$($local:AssetId)"
}

<#
.SYNOPSIS
Edit existing asset in Safeguard via the Web API.

.DESCRIPTION
Edit an existing asset in Safeguard that can be used to manage accounts.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID  or a string containing the name of the asset partition
to edit an asset in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to edit an asset in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER AssetToEdit
An integer containing the ID of the asset to edit or a string containing the name.

.PARAMETER DisplayName
A string containing the display name for this asset. Optional, unless
NetworkAddress is an IP address rather than a DNS name.

.PARAMETER Description
A string containing a description for this asset.

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

.PARAMETER ServiceAccountCredentialType
Type of credential to use to authenticate the asset.

.PARAMETER ServiceAccountSecretKey
A string containing an API access key for the service account.

.PARAMETER ServiceAccountDistinguishedName
A string containing the LDAP distinguished name of a service account.  This is used for
creating LDAP directories.

.PARAMETER NoSslEncryption
Do not use SSL encryption for LDAP directory.

.PARAMETER DoNotVerifyServerSslCertificate
Do not verify Server SSL certificate of LDAP directory.

.PARAMETER PrivilegeElevationCommand
A string containing the privilege elevation command, ex. sudo.

.PARAMETER AssetObject
An object containing the existing asset with desired properties set.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Edit-SafeguardAsset -AccessToken $token -Appliance 10.5.32.54 -Insecure -AssetObject $obj

.EXAMPLE
Edit-SafeguardAsset winserver.domain.corp 31 archie

.EXAMPLE
Edit-SafeguardAsset -AssetToEdit "fooLdapAsset" -UseSslEncryption $True
#>
function Edit-SafeguardAsset
{
    [CmdletBinding(DefaultParameterSetName="Attributes")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false,Position=0)]
        [object]$AssetToEdit,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$DisplayName,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$Description,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$NetworkAddress,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [object]$Platform,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [int]$Port,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [ValidateSet("None","Password","SshKey","DirectoryPassword","LocalHostPassword","AccessKey","AccountPassword",IgnoreCase=$true)]
        [string]$ServiceAccountCredentialType,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$ServiceAccountDomainName,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$ServiceAccountName,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [SecureString]$ServiceAccountPassword,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$ServiceAccountSecretKey,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$ServiceAccountDistinguishedName,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [boolean]$UseSslEncryption,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [boolean]$VerifyServerSslCertificate,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$PrivilegeElevationCommand,
        [Parameter(ParameterSetName="Object",Mandatory=$true,ValueFromPipeline=$true)]
        [object]$AssetObject
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local

    if ($PsCmdlet.ParameterSetName -eq "Object" -and -not $AssetObject)
    {
        throw "AssetObject must not be null"
    }

    if ($PsCmdlet.ParameterSetName -eq "Attributes")
    {
        if (-not $PSBoundParameters.ContainsKey("AssetToEdit"))
        {
            $AssetToEdit = (Read-Host "AssetToEdit")
        }
        $local:AssetId = (Resolve-SafeguardAssetId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                             -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId $AssetToEdit)
    }

    if (-not ($PsCmdlet.ParameterSetName -eq "Object"))
    {
        $AssetObject = (Get-SafeguardAsset -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $local:AssetId)

        # Connection Properties
        if (-not $AssetObject.ConnectionProperties) { $AssetObject.ConnectionProperties = @{} }
        if ($PSBoundParameters.ContainsKey("Port")) { $AssetObject.ConnectionProperties.Port = $Port }
        if ($PSBoundParameters.ContainsKey("ServiceAccountCredentialType")) { $AssetObject.ConnectionProperties.ServiceAccountCredentialType = $ServiceAccountCredentialType }
        if ($PSBoundParameters.ContainsKey("ServiceAccountDomainName")) { $AssetObject.ConnectionProperties.ServiceAccountDomainName = $ServiceAccountDomainName }
        if ($PSBoundParameters.ContainsKey("ServiceAccountName")) { $AssetObject.ConnectionProperties.ServiceAccountName = $ServiceAccountName }
        if ($PSBoundParameters.ContainsKey("PrivilegeElevationCommand")) { $AssetObject.ConnectionProperties.PrivilegeElevationCommand = $PrivilegeElevationCommand }

        #Ldap Connection properties
        if ($PSBoundParameters.ContainsKey("ServiceAccountDistinguishedName")) { $AssetObject.ConnectionProperties.ServiceAccountDistinguishedName = $ServiceAccountDistinguishedName }
        if ($PSBoundParameters.ContainsKey("UseSslEncryption")) { $AssetObject.ConnectionProperties.UseSslEncryption = $UseSslEncryption }
        if ($PSBoundParameters.ContainsKey("VerifyServerSslCertificate")) { $AssetObject.ConnectionProperties.VerifySslCertificate = $VerifyServerSslCertificate }
        if (-not $UseSslEncryption)
        {
            $AssetObject.ConnectionProperties.UseSslEncryption = $false
            $AssetObject.ConnectionProperties.VerifySslCertificate = $false
        }

        if ($PSBoundParameters.ContainsKey("ServiceAccountPassword"))
        {
            $AssetObject.ConnectionProperties.ServiceAccountPassword = `
                [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ServiceAccountPassword))
        }
        if ($PSBoundParameters.ContainsKey("ServiceAccountSecretKey")) { AssetObject.ConnectionProperties.ServiceAccountSecretKey = $ServiceAccountSecretKey }

        # Body
        if ($PSBoundParameters.ContainsKey("DisplayName")) { $AssetObject.Name = $DisplayName }
        if ($PSBoundParameters.ContainsKey("Description")) { $AssetObject.Description = $Description }
        if ($PSBoundParameters.ContainsKey("NetworkAddress")) { $AssetObject.NetworkAddress = $NetworkAddress }
        if ($PSBoundParameters.ContainsKey("Platform"))
        {
            $local:PlatformId = Resolve-SafeguardPlatform -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Platform
            $AssetObject.PlatformId = $local:PlatformId
        }
    }
    else
    {
        # Make sure it is actually in the partition (just in case caller has called Enter-SafeguardAssetPartition)
        $local:AssetId = (Resolve-SafeguardAssetId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                             -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId $AssetObject.Id)
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "Assets/$($AssetObject.Id)" -Body $AssetObject
}

<#
.SYNOPSIS
Synchronize an existing directory asset in Safeguard via the Web API.

.DESCRIPTION
Synchronize an existing directory asset in Safeguard.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID  or a string containing the name of the asset partition
to sync the directory asset in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to sync the directory asset in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER DirectoryAssetToSync
An integer containing the ID of the directory to synchronize or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Sync-SafeguardDirectoryAsset -AccessToken $token -Appliance 10.5.32.54 -Insecure -1 5

.EXAMPLE
Sync-SafeguardDirectoryAsset -AssetPartition fooPartition internal.domain.corp
#>
function Sync-SafeguardDirectoryAsset
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$DirectoryAssetToSync
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:AssetId = (Resolve-SafeguardAssetId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                          -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId $DirectoryAssetToSync)
    $local:DirectoryAsset = (Get-SafeguardAsset -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                                 -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId $local:AssetId)

    if(-not $local:DirectoryAsset.IsDirectory)
    {
        throw "Asset '$($local:DirectoryAsset.Name)' is not a directory asset"
    }
    Write-Host "Triggering sync for directory: $($local:DirectoryAsset.Name)"
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "Assets/$($local:DirectoryAsset.Id)/Synchronize"
}

<#
.SYNOPSIS
Get accounts on assets managed by Safeguard via the Web API.

.DESCRIPTION
Get accounts on assets managed by Safeguard.  Accounts passwords can be managed,
and Safeguard can be configured to check and change those passwords.  Policy can
be created to allow access to passwords and sessions based on those passwords.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to get asset accounts from.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to get asset accounts from.
(If specified, this will override the AssetPartition parameter)

.PARAMETER AssetToGet
An integer containing the ID of the asset to get accounts from or a string containing the name.

.PARAMETER AccountToGet
An integer containing the ID of the account to get or a string containing the name.

.PARAMETER Fields
An array of the account property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardAssetAccount -AccessToken $token -Appliance 10.5.32.54 -Insecure windows.blah.corp administrator

.EXAMPLE
Get-SafeguardAssetAccount -AccountToGet oracle -Fields AssetId,Id,AssetName,Name
#>
function Get-SafeguardAssetAccount
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$false,Position=0)]
        [object]$AssetToGet,
        [Parameter(Mandatory=$false,Position=1)]
        [object]$AccountToGet,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Parameters = $null
    if ($Fields)
    {
        $local:Parameters = @{ fields = ($Fields -join ",")}
    }

    if ($PSBoundParameters.ContainsKey("AccountToGet"))
    {
        $local:AccountId = (Resolve-SafeguardAssetAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                                -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -Asset $AssetToGet -Account $AccountToGet)
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "AssetAccounts/$($local:AccountId)" -Parameters $local:Parameters
    }
    elseif ($PSBoundParameters.ContainsKey("AssetToGet"))
    {
        $local:AssetId = (Resolve-SafeguardAssetId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                              -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -Asset $AssetToGet)
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Assets/$($local:AssetId)/Accounts" -Parameters $local:Parameters
    }
    else
    {
        $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                                -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId)
        if ($AssetPartitionId)
        {
            $local:RelPath = "AssetPartitions/$AssetPartitionId/Accounts"
        }
        else
        {
            $local:RelPath = "Accounts"
        }
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" -Parameters $local:Parameters
    }
}

<#
.SYNOPSIS
Search for an asset account in Safeguard via the Web API.

.DESCRIPTION
Search for an asset account in Safeguard for any string fields containing
the SearchString.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to find asset accounts in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to find asset accounts in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER SearchString
A string to search for in the asset account.

.PARAMETER QueryFilter
A string to pass to the -filter query parameter in the Safeguard Web API.

.PARAMETER Fields
An array of the account property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Find-SafeguardAssetAccount -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Find-SafeguardAssetAccount "root"

.EXAMPLE
Find-SafeguardAssetAccount -QueryFilter "CreatedByUserDisplayName eq 'George Smith'"
#>
function Find-SafeguardAssetAccount
{
    [CmdletBinding(DefaultParameterSetName="Search")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=0,ParameterSetName="Search")]
        [string]$SearchString,
        [Parameter(Mandatory=$true,Position=0,ParameterSetName="Query")]
        [string]$QueryFilter,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                            -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId)
    if ($AssetPartitionId)
    {
        $local:RelPath = "AssetPartitions/$AssetPartitionId/Accounts"
    }
    else
    {
        $local:RelPath = "AssetAccounts"
    }

    if ($PSCmdlet.ParameterSetName -eq "Search")
    {
        $local:Parameters = @{ q = $SearchString }
    }
    else
    {
        $local:Parameters = @{ filter = $QueryFilter }
    }

    if ($Fields)
    {
        $local:Parameters["fields"] = ($Fields -join ",")
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" -Parameters $local:Parameters
}

<#
.SYNOPSIS
Create a new account on an asset managed by Safeguard via the Web API.

.DESCRIPTION
Create a representation of an account on a managed asset.  Accounts passwords can
be managed, and Safeguard can be configured to check and change those passwords.
Policy can be created to allow access to passwords and sessions based on those passwords.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER ParentAsset
An integer containing the ID of the asset to get accounts from or a string containing the name.

.PARAMETER NewAccountName
A string containing the name for the account.

.PARAMETER Description
A string containing the description for the account.

.PARAMETER DomainName
A string containing the domain name for the account.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
New-SafeguardAssetAccount -AccessToken $token -Appliance 10.5.32.54 -Insecure windows.blah.corp administrator

.EXAMPLE
New-SafeguardAssetAccount linux.server.corp oracle -Description "Oracle database service account"
#>
function New-SafeguardAssetAccount
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
        [object]$ParentAsset,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$NewAccountName,
        [Parameter(Mandatory=$false)]
        [string]$Description,
        [Parameter(Mandatory=$false)]
        [string]$DomainName,
        [Parameter(Mandatory=$false)]
        [string]$DistinguishedName
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:AssetId = (Resolve-SafeguardAssetId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $ParentAsset)

    $local:Body = @{
        "AssetId" = $local:AssetId;
        "Name" = $NewAccountName
    }

    if ($PSBoundParameters.ContainsKey("Description")) { $local:Body.Description = $Description }
    if ($PSBoundParameters.ContainsKey("DomainName")) { $local:Body.DomainName = $DomainName }
    if ($PSBoundParameters.ContainsKey("DistinguishedName")) { $local:Body.DistinguishedName = $DistinguishedName }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "AssetAccounts" -Body $local:Body
}

<#
.SYNOPSIS
Edit an existing account on an asset managed by Safeguard via the Web API.

.DESCRIPTION
Edit an existing account in Safeguard.  Accounts passwords can be managed,
and Safeguard can be configured to check and change those passwords.
Policy can be created to allow access to passwords and sessions based
on those passwords.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetToEdit
An integer containing the ID of the asset to edit the account of or a string containing the name.

.PARAMETER AccountToEdit
An integer containing the ID of the account to edit or a string containing the name.

.PARAMETER Description
A string containing the description for the account.

.PARAMETER DomainName
A string containing the domain name for the account.

.PARAMETER AccountObject
An object containing the existing asset account with desired properties set.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Edit-SafeguardAssetAccount -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Edit-SafeguardAssetAccount mysystem.domain.com root -Description "ADMIN"

.EXAMPLE
Edit-SafeguardAssetAccount -AccountObject $obj
#>
function Edit-SafeguardAssetAccount
{
    [CmdletBinding(DefaultParameterSetName="Attributes")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false,Position=0)]
        [object]$AssetToEdit,
        [Parameter(ParameterSetName="Attributes",Mandatory=$true,Position=1)]
        [object]$AccountToEdit,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$Description,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$DomainName,
        [Parameter(ParameterSetName="Object",Mandatory=$true)]
        [object]$AccountObject
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PsCmdlet.ParameterSetName -eq "Object" -and -not $AccountObject)
    {
        throw "AccountObject must not be null"
    }

    if ($PsCmdlet.ParameterSetName -eq "Attributes")
    {
        if ($PSBoundParameters.ContainsKey("AssetToEdit"))
        {
            $local:AssetId = (Resolve-SafeguardAssetId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AssetToEdit)
            $local:AccountId = (Resolve-SafeguardAssetAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetId $local:AssetId $AccountToEdit)
        }
        else
        {
            $local:AccountId = (Resolve-SafeguardAssetAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AccountToEdit)
        }
    }

    if (-not ($PsCmdlet.ParameterSetName -eq "Object"))
    {
        $AccountObject = (Get-SafeguardAssetAccount -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AccountToGet $local:AccountId)

        if ($PSBoundParameters.ContainsKey("Description")) { $AccountObject.Description = $Description }
        if ($PSBoundParameters.ContainsKey("DomainName")) { $AccountObject.DomainName = $DomainName }
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "AssetAccounts/$($AccountObject.Id)" -Body $AccountObject
}

<#
.SYNOPSIS
Set account password inside Safeguard for assets under management via the Web API.

.DESCRIPTION
Set the password in Safeguard for an account on an asset under management.  This
just modifies what is stored in Safeguard.  It does not change the actual password
of the account.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetToSet
An integer containing the ID of the asset to set account password on or a string containing the name.

.PARAMETER AccountToSet
An integer containing the ID of the account to set password on or a string containing the name.

.PARAMETER NewPassword
A SecureString containing the new password to set.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Set-SafeguardAssetAccountPassword -AccessToken $token -Appliance 10.5.32.54 -Insecure windows.blah.corp administrator

.EXAMPLE
Set-SafeguardAssetAccountPassword -AccountToSet oracle -NewPassword $pass
#>
function Set-SafeguardAssetAccountPassword
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
        [object]$AssetToSet,
        [Parameter(Mandatory=$true,Position=1)]
        [object]$AccountToSet,
        [Parameter(Mandatory=$false,Position=2)]
        [SecureString]$NewPassword
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSBoundParameters.ContainsKey("AssetToSet"))
    {
        $local:AssetId = (Resolve-SafeguardAssetId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AssetToSet)
        $local:AccountId = (Resolve-SafeguardAssetAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetId $local:AssetId $AccountToSet)
    }
    else
    {
        $local:AccountId = (Resolve-SafeguardAssetAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AccountToSet)
    }
    if (-not $NewPassword)
    {
        $NewPassword = (Read-Host -AsSecureString "NewPassword")
    }
    $local:PasswordPlainText = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($NewPassword))
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "AssetAccounts/$($local:AccountId)/Password" `
        -Body $local:PasswordPlainText
}

<#
.SYNOPSIS
Generate an account password based on profile via the Web API.

.DESCRIPTION
Generate an account password based on profile.  The password is not actually stored in
Safeguard, but it could be stored using Set-SafeguardAssetAccountPassword.  This can
be used to facilitate manual password management.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetToUse
An integer containing the ID of the asset to generate password for or a string containing the name.

.PARAMETER AccountToUse
An integer containing the ID of the account to generate password for or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
New-SafeguardAssetAccountRandomPassword -AccessToken $token -Appliance 10.5.32.54 -Insecure windows.blah.corp administrator

.EXAMPLE
New-SafeguardAssetAccountRandomPassword -AccountToUse oracle
#>
function New-SafeguardAssetAccountRandomPassword
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
        [object]$AssetToUse,
        [Parameter(Mandatory=$true,Position=1)]
        [object]$AccountToUse
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSBoundParameters.ContainsKey("AssetToUse"))
    {
        $local:AssetId = (Resolve-SafeguardAssetId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AssetToUse)
        $local:AccountId = (Resolve-SafeguardAssetAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetId $local:AssetId $AccountToUse)
    }
    else
    {
        $local:AccountId = (Resolve-SafeguardAssetAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AccountToUse)
    }
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "AssetAccounts/$($local:AccountId)/GeneratePassword"
}

<#
.SYNOPSIS
Run check password on an account managed by Safeguard via the Web API.

.DESCRIPTION
Run a task to check whether Safeguard still has the correct password for
an account on a managed asset.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetToUse
An integer containing the ID of the asset to check password for or a string containing the name.

.PARAMETER AccountToUse
An integer containing the ID of the account to check password for or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Test-SafeguardAssetAccountPassword -AccessToken $token -Appliance 10.5.32.54 -Insecure windows.blah.corp administrator

.EXAMPLE
Test-SafeguardAssetAccountPassword -AccountToUse oracle
#>
function Test-SafeguardAssetAccountPassword
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
        [object]$AssetToUse,
        [Parameter(Mandatory=$true,Position=1)]
        [object]$AccountToUse
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSBoundParameters.ContainsKey("AssetToUse"))
    {
        $local:AssetId = (Resolve-SafeguardAssetId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AssetToUse)
        $local:AccountId = (Resolve-SafeguardAssetAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetId $local:AssetId $AccountToUse)
    }
    else
    {
        $local:AccountId = (Resolve-SafeguardAssetAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AccountToUse)
    }
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "AssetAccounts/$($local:AccountId)/CheckPassword" -LongRunningTask
}

<#
.SYNOPSIS
Run change password on an account managed by Safeguard via the Web API.

.DESCRIPTION
Run a task to change the password on an account managed by Safeguard.  This rotates the
password on the actual asset and stores the new value in Safeguard.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetToUse
An integer containing the ID of the asset to change password for or a string containing the name.

.PARAMETER AccountToUse
An integer containing the ID of the account to change password for or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Invoke-SafeguardAssetAccountPasswordChange -AccessToken $token -Appliance 10.5.32.54 -Insecure windows.blah.corp administrator

.EXAMPLE
Invoke-SafeguardAssetAccountPasswordChange -AccountToUse oracle
#>
function Invoke-SafeguardAssetAccountPasswordChange
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
        [object]$AssetToUse,
        [Parameter(Mandatory=$true,Position=1)]
        [object]$AccountToUse
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSBoundParameters.ContainsKey("AssetToUse"))
    {
        $local:AssetId = (Resolve-SafeguardAssetId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AssetToUse)
        $local:AccountId = (Resolve-SafeguardAssetAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetId $local:AssetId $AccountToUse)
    }
    else
    {
        $local:AccountId = (Resolve-SafeguardAssetAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AccountToUse)
    }
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "AssetAccounts/$($local:AccountId)/ChangePassword" -LongRunningTask
}

<#
.SYNOPSIS
Remove an asset account from Safeguard via the Web API.

.DESCRIPTION
Remove an asset account from Safeguard. Make sure it is not in use before
you remove it.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetToUse
An integer containing the ID of the asset to remove the account from or a string containing the name.

.PARAMETER AccountToDelete
An integer containing the ID of the asset account to remove or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardAssetAccount -AccessToken $token -Appliance 10.5.32.54 -Insecure 5 23

.EXAMPLE
Remove-SafeguardAssetAccount computer.domain.com root
#>
function Remove-SafeguardAssetAccount
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
        [object]$AssetToUse,
        [Parameter(Mandatory=$true,Position=1)]
        [object]$AccountToDelete
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSBoundParameters.ContainsKey("AssetToUse"))
    {
        $local:AssetId = (Resolve-SafeguardAssetId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AssetToUse)
        $local:AccountId = (Resolve-SafeguardAssetAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetId $local:AssetId $AccountToDelete)
    }
    else
    {
        $local:AccountId = (Resolve-SafeguardAssetAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AccountToDelete)
    }
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "AssetAccounts/$($local:AccountId)"
}
