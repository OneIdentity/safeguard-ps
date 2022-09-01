# Helper
function Resolve-SafeguardAsset
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

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
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
                                     -Parameters @{ filter = "NetworkAddress ieq '$Asset'" })
            }
        }
        catch
        {
            Write-Verbose $_
            Write-Verbose "Caught exception with ieq filter, trying with q parameter"
            $local:Assets = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" `
                                 -Parameters @{ q = $Asset })
        }
        if (-not $local:Assets)
        {
            throw "Unable to find asset matching '$Asset'$($local:ErrMsgSuffix)"
        }
        if ($local:Assets.Count -ne 1)
        {
            throw "Found $($local:Assets.Count) assets matching '$Asset'$($local:ErrMsgSuffix)"
        }
        $local:Assets[0]
    }
    else
    {
        if ($AssetPartitionId)
        {
            $local:Filter = "Id eq $Asset and AssetPartitionId eq $AssetPartitionId"
        }
        else
        {
            $local:Filter = "Id eq $Asset"
        }
        $local:Assets = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" `
                                -Parameters @{ filter = $local:Filter })
        if (-not $local:Assets)
        {
            throw "Unable to find asset matching '$Asset'$($local:ErrMsgSuffix)"
        }
        $local:Assets[0]
    }
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

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
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
                                 -Parameters @{ filter = "Name ieq '$Asset'"; fields = "Id" })
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
            # Make sure it actually exists
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
        [int]$AssetId = $null,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$Account
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($Account.Id -as [int])
    {
        $Account = $Account.Id
    }

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
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
                                 -Parameters @{ filter = "Id eq $Account and AssetPartitionId eq $AssetPartitionId"; fields = "Id" })
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
    $local:AssetObj.SshHostKey = @{ SshHostKey = $local:SshHostKey.SshHostKey }
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

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
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

.PARAMETER OrderBy
An array of the asset property names to order by.

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

.EXAMPLE
Find-SafeguardAsset -QueryFilter "Name contains 'db-'" -Fields Id,Name -OrderBy Platform.PlatformFamily,-Name
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
        [string[]]$Fields,
        [Parameter(Mandatory=$false)]
        [string[]]$OrderBy
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
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
    if ($OrderBy)
    {
        $local:Parameters["orderby"] = ($OrderBy -join ",")
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
                    $local:ConnectionProperties.ServiceAccountPassword = [System.Net.NetworkCredential]::new("", $ServiceAccountPassword).Password
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

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
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

.PARAMETER UseSslEncryption
Whether or not to use SSL encryption for LDAP directory.

.PARAMETER VerifyServerSslCertificate
Whether or not to verify Server SSL certificate of LDAP directory.

.PARAMETER PrivilegeElevationCommand
A string containing the privilege elevation command, ex. sudo.

.PARAMETER AllowSessionRequests
Whether or not to allow session access requests.

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
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [bool]$AllowSessionRequests,
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
        $AssetObject = (Get-SafeguardAsset -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                            -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId $local:AssetId)

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
            $AssetObject.ConnectionProperties.ServiceAccountPassword = [System.Net.NetworkCredential]::new("", $ServiceAccountPassword).Password
        }
        if ($PSBoundParameters.ContainsKey("ServiceAccountSecretKey")) { AssetObject.ConnectionProperties.ServiceAccountSecretKey = $ServiceAccountSecretKey }

        # Body
        if ($PSBoundParameters.ContainsKey("DisplayName")) { $AssetObject.Name = $DisplayName }
        if ($PSBoundParameters.ContainsKey("Description")) { $AssetObject.Description = $Description }
        if ($PSBoundParameters.ContainsKey("NetworkAddress")) { $AssetObject.NetworkAddress = $NetworkAddress }
        if ($PSBoundParameters.ContainsKey("AllowSessionRequests")) { $AssetObject.AllowSessionRequests = $AllowSessionRequests }
        if ($PSBoundParameters.ContainsKey("Platform"))
        {
            Import-Module -Name "$PSScriptRoot\datatypes.psm1" -Scope Local
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
Get-SafeguardAssetAccount -AccountToGet oracle -Fields Asset.Id,Id,Asset.Name,Name
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
        Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
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

.PARAMETER OrderBy
An array of the account property names to order by.

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
        [string[]]$Fields,
        [Parameter(Mandatory=$false)]
        [string[]]$OrderBy
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
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
    if ($OrderBy)
    {
        $local:Parameters["orderby"] = ($OrderBy -join ",")
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

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to create the new asset account in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to create the new asset account in.
(If specified, this will override the AssetPartition parameter)

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
        [Parameter(Mandatory=$false)]
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
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

    $local:AssetObj = (Resolve-SafeguardAsset -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                          -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -Asset $ParentAsset)

    $local:Body = @{
        "Asset" = @{ "Id" = $local:AssetObj.Id };
        "Name" = $NewAccountName
    }

    if ($PSBoundParameters.ContainsKey("Description")) { $local:Body.Description = $Description }
    if ($PSBoundParameters.ContainsKey("DomainName")) { $local:Body.DomainName = $DomainName }
    if ($PSBoundParameters.ContainsKey("DistinguishedName")) { $local:Body.DistinguishedName = $DistinguishedName }

    if ($local:AssetObj.IsDirectory -and $local:AssetObj.DirectoryAssetProperties.Domains[0])
    {
        if (-not $local:Body.DomainName)
        {
            $local:Body.DomainName = $local:AssetObj.DirectoryAssetProperties.Domains[0].DomainName
        }
    }

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

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to edit the asset account in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to edit the asset account in.
(If specified, this will override the AssetPartition parameter)

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
        [Parameter(Mandatory=$false)]
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
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
        $local:AccountId = (Resolve-SafeguardAssetAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                                -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -Asset $AssetToEdit -Account $AccountToEdit)
    }

    if (-not ($PsCmdlet.ParameterSetName -eq "Object"))
    {
        $AccountObject = (Get-SafeguardAssetAccount -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                              -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -AssetToGet $AssetToEdit -AccountToGet $local:AccountId)

        if ($PSBoundParameters.ContainsKey("Description")) { $AccountObject.Description = $Description }
        if ($PSBoundParameters.ContainsKey("DomainName")) { $AccountObject.DomainName = $DomainName }
    }
    else
    {
        # Make sure it is actually in the partition (just in case caller has called Enter-SafeguardAssetPartition)
        $local:AccountId = (Resolve-SafeguardAssetAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                              -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId  $AccountObject.Id)
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

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to set the asset account password in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to set the asset account password in.
(If specified, this will override the AssetPartition parameter)

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
        [Parameter(Mandatory=$false)]
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$false,Position=0)]
        [object]$AssetToSet,
        [Parameter(Mandatory=$true,Position=1)]
        [object]$AccountToSet,
        [Parameter(Mandatory=$false,Position=2)]
        [SecureString]$NewPassword
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:AccountId = (Resolve-SafeguardAssetAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                           -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -Asset $AssetToSet -Account $AccountToSet)
    if (-not $NewPassword)
    {
        $NewPassword = (Read-Host -AsSecureString "NewPassword")
    }
    $local:PasswordPlainText = [System.Net.NetworkCredential]::new("", $NewPassword).Password
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

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to generate the asset account password in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to generate the asset account password in.
(If specified, this will override the AssetPartition parameter)

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
        [Parameter(Mandatory=$false)]
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$false,Position=0)]
        [object]$AssetToUse,
        [Parameter(Mandatory=$true,Position=1)]
        [object]$AccountToUse
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:AccountId = (Resolve-SafeguardAssetAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                           -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -Asset $AssetToUse -Account $AccountToUse)
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

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to check the asset account password in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to check the asset account password in.
(If specified, this will override the AssetPartition parameter)

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
        [Parameter(Mandatory=$false)]
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$false,Position=0)]
        [object]$AssetToUse,
        [Parameter(Mandatory=$true,Position=1)]
        [object]$AccountToUse
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:AccountId = (Resolve-SafeguardAssetAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                           -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -Asset $AssetToUse -Account $AccountToUse)
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

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to change the asset account password in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to change the asset account password in.
(If specified, this will override the AssetPartition parameter)

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
        [Parameter(Mandatory=$false)]
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$false,Position=0)]
        [object]$AssetToUse,
        [Parameter(Mandatory=$true,Position=1)]
        [object]$AccountToUse
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:AccountId = (Resolve-SafeguardAssetAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                           -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -Asset $AssetToUse -Account $AccountToUse)
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

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to change the asset account password in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to change the asset account password in.
(If specified, this will override the AssetPartition parameter)

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
        [Parameter(Mandatory=$false)]
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$false,Position=0)]
        [object]$AssetToUse,
        [Parameter(Mandatory=$true,Position=1)]
        [object]$AccountToDelete
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:AccountId = (Resolve-SafeguardAssetAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                           -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -Asset $AssetToUse -Account $AccountToDelete)
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "AssetAccounts/$($local:AccountId)"
}

<#
.SYNOPSIS
Set account SSH Key inside Safeguard for assets under management via the Web API.

.DESCRIPTION
Set the SSH Key in Safeguard for an account on an asset under management.  This
just modifies what is stored in Safeguard.  It does not change the actual SSH Key
of the account.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to set the asset account SSH Key in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to set the asset account SSH Key in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER AssetToSet
An integer containing the ID of the asset to set account SSH Key on or a string containing the name.

.PARAMETER AccountToSet
An integer containing the ID of the account to set SSH Key on or a string containing the name.

.PARAMETER Passphrase
A SecureString containing the passphrase used to decrypt the private key.

.PARAMETER PrivateKey
A SecureString containing the SSH Key to assign to the account.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Set-SafeguardAssetAccountSshKey -AccessToken $token -Appliance 10.5.32.54 -Insecure windows.blah.corp administrator

.EXAMPLE
Set-SafeguardAssetAccountSshKey -AccountToSet oracle -NewSshKey $sshkey
#>
function Set-SafeguardAssetAccountSshKey
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true)]
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true)]
        [object]$AssetToSet,
        [Parameter(Mandatory=$true)]
        [object]$AccountToSet,
        [Parameter(Mandatory=$false)]
        [string]$Passphrase,
        [Parameter(Mandatory=$true)]
        [string]$PrivateKey
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:AccountId = (Resolve-SafeguardAssetAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                           -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -Asset $AssetToSet -Account $AccountToSet)

    $local:Body = @{
        "Passphrase" = $Passphrase
        "PrivateKey" = $PrivateKey
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "AssetAccounts/$($local:AccountId)/SshKey" `
        -Parameters @{ keyFormat="OpenSsh" } -Body $local:Body
}


<#
.SYNOPSIS
Creates a template file containing the headers for importing assets.

.DESCRIPTION
Creates a template file containing the headers for importing assets. Specify the optional columns with parameters.

Default Columns

-DisplayName : A string containing the display name for this asset. Optional, unless NetworkAddress is an IP address rather than a DNS name.

-Platform : A platform ID for a specific platform type or a string to search for desired platform type.
            For more information on Platforms run Get-SafeguardPlatform -Fields ID,PlatformType,DisplayName

.PARAMETER Path
A string containing the path of the template file.

.PARAMETER All
Adds all headers to the template file.

.PARAMETER Description
Adds the Description header to the template file. 
Value - A string containing a description for this asset.

.PARAMETER AssetPartition
Adds the AssetPartition header to the template file. 
Value - An integer containing an ID  or a string containing the name of the asset partition
where this asset should be created.

.PARAMETER NetworkAddress
Adds the NetworkAddress header to the template file. 
Value - A string containing the network address for this asset.

.PARAMETER Port
Adds the Port header to the template file. 
Value - An integer containing the port for this asset.

.PARAMETER ServiceAccountDomainName
Adds the ServiceAccountDomainName header to the template file. 
Value - A string containing the service account domain name if it has one.

.PARAMETER ServiceAccountName
Adds the ServiceAccountName header to the template file. 
Value - A string containing the service account name.

.PARAMETER ServiceAccountPassword
Adds the ServiceAccountPassword header to the template file. 
Value - A string containing the password to use for the service account.

.PARAMETER ServiceAccountCredentialType
Adds the ServiceAccountCredentialType header to the template file. 
Value - Type of credential to use to authenticate the asset.

.PARAMETER ServiceAccountSecretKey
Adds the ServiceAccountSecretKey header to the template file. 
Value - A string containing an API access key for the service account.

.PARAMETER ServiceAccountDistinguishedName
Adds the ServuceAccountDistinguishedName header to the template file. 
Value - A string containing the LDAP distinguished name of a service account.  This is used for
creating LDAP directories.

.PARAMETER PrivilegeElevationCommand
Adds the PrivilegeElevationCommand header to the template file. 
Value - A string containing the privilege elevation command, ex. sudo.

.INPUTS
None.

.OUTPUTS
A CSV file with the headers.

.EXAMPLE
New-SafeguardAssetImportTemplate -DisplayName -Description -AssetPartition

.EXAMPLE
New-SafeguardAssetImportTemplate 'C:\tmp\template.csv' -DisplayName -Description -AssetPartition

#>
function New-SafeguardAssetImportTemplate
{
    [CmdletBinding(DefaultParameterSetName="Specific")]
    Param(
        [Parameter(Mandatory=$false, Position=0)]
        [string]$Path = '.\SafeguardAssetImportTemplate.csv',
        [Parameter(Mandatory=$false,ParameterSetName="All")]
        [switch]$All,
        [Parameter(Mandatory=$false,ParameterSetName="Specific")]
        [switch]$Description,
        [Parameter(Mandatory=$false,ParameterSetName="Specific")]
        [switch]$AssetPartition,
        [Parameter(Mandatory=$false,ParameterSetName="Specific")]
        [switch]$NetworkAddress,
        [Parameter(Mandatory=$false,ParameterSetName="Specific")]
        [switch]$Port,
        [Parameter(Mandatory=$false,ParameterSetName="Specific")]
        [switch]$ServiceAccountDomainName,
        [Parameter(Mandatory=$false,ParameterSetName="Specific")]
        [switch]$ServiceAccountName,
        [Parameter(Mandatory=$false,ParameterSetName="Specific")]
        [switch]$ServiceAccountPassword,
        [Parameter(Mandatory=$false,ParameterSetName="Specific")]
        [switch]$ServiceAccountCredentialType,
        [Parameter(Mandatory=$false,ParameterSetName="Specific")]
        [switch]$ServiceAccountSecretKey,
        [Parameter(Mandatory=$false,ParameterSetName="Specific")]
        [switch]$ServiceAccountDistinguishedName,
        [Parameter(Mandatory=$false,ParameterSetName="Specific")]
        [switch]$PrivilegeElevationCommand
    )

    $local:Headers = '"DisplayName","Platform"'

    if ($PSBoundParameters.ContainsKey("Description") -or $PSBoundParameters.ContainsKey("All")) { $local:Headers = $local:Headers + ',"Description"' }
    if ($PSBoundParameters.ContainsKey("AssetPartition") -or $PSBoundParameters.ContainsKey("All")) { $local:Headers = $local:Headers + ',"AssetPartition"' }
    if ($PSBoundParameters.ContainsKey("NetworkAddress") -or $PSBoundParameters.ContainsKey("All")) { $local:Headers = $local:Headers + ',"NetworkAddress"' }
    if ($PSBoundParameters.ContainsKey("Port") -or $PSBoundParameters.ContainsKey("All")) { $local:Headers = $local:Headers + ',"Port"' }
    if ($PSBoundParameters.ContainsKey("ServiceAccountDomainName") -or $PSBoundParameters.ContainsKey("All")) { $local:Headers = $local:Headers + ',"ServiceAccountDomainName"' }
    if ($PSBoundParameters.ContainsKey("ServiceAccountName") -or $PSBoundParameters.ContainsKey("All")) { $local:Headers = $local:Headers + ',"ServiceAccountName"' }
    if ($PSBoundParameters.ContainsKey("ServiceAccountPassword") -or $PSBoundParameters.ContainsKey("All")) { $local:Headers = $local:Headers + ',"ServiceAccountPassword"' }
    if ($PSBoundParameters.ContainsKey("ServiceAccountCredentialType") -or $PSBoundParameters.ContainsKey("All")) { $local:Headers = $local:Headers + ',"ServiceAccountCredentialType"' }
    if ($PSBoundParameters.ContainsKey("ServiceAccountSecretKey") -or $PSBoundParameters.ContainsKey("All")) { $local:Headers = $local:Headers + ',"ServiceAccountSecretKey"' }
    if ($PSBoundParameters.ContainsKey("ServiceAccountDistinguishedName") -or $PSBoundParameters.ContainsKey("All")) { $local:Headers = $local:Headers + ',"ServiceAccountDistinguishedName"' }
    if ($PSBoundParameters.ContainsKey("PrivilegeElevationCommand") -or $PSBoundParameters.ContainsKey("All")) { $local:Headers = $local:Headers + ',"PrivilegeElevationCommand"' }

    Set-Content -Path $Path -Value $local:Headers -Force
}

<#
.SYNOPSIS
Imports safeguard assets.

.DESCRIPTION
Imports assets into safeguard from a csv file.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Path
Specifies the path to the CSV file to import.

.INPUTS
None.

.OUTPUTS
A CSV file with any imports that failed.  If there are no failures no output file will be generated.

.EXAMPLE
Import-SafeguardAsset -Path '<path to csv file>'

#>
function Import-SafeguardAsset
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Path
    )

	# Intercept Read-Host and return an empty string
	function Read-Host {
		return ""
	}

    $local:Assets = Import-Csv -Path $Path

    $local:FailedImports = New-Object System.Collections.ArrayList

    Write-Progress -Activity "Importing Assets ..." -PercentComplete 0

    $local:CurrAsset = 1;
    foreach($local:Asset in $local:Assets)
    {
        try 
        {
            $local:Args = @{
                AccessToken = $AccessToken
                Appliance = $Appliance
                Insecure = $true
                DisplayName = $local:Asset.DisplayName
                Platform = $local:Asset.Platform
                NoSshHostKeyDiscovery = $true
            }

            if($null -ne $local:Asset.Description) 
            {
                $local:Args.Add("Description", $local:Asset.Description)
            }

            if($null -ne $local:Asset.AssetPartition) 
            {
                $local:Args.Add("AssetPartition", $local:Asset.AssetPartition)
            }

            if($null -ne $local:Asset.NetworkAddress) 
            {
                $local:Args.Add("NetworkAddress", $local:Asset.NetworkAddress)
            }

            if($null -ne $local:Asset.Port) 
            {
                $local:Args.Add("Port", $local:Asset.Port)
            }

            if($null -ne $local:Asset.ServiceAccountDomainName) 
            {
                $local:Args.Add("ServiceAccountDomainName", $local:Asset.ServiceAccountDomainName)
            }

            if($null -ne $local:Asset.ServiceAccountName) 
            {
                $local:Args.Add("ServiceAccountName", $local:Asset.ServiceAccountName)
            }

            if(![string]::IsNullOrEmpty($local:Asset.ServiceAccountPassword))
            {
                $local:SecureServiceAccountPassword = $local:Asset.ServiceAccountPassword | ConvertTo-SecureString -AsPlainText -Force
                $local:Args.Add("ServiceAccountPassword", $local:SecureServiceAccountPassword)
            }

            if($null -ne $local:Asset.ServiceAccountCredentialType) 
            {
                $local:Args.Add("ServiceAccountCredentialType", $local:Asset.ServiceAccountCredentialType)
            }

            if($null -ne $local:Asset.ServiceAccountSecretKey) 
            {
                $local:Args.Add("ServiceAccountSecretKey", $local:Asset.ServiceAccountSecretKey)
            }

            if($null -ne $local:Asset.ServiceAccountDistinguishedName) 
            {
                $local:Args.Add("ServiceAccountDistinguishedName", $local:Asset.ServiceAccountDistinguishedName)
            }

            if($null -ne $local:Asset.PrivilegeElevationCommand) 
            {
                $local:Args.Add("PrivilegeElevationCommand", $local:Asset.PrivilegeElevationCommand)
            }

            New-SafeguardAsset @local:Args
        }
        catch 
        {
            if ($local:Asset.PSobject.Properties.Name -contains "Error")
            {
                $local:Asset.Error = $_
            }
            else 
            {
                $local:Asset | Add-Member -MemberType NoteProperty -Name "Error" -Value  $_
            }
            $local:FailedImports.Add($local:Asset)
        }
        
        Write-Progress -Activity "Importing Assets ..." -PercentComplete (($local:CurrAsset/$local:Assets.Count)*100)
        $local:CurrAsset++
    }

    Write-Host ($local:Assets.Count - $local:FailedImports.Count) "Successful Imports," $local:FailedImports.Count "Failed Imports"
    
    if ($local:FailedImports.Count -gt 0) 
    {
        Write-Host "Please refer to AssetImportResults.csv for more information on failures."
        $local:FailedImports | Export-Csv -Path ".\AssetImportResults.csv" -NoTypeInformation -Force
    }
}

<#
.SYNOPSIS
Creates a template file containing the headers for importing assets.

.DESCRIPTION
Creates a template file containing the headers for importing assets. Specify the optional columns with parameters.

Default Columns

- ParentAsset : An integer containing the ID of the asset to get accounts from or a string containing the name.

- NewAccountName : A string containing the name for the account.

.PARAMETER Path
A string containing the path of the template file.

.PARAMETER All
Adds all headers to the template file.

.PARAMETER Description
Adds the Description header to the template file. 
Value - A string containing the description for the account.

.PARAMETER DomainName
Adds the DomainName header to the template file. 
Value - A string containing the domain name for the account.

.PARAMETER DistinguishedName
Adds the DistinguishedName header to the template file. 
Value - A string containing the distinguished name for the account.

.PARAMETER AssetPartition
Adds the AssetPartition header to the template file. 
Value - An integer containing an ID or a string containing the name of the asset partition
to create the new asset account in.

.INPUTS
None.

.OUTPUTS
A CSV file with the headers.

.EXAMPLE
New-SafeguardAssetAccountImportTemplate -Description -AssetPartition

.EXAMPLE
New-SafeguardAssetAccountImportTemplate 'C:\tmp\template.csv' -Description -AssetPartition

#>
function New-SafeguardAssetAccountImportTemplate
{
    [CmdletBinding(DefaultParameterSetName="Specific")]
    Param(
        [Parameter(Mandatory=$false, Position=0)]
        [string]$Path = '.\SafeguardAssetAccountImportTemplate.csv',
        [Parameter(Mandatory=$false,ParameterSetName="All")]
        [switch]$All,
        [Parameter(Mandatory=$false,ParameterSetName="Specific")]
        [switch]$Description,
        [Parameter(Mandatory=$false,ParameterSetName="Specific")]
        [switch]$AssetPartition,
        [Parameter(Mandatory=$false,ParameterSetName="Specific")]
        [switch]$DomainName,
        [Parameter(Mandatory=$false,ParameterSetName="Specific")]
        [switch]$DistinguishedName
    )

    $local:Headers = '"ParentAsset","NewAccountName"'

    if ($PSBoundParameters.ContainsKey("Description") -or $PSBoundParameters.ContainsKey("All")) { $local:Headers = $local:Headers + ',"Description"' }
    if ($PSBoundParameters.ContainsKey("AssetPartition") -or $PSBoundParameters.ContainsKey("All")) { $local:Headers = $local:Headers + ',"AssetPartition"' }
    if ($PSBoundParameters.ContainsKey("DomainName") -or $PSBoundParameters.ContainsKey("All")) { $local:Headers = $local:Headers + ',"DomainName"' }
    if ($PSBoundParameters.ContainsKey("DistinguishedName") -or $PSBoundParameters.ContainsKey("All")) { $local:Headers = $local:Headers + ',"DistinguishedName"' }

    Set-Content -Path $Path -Value $local:Headers -Force
}

<#
.SYNOPSIS
Imports safeguard asset accounts.

.DESCRIPTION
Imports asset accounts into safeguard from a csv file.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Path
Specifies the path to the CSV file to import.

.INPUTS
None.

.OUTPUTS
A CSV file with any imports that failed.  If there are no failures no output file will be generated.

.EXAMPLE
Import-SafeguardAssetAccount -Path '<path to csv file>'

#>
function Import-SafeguardAssetAccount
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Path
    )

	# Intercept Read-Host and return an empty string
	function Read-Host {
		return ""
	}

    $local:Accounts = Import-Csv -Path $Path

    $local:FailedImports = New-Object System.Collections.ArrayList

    Write-Progress -Activity "Importing Accounts ..." -PercentComplete 0

    $local:CurrAccount = 1;
    foreach($local:Account in $local:Accounts)
    {
        try 
        {
            $local:Args = @{
                AccessToken = $AccessToken
                Appliance = $Appliance
                Insecure = $true
                ParentAsset = $local:Account.ParentAsset
                NewAccountName = $local:Account.NewAccountName
            }

            if($null -ne $local:Account.Description) 
            {
                $local:Args.Add("Description", $local:Account.Description)
            }

            if($null -ne $local:Account.AssetPartition) 
            {
                $local:Args.Add("AssetPartition", $local:Account.AssetPartition)
            }

            if($null -ne $local:Account.DomainName) 
            {
                $local:Args.Add("DomainName", $local:Account.DomainName)
            }
            
            if($null -ne $local:Account.DistinguishedName) 
            {
                $local:Args.Add("DistinguishedName", $local:Account.DistinguishedName)
            }

            New-SafeguardAssetAccount @local:Args
        }
        catch 
        {
            if ($local:Account.PSobject.Properties.Name -contains "Error")
            {
                $local:Account.Error = $_
            }
            else 
            {
                $local:Account | Add-Member -MemberType NoteProperty -Name "Error" -Value  $_
            }
            $local:FailedImports.Add($local:Account)
        }
        
        Write-Progress -Activity "Importing Asset Accounts ..." -PercentComplete (($local:CurrAccount/$local:Accounts.Count)*100)
        $local:CurrAccount++
    }

    Write-Host ($local:Accounts.Count - $local:FailedImports.Count) "Successful Imports," $local:FailedImports.Count "Failed Imports"
    
    if ($local:FailedImports.Count -gt 0) 
    {
        Write-Host "Please refer to AssetAccountImportResults.csv for more information on failures."
        $local:FailedImports | Export-Csv -Path ".\AssetAccountImportResults.csv" -NoTypeInformation -Force
    }
}

<#
.SYNOPSIS
Creates a template file containing the headers for importing assets.

.DESCRIPTION
Creates a template file containing the headers for importing assets.

Columns

- AssetPartition : An integer containing an ID or a string containing the name of the asset partition to set the asset account password in.

- AssetToSet : An integer containing the ID of the asset to set account password on or a string containing the name.

- AccountToSet : An integer containing the ID of the account to set password on or a string containing the name.

- NewPassword : A string containing the new password to set.

.PARAMETER Path
A string containing the path of the template file.

.INPUTS
None.

.OUTPUTS
A CSV file with the headers.

.EXAMPLE
New-SafeguardAssetAccountPasswordImportTemplate

.EXAMPLE
New-SafeguardAssetAccountPasswordImportTemplate 'C:\tmp\template.csv'

#>
function New-SafeguardAssetAccountPasswordImportTemplate
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false, Position=0)]
        [string]$Path = '.\SafeguardAssetAccountPasswordImportTemplate.csv'
    )

    $local:Headers = '"AssetPartition","AssetToSet","AccountToSet","NewPassword"'

    Set-Content -Path $Path -Value $local:Headers -Force
}

<#
.SYNOPSIS
Imports safeguard asset account passwords.

.DESCRIPTION
Imports asset account passwords into safeguard from a csv file.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Path
Specifies the path to the CSV file to import.

.INPUTS
None.

.OUTPUTS
A CSV file with any imports that failed.  If there are no failures no output file will be generated.

.EXAMPLE
Import-SafeguardAssetAccountPassword -Path '<path to csv file>'

#>
function Import-SafeguardAssetAccountPassword
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Path
    )

	# Intercept Read-Host and return an empty string
	function Read-Host {
		return ""
	}

    $local:Passwords = Import-Csv -Path $Path

    $local:FailedImports = New-Object System.Collections.ArrayList

    Write-Progress -Activity "Importing Asset Account Passwords ..." -PercentComplete 0

    $local:CurrPassword = 1;
    foreach($local:Password in $local:Passwords)
    {
        try 
        {
            $local:Args = @{
                AccessToken = $AccessToken
                Appliance = $Appliance
                Insecure = $true
                AssetPartition = $local:Password.AssetPartition
                AssetToSet = $local:Password.AssetToSet
                AccountToSet = $local:Password.AccountToSet
            }

            if(![string]::IsNullOrEmpty($local:Password.NewPassword))
            {
                $local:NewSecurePassword = $local:Password.NewPassword | ConvertTo-SecureString -AsPlainText -Force
                $local:Args.Add("NewPassword", $local:NewSecurePassword)
            }
        
            Set-SafeguardAssetAccountPassword @local:Args
        }
        catch 
        {
            if ($local:Password.PSobject.Properties.Name -contains "Error")
            {
                $local:Password.Error = $_
            }
            else 
            {
                $local:Password | Add-Member -MemberType NoteProperty -Name "Error" -Value  $_
            }
            $local:FailedImports.Add($local:Password)
        }
        
        Write-Progress -Activity "Importing Asset Account Passwords ..." -PercentComplete (($local:CurrPassword/$local:Passwords.Count)*100)
        $local:CurrPassword++
    }

    Write-Host ($local:Passwords.Count - $local:FailedImports.Count) "Successful Imports," $local:FailedImports.Count "Failed Imports"
    
    if ($local:FailedImports.Count -gt 0) 
    {
        Write-Host "Please refer to AssetAccountPasswordImportResults.csv for more information on failures."
        $local:FailedImports | Export-Csv -Path ".\AssetAccountPasswordImportResults.csv" -NoTypeInformation -Force
    }
}

<#
.SYNOPSIS
Creates a template file containing the headers for importing assets.

.DESCRIPTION
Creates a template file containing the headers for importing assets.

Columns

- AssetPartition : An integer containing an ID or a string containing the name of the asset partition to set the asset account password in.

- AssetToSet : An integer containing the ID of the asset to set account password on or a string containing the name.

- AccountToSet : An integer containing the ID of the account to set password on or a string containing the name.

- PrivateKey : A string containing the private key to assign to the account.

.PARAMETER Path
A string containing the path of the template file.

.PARAMETER Passphrase
Adds the Passphrase header to the template file. 
Value - A string containing the passphrase used to decrypt the private key.

.INPUTS
None.

.OUTPUTS
A CSV file with the headers.

.EXAMPLE
New-SafeguardAssetAccountSshKeyImportTemplate

.EXAMPLE
New-SafeguardAssetAccountSshKeyImportTemplate 'C:\tmp\template.csv'

#>
function New-SafeguardAssetAccountSshKeyImportTemplate
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false, Position=0)]
        [string]$Path = '.\SafeguardAssetAccountSshKeyImportTemplate.csv',
        [Parameter(Mandatory=$false)]
        [switch]$Passphrase
    )

    $local:Headers = '"AssetPartition","AssetToSet","AccountToSet","PrivateKey"'

    if ($PSBoundParameters.ContainsKey("Passphrase")) { $local:Headers = $local:Headers + ',"Passphrase"' }

    Set-Content -Path $Path -Value $local:Headers -Force
}

<#
.SYNOPSIS
Imports safeguard asset account SSH Keys.

.DESCRIPTION
Imports asset account SSH Keys into safeguard from a csv file.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Path
Specifies the path to the CSV file to import.

.INPUTS
None.

.OUTPUTS
A CSV file with any imports that failed.  If there are no failures no output file will be generated.

.EXAMPLE
Import-SafeguardAssetAccountSshKey -Path '<path to csv file>'

#>
function Import-SafeguardAssetAccountSshKey
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Path
    )

	# Intercept Read-Host and return an empty string
	function Read-Host {
		return ""
	}

    $local:SshKeys = Import-Csv -Path $Path

    $local:FailedImports = New-Object System.Collections.ArrayList

    Write-Progress -Activity "Importing Asset Account SSH Keys ..." -PercentComplete 0

    $local:CurrSshKey = 1;
    foreach($local:SshKey in $local:SshKeys)
    {
        try 
        {
            $local:Args = @{
                AccessToken = $AccessToken
                Appliance = $Appliance
                Insecure = $true
                AssetPartition = $local:SshKey.AssetPartition
                AssetToSet = $local:SshKey.AssetToSet
                AccountToSet = $local:SshKey.AccountToSet
                PrivateKey = $local:SshKey.PrivateKey
            }

            if(![string]::IsNullOrEmpty($local:SshKey.Passphrase))
            {
                $local:NewSecurePassphrase = $local:SshKey.Passphrase | ConvertTo-SecureString -AsPlainText -Force
                $local:Args.Add("Passphrase", $local:NewSecurePassphrase)
            }

        
            Set-SafeguardAssetAccountSshKey @local:Args
        }
        catch 
        {
            if ($local:SshKey.PSobject.Properties.Name -contains "Error")
            {
                $local:SshKey.Error = $_
            }
            else 
            {
                $local:SshKey | Add-Member -MemberType NoteProperty -Name "Error" -Value  $_
            }
            $local:FailedImports.Add($local:SshKey)
        }
        
        Write-Progress -Activity "Importing Asset Account SSH Keys ..." -PercentComplete (($local:CurrSshKey/$local:SshKeys.Count)*100)
        $local:CurrSshKey++
    }

    Write-Host ($local:SshKeys.Count - $local:FailedImports.Count) "Successful Imports," $local:FailedImports.Count "Failed Imports"
    
    if ($local:FailedImports.Count -gt 0) 
    {
        Write-Host "Please refer to AssetAccountSshKeyImportResults.csv for more information on failures."
        $local:FailedImports | Export-Csv -Path ".\AssetAccountSshKeyImportResults.csv" -NoTypeInformation -Force
    }
}