# Helper
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
        [Parameter(Mandatory=$true,Position=0)]
        [object]$Asset
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not ($Asset -as [int]))
    {
        try
        {
            $local:Assets = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Assets `
                                 -Parameters @{ filter = "Name ieq '$Asset'" })
            if (-not $local:Assets)
            {
                $local:Assets = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Assets `
                                     -Parameters @{ filter = "NetworkAddress ieq '$Asset'" })
            }
        }
        catch
        {
            Write-Verbose $_
            Write-Verbose "Caught exception with ieq filter, trying with q parameter"
            $local:Assets = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Assets `
                                 -Parameters @{ q = $Asset })
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
        [int]$AssetId,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$Account
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not ($Account -as [int]))
    {
        if ($PSBoundParameters.ContainsKey("AssetId"))
        {
            $local:RelativeUrl = "Assets/$AssetId/Accounts"
        }
        else
        {
            $local:RelativeUrl = "AssetAccounts"
        }
        try
        {
            $local:Accounts = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET $local:RelativeUrl `
                                   -Parameters @{ filter = "Name ieq '$Account'" })
        }
        catch
        {
            Write-Verbose $_
            Write-Verbose "Caught exception with ieq filter, trying with q parameter"
            $local:Accounts = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET $local:RelativeUrl `
                                   -Parameters @{ q = $Account })
        }
        if (-not $local:Accounts)
        {
            throw "Unable to find account matching '$Account'"
        }
        if ($local:Accounts.Count -ne 1)
        {
            throw "Found $($local:Accounts.Count) accounts matching '$Account'"
        }
        $local:Accounts[0].Id
    }
    else
    {
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
        [Parameter(Mandatory=$true,Position=0)]
        [object]$Asset,
        [Parameter(Mandatory=$false)]
        [object]$AcceptSshHostKey
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local

    if (($Asset -as [int]) -or ($Asset -is [string]))
    {
        $local:AssetObj = (Get-SafeguardAsset -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Asset)
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

.PARAMETER AssetToGet
An integer containing the ID of the asset to get or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardAsset -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardAsset
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
        [Parameter(Mandatory=$false,Position=0)]
        [object]$AssetToGet
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSBoundParameters.ContainsKey("AssetToGet"))
    {
        $local:AssetId = Resolve-SafeguardAssetId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AssetToGet
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Assets/$($local:AssetId)"
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
A string to search for in the asset.

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
    [CmdletBinding()]
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
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Assets" `
        -Parameters @{ q = $SearchString }
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

.PARAMETER NoSshHostKeyDiscovery
Whether or not to skip SSH host key discovery for platforms that support it.

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
    [CmdletBinding()]
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
        [Parameter(Mandatory=$false,Position=2)]
        [string]$ServiceAccountName,
        [Parameter(Mandatory=$false,Position=3)]
        [SecureString]$ServiceAccountPassword,
        [Parameter(Mandatory=$false)]
        [string]$ServiceAccountSecretKey,
        [Parameter(Mandatory=$false)]
        [switch]$NoSshHostKeyDiscovery = $false,
        [Parameter(Mandatory=$false)]
        [switch]$AcceptSshHostKey = $false
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
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

    if ($PSBoundParameters.ContainsKey("Port")) { $local:ConnectionProperties.Port = $Port }
    if ($ServiceAccountCredentialType -ne "None")
    {
        switch ($ServiceAccountCredentialType.ToLower())
        {
            {$_ -in "password","accountpassword","accesskey"} {
                if (-not $PSBoundParameters.ContainsKey("ServiceAccountName"))
                {
                    $ServiceAccountName = (Read-Host "ServiceAccountName")
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
            "sshkey" {
                throw "SSH Keys are not supported for asset creation yet"
            }
            default {
                throw "$ServiceAccountCredentialType are not supported yet"
            }
        }
    }
    else
    {
        # No Service Account -- so don't detect SSH host key
        $NoSshHostKeyDiscovery = $true
    }

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
        [Parameter(Mandatory=$false,Position=0)]
        [object]$AssetToTest
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $PSBoundParameters.ContainsKey("AssetToTest"))
    {
        $AssetToTest = (Read-Host "AssetToTest")
    }
    $local:AssetId = Resolve-SafeguardAssetId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AssetToTest

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
        [Parameter(Mandatory=$false,Position=0)]
        [object]$AssetToDelete
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $PSBoundParameters.ContainsKey("AssetToDelete"))
    {
        $AssetToDelete = (Read-Host "AssetToDelete")
    }

    $local:AssetId = Resolve-SafeguardAssetId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AssetToDelete
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

.PARAMETER ServiceAccountSecretKey
A string containing an API access key for the service account.

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
        [Parameter(ParameterSetName="Object",Mandatory=$true,ValueFromPipeline=$true)]
        [object]$AssetObject
    )

    $ErrorActionPreference = "Stop"
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
        $local:AssetId = Resolve-SafeguardAssetId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AssetToEdit
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
        if ($PSBoundParameters.ContainsKey("ServiceAccountPassword"))
        {
            $AssetObject.ConnectionProperties.ServiceAccountPassword = `
                [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ServiceAccountPassword))
        }
        if ($PSBoundParameters.ContainsKey("ServiceAccountSecretKey")) { AssetObject.ConnectionProperties.ServiceAccountSecretKey = $ServiceAccountSecretKey }

        # Body
        if ($PSBoundParameters.ContainsKey("DisplayName")) { $AssetObject.DisplayName = $DisplayName }
        if ($PSBoundParameters.ContainsKey("Description")) { $AssetObject.Description = $Description }
        if ($PSBoundParameters.ContainsKey("NetworkAddress")) { $AssetObject.NetworkAddress = $NetworkAddress }
        if ($PSBoundParameters.ContainsKey("Platform"))
        {
            $local:PlatformId = Resolve-SafeguardPlatform -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Platform
            $AssetObject.PlatformId = $local:PlatformId
        }
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "Assets/$($AssetObject.Id)" -Body $AssetObject
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

.PARAMETER AssetToGet
An integer containing the ID of the asset to get accounts from or a string containing the name.

.PARAMETER AccountToGet
An integer containing the ID of the account to get or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardAssetAccount -AccessToken $token -Appliance 10.5.32.54 -Insecure windows.blah.corp administrator

.EXAMPLE
Get-SafeguardAssetAccount -AccountToGet oracle
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
        [Parameter(Mandatory=$false,Position=0)]
        [object]$AssetToGet,
        [Parameter(Mandatory=$false,Position=1)]
        [object]$AccountToGet
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSBoundParameters.ContainsKey("AssetToGet"))
    {
        $local:AssetId = (Resolve-SafeguardAssetId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AssetToGet)
        if ($PSBoundParameters.ContainsKey("AccountToGet"))
        {
            $local:AccountId = (Resolve-SafeguardAssetAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetId $local:AssetId $AccountToGet)
            Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "AssetAccounts/$($local:AccountId)"
        }
        else
        {
            Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Assets/$($local:AssetId)/Accounts"
        }
    }
    else
    {
        if ($PSBoundParameters.ContainsKey("AccountToGet"))
        {
            $local:AccountId = (Resolve-SafeguardAssetAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AccountToGet)
            Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "AssetAccounts/$($local:AccountId)"
        }
        else
        {
            Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "AssetAccounts"
        }
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

.PARAMETER SearchString
A string to search for in the asset account.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Find-SafeguardAssetAccount -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Find-SafeguardAssetAccount "root"
#>
function Find-SafeguardAssetAccount
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
        [string]$SearchString
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "AssetAccounts" `
        -Parameters @{ q = $SearchString }
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
        [string]$Description
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:AssetId = (Resolve-SafeguardAssetId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $ParentAsset)

    $local:Body = @{
        "AssetId" = $local:AssetId;
        "Name" = $NewAccountName
    }

    if ($PSBoundParameters.ContainsKey("Description")) { $local:Body.Description = $Description }

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
        [Parameter(ParameterSetName="Object",Mandatory=$true)]
        [object]$AccountObject
    )

    $ErrorActionPreference = "Stop"
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
        $AccountObject = (Get-SafeguardAssetAccount -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $local:AccountId)

        if ($PSBoundParameters.ContainsKey("Description")) { $AccountObject.Description = $Description }
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

    $ErrorActionPreference = "Stop"
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

    $ErrorActionPreference = "Stop"
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

    $ErrorActionPreference = "Stop"
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

    $ErrorActionPreference = "Stop"
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

    $ErrorActionPreference = "Stop"
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
