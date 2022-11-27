# Helper
function Resolve-SafeguardDirectoryIdentityProviderId
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
        [object]$Directory
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($Directory.Id -as [int])
    {
        $Directory = $Directory.Id
    }

    if (-not ($Directory -as [int]))
    {
        try
        {
            $local:Idps = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET IdentityProviders `
                               -Parameters @{ Filter = "Name ieq '$Directory'" })
            if (-not $local:Idps)
            {
                $local:Idps = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET IdentityProviders `
                                   -Parameters @{ Filter = "DirectoryProperties.Domains.DomainName ieq '$Directory'" })
            }
        }
        catch
        {
            Write-Verbose $_
            Write-Verbose "Caught exception with ieq filter, trying with q parameter"
            $local:Idps = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET IdentityProviders `
                                      -Parameters @{ q = $Directory })
        }
        if (-not $local:Idps)
        {
            throw "Unable to find directory identity provider matching '$Directory'"
        }
        if ($local:Idps.Count -ne 1)
        {
            throw "Found $($local:Idps.Count) directory identity providers matching '$Directory'"
        }
        $local:Idps[0].Id
    }
    else
    {
        $Directory
    }
}
function Resolve-SafeguardDirectoryId
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
        [object]$Directory
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($Directory.Id -as [int])
    {
        $Directory = $Directory.Id
    }

    if (-not ($Directory -as [int]))
    {
        $local:Directories = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Assets `
                                 -Parameters @{ filter = "IsDirectory eq true and Name ieq '$Directory'" })
        if (-not $local:Directories)
        {
            $local:Directories = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Assets `
                                     -Parameters @{ filter = "IsDirectory eq true and NetworkAddress ieq '$Directory'" })
        }
        if (-not $local:Directories)
        {
            $local:Directories = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Assets `
                                     -Parameters @{ filter = "IsDirectory eq true and DirectoryAssetProperties.Domains.DomainName ieq '$Directory'" })
        }

        if (-not $local:Directories)
        {
            throw "Unable to find directory matching '$Directory'"
        }
        if ($local:Directories.Count -ne 1)
        {
            throw "Found $($local:Directories.Count) directories matching '$Directory'"
        }
        $local:Directories[0].Id
    }
    else
    {
        $Directory
    }
}
function Resolve-SafeguardDirectoryAccountId
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
        [int]$DirectoryId,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$Account
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($Account.Id -as [int])
    {
        $Account = $Account.Id
    }

    if (-not ($Account -as [int]))
    {
        if ($PSBoundParameters.ContainsKey("DirectoryId"))
        {
            $local:RelativeUrl = "Assets/$DirectoryId/Accounts"
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
Get directory identity providers used by Safeguard via the Web API.

.DESCRIPTION
Safeguard directory users can be added from Safeguard directory identity providers to
enable domain users to log into Safeguard.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER DirectoryToGet
An integer containing the ID of the directory to get or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardDirectoryIdentityProvider -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardDirectoryIdentityProvider x.domain.corp
#>
function Get-SafeguardDirectoryIdentityProvider
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
        [object]$DirectoryToGet
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSBoundParameters.ContainsKey("DirectoryToGet"))
    {
        $local:Id = (Resolve-SafeguardDirectoryIdentityProviderId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $DirectoryToGet)
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "IdentityProviders/$($local:Id)"
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET IdentityProviders `
            -Parameters @{ Filter = "(TypeReferenceName eq 'ActiveDirectory') or (TypeReferenceName eq 'Ldap')" }
    }
}

<#
.SYNOPSIS
Get domains of a directory identity provider used by Safeguard via the Web API.

.DESCRIPTION
Safeguard directory users can be added from Safeguard directory identity providers to
enable domain users to log into Safeguard.  This cmdlet will report on which domains
are included within that directory identity provider.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER DirectoryToGet
An integer containing the ID of the directory to get or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardDirectoryIdentityProviderDomain -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardDirectoryIdentityProviderDomain x.domain.corp
#>
function Get-SafeguardDirectoryIdentityProviderDomain
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
        [object]$DirectoryToGet
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    (Get-SafeguardDirectoryIdentityProvider -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
        $DirectoryToGet).DirectoryProperties.Domains
}

<#
.SYNOPSIS
Create new directory identity provider in Safeguard via the Web API.

.DESCRIPTION
Create a new directory identity provider in Safeguard for adding directory users that can log into
Safeguard via the Web API.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER ServiceAccountDomainName
A string containing the service account domain name if it has one.  This is used
for creating AD directory identity providers.

.PARAMETER ServiceAccountName
A string containing the service account name.  This is used for creating AD directories.

.PARAMETER ServiceAccountDistinguishedName
A string containing the LDAP distinguished name of a service account.  This is used for
creating LDAP directory identity providers.

.PARAMETER ServiceAccountPassword
A SecureString containing the password to use for the service account.

.PARAMETER NetworkAddress
A string containing the network address for this directory identity provider.  This is used for creating
LDAP directory identity providers.

.PARAMETER Port
An integer containing the port for this directory identity provider.  This is used for creating
LDAP directory identity providers.

.PARAMETER NoSslEncryption
Do not use SSL encryption for LDAP directory identity provider.

.PARAMETER DoNotVerifyServerSslCertificate
Do not verify Server SSL certificate of LDAP directory identity provider.

.PARAMETER DisplayName
Name for the directory identity provider (default for AD is ServiceAccountDomainName)

.PARAMETER Description
A string containing a description for this directory identity provider.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
New-SafeguardDirectoryIdentityProvider -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
New-SafeguardDirectoryIdentityProvider internal.domain.corp svc-user

.EXAMPLE
New-SafeguardDirectoryIdentityProvider -ServiceAccountDistinguishedName "cn=dev-sa,ou=people,dc=ldap,dc=domain,dc=corp" -NoSslEncryption
#>
function New-SafeguardDirectoryIdentityProvider
{
    [CmdletBinding(DefaultParameterSetName="Ad")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,ParameterSetName="Ad",Position=0)]
        [string]$ServiceAccountDomainName,
        [Parameter(Mandatory=$true,ParameterSetName="Ad",Position=1)]
        [string]$ServiceAccountName,
        [Parameter(Mandatory=$true,ParameterSetName="Ldap",Position=0)]
        [string]$ServiceAccountDistinguishedName,
        [Parameter(Mandatory=$false,ParameterSetName="Ad",Position=2)]
        [Parameter(Mandatory=$false,ParameterSetName="Ldap",Position=1)]
        [SecureString]$ServiceAccountPassword,
        [Parameter(Mandatory=$true,ParameterSetName="Ldap")]
        [string]$NetworkAddress,
        [Parameter(Mandatory=$false,ParameterSetName="Ldap")]
        [int]$Port,
        [Parameter(Mandatory=$false,ParameterSetName="Ldap")]
        [switch]$NoSslEncryption,
        [Parameter(Mandatory=$false,ParameterSetName="Ldap")]
        [switch]$DoNotVerifyServerSslCertificate,
        [Parameter(Mandatory=$false)]
        [string]$DisplayName,
        [Parameter(Mandatory=$false)]
        [string]$Description
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $PSBoundParameters.ContainsKey("ServiceAccountPassword"))
    {
        $ServiceAccountPassword = (Read-Host -AsSecureString "ServiceAccountPassword")
    }

    if (-not $PSBoundParameters.ContainsKey("DisplayName"))
    {
        if ($ServiceAccountDomainName)
        {
            $DisplayName = $ServiceAccountDomainName
        }
        else
        {
            $DisplayName = (Read-Host "DisplayName")
        }
    }

    if ($PSCmdlet.ParameterSetName -eq "Ldap")
    {
        $local:Body = @{
            Name = $DisplayName;
            TypeReferenceName = "Ldap";
            DirectoryProperties = @{
                ConnectionProperties = @{
                    UseSslEncryption = $true;
                    VerifySslCertificate = $true;
                    ServiceAccountDistinguishedName = $ServiceAccountDistinguishedName;
                    ServiceAccountPassword = [System.Net.NetworkCredential]::new("", $ServiceAccountPassword).Password
                }
            }
        }
        if ($PSBoundParameters.ContainsKey("NetworkAddress"))
        {
            $local:Body.ConnectionProperties.NetworkAddress = $NetworkAddress
        }
        if ($PSBoundParameters.ContainsKey("Port"))
        {
            $local:Body.ConnectionProperties.Port = $Port
        }
        if ($NoSslEncryption)
        {
            $local:Body.ConnectionProperties.UseSslEncryption = $false
            $local:Body.ConnectionProperties.VerifySslCertificate = $false
        }
        if ($DoNotVerifyServerSslCertificate)
        {
            $local:Body.ConnectionProperties.VerifySslCertificate = $false
        }
    }
    else
    {
        $local:Body = @{
            Name = $DisplayName;
            TypeReferenceName = "ActiveDirectory";
            DirectoryProperties = @{
                ConnectionProperties = @{
                    ServiceAccountDomainName = $ServiceAccountDomainName;
                    ServiceAccountName = $ServiceAccountName;
                    ServiceAccountPassword = [System.Net.NetworkCredential]::new("", $ServiceAccountPassword).Password
                }
            }
        }
    }
    if ($PSBoundParameters.ContainsKey("Description"))
    {
        $local:Body.Description = $Description
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST IdentityProviders -Body $local:Body
}

<#
.SYNOPSIS
Remove a directory identity provider from Safeguard via the Web API.

.DESCRIPTION
Remove a directory identify provider from Safeguard. Make sure it is not
in use before you remove it.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER DirectoryToDelete
An integer containing the ID of the directory identity provider to remove or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardDirectoryIdentityProvider -AccessToken $token -Appliance 10.5.32.54 -Insecure 5

.EXAMPLE
Remove-SafeguardDirectoryIdentityProvider internal.domain.corp
#>
function Remove-SafeguardDirectoryIdentityProvider
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
        [object]$DirectoryToDelete
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:IdpId = (Resolve-SafeguardDirectoryIdentityProviderId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $DirectoryToDelete)
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "IdentityProviders/$($local:IdpId)"
}

<#
.SYNOPSIS
Edit existing directory identity provider in Safeguard via the Web API.

.DESCRIPTION
Edit an existing directory identity provider in Safeguard that can be used to manage accounts.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER DirectoryToEdit
An integer containing the ID of the directory identity provider to edit or a string containing the name.

.PARAMETER NetworkAddress
A string containing the network address for this directory identity provider.  This is used for creating
LDAP directory identity providers.

.PARAMETER Port
An integer containing the port for this directory identiy provider.  This is used for creating
LDAP directory identity providers.

.PARAMETER NoSslEncryption
Do not use SSL encryption for LDAP directory identity provider.

.PARAMETER DoNotVerifyServerSslCertificate
Do not verify Server SSL certificate of LDAP directory identity provider.

.PARAMETER Description
A string containing a description for this directory identity provider.

.PARAMETER DirectoryObject
An object containing the existing directory identity provider with desired properties set.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Edit-SafeguardDirectoryIdentityProvider -AccessToken $token -Appliance 10.5.32.54 -Insecure internal.domain.corp

.EXAMPLE
Edit-SafeguardDirectoryIdentityProvider ldap.domain.corp -ServiceAccountDistinguishedName "cn=dev-sa,ou=people,dc=ldap,dc=domain,dc=corp" -NoSslEncryption

.EXAMPLE
Edit-SafeguardDirectoryIdentityProvider -DirectoryObject $obj
#>
function Edit-SafeguardDirectoryIdentityProvider
{
    [CmdletBinding(DefaultParameterSetName="Attributes")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(ParameterSetName="Attributes",Mandatory=$true,Position=0)]
        [object]$DirectoryToEdit,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$NetworkAddress,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [int]$Port,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [switch]$NoSslEncryption,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [switch]$DoNotVerifyServerSslCertificate,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$DisplayName,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$Description,
        [Parameter(ParameterSetName="Object",Mandatory=$true,ValueFromPipeline=$true)]
        [object]$DirectoryObject
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PsCmdlet.ParameterSetName -eq "Object" -and -not $DirectoryObject)
    {
        throw "DirectoryObject must not be null"
    }

    if ($PsCmdlet.ParameterSetName -eq "Attributes")
    {
        if (-not $PSBoundParameters.ContainsKey("DirectoryToEdit"))
        {
            $DirectoryToEdit = (Read-Host "DirectoryToEdit")
        }
        $local:IdpId = (Resolve-SafeguardDirectoryIdentityProviderId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $DirectoryToEdit)
    }

    if (-not ($PsCmdlet.ParameterSetName -eq "Object"))
    {
        $local:IdpObject = (Get-SafeguardDirectoryIdentityProvider -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $local:IdpId)

        # Connection Properties
        if (-not $local:IdpObject.DirectoryProperties.ConnectionProperties) { $local:IdpObject.DirectoryProperties.ConnectionProperties = @{} }
        if (-not $local:IdpObject.DirectoryProperties) { $local:IdpObject.DirectoryProperties = @{} }
        if ($PSBoundParameters.ContainsKey("Port")) { $local:IdpObject.DirectoryProperties.ConnectionProperties.Port = $Port }
        if ($NoSslEncryption)
        {
            $local:IdpObject.DirectoryProperties.ConnectionProperties.UseSslEncryption = $false
            $local:IdpObject.DirectoryProperties.ConnectionProperties.VerifySslCertificate = $false
        }
        if ($DoNotVerifyServerSslCertificate)
        {
            $local:IdpObject.DirectoryProperties.ConnectionProperties.VerifySslCertificate = $false
        }

        # Body
        if ($PSBoundParameters.ContainsKey("DisplayName")) { $local:IdpObject.Name = $DisplayName }
        if ($PSBoundParameters.ContainsKey("Description")) { $local:IdpObject.Description = $Description }
        if ($PSBoundParameters.ContainsKey("NetworkAddress")) { $local:IdpObject.NetworkAddress = $NetworkAddress }

        $DirectoryObject = $local:IdpObject
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "IdentityProviders/$($DirectoryObject.Id)" -Body $DirectoryObject
}

<#
.SYNOPSIS
Synchronize a directory identity provider in Safeguard via the Web API.

.DESCRIPTION
Synchronize a directory identity provider to update the information in Safeguard.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER DirectoryToSync
An integer containing the ID of the directory identity provider to synchronize or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Sync-SafeguardDirectoryIdentityProvider 5

.EXAMPLE
Sync-SafeguardDirectoryIdentityProvider internal.domain.corp
#>
function Sync-SafeguardDirectoryIdentityProvider
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
        [object]$DirectoryToSync,
        [Parameter(Mandatory=$false)]
        [switch]$FullSync
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:IdpId = (Resolve-SafeguardDirectoryIdentityProviderId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $DirectoryToSync)
    if ($FullSync)
    {
        $Parameters = @{ fullSync = $true }
    }
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
        POST "IdentityProviders/$($local:IdpId)/Synchronize" -LongRunningTask -Parameters $Parameters
}

<#
.SYNOPSIS
Get the schema mapping from a directory identity provider in Safeguard via the Web API.

.DESCRIPTION
Edit an existing directory identity provider in Safeguard that can be used to manage accounts.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER DirectoryToEdit
An integer containing the ID of the directory identity provider to edit or a string containing the name.

.PARAMETER SchemaType
A string containing which schema type to get.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardDirectoryIdentityProviderSchemaMapping -AccessToken $token -Appliance 10.5.32.54 -Insecure internal.domain.corp -SchemaType Group

.EXAMPLE
Get-SafeguardDirectoryIdentityProviderSchemaMapping internal.domain.corp User
#>
function Get-SafeguardDirectoryIdentityProviderSchemaMapping
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
        [object]$DirectoryToGet,
        [Parameter(Mandatory=$true,Position=1)]
        [ValidateSet("User","Group",IgnoreCase=$true)]
        [string]$SchemaType
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:SchemaProperties = (Get-SafeguardDirectoryIdentityProvider -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
        $DirectoryToGet).DirectoryProperties.SchemaProperties
    switch ($SchemaType)
    {
        User {$local:SchemaProperties.UserProperties}
        Group {$local:SchemaProperties.GroupProperties | Format-List}
    }
}

<#
.SYNOPSIS
Set the schema mapping for a directory identity provider in Safeguard via the Web API.

.DESCRIPTION
Edit an existing directory identity provider in Safeguard that can be used to manage accounts.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER DirectoryToEdit
An integer containing the ID of the directory identity provider to edit or a string containing the name.

.PARAMETER SchemaType
A string containing which schema type to get.

.PARAMETER SchemaMappingObj
An object containing the directory identity provider schema mapping with desired properties set.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Set-SafeguardDirectoryIdentityProviderSchemaMapping -AccessToken $token -Appliance 10.5.32.54 -Insecure internal.domain.corp -SchemaType User -SchemaMappingObj $schema

.EXAMPLE
Set-SafeguardDirectoryIdentityProviderSchemaMapping internal.domain.corp user @{ DescriptionAttribute = "userPrincipalName" }
#>
function Set-SafeguardDirectoryIdentityProviderSchemaMapping
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
        [object]$DirectoryToGet,
        [Parameter(Mandatory=$true,Position=1)]
        [ValidateSet("User","Group",IgnoreCase=$true)]
        [string]$SchemaType,
        [Parameter(Mandatory=$true,Position=2)]
        [object]$SchemaMappingObj
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:IdpObject = (Get-SafeguardDirectoryIdentityProvider -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $DirectoryToGet)

    switch ($SchemaType)
    {
        User {
            $local:IdpObject.DirectoryProperties.SchemaProperties.UserProperties = $SchemaMappingObj
            (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "IdentityProviders/$($local:IdpObject.Id)" `
                -Body $local:IdpObject).DirectoryProperties.SchemaProperties.UserProperties
        }
        Group {
            $local:IdpObject.DirectoryProperties.SchemaProperties.GroupProperties = $SchemaMappingObj
            (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "IdentityProviders/$($local:IdpObject.Id)" `
                -Body $local:IdpObject).DirectoryProperties.SchemaProperties.GroupProperties | Format-List
        }
    }

}


<#
.SYNOPSIS
Get directories managed by Safeguard via the Web API.

.DESCRIPTION
Get the directories managed by Safeguard.  Accounts can be added to these directories,
and Safeguard can be configured to manage their passwords.  Once a directory is added
to Safeguard, a user administrator can create a Safeguard user from the directory
identity provider.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER DirectoryToGet
An integer containing the ID of the directory to get or a string containing the name.

.PARAMETER Fields
An array of the directory property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardDirectory -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardDirectory x.domain.corp
#>
function Get-SafeguardDirectory
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
        [object]$DirectoryToGet,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSBoundParameters.ContainsKey("DirectoryToGet"))
    {
        Get-SafeguardAsset -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $DirectoryToGet -Fields $Fields
    }
    else
    {
        if ($Fields)
        {
            $Fields += "IsDirectory"
        }
        (Get-SafeguardAsset -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -Fields $Fields) | Where-Object { $_.IsDirectory }
    }
}

<#
.SYNOPSIS
Create new directory asset in Safeguard via the Web API.

.DESCRIPTION
Create a new directory in Safeguard that can be used to manage accounts. This
cmdlet can be used to create an asset to represent Active Directory or any LDAP
directory.

NOTE: As of Safeguard version 2.7 and greater this cmdlet no longer creates an
identity provider, so it will no longer allow the creation of Safeguard users
from the added directory.  To create Safeguard users from a directory, use the
New-SafeguardDirectoryIdentityProvider cmdlet to add the identity provider.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Platform
A platform ID for a specific platform type or a string to search for desired platform type.

.PARAMETER ServiceAccountDomainName
A string containing the service account domain name if it has one.  This is used
for creating AD directories.

.PARAMETER ServiceAccountName
A string containing the service account name.  This is used for creating AD directories.

.PARAMETER ServiceAccountDistinguishedName
A string containing the LDAP distinguished name of a service account.  This is used for
creating LDAP directories.

.PARAMETER ServiceAccountPassword
A SecureString containing the password to use for the service account.

.PARAMETER NetworkAddress
A string containing the network address for this directory.  This is used for creating
LDAP directories.

.PARAMETER Port
An integer containing the port for this directory.  This is used for creating
LDAP directories.

.PARAMETER NoSslEncryption
Do not use SSL encryption for LDAP directory.

.PARAMETER DoNotVerifyServerSslCertificate
Do not verify Server SSL certificate of LDAP directory.

.PARAMETER Description
A string containing a description for this directory.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
New-SafeguardDirectory -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
New-SafeguardDirectory internal.domain.corp svc-user

.EXAMPLE
New-SafeguardDirectory -ServiceAccountDistinguishedName "cn=dev-sa,ou=people,dc=ldap,dc=domain,dc=corp" -NoSslEncryption
#>
function New-SafeguardDirectory
{
    [CmdletBinding(DefaultParameterSetName="Ad")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [object]$Platform,
        [Parameter(Mandatory=$true,ParameterSetName="Ad",Position=0)]
        [string]$ServiceAccountDomainName,
        [Parameter(Mandatory=$true,ParameterSetName="Ad",Position=1)]
        [string]$ServiceAccountName,
        [Parameter(Mandatory=$true,ParameterSetName="Ldap",Position=0)]
        [string]$ServiceAccountDistinguishedName,
        [Parameter(Mandatory=$false,ParameterSetName="Ad",Position=2)]
        [Parameter(Mandatory=$false,ParameterSetName="Ldap",Position=1)]
        [SecureString]$ServiceAccountPassword,
        [Parameter(Mandatory=$true,ParameterSetName="Ldap")]
        [string]$NetworkAddress,
        [Parameter(Mandatory=$false,ParameterSetName="Ldap")]
        [int]$Port,
        [Parameter(Mandatory=$false,ParameterSetName="Ldap")]
        [switch]$NoSslEncryption,
        [Parameter(Mandatory=$false,ParameterSetName="Ldap")]
        [switch]$DoNotVerifyServerSslCertificate,
        [Parameter(Mandatory=$false)]
        [string]$Description
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    Import-Module -Name "$PSScriptRoot\datatypes.psm1" -Scope Local
    Import-Module -Name "$PSScriptRoot\sg-utilities.psm1" -Scope Local

    if (-not $PSBoundParameters.ContainsKey("ServiceAccountPassword"))
    {
        $ServiceAccountPassword = (Read-Host -AsSecureString "ServiceAccountPassword")
    }

    if ($PSCmdlet.ParameterSetName -eq "Ldap")
    {
        if (-not $Port)
        {
            # defaults based on TLS
            if ($NoSslEncryption) { $Port = 389 }
            else { $Port = 636 }
        }

        $local:LdapPlatformId = (Resolve-SafeguardLdapDirectoryPlatform $Platform -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure)
        New-SafeguardAsset -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -DisplayName $NetworkAddress -Platform $local:LdapPlatformId `
            -ServiceAccountDistinguishedName $ServiceAccountDistinguishedName -ServiceAccountPassword $ServiceAccountPassword `
            -ServiceAccountCredentialType "password" -Description $Description -NetworkAddress $NetworkAddress -Port $Port `
            -NoSslEncryption:$NoSslEncryption -DoNotVerifyServerSslCertificate:$DoNotVerifyServerSslCertificate
    }
    else
    {
        $local:AdPlatformId = (Find-SafeguardPlatform "Active Directory" -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure)[0].Id
        New-SafeguardAsset -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -DisplayName $ServiceAccountDomainName -Platform $local:AdPlatformId `
            -ServiceAccountName $ServiceAccountName -ServiceAccountDomainName $ServiceAccountDomainName -ServiceAccountPassword $ServiceAccountPassword `
            -ServiceAccountCredentialType "password" -NetworkAddress $ServiceAccountDomainName -Description $Description
    }
}

<#
.SYNOPSIS
Test connection to a directory in Safeguard via the Web API.

.DESCRIPTION
Test the connection to a directory by attempting to determine whether or
not the configured service account can manage passwords for this directory.
This is an asynchronous task in Safeguard.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER DirectoryToTest
An integer containing the ID of the directory to test connection to or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Test-SafeguardDirectory -AccessToken $token -Appliance 10.5.32.54 -Insecure 5

.EXAMPLE
Test-SafeguardDirectory internal.domain.corp
#>
function Test-SafeguardDirectory
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
        [object]$DirectoryToTest
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Test-SafeguardAsset -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetToTest $DirectoryToTest
}

<#
.SYNOPSIS
Remove a directory from Safeguard via the Web API.

.DESCRIPTION
Remove a directory from Safeguard. Make sure it is not in use before
you remove it.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER DirectoryToDelete
An integer containing the ID of the directory to remove or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardDirectory -AccessToken $token -Appliance 10.5.32.54 -Insecure 5

.EXAMPLE
Remove-SafeguardDirectory internal.domain.corp
#>
function Remove-SafeguardDirectory
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
        [object]$DirectoryToDelete
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Remove-SafeguardAsset -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetToDelete $DirectoryToDelete
}

<#
.SYNOPSIS
Edit existing directory in Safeguard via the Web API.

.DESCRIPTION
Edit an existing directory in Safeguard that can be used to manage accounts.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER DirectoryToEdit
An integer containing the ID of the directory to edit or a string containing the name.

.PARAMETER ServiceAccountDomainName
A string containing the service account domain name if it has one.  This is used
for creating AD directories.

.PARAMETER ServiceAccountName
A string containing the service account name.  This is used for creating AD directories.

.PARAMETER ServiceAccountDistinguishedName
A string containing the LDAP distinguished name of a service account.  This is used for
creating LDAP directories.

.PARAMETER ServiceAccountPassword
A SecureString containing the password to use for the service account.

.PARAMETER NetworkAddress
A string containing the network address for this directory.  This is used for creating
LDAP directories.

.PARAMETER Port
An integer containing the port for this directory.  This is used for creating
LDAP directories.

.PARAMETER NoSslEncryption
Do not use SSL encryption for LDAP directory.

.PARAMETER DoNotVerifyServerSslCertificate
Do not verify Server SSL certificate of LDAP directory.

.PARAMETER Description
A string containing a description for this directory.

.PARAMETER DirectoryObject
An object containing the existing directory with desired properties set.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Edit-SafeguardDirectory -AccessToken $token -Appliance 10.5.32.54 -Insecure internal.domain.corp

.EXAMPLE
Edit-SafeguardDirectory ldap.domain.corp -ServiceAccountDistinguishedName "cn=dev-sa,ou=people,dc=ldap,dc=domain,dc=corp" -NoSslEncryption

.EXAMPLE
Edit-SafeguardDirectory -DirectoryObject $obj
#>
function Edit-SafeguardDirectory
{
    [CmdletBinding(DefaultParameterSetName="Attributes")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(ParameterSetName="Attributes",Mandatory=$true,Position=0)]
        [object]$DirectoryToEdit,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$ServiceAccountDomainName,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$ServiceAccountName,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$ServiceAccountDistinguishedName,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [SecureString]$ServiceAccountPassword,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$NetworkAddress,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [int]$Port,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [switch]$NoSslEncryption,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [switch]$DoNotVerifyServerSslCertificate,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$Description,
        [Parameter(ParameterSetName="Object",Mandatory=$true,ValueFromPipeline=$true)]
        [object]$DirectoryObject
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PsCmdlet.ParameterSetName -eq "Object" -and -not $DirectoryObject)
    {
        throw "DirectoryObject must not be null"
    }

    if ($PsCmdlet.ParameterSetName -eq "Attributes")
    {
        if (-not $PSBoundParameters.ContainsKey("DirectoryToEdit"))
        {
            $DirectoryToEdit = (Read-Host "DirectoryToEdit")
        }
        $local:DirectoryId = (Resolve-SafeguardDirectoryId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $DirectoryToEdit)
    }

    if (-not ($PsCmdlet.ParameterSetName -eq "Object"))
    {
        $DirectoryObject = (Get-SafeguardDirectory -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $local:DirectoryId)

        # Connection Properties
        if (-not $DirectoryObject.ConnectionProperties) { $DirectoryObject.ConnectionProperties = @{} }
        if ($PSBoundParameters.ContainsKey("Port")) { $DirectoryObject.ConnectionProperties.Port = $Port }

        if ($PSBoundParameters.ContainsKey("ServiceAccountDomainName")) { $DirectoryObject.ConnectionProperties.ServiceAccountDomainName = $ServiceAccountDomainName }
        if ($PSBoundParameters.ContainsKey("ServiceAccountName")) { $DirectoryObject.ConnectionProperties.ServiceAccountName = $ServiceAccountName }
        if ($PSBoundParameters.ContainsKey("ServiceAccountPassword"))
        {
            $DirectoryObject.ConnectionProperties.ServiceAccountPassword = [System.Net.NetworkCredential]::new("", $ServiceAccountPassword).Password
        }
        if ($PSBoundParameters.ContainsKey("ServiceAccountDistinguishedName")) { $DirectoryObject.ConnectionProperties.ServiceAccountDistinguishedName = $ServiceAccountDistinguishedName }
        if ($NoSslEncryption)
        {
            $DirectoryObject.ConnectionProperties.UseSslEncryption = $false
            $DirectoryObject.ConnectionProperties.VerifySslCertificate = $false
        }
        if ($DoNotVerifyServerSslCertificate)
        {
            $DirectoryObject.ConnectionProperties.VerifySslCertificate = $false
        }

        # Body
        if ($PSBoundParameters.ContainsKey("Description")) { $DirectoryObject.Description = $Description }
        if ($PSBoundParameters.ContainsKey("NetworkAddress")) { $DirectoryObject.NetworkAddress = $NetworkAddress }
    }

    # Need AssetPartitionId to PUT a directory/asset object. Object returned from Directories endpoint does not contain AssetPartitionId property.
    # Get the directory object from Asset endpoint instead
    if(-not $DirectoryObject.AssetPartitionId)
    {
        $AssetObject = (Get-SafeguardAsset -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $DirectoryObject.Id)
        $DirectoryObject | Add-Member -MemberType ScriptProperty -Name 'AssetPartitionId' -Value { $AssetObject.AssetPartitionId }
    }

    Edit-SafeguardAsset -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetObject $DirectoryObject
}

<#
.SYNOPSIS
synchronize an existing directory in Safeguard via the Web API.

.DESCRIPTION
synchronize an existing directory in Safeguard.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER DirectoryToSync
An integer containing the ID of the directory to synchronize or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Sync-SafeguardDirectory -AccessToken $token -Appliance 10.5.32.54 -Insecure 5

.EXAMPLE
Sync-SafeguardDirectory internal.domain.corp
#>
function Sync-SafeguardDirectory
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
        [object]$DirectoryToSync,
        [Parameter(Mandatory=$false,Position=1)]
        [object]$AssetPartition = -1
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Write-Host "Triggering sync for directory: $($local:Directory.Name)"
    Sync-SafeguardDirectoryAsset -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                                 -AssetPartition $AssetPartition -DirectoryAssetToSync $DirectoryToSync
}

<#
.SYNOPSIS
Get accounts on directories managed by Safeguard via the Web API.

.DESCRIPTION
Get accounts on directories managed by Safeguard.  Accounts passwords can be managed,
and Safeguard can be configured to check and change those passwords.  Policy can
be created to allow access to passwords and sessions based on those passwords.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER DirectoryToGet
An integer containing the ID of the directory to get accounts from or a string containing the name.

.PARAMETER AccountToGet
An integer containing the ID of the account to get or a string containing the name.

.PARAMETER Fields
An array of the account property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardDirectoryAccount -AccessToken $token -Appliance 10.5.32.54 -Insecure domain.blah.corp administrator

.EXAMPLE
Get-SafeguardDirectoryAccount -AccountToGet adm-domain-a
#>
function Get-SafeguardDirectoryAccount
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
        [object]$DirectoryToGet,
        [Parameter(Mandatory=$false,Position=1)]
        [object]$AccountToGet,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSBoundParameters.ContainsKey("DirectoryToGet"))
    {
        if ($PSBoundParameters.ContainsKey("AccountToGet"))
        {
            Get-SafeguardAssetAccount -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                -AssetToGet $DirectoryToGet -AccountToGet $AccountToGet -Fields $Fields
        }
        else
        {
            Get-SafeguardAssetAccount -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                -AssetToGet $DirectoryToGet -Fields $Fields
        }
    }
    else
    {
        if ($PSBoundParameters.ContainsKey("AccountToGet"))
        {
            Get-SafeguardAssetAccount -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                -AccountToGet $AccountToGet -Fields $Fields
        }
        else
        {
            # TODO: This is an imperfect solution for now -- need Asset.IsDirectory or Platform.DeviceClass
            # This is sufficient for now.  It really just misses Cisco ISE.
            if ($Fields)
            {
                $Fields += "DomainName"
            }
            (Get-SafeguardAssetAccount -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -Fields $Fields) | Where-Object { $_.DomainName }
        }
    }
}

<#
.SYNOPSIS
Search for a directory account in Safeguard via the Web API.

.DESCRIPTION
Search for a directory account in Safeguard for any string fields containing
the SearchString.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER SearchString
A string to search for in the directory account.

.PARAMETER QueryFilter
A string to pass to the -filter query parameter in the Safeguard Web API.

.PARAMETER Fields
An array of the directory account property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Find-SafeguardDirectoryAccount -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Find-SafeguardDirectoryAccount "-adm"

.EXAMPLE
Find-SafeguardDirectoryAccount -QueryFilter "DirectoryProperties.DomainName eq 'child.sample.net'"
#>
function Find-SafeguardDirectoryAccount
{
    [CmdletBinding(DefaultParameterSetName="Search")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0,ParameterSetName="Search")]
        [string]$SearchString,
        [Parameter(Mandatory=$true,Position=0,ParameterSetName="Query")]
        [string]$QueryFilter,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    # TODO: This is an imperfect solution for now -- need Asset.IsDirectory or Platform.DeviceClass
    # This is sufficient for now.  It really just misses Cisco ISE.
    if ($Fields)
    {
        $Fields += "DomainName"
    }
    if ($PSCmdlet.ParameterSetName -eq "Search")
    {
        (Find-SafeguardAssetAccount -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -Fields $Fields -SearchString $SearchString) `
            | Where-Object { $_.DomainName }
    }
    else
    {
        (Find-SafeguardAssetAccount -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -Fields $Fields -QueryFilter $QueryFilter) `
            | Where-Object { $_.DomainName }
    }

}

<#
.SYNOPSIS
Create a new account on a directory managed by Safeguard via the Web API.

.DESCRIPTION
Create a representation of an account on a managed directory.  Accounts passwords can
be managed, and Safeguard can be configured to check and change those passwords.
Policy can be created to allow access to passwords and sessions based on those passwords.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER ParentDirectory
An integer containing the ID of the directory to get accounts from or a string containing the name.

.PARAMETER NewAccountName
A string containing the name for the account.

.PARAMETER DomainName
A string containing the domain name for the account if different from parent directory.

.PARAMETER DistinguishedName
A string containing the distinguished name of the new account in LDAP.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
New-SafeguardDirectoryAccount -AccessToken $token -Appliance 10.5.32.54 -Insecure blah.corp administrator -DomainName sub.blah.corp

.EXAMPLE
New-SafeguardDirectoryAccount ldap.company.corp administrator -DistinguishedName "cn=administrator,dc=ldap,dc=company,dc=corp"
#>
function New-SafeguardDirectoryAccount
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
        [object]$ParentDirectory,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$NewAccountName,
        [Parameter(Mandatory=$false)]
        [string]$DomainName,
        [Parameter(Mandatory=$false)]
        [string]$DistinguishedName,
        [Parameter(Mandatory=$false)]
        [string]$Description
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    New-SafeguardAssetAccount -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -ParentAsset $ParentDirectory `
        -NewAccountName $NewAccountName -DomainName $DomainName -DistinguishedName $DistinguishedName -Description $Description
}

<#
.SYNOPSIS
Edit an existing account on a directory managed by Safeguard via the Web API.

.DESCRIPTION
Edit an existing directory account in Safeguard.  Accounts passwords can be managed,
and Safeguard can be configured to check and change those passwords.
Policy can be created to allow access to passwords and sessions based
on those passwords.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AccountObject
An object containing the existing asset account with desired properties set.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Edit-SafeguardDirectoryAccount -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Edit-SafeguardDirectoryAccount -AccountObject $obj
#>
function Edit-SafeguardDirectoryAccount
{
    [CmdletBinding(DefaultParameterSetName="Object")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(ParameterSetName="Object",Mandatory=$true)]
        [object]$AccountObject
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PsCmdlet.ParameterSetName -eq "Object" -and -not $AccountObject)
    {
        throw "AccountObject must not be null"
    }
    $AccountObject = Get-SafeguardAssetAccount -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AccountToGet $AccountObject.Id
    Edit-SafeguardAssetAccount -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AccountObject $AccountObject
}

<#
.SYNOPSIS
Set account password inside Safeguard for directory under management via the Web API.

.DESCRIPTION
Set the password in Safeguard for an account on a directory under management.  This
just modifies what is stored in Safeguard.  It does not change the actual password
of the account.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER DirectoryToSet
An integer containing the ID of the directory to set account password on or a string containing the name.

.PARAMETER AccountToSet
An integer containing the ID of the account to set password on or a string containing the name.

.PARAMETER NewPassword
A SecureString containing the new password to set.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Set-SafeguardDirectoryAccountPassword -AccessToken $token -Appliance 10.5.32.54 -Insecure internal.blah.corp administrator

.EXAMPLE
Set-SafeguardDirectoryAccountPassword -AccountToSet oracle -NewPassword $pass
#>
function Set-SafeguardDirectoryAccountPassword
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
        [object]$DirectoryToSet,
        [Parameter(Mandatory=$true,Position=1)]
        [object]$AccountToSet,
        [Parameter(Mandatory=$false,Position=2)]
        [SecureString]$NewPassword
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $NewPassword)
    {
        $NewPassword = (Read-Host -AsSecureString "NewPassword")
    }

    if ($PSBoundParameters.ContainsKey("DirectoryToSet"))
    {
        Set-SafeguardAssetAccountPassword -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -NewPassword $NewPassword -AssetToSet $DirectoryToSet -AccountToSet $AccountToSet
    }
    else
    {
        Set-SafeguardAssetAccountPassword -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -NewPassword $NewPassword -AccountToSet $AccountToSet
    }
}

<#
.SYNOPSIS
Generate a directory account password based on profile via the Web API.

.DESCRIPTION
Generate a directory account password based on profile.  The password is not actually stored in
Safeguard, but it could be stored using Set-SafeguardDirectoryAccountPassword.  This can
be used to facilitate manual password management.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER DirectoryToUse
An integer containing the ID of the directory to generate password for or a string containing the name.

.PARAMETER AccountToUse
An integer containing the ID of the account to generate password for or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
New-SafeguardDirectoryAccountRandomPassword -AccessToken $token -Appliance 10.5.32.54 -Insecure domain.blah.corp administrator

.EXAMPLE
New-SafeguardDirectoryAccountRandomPassword -AccountToUse administrator
#>
function New-SafeguardDirectoryAccountRandomPassword
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
        [object]$DirectoryToUse,
        [Parameter(Mandatory=$true,Position=1)]
        [object]$AccountToUse
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSBoundParameters.ContainsKey("DirectoryToUse"))
    {
        New-SafeguardAssetAccountRandomPassword -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetToUse $DirectoryToUse -AccountToUse $AccountToUse
    }
    else
    {
        New-SafeguardAssetAccountRandomPassword -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AccountToUse $AccountToUse
    }
}

<#
.SYNOPSIS
Run check password on a directory account managed by Safeguard via the Web API.

.DESCRIPTION
Run a task to check whether Safeguard still has the correct password for
an account on a managed directory.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER DirectoryToUse
An integer containing the ID of the directory to check password for or a string containing the name.

.PARAMETER AccountToUse
An integer containing the ID of the account to check password for or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Test-SafeguardDirectoryAccountPassword -AccessToken $token -Appliance 10.5.32.54 -Insecure domain.blah.corp administrator

.EXAMPLE
Test-SafeguardDirectoryAccountPassword -AccountToUse administrator
#>
function Test-SafeguardDirectoryAccountPassword
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
        [object]$DirectoryToUse,
        [Parameter(Mandatory=$true,Position=1)]
        [object]$AccountToUse
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSBoundParameters.ContainsKey("DirectoryToUse"))
    {
        Test-SafeguardAssetAccountPassword -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetToUse $DirectoryToUse -AccountToUse $AccountToUse
    }
    else
    {
        Test-SafeguardAssetAccountPassword -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AccountToUse $AccountToUse
    }
}

<#
.SYNOPSIS
Run change password on a directory account managed by Safeguard via the Web API.

.DESCRIPTION
Run a task to change the password on a directory account managed by Safeguard.  This rotates the
password on the actual directory and stores the new value in Safeguard.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER DirectoryToUse
An integer containing the ID of the directory to change password for or a string containing the name.

.PARAMETER AccountToUse
An integer containing the ID of the account to change password for or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Invoke-SafeguardDomainAccountPasswordChange -AccessToken $token -Appliance 10.5.32.54 -Insecure domain.blah.corp administrator

.EXAMPLE
Invoke-SafeguardDomainAccountPasswordChange -AccountToUse administrator
#>
function Invoke-SafeguardDirectoryAccountPasswordChange
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
        [object]$DirectoryToUse,
        [Parameter(Mandatory=$true,Position=1)]
        [object]$AccountToUse
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSBoundParameters.ContainsKey("DirectoryToUse"))
    {
        Invoke-SafeguardAssetAccountPasswordChange -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetToUse $DirectoryToUse -AccountToUse $AccountToUse
    }
    else
    {
        Invoke-SafeguardAssetAccountPasswordChange -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AccountToUse $AccountToUse
    }
}

<#
.SYNOPSIS
Remove a directory account from Safeguard via the Web API.

.DESCRIPTION
Remove a directory account from Safeguard. Make sure it is not in use before
you remove it.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER DirectoryToUse
An integer containing the ID of the directory to remove the account from or a string containing the name.

.PARAMETER AccountToDelete
An integer containing the ID of the directory account to remove or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardDirectoryAccount -AccessToken $token -Appliance 10.5.32.54 -Insecure 5 23

.EXAMPLE
Remove-SafeguardDirectoryAccount my.domain.com administrator
#>
function Remove-SafeguardDirectoryAccount
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
        [object]$DirectoryToUse,
        [Parameter(Mandatory=$true,Position=1)]
        [object]$AccountToDelete
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSBoundParameters.ContainsKey("DirectoryToUse"))
    {
        Remove-SafeguardAssetAccount -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetToUse $DirectoryToUse -AccountToDelete $AccountToDelete
    }
    else
    {
        Remove-SafeguardAssetAccount -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AccountToDelete $AccountToDelete
    }
}

<#
.SYNOPSIS
Get directory migration data from Safeguard audit log via the Web API.

.DESCRIPTION
Early versions of Safeguard treated directories as a dual entity that was
part identity provider (used for Safeguard user login) and part asset
(used for managing Safeguard accounts).  Safeguard version 2.7 and greater
removed the concept of directories as a dual entity and split them into
identity providers and assets.  This cmdlet will get a report of the migrated
directories and what their new identity provider and asset IDs are.

Use the -Verbose parameter to dsee additional information.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.EXAMPLE
Get-SafeguardDirectoryMigrationData

.EXAMPLE
Get-SafeguardDirectoryMigrationData -Verbose
#>
function Get-SafeguardDirectoryMigrationData
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    Import-Module -Name "$PSScriptRoot\sg-utilities.psm1" -Scope Local

    if (-not (Test-SafeguardMinVersionInternal -Appliance $Appliance -Insecure:$Insecure -MinVersion 2.7))
    {
        throw "Directory migration data is only available for Safeguard version 2.7 and greater"
    }

    $local:DirectoriesCreated = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
        Core GET "AuditLog/ObjectChanges/Directory" -Version 3 `
        -Parameters @{filter = "EventName eq 'DirectoryCreated'"; fields = "LogTime,EventName,ObjectName,ObjectId";
                      startDate = (Get-EntireAuditLogStartDateAsString)})
    Write-Verbose "Directories Created:"
    Write-Verbose ($local:DirectoriesCreated | Format-Table | Out-String)

    $local:DirectoriesDeleted = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
        Core GET "AuditLog/ObjectChanges/Directory" -Version 3 `
        -Parameters @{filter = "EventName eq 'DirectoryDeleted'"; fields = "LogTime,EventName,ObjectName,ObjectId";
                      startDate = (Get-EntireAuditLogStartDateAsString)})
    Write-Verbose "Directories Deleted:"
    Write-Verbose ($local:DirectoriesDeleted | Format-Table | Out-String)

    $local:IdentityProvidersCreated = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
        Core GET "AuditLog/ObjectChanges/IdentityProvider" -Version 3 `
        -Parameters @{filter = "EventName eq 'IdentityProviderCreated'"; fields = "LogTime,EventName,ObjectName,ObjectId";
                      startDate = (Get-EntireAuditLogStartDateAsString)})
    Write-Verbose "Directory Identity Providers Created:"
    Write-Verbose ($local:IdentityProvidersCreated | Format-Table | Out-String)

    $local:DirectoryAssetsCreated = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
        Core GET "AuditLog/ObjectChanges/Asset" -Version 3 `
        -Parameters @{filter = "EventName eq 'AssetCreated' and NewValue contains '`"IsDirectory`":true'";
                      fields = "LogTime,EventName,ObjectName,ObjectId";
                      startDate = (Get-EntireAuditLogStartDateAsString)})
    Write-Verbose "Directory Assets Created:"
    Write-Verbose ($local:DirectoryAssetsCreated | Format-Table | Out-String)

    Write-Verbose "Pruning Deleted Directories..."
    $local:MigratedDirectories = @()
    $local:DirectoriesCreated | ForEach-Object {
        if (-not ($_.ObjectId -in $local:DirectoriesDeleted.ObjectId))
        {
            $local:MigratedDirectories += $_
        }
    }
    Write-Verbose "$($local:DirectoriesCreated.Count - $local:MigratedDirectories.Count) directories pruned from migration data set"

    Write-Verbose "Calculating Directory Migration Data..."
    $local:MigrationData = @()
    $local:IdentityProvidersCreated | ForEach-Object {
        $local:IdentityProvder = $_
        $local:MigratedDirectories | ForEach-Object {
            if ($local:IdentityProvder.ObjectName -eq $_.ObjectName)
            {
                $local:MigrationData += (New-Object PSObject -Property ([ordered]@{
                    SchemaType = "IdentityProvider";
                    Name = $_.ObjectName;
                    OldId = $_.ObjectId;
                    NewId = $local:IdentityProvder.ObjectId
                }))
            }
        }
    }
    $local:DirectoryAssetsCreated | ForEach-Object {
        $local:DirectoryAsset = $_
        $local:MigratedDirectories | ForEach-Object {
            if ($local:DirectoryAsset.ObjectName -eq $_.ObjectName)
            {
                $local:MigrationData += (New-Object PSObject -Property ([ordered]@{
                    SchemaType = "Directory";
                    Name = $_.ObjectName;
                    OldId = $_.ObjectId;
                    NewId = $local:DirectoryAsset.ObjectId
                }))
            }
        }
    }

    $local:MigrationData
}
