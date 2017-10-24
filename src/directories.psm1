# Helper
function Resolve-SafeguardDirectoryId
{
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

    if (-not ($Directory -as [int]))
    {
        $local:Directories = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Directories `
                                                     -Parameters @{ filter = "Name ieq '$Directory'" })
        if (-not $local:Directories)
        {
            $local:Directories = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Directories `
                                                         -Parameters @{ filter = "NetworkAddress ieq '$Directory'" })
        }
        if (-not $local:Directories)
        {
            $local:Directories = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Directories `
                                                         -Parameters @{ filter = "Domains.DomainName ieq '$Directory'" })
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

    $ErrorActionPreference = "Stop"

    if (-not ($Account -as [int]))
    {
        if ($PSBoundParameters.ContainsKey("DirectoryId"))
        {
            $local:RelativeUrl = "Directories/$DirectoryId/Accounts"
        }
        else
        {
            $local:RelativeUrl = "DirectoryAccounts"
        }
        $local:Accounts = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET $local:RelativeUrl `
                                                  -Parameters @{ filter = "Name ieq '$Account'" })
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

    $ErrorActionPreference = "Stop"

    if ($PSBoundParameters.ContainsKey("DirectoryToGet"))
    {
        $local:DirectoryId = Resolve-SafeguardDirectoryId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $DirectoryToGet
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Directories/$($local:DirectoryId)"
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Directories
    }
}

<#
.SYNOPSIS
Create new directory in Safeguard via the Web API.

.DESCRIPTION
Create a new directory in Safeguard that can be used to manage accounts and
enables the creation of Safeguard users from that directory.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

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
        [Parameter(Mandatory=$true,ParameterSetName="Ad",Position=0)]
        [string]$ServiceAccountDomainName,
        [Parameter(Mandatory=$true,ParameterSetName="Ad",Position=1)]
        [string]$ServiceAccountName,
        [Parameter(Mandatory=$true,ParameterSetName="Ldap",Position=0)]
        [string]$ServiceAccountDistinguishedName,
        [Parameter(Mandatory=$false,ParameterSetName="Ad",Position=2)]
        [Parameter(Mandatory=$false,ParameterSetName="Ldap",Position=1)]
        [SecureString]$ServiceAccountPassword,
        [Parameter(Mandatory=$false,ParameterSetName="Ldap")]
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

    $ErrorActionPreference = "Stop"
    Import-Module -Name "$PSScriptRoot\datatypes.psm1" -Scope Local

    if (-not $PSBoundParameters.ContainsKey("ServiceAccountPassword"))
    {
        $ServiceAccountPassword = (Read-Host -AsSecureString "ServiceAccountPassword")
    }

    if ($PSCmdlet.ParameterSetName -eq "Ldap")
    {
        $local:LdapPlatformId = (Find-SafeguardPlatform "OpenLDAP")[0].Id
        $local:Body = @{
            PlatformId = $local:LdapPlatformId;
            ConnectionProperties = @{
                UseSslEncryption = $true;
                VerifySslCertificate = $true;
                ServiceAccountDistinguishedName = $ServiceAccountDistinguishedName;
                ServiceAccountPassword = `
                    [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ServiceAccountPassword))
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
        $local:AdPlatformId = (Find-SafeguardPlatform "Active Directory")[0].Id
        $local:Body = @{
            PlatformId = $local:AdPlatformId;
            ConnectionProperties = @{
                ServiceAccountDomainName = $ServiceAccountDomainName;
                ServiceAccountName = $ServiceAccountName;
                ServiceAccountPassword = `
                    [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ServiceAccountPassword))
            }
        }
    }
    if ($PSBoundParameters.ContainsKey("Description"))
    {
        $local:Body.Description = $Description
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST Directories -Body $local:Body
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
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [object]$DirectoryToTest
    )

    $ErrorActionPreference = "Stop"

    if (-not $PSBoundParameters.ContainsKey("DirectoryToTest"))
    {
        $DirectoryToTest = (Read-Host "DirectoryToTest")
    }
    $local:DirectoryId = Resolve-SafeguardDirectoryId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $DirectoryToTest

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
        POST "Directories/$($local:DirectoryId)/TestConnection" -LongRunningTask
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

    $ErrorActionPreference = "Stop"

    if (-not $PSBoundParameters.ContainsKey("DirectoryToDelete"))
    {
        $DirectoryToDelete = (Read-Host "DirectoryToDelete")
    }

    $local:DirectoryId = Resolve-SafeguardDirectoryId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $DirectoryToDelete
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "Directories/$($local:DirectoryId)"
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
        [Parameter(ParameterSetName="Attributes",Mandatory=$false,Position=0)]
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
        $local:DirectoryId = Resolve-SafeguardDirectoryId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $DirectoryToEdit
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
            $DirectoryObject.ConnectionProperties.ServiceAccountPassword = `
                [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ServiceAccountPassword))
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

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "Directories/$($DirectoryObject.Id)" -Body $DirectoryObject
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
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [object]$DirectoryToSync
    )

    $ErrorActionPreference = "Stop"

    if (-not $PSBoundParameters.ContainsKey("DirectoryToSync"))
    {
        $DirectoryToSync = (Read-Host "DirectoryToSync")
    }

    $local:Directory = Get-SafeguardDirectory -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $DirectoryToSync
    Write-Host "Triggered sync for directory: $($local:Directory.Name)"
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "Directories/$($local:Directory.Id)/Synchronize"
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
        [object]$AccountToGet
    )

    $ErrorActionPreference = "Stop"

    if ($PSBoundParameters.ContainsKey("DirectoryToGet"))
    {
        $local:DirectoryId = (Resolve-SafeguardDirectoryId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $DirectoryToGet)
        if ($PSBoundParameters.ContainsKey("DirectoryToGet"))
        {
            $local:AccountId = (Resolve-SafeguardDirectoryAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -DirectoryId $local:DirectoryId $AccountToGet)
            Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "DirectoryAccounts/$($local:AccountId)"
        }
        else
        {
            Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Directories/$($local:DirectoryId)/Accounts"
        }
    }
    else
    {
        if ($PSBoundParameters.ContainsKey("AccountToGet"))
        {
            $local:AccountId = (Resolve-SafeguardDirectoryAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AccountToGet)
            Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "DirectoryAccounts/$($local:AccountId)"
        }
        else
        {
            Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "DirectoryAccounts"
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

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Find-SafeguardDirectoryAccount -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Find-SafeguardDirectoryAccount "-adm"
#>
function Find-SafeguardDirectoryAccount
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

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "DirectoryAccounts" `
        -Parameters @{ q = $SearchString }
}

<#
.SYNOPSIS
Create a new account on an directory managed by Safeguard via the Web API.

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
        [string]$DistinguishedName
    )

    $ErrorActionPreference = "Stop"

    $local:Directory = (Get-SafeguardDirectory -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $ParentDirectory)

    $local:Body = @{
        "Name" = $NewAccountName;
        "DirectoryProperties" = @{
            "DirectoryId" = $local:Directory.Id;
        }
    }

    if ($PSBoundParameters.ContainsKey("DomainName"))
    {
        $local:Body.DirectoryProperties.DomainName = $DomainName
    }
    elseif ($PSBoundParameters.ContainsKey("DistinguishedName"))
    {
        $local:Body.DirectoryProperties.DistinguishedName = $DistinguishedName
    }
    else
    {
        if ($ParentDirectory -as [string])
        {
            $local:MatchedDomain = ($local:Directory.Domains | Where-Object { $_.DomainName -ieq ([string]$ParentDirectory) })
        }
        if ($local:MatchedDomain)
        {
            $local:Body.DirectoryProperties.DomainName = $local:MatchedDomain.DomainName
        }
        else
        {
            $local:Body.DirectoryProperties.DomainName = $local:Directory.Domains[0].DomainName
        }
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "DirectoryAccounts" -Body $local:Body
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

    $ErrorActionPreference = "Stop"

    if ($PSBoundParameters.ContainsKey("DirectoryToSet"))
    {
        $local:DirectoryId = (Resolve-SafeguardDirectoryId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $DirectoryToSet)
        $local:AccountId = (Resolve-SafeguardDirectoryAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -DirectoryId $local:DirectoryId $AccountToSet)
    }
    else
    {
        $local:AccountId = (Resolve-SafeguardDirectoryAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AccountToSet)
    }
    if (-not $NewPassword)
    {
        $NewPassword = (Read-Host -AsSecureString "NewPassword")
    }
    $local:PasswordPlainText = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($NewPassword))
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "DirectoryAccounts/$($local:AccountId)/Password" `
        -Body $local:PasswordPlainText
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

    $ErrorActionPreference = "Stop"

    if ($PSBoundParameters.ContainsKey("DirectoryToUse"))
    {
        $local:DirectoryId = (Resolve-SafeguardDirectoryId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $DirectoryToUse)
        $local:AccountId = (Resolve-SafeguardDirectoryAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -DirectoryId $local:DirectoryId $AccountToUse)
    }
    else
    {
        $local:AccountId = (Resolve-SafeguardDirectoryAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AccountToUse)
    }
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "DirectoryAccounts/$($local:AccountId)/GeneratePassword"
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

    if ($PSBoundParameters.ContainsKey("DirectoryToUse"))
    {
        $local:DirectoryId = (Resolve-SafeguardDirectoryId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $DirectoryToUse)
        $local:AccountId = (Resolve-SafeguardDirectoryAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -DirectoryId $local:DirectoryId $AccountToUse)
    }
    else
    {
        $local:AccountId = (Resolve-SafeguardDirectoryAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AccountToUse)
    }
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "DirectoryAccounts/$($local:AccountId)/CheckPassword" -LongRunningTask
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

    if ($PSBoundParameters.ContainsKey("DirectoryToUse"))
    {
        $local:DirectoryId = (Resolve-SafeguardDirectoryId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $DirectoryToUse)
        $local:AccountId = (Resolve-SafeguardDirectoryAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -DirectoryId $local:DirectoryId $AccountToUse)
    }
    else
    {
        $local:AccountId = (Resolve-SafeguardDirectoryAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AccountToUse)
    }
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "DirectoryAccounts/$($local:AccountId)/ChangePassword" -LongRunningTask
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

    $ErrorActionPreference = "Stop"

    if ($PSBoundParameters.ContainsKey("DirectoryToUse"))
    {
        $local:DirectoryId = (Resolve-SafeguardDirectoryId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $DirectoryToUse)
        $local:AccountId = (Resolve-SafeguardDirectoryAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -DirectoryId $local:DirectoryId $AccountToDelete)
    }
    else
    {
        $local:AccountId = (Resolve-SafeguardDirectoryAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AccountToDelete)
    }
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "DirectoryAccounts/$($local:AccountId)"
}
