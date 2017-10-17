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
        $local:Directories = @(Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Directories `
                                   -Parameters @{ filter = "Name ieq '$Directory'" })
        if (-not $local:Directories)
        {
            $local:Directories = @(Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Directories `
                                       -Parameters @{ filter = "NetworkAddress ieq '$Directory'" })
        }
        if (-not $local:Directories)
        {
            $local:Directories = @(Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Directories `
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
        $local:Accounts = @(Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET $local:RelativeUrl `
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


function New-SafeguardDirectoryAccount
{
}


function Edit-SafeguardDirectoryAccount
{

}

function Set-SafeguardDirectoryAccountPassword
{
}

function New-SafeguardDirectoryAccountRandomPassword
{

}

function Test-SafeguardDirectoryAccountPassword
{
}

function Invoke-SafeguardDirectoryAccountPasswordChange
{

}
