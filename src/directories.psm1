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
            $local:Directories = @(Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Assets `
                                       -Parameters @{ filter = "NetworkAddress ieq '$Directory'" })
        }
        if (-not $local:Directories)
        {
            $local:Directories = @(Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Assets `
                                       -Parameters @{ filter = "Domains.DomainName ieq '$Directory'" })
        }
        if (-not $local:Directories)
        {
            throw "Unable to find asset matching '$Directory'"
        }
        if ($local:Directories.Count -ne 1)
        {
            throw "Found $($local:Directories.Count) assets matching '$Directory'"
        }
        $local:Directories[0].Id
    }
    else
    {
        $Directory
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
        [string]$ServiceAccountDomain,
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
                ServiceAccountDomainName = $ServiceAccountDomain;
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

}

function Get-SafeguardDirectoryAccount
{

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
