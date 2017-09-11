<#
.SYNOPSIS
Get archive servers defined in Safeguard via the Web API.

.DESCRIPTION
Get the archive servers defined in Safeguard that can be used for archiving
backups and session recordings.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardArchiveServer -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardArchiveServer
#>
function Get-SafeguardArchiveServer
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure
    )

    $ErrorActionPreference = "Stop"

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET ArchiveServers
}

<#
.SYNOPSIS
Get archive servers defined in Safeguard via the Web API.

.DESCRIPTION
Get the archive servers defined in Safeguard that can be used for archiving
backups and session recordings.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER DisplayName
A string containing the display name for this archive server. Optional, unless
NetworkAddress is an IP address rather than a DNS name.

.PARAMETER Description
A string containing a description for this archive server.

.PARAMETER NetworkAddress
A string containing the network address for this archive server.

.PARAMETER TransferProtocol
A string containing the protocol (options: Smb, Scp, Sftp)

.PARAMETER Port
An integer containing the port for this archive server (defaults: Smb=445, Scp=22, Sftp=22)

.PARAMETER StoragePath
A string containing the path on the archive server to use for storage.

.PARAMETER ServiceAccountDomainName
A string containing the service account domain name if it has one.

.PARAMETER ServiceAccountName
A string containing the service account name.

.PARAMETER ServiceAccountPassword
A SecureString containing the password to use for the service account

.PARAMETER AcceptSshHostKey
Whether or not to auto-accept SSH host key for Scp and Sftp.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
New-SafeguardArchiveServer -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
New-SafeguardArchiveServer smb1.domain.corp Smb -Domain domain.corp archie -StoragePath archives
#>
function New-SafeguardArchiveServer
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
        [Parameter(Mandatory=$true,Position=1)]
        [ValidateSet("Smb","Scp","Sftp",IgnoreCase=$true)]
        [string]$TransferProtocol,
        [Parameter(Mandatory=$false)]
        [int]$Port,
        [Parameter(Mandatory=$false)]
        [string]$StoragePath,
        [Parameter(Mandatory=$true)]
        [ValidateSet("None","Password","SshKey","DirectoryPassword","LocalHostPassword","AccessKey","AccountPassword")]
        [string]$ServiceAccountCredentialType,
        [Parameter(Mandatory=$false)]
        [string]$ServiceAccountDomainName,
        [Parameter(Mandatory=$true,Position=2)]
        [string]$ServiceAccountName,
        [Parameter(Mandatory=$false,Position=3)]
        [SecureString]$ServiceAccountPassword,
        [Parameter(Mandatory=$false)]
        [switch]$AcceptSshHostKey = $false
    )

    $ErrorActionPreference = "Stop"
    Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local

    if (-not $ServiceAccountPassword)
    {
        $ServiceAccountPassword = (Read-Host "ServiceAccountPassword" -AsSecureString)
    }
    if (-not $Port)
    {
        switch ($TransferProtocol)
        {
            "Smb" { $Port = 445 }
            "Scp" { $Port = 22 }
            "Sftp" { $Port = 22 }
        }
    }
    if (-not $DisplayName)
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
    if (-not $StoragePath -and $TransferProtocol -eq "Smb")
    {
        $StoragePath = (Read-Host "StoragePath")
    }

    $ConnectionProperties = @{
        TransferProtocolType = "$TransferProtocol";
        Port = $Port;
        ServiceAccountCredentialType = $ServiceAccountCredentialType;
        ServiceAccountName = "$ServiceAccountName";
        ServiceAccountPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ServiceAccountPassword))
    }

    if ($ServiceAccountDomainName)
    {
        $ConnectionProperties["ServiceAccountDomainName"] = "$ServiceAccountDomainName"
    }

    $Body = @{
        Name = "$DisplayName";
        Description = "$Description";
        NetworkAddress = "$NetworkAddress";
        StoragePath = "$StoragePath";
        ConnectionProperties = $ConnectionProperties
    }

    $NewArchiveServer = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                             POST ArchiveServers -Body $Body)

    try
    {
        if ($TransferProtocol -ieq "Scp" -or $TransferProtocol -ieq "Sftp")
        {
            Write-Host "Discovering SSH host key..."
            $SshHostKey = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                               POST "ArchiveServers/$($NewArchiveServer.Id)/DiscoverSshHostKey")
            $NewArchiveServer.SshHostKey = $SshHostKey.SshHostKey
            if ($AcceptSshHostKey)
            {
                Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                    PUT "ArchiveServers/$($NewArchiveServer.Id)" -Body $NewArchiveServer
            }
            else
            {
                if (Show-SshHostKeyPrompt $SshHostKey.SshHostKey $SshHostKey.Fingerprint)
                {
                    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                        PUT "ArchiveServers/$($NewArchiveServer.Id)" -Body $NewArchiveServer
                }
                else
                {
                    throw "SSH host key not accepted"
                }
            }
        }
        else
        {
            $NewArchiveServer
        }
    }
    catch
    {
        Write-Host -ForegroundColor Yellow "Error setting up SSH host key, removing archive server..."
        Remove-SafeguardArchiveServer  -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $NewArchiveServer.Id
        throw
    }
}

<#
.SYNOPSIS
Test connection to an archive server defined in Safeguard via the Web API.

.DESCRIPTION
Test the connection to an archive server by attempting to copy an empty file
to it.  This is an asynchronous task in Safeguard.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER ArchiveServerId
An integer containing the archive server ID to test connection to.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Test-SafeguardArchiveServer -AccessToken $token -Appliance 10.5.32.54 -Insecure 5

.EXAMPLE
Test-SafeguardArchiveServer 5
#>
function Test-SafeguardArchiveServer
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [int]$ArchiveServerId
    )

    $ErrorActionPreference = "Stop"

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
        POST "ArchiveServers/$ArchiveServerId/TestConnection"
}

<#
.SYNOPSIS
Remove an archive server from Safeguard via the Web API.

.DESCRIPTION
Remove an archive server from Safeguard.  Archive servers are used to
archive backups and session recordings.  Make sure it is not in use before
you remove it.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER ArchiveServerId
An integer containing the archive server ID to remove.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardArchiveServer -AccessToken $token -Appliance 10.5.32.54 -Insecure 5

.EXAMPLE
Remove-SafeguardArchiveServer 5
#>
function Remove-SafeguardArchiveServer
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [int]$ArchiveServerId
    )

    $ErrorActionPreference = "Stop"

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
        DELETE "ArchiveServers/$ArchiveServerId"
}

# Use parameter sets here to also allow editing the object rather than tons of individual attributes
# Do we support partial attributes?
function Edit-SafeguardArchiveServer
{

}