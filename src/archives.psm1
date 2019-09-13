# Helper
function Invoke-ArchiveServerSshHostKeyDiscovery
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
        [object]$ArchiveServer,
        [Parameter(Mandatory=$false)]
        [object]$AcceptSshHostKey
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Write-Host "Discovering SSH host key..."
    $local:SshHostKey = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                       POST "ArchiveServers/$($ArchiveServer.Id)/DiscoverSshHostKey")
    $ArchiveServer.SshHostKey = $local:SshHostKey.SshHostKey
    if ($AcceptSshHostKey)
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            PUT "ArchiveServers/$($ArchiveServer.Id)" -Body $ArchiveServer
    }
    else
    {
        if (Show-SshHostKeyPrompt $local:SshHostKey.SshHostKey $local:SshHostKey.Fingerprint)
        {
            Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                PUT "ArchiveServers/$($ArchiveServer.Id)" -Body $ArchiveServer
        }
        else
        {
            throw "SSH host key not accepted"
        }
    }
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

.PARAMETER ArchiveServerId
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
function Get-SafeguardArchiveServer
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
        [int]$ArchiveServerId
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $PSBoundParameters.ContainsKey("ArchiveServerId"))
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET ArchiveServers
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "ArchiveServers/$ArchiveServerId"
    }
}

<#
.SYNOPSIS
Create a new archive server in Safeguard via the Web API.

.DESCRIPTION
Create an archive server in Safeguard that can be used for archiving
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
        [Parameter(Mandatory=$true,Position=0)]
        [string]$NetworkAddress,
        [Parameter(Mandatory=$true,Position=1)]
        [ValidateSet("Smb","Scp","Sftp",IgnoreCase=$true)]
        [string]$TransferProtocol,
        [Parameter(Mandatory=$false)]
        [int]$Port,
        [Parameter(Mandatory=$false)]
        [string]$StoragePath,
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
        [switch]$AcceptSshHostKey = $false
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local
    Import-Module -Name "$PSScriptRoot\datatypes.psm1" -Scope Local

    if (-not $PSBoundParameters.ContainsKey("ServiceAccountCredentialType"))
    {
        $ServiceAccountCredentialType = (Resolve-SafeguardServiceAccountCredentialType)
    }
    

    if (-not $PSBoundParameters.ContainsKey("ServiceAccountPassword"))
    {
        $ServiceAccountPassword = (Read-Host "ServiceAccountPassword" -AsSecureString)
    }
    if (-not $PSBoundParameters.ContainsKey("Port"))
    {
        switch ($TransferProtocol)
        {
            "Smb" { $Port = 445 }
            "Scp" { $Port = 22 }
            "Sftp" { $Port = 22 }
        }
    }
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
    if (-not $PSBoundParameters.ContainsKey("StoragePath") -and $TransferProtocol -eq "Smb")
    {
        $StoragePath = (Read-Host "StoragePath")
    }

    $local:ConnectionProperties = @{
        TransferProtocolType = "$TransferProtocol";
        Port = $Port;
        ServiceAccountCredentialType = $ServiceAccountCredentialType;
        ServiceAccountName = "$ServiceAccountName";
        ServiceAccountPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ServiceAccountPassword))
    }

    if ($PSBoundParameters.ContainsKey("ServiceAccountDomainName"))
    {
        $ConnectionProperties.ServiceAccountDomainName = "$ServiceAccountDomainName"
    }

    $local:Body = @{
        Name = "$DisplayName";
        Description = "$Description";
        NetworkAddress = "$NetworkAddress";
        StoragePath = "$StoragePath";
        ConnectionProperties = $local:ConnectionProperties
    }

    $local:NewArchiveServer = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                             POST ArchiveServers -Body $local:Body)
    try
    {
        if ($TransferProtocol -ieq "Scp" -or $TransferProtocol -ieq "Sftp")
        {
            Invoke-ArchiveServerSshHostKeyDiscovery -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $local:NewArchiveServer -AcceptSshHostKey:$AcceptSshHostKey
        }
        else
        {
            $local:NewArchiveServer
        }
    }
    catch
    {
        Write-Host -ForegroundColor Yellow "Error setting up SSH host key, removing archive server..."
        Remove-SafeguardArchiveServer  -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $local:NewArchiveServer.Id
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
An integer containing the ID of the archive server to test connection to.

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
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [int]$ArchiveServerId
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $PSBoundParameters.ContainsKey("ArchiveServerId"))
    {
        $local:AllArchiveServers = (Get-SafeguardArchiveServer -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure)
        Write-Host "Archive servers:"
        Write-Host "["
        $local:AllArchiveServers | ForEach-Object {
            Write-Host ("    {0,2} - {1}" -f $_.Id,$_.Name)
        }
        Write-Host "]"
        $ArchiveServerId = (Read-Host "ArchiveServerId")
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
        POST "ArchiveServers/$ArchiveServerId/TestConnection" -LongRunningTask
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
An integer containing the ID of archive server to remove.

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
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [int]$ArchiveServerId
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $PSBoundParameters.ContainsKey("ArchiveServerId"))
    {
        $local:AllArchiveServers = (Get-SafeguardArchiveServer -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure)
        Write-Host "Archive servers:"
        Write-Host "["
        $local:AllArchiveServers | ForEach-Object {
            Write-Host ("    {0,2} - {1}" -f $_.Id,$_.Name)
        }
        Write-Host "]"
        $ArchiveServerId = (Read-Host "ArchiveServerId")
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
        DELETE "ArchiveServers/$ArchiveServerId"
}

<#
.SYNOPSIS
Edit an archive server that has been added to Safeguard via the Web API.

.DESCRIPTION
Edit an archive server to change properties.  Accept as parameters either an object that as
been modified or an ID and the properties to change.

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
A string containing the protocol (options: Smb, Scp, Sftp).

.PARAMETER Port
An integer containing the port for this archive server (defaults: Smb=445, Scp=22, Sftp=22).

.PARAMETER StoragePath
A string containing the path on the archive server to use for storage.

.PARAMETER ServiceAccountDomainName
A string containing the service account domain name if it has one.

.PARAMETER ServiceAccountName
A string containing the service account name.

.PARAMETER ServiceAccountPassword
A SecureString containing the password to use for the service account.

.PARAMETER AcceptSshHostKey
Whether or not to auto-accept SSH host key for Scp and Sftp.

.PARAMETER ArchiveServerObject
An object containing the existing archive server with desired properties set.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Edit-SafeguardArchiveServer -AccessToken $token -Appliance 10.5.32.54 -Insecure 10 -TransferProtocol Sftp

.EXAMPLE
Edit-SafeguardArchiveServer 10 -DisplayName "linux-ubuntu" -Description "My Linux Archive Server"
#>
function Edit-SafeguardArchiveServer
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
        [int]$ArchiveServerId,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$DisplayName,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$Description,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$NetworkAddress,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [ValidateSet("Smb","Scp","Sftp",IgnoreCase=$true)]
        [string]$TransferProtocol,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [int]$Port,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$StoragePath,
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
        [switch]$AcceptSshHostKey = $false,
        [Parameter(ParameterSetName="Object",Mandatory=$true,ValueFromPipeline=$true)]
        [object]$ArchiveServerObject
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local

    if ($PsCmdlet.ParameterSetName -eq "Object" -and -not $ArchiveServerObject)
    {
        throw "ArchiveServerObject must not be null"
    }

    if ($PsCmdlet.ParameterSetName -eq "Attributes" -and -not $PSBoundParameters.ContainsKey("ArchiveServerId"))
    {
        $local:AllArchiveServers = (Get-SafeguardArchiveServer -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure)
        Write-Host "Archive servers:"
        Write-Host "["
        $local:AllArchiveServers | ForEach-Object {
            Write-Host ("    {0,2} - {1}" -f $_.Id,$_.Name)
        }
        Write-Host "]"
        $ArchiveServerId = (Read-Host "ArchiveServerId")
    }

    if (-not ($PsCmdlet.ParameterSetName -eq "Object"))
    {
        $ArchiveServerObject = (Get-SafeguardArchiveServer -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $ArchiveServerId)

        # ConnectionProperties
        if (-not $ArchiveServerObject.ConnectionProperties) { $ArchiveServerObject.ConnectionProperties = @{} }
        if ($PSBoundParameters.ContainsKey("TransferProtocol"))
        {
            $local:OldTransferProtocol = $ArchiveServerObject.ConnectionProperties.TransferProtocolType
            if ($TransferProtocol -ieq "Scp" -or $TransferProtocol -ieq "Sftp")
            {
                if (-not ($local:OldTransferProtocol -ieq "Scp" -or $local:OldTransferProtocol -ieq "Sftp"))
                {
                    $local:DoSshHostKeyDiscovery = $true
                }
            }
            else
            {
                $ArchiveServerObject.SshHostKey = $null
            }
            $ArchiveServerObject.ConnectionProperties.TransferProtocolType = "$TransferProtocol"
        }
        if ($PSBoundParameters.ContainsKey("Port")) { $ArchiveServerObject.ConnectionProperties.Port = $Port }
        if ($PSBoundParameters.ContainsKey("ServiceAccountCredentialType")) { $ArchiveServerObject.ConnectionProperties.ServiceAccountCredentialType = "$ServiceAccountCredentialType" }
        if ($PSBoundParameters.ContainsKey("ServiceAccountDomainName")) { $ArchiveServerObject.ConnectionProperties.ServiceAccountDomainName = "$ServiceAccountDomainName" }
        if ($PSBoundParameters.ContainsKey("ServiceAccountName")) { $ArchiveServerObject.ConnectionProperties.ServiceAccountName = "$ServiceAccountName" }
        if ($PSBoundParameters.ContainsKey("ServiceAccountPassword"))
        {
            $ArchiveServerObject.ConnectionProperties.ServiceAccountName = `
                [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ServiceAccountPassword))
        }
        # Body
        if ($PSBoundParameters.ContainsKey("DisplayName")) { $ArchiveServerObject.Name = "$DisplayName" }
        if ($PSBoundParameters.ContainsKey("Description")) { $ArchiveServerObject.Description = "$Description" }
        if ($PSBoundParameters.ContainsKey("NetworkAddress")) { $ArchiveServerObject.NetworkAddress = "$NetworkAddress" }
        if ($PSBoundParameters.ContainsKey("StoragePath")) { $ArchiveServerObject.StoragePath = "$StoragePath" }
    }
    $ArchiveServerObject = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                                PUT "ArchiveServers/$($ArchiveServerObject.Id)" -Body $ArchiveServerObject)
    try
    {
        if ($local:DoSshHostKeyDiscovery)
        {
            Invoke-ArchiveServerSshHostKeyDiscovery -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $ArchiveServerObject -AcceptSshHostKey:$AcceptSshHostKey
        }
        else
        {
            $ArchiveServerObject
        }
    }
    catch
    {
        Write-Host -ForegroundColor Yellow "Error setting up SSH host key, resetting to previous transfer protocol '$($local:OldTransferProtocol)'..."
        $local:DoSshHostKeyDiscovery = $false
        Edit-SafeguardArchiveServer -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $ArchiveServerObject.Id -TransferProtocol $local:OldTransferProtocol
        throw
    }
}
