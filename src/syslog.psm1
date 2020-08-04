#Helper
function Resolve-SafeguardSyslogServerId
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
        [object]$ToResolve
    )

    $local:RelPath = "SyslogServers"
    $local:ResourceType = "syslog server"
    $local:ErrMsgSuffix = "in $($local:ResourceType)"
    $local:Resources = $null

    if ($ToResolve.Id -as [int])
    {
        $ToResolve = $ToResolve.Id
    }

    if (-not ($ToResolve -as [int]))
    {
        try
        {
            $local:Resources = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" `
                                 -Parameters @{ filter = "Name ieq '$ToResolve'"; fields = "Id" })
            if (-not $local:Resources)
            {
                $local:Resources = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" `
                                     -Parameters @{ filter = "NetworkAddress ieq '$ToResolve'"; fields = "Id" })
            }
        }
        catch
        {
            Write-Verbose $_
            Write-Verbose "Caught exception with ieq filter, trying with q parameter"
            $local:Resources = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" `
                                 -Parameters @{ q = $ToResolve; fields = "Id" })
        }
        if (-not $local:Resources)
        {
            throw "Unable to find $($local:ResourceType) matching '$ToResolve' $($local:ErrMsgSuffix)"
        }
        if ($local:Resources.Count -ne 1)
        {
            throw "Found $($local:Resources.Count) $($local:ResourceType) matching '$ToResolve' $($local:ErrMsgSuffix)"
        }
        $local:Resources[0].Id
    }
    else
    {
        # Make sure it actually exists
        $local:Resources = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" `
            -Parameters @{ filter = "Id eq $ToResolve"; fields = "Id" })
        if (-not $local:Resources)
        {
            throw "Unable to find $($local:ResourceType) matching '$ToResolve' $($local:ErrMsgSuffix)"
        }
        $ToResolve
    }
}

<#
.SYNOPSIS
Returns a list of configured syslog servers

.DESCRIPTION
Returns a list of configured syslog servers

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
Get-SafeguardSyslogServer -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardSyslogServer
#>
function Get-SafeguardSyslogServer
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false, Position=0)]
        [string]$ServerToGet,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:RelPath = "SyslogServers"
    $local:Parameters = $null
    if ($Fields)
    {
        $local:Parameters = @{ fields = ($Fields -join ",")}
    }

    if($PSBoundParameters.ContainsKey("ServerToGet"))
    {
        $local:id = Resolve-SafeguardSyslogServerId $ServerToGet -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure 
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)/$($local:id)" -Parameters $local:Parameters
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" -Parameters $local:Parameters
    }
}

<#
.SYNOPSIS
Configure a new syslog server

.DESCRIPTION
Configure Safeguard with a new syslog server. Syslog servers defined here are
only a reference. Nothing will be sent to the syslog server until you configure
debug logging or event subscribers to use the server. You may configure
more than one server for different uses.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER NetworkAddress
The network address of the syslog server.

.PARAMETER Name
A display name for the syslog server. If omitted, it will default to the
network address.

.PARAMETER Port
The syslog server port. Defaults to 514.

.PARAMETER Protocol
The syslog protocol and format to use. The options are 'LegacyUdp', 'Udp' and 'Tcp'. The
'Udp' and 'Tcp' options use RFC 5424. 'LegacyUdp' uses RFC 3164.

.PARAMETER UseTls
Whether to use TLS when sending messages to the syslog server. This requires that
the server is configured to accept TLS connections. This option is only supported for 
'Tcp' protocol.

.PARAMETER UseClientCertificate
Whether to use client certificate authentication when sending messages to the syslog
server. This requires that the syslog server is configured to accept client certificate
authentication. Implies UseTls. This option is only supported for 'Tcp' protocol.

.PARAMETER VerifyServerCertificate
Whether to validate the TLS certificate presented by the syslog server. Safeguard must
be configured to trust the issuer of the syslog server TLS certificate. Implies UseTls.
This option is only supported for 'Tcp' protocol.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
New-SafeguardSyslogServer -AccessToken $token -Appliance 10.5.32.54 -Insecure "syslog.example.com"

.EXAMPLE
New-SafeguardSyslogServer -NetworkAddress "syslog.example.com" -Name "My Syslog Server" -Port 6514 -Protocol "Tcp" -UseTls $true -UseClientCertificate $true -VerifyServerCertificate $true
#>
function New-SafeguardSyslogServer
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
        [string]$NetworkAddress,
        [Parameter(Mandatory=$false)]
        [string]$Name = $null,
        [Parameter(Mandatory=$false)]
        [int]$Port = 514,
        [Parameter(Mandatory=$false)]
        [string]$Protocol = "LegacyUdp",
        [Parameter(Mandatory=$false)]
        [bool]$UseTls = $false,
        [Parameter(Mandatory=$false)]
        [bool]$UseClientCertificate = $false,
        [Parameter(Mandatory=$false)]
        [bool]$VerifyServerCertificate = $false

    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if([string]::IsNullOrEmpty($Name)) {
        $Name = $NetworkAddress
    }

    if($UseClientCertificate -or $VerifyServerCertificate) {
        $UseTls = $true
    }

    $syslogServer = @{
        Name = $Name;
        NetworkAddress = $NetworkAddress;
        Port = $Port;
        Protocol = $Protocol;
        UseSslEncryption = $UseTls;
        UseClientCertificate = $UseClientCertificate;
        VerifySslCertificate = $VerifyServerCertificate;
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "SyslogServers" -Body $syslogServer
}

<#
.SYNOPSIS
Removes a syslog server configuration from Safeguard.

.DESCRIPTION
Removes a syslog server configuration from Safeguard. If there are other resources
that depend on this syslog server you will receive an API error when trying to remove
the syslog server unless you specify the -Force parameter. If -Force is specified any
resources that depend on this syslog server such as debug logging or event subscribers
will also be removed.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER ServerToRemove
The syslog server object to remove. Can also be specified as the syslog server ID, Name or
NetworkAddress.

.PARAMETER Force
If specified, also remove any resources that depend on this syslog server.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardSyslogServer -AccessToken $token -Appliance 10.5.32.54 -Insecure "My Syslog Server"

.EXAMPLE
Remove-SafeguardSyslogServer 5 -Force
#>
function Remove-SafeguardSyslogServer
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
        [object]$ServerToRemove,
        [Parameter(Mandatory=$false)]
        [switch]$Force
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if($Force)
    {
        $local:ExtraHeaders = @{
            "x-force-delete" = "true";
        }
    }

    $local:id = Resolve-SafeguardSyslogServerId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $ServerToRemove
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "SyslogServers/$($local:id)" -ExtraHeaders $local:ExtraHeaders
}


<#
.SYNOPSIS
Edits an existing syslog server configuration

.DESCRIPTION
Edits an existing syslog server configuration. To get the current configuration
use Get-SafeguardSyslogServer. Modify the properties of the syslog server 
configuration and pass the object as the -SyslogServer parameter.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER SyslogServer
The syslog server object to update.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
$server = Get-SafeguardSyslogServer
PS C:\>$server.NetworkAddress = "new-server.example.com"

PS C:\>Edit-SafeguardSyslogServer -SyslogServer $server

.EXAMPLE
Edit-SafeguardSyslogServer -AccessToken $token -Appliance 10.5.32.54 -Insecure $server
#>
function Edit-SafeguardSyslogServer
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
        [object]$SyslogServer
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:id = Resolve-SafeguardSyslogServerId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $SyslogServer
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance PUT "SyslogServers/$($local:id)" -Body $SyslogServer
}