<#
.SYNOPSIS
Gets Safeguard debug log settings

.DESCRIPTION
Gets Safeguard debug log settings. Debug settings allow you to specify which Safeguard 
services should log to which syslog server, at which log level, and whether to log TLS 
connection details.

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
Get-SafeguardDebugSettings -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Set-SafeguardDebugSettings 
#>
function Get-SafeguardDebugSettings
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

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance GET "Service/Debug"
}

<#
.SYNOPSIS
Sets Safeguard debug log settings

.DESCRIPTION
Sets Safeguard debug log settings. Debug settings allow you to specify which Safeguard 
services should log to which syslog server, at which log level, and whether to log TLS 
connection details. Use Get-SafeguardDebugSettings to get the current settings.

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
Get-SafeguardDebugSettings -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Set-SafeguardDebugSettings 
#>
function Set-SafeguardDebugSettings
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
        [object]$DebugSettings
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance PUT "Service/Debug" -Body $DebugSettings
}

<#
.SYNOPSIS
Enables TLS connection logging in Safeguard debug logs

.DESCRIPTION
Enables TLS connection logging in Safeguard debug logs. Outgoing TLS connections and 
incoming connections will be logged. It is recommended to disable this unless you are
auditing or troubleshooting TLS connections.

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
Enable-SafeguardTlsLogging -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Enable-SafeguardTlsLogging
#>
function Enable-SafeguardTlsLogging
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
    $DebugSettings = Get-SafeguardDebugSettings -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure
    $DebugSettings.NetworkDebugEnabled = $true
    Set-SafeguardDebugSettings $DebugSettings -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure
}

<#
.SYNOPSIS
Disables TLS connection logging in Safeguard debug logs

.DESCRIPTION
Disables TLS connection logging in Safeguard debug logs. Outgoing TLS connections and 
incoming connections will not be logged. It is recommended to disable this unless you are
auditing or troubleshooting TLS connections.

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
Disable-SafeguardTlsLogging -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Disable-SafeguardTlsLogging
#>
function Disable-SafeguardTlsLogging
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
    $DebugSettings = Get-SafeguardDebugSettings -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure
    $DebugSettings.NetworkDebugEnabled = $false
    Set-SafeguardDebugSettings $DebugSettings -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure
}


