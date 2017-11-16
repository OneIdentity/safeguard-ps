<#
.SYNOPSIS
Ping a network address from a Safeguard appliance via the Web API.

.DESCRIPTION
Try to ping a network address from Safeguard. Used to diagnose connectivity
problems from Safeguard.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER NetworkAddress
A string containing the network address of the host to try to ping.

.INPUTS
None.

.OUTPUTS
String output from ping command.

.EXAMPLE
Invoke-SafeguardPing 10.5.33.100

.EXAMPLE
Invoke-SafeguardPing -AccessToken $token -Appliance 10.5.32.54 -Insecure 10.5.33.100
#>
function Invoke-SafeguardPing
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [string]$NetworkAddress
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance POST NetworkDiagnostics/Ping -Body @{
        NetworkAddress = "$NetworkAddress"
    }
}

<#
.SYNOPSIS
Ping a network address from a Safeguard appliance sessions module via the Web API.

.DESCRIPTION
Try to ping a network address from the Safeguard sessios module. Used to diagnose connectivity
problems from Safeguard for connecting privileged sessions.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER NetworkAddress
A string containing the network address of the host to try to ping.

.INPUTS
None.

.OUTPUTS
String output from ping command.

.EXAMPLE
Invoke-SafeguardSessionsPing 10.5.33.100

.EXAMPLE
Invoke-SafeguardSessionsPing -AccessToken $token -Appliance 10.5.32.54 -Insecure 10.5.33.100
#>
function Invoke-SafeguardSessionsPing
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [string]$NetworkAddress
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance POST NetworkDiagnostics/Sessions/Ping -Body @{
        NetworkAddress = "$NetworkAddress"
    }
}

<#
.SYNOPSIS
Telnet to a network address and port from a Safeguard appliance via the Web API.

.DESCRIPTION
Try to connect to a network address and port from Safeguard. Used to diagnose
connectivity problems from Safeguard.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER NetworkAddress
A string containing the network address of the host to connect to.

.PARAMETER Port
An integer containing the port of the host to connect to.

.INPUTS
None.

.OUTPUTS
String output from ping command.

.EXAMPLE
Invoke-SafeguardTelnet 10.5.33.100 22

.EXAMPLE
Invoke-SafeguardTelnet -AccessToken $token -Appliance 10.5.32.54 -Insecure 10.5.33.100 22
#>
function Invoke-SafeguardTelnet
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [string]$NetworkAddress,
        [Parameter(Mandatory=$true,Position=1)]
        [int]$Port
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance POST NetworkDiagnostics/Telnet -Body @{
        NetworkAddress = "$NetworkAddress";
        Port = $Port
    }
}

<#
.SYNOPSIS
Telnet to a network address and port from a Safeguard appliance sessions module via the Web API.

.DESCRIPTION
Try to connect to a network address and port from the Safeguard sessios module. Used to diagnose
connectivity problems from Safeguard.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER NetworkAddress
A string containing the network address of the host to try to ping.

.PARAMETER Port
An integer containing the port of the host to connect to.

.INPUTS
None.

.OUTPUTS
String output from ping command.

.EXAMPLE
Invoke-SafeguardSessionsPing 10.5.33.100

.EXAMPLE
Invoke-SafeguardSessionsPing -AccessToken $token -Appliance 10.5.32.54 -Insecure 10.5.33.100
#>
function Invoke-SafeguardSessionsTelnet
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [string]$NetworkAddress,
        [Parameter(Mandatory=$true,Position=1)]
        [int]$Port
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance POST NetworkDiagnostics/Sessions/Telnet -Body @{
        NetworkAddress = "$NetworkAddress";
        Port = $Port
    }
}
