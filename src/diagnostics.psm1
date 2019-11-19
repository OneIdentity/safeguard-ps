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

.PARAMETER Count
An integer of the number of echo requests to send.

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
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [string]$NetworkAddress,
        [Parameter(Mandatory=$false)]
        [int]$Count = 4
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Timeout = 300
    if (($Count * 3) -gt $local:Timeout)
    {
        $local:Timeout = ($Count * 3)
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance POST NetworkDiagnostics/Ping `
        -Timeout $local:Timeout -Body @{
            NetworkAddress = "$NetworkAddress";
            NumberEchoRequests = $Count
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
    [CmdletBinding()]
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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
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
    [CmdletBinding()]
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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
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
Invoke-SafeguardSessionsTelnet 10.5.33.100

.EXAMPLE
Invoke-SafeguardSessionsTelnet -AccessToken $token -Appliance 10.5.32.54 -Insecure 10.5.33.100
#>
function Invoke-SafeguardSessionsTelnet
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
        [string]$NetworkAddress,
        [Parameter(Mandatory=$true,Position=1)]
        [int]$Port
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance POST NetworkDiagnostics/Sessions/Telnet -Body @{
        NetworkAddress = "$NetworkAddress";
        Port = $Port
    }
}

<#
.SYNOPSIS
Get the currently staged safeguard diagnostic package if any exists

.DESCRIPTION
If no package is currently staged, returns null.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.INPUTS
None.

.OUTPUTS
None.

.EXAMPLE
Get-SafeguardDiagnosticPackage

.EXAMPLE
Get-SafeguardDiagnosticPackage -AccessToken $token -Appliance 10.5.32.54 -Insecure
#>
function Get-SafeguardDiagnosticPackage
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

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance GET DiagnosticPackage
}

<#
.SYNOPSIS
Upload a safeguard diagnostic package .sgd file

.DESCRIPTION
Try to upload a diagnostic package file. Used to diagnose a specific problem with Safeguard.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER PackagePath
A string containing the path to a safeguard diagnostic package file.

.INPUTS
None.

.OUTPUTS
None.

.EXAMPLE
Set-SafeguardDiagnosticPackage .\MyPackage.sgd

.EXAMPLE
Set-SafeguardDiagnosticPackage -AccessToken $token -Appliance 10.5.32.54 -Insecure .\MyPackage.sgd
#>
function Set-SafeguardDiagnosticPackage
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
        [string]$PackagePath
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance POST DiagnosticPackage -InFile $PackagePath
}

<#
.SYNOPSIS
Execute a staged safeguard diagnostic package

.DESCRIPTION
Execute a staged safeguard diagnostic package

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.INPUTS
None.

.OUTPUTS
None.

.EXAMPLE
Invoke-SafeguardDiagnosticPackage

.EXAMPLE
Invoke-SafeguardDiagnosticPackage -AccessToken $token -Appliance 10.5.32.54 -Insecure
#>
function Invoke-SafeguardDiagnosticPackage
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

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance POST DiagnosticPackage/Execute
}

<#
.SYNOPSIS
Download a safeguard diagnostic package log file

.DESCRIPTION
Try to download a diagnostic package log file generated from an uploaded and executed safeguard diagnostic package.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER OutputPath
A string containing the path where the downloaded log file will be saved on the local appliance.

.INPUTS
None.

.OUTPUTS
None.

.EXAMPLE
Get-SafeguardDiagnosticPackageLog MyDiagnostic.log

.EXAMPLE
Get-SafeguardDiagnosticPackageLog -AccessToken $token -Appliance 10.5.32.54 -Insecure MyDiagnostic.log
#>
function Get-SafeguardDiagnosticPackageLog
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
        [string]$OutputPath
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance GET DiagnosticPackage/Log -OutFile $OutputPath
}

<#
.SYNOPSIS
Remove a safeguard diagnostic package

.DESCRIPTION
Remove a safeguard diagnostic package from a safeguard appliance along with any log files it may have generated

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.INPUTS
None.

.OUTPUTS
None.

.EXAMPLE
Clear-SafeguardDiagnosticPackage

.EXAMPLE
Clear-SafeguardDiagnosticPackage -AccessToken $token -Appliance 10.5.32.54 -Insecure
#>
function Clear-SafeguardDiagnosticPackage
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

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance DELETE DiagnosticPackage
}
