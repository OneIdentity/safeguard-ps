# Helpers
function Wait-ForDiagnosticComplete
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
        [int]$Timeout = 600
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Start-Sleep 3 # up front wait to solve new transition timing issues

    $local:StartTime = (Get-Date)
    $local:Status = "Unknown"
    $local:TimeElapsed = 10
    do {
        Write-Progress -Activity "Waiting for Completed Status" -Status "Current: $($local:Status)" -PercentComplete (($local:TimeElapsed / $Timeout) * 100)
        try
        {
            $local:Status = (Get-SafeguardDiagnosticPackageStatus -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure).Status
        }
        catch {}
        Start-Sleep 2
        $local:TimeElapsed = (((Get-Date) - $local:StartTime).TotalSeconds)
        if ($local:TimeElapsed -gt $Timeout)
        {
            throw "Timed out waiting for Completed Status, timeout was $Timeout seconds"
        }
    } until ($local:Status -ieq "Completed")
    Write-Progress -Activity "Waiting for Completed Status" -Status "Current: $($local:Status)" -PercentComplete 100
}

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

.PARAMETER Size
An integer containing the size of the packet to send.

.PARAMETER NoFrag
Whether or not to allow packet fragmentation.

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
        [int]$Count = 4,
        [Parameter(Mandatory=$false)]
        [int]$Size = 0,
        [Parameter(Mandatory=$false)]
        [switch]$NoFrag
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Timeout = 300
    if (($Count * 3) -gt $local:Timeout)
    {
        $local:Timeout = ($Count * 3)
    }

    $local:Body = @{
        NetworkAddress = "$NetworkAddress";
        NumberEchoRequests = $Count
    }

    if ($Size -gt 0) { $local:Body["BufferSize"] = $Size }
    if ($NoFrag) { $local:Body["DontFragmentFlag"] = $true }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance POST NetworkDiagnostics/Ping `
        -Timeout $local:Timeout -Body $local:Body
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

    (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance GET DiagnosticPackage).ManifestData
}

<#
.SYNOPSIS
Get the status of staged safeguard diagnostic package if any exists

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
Get-SafeguardDiagnosticPackageStatus

.EXAMPLE
Get-SafeguardDiagnosticPackageStatus -AccessToken $token -Appliance 10.5.32.54 -Insecure
#>
function Get-SafeguardDiagnosticPackageStatus
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

    (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance GET DiagnosticPackage).StatusData
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

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance POST DiagnosticPackage -InFile $PackagePath -ContentType "application/octet-stream"
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

.PARAMETER NoWait
Specify this flag to continue immediately without waiting for the diagnostic to complete.

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
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [switch]$NoWait = $false
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance POST DiagnosticPackage/Execute

    if (-not $NoWait)
    {
        Write-Host "Waiting for operation to complete..."
        Wait-ForDiagnosticComplete -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure
        Write-Host "Use Get-SafeguardDiagnosticPackageLog to retrieve the output"
    }
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

.PARAMETER OutFile
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
    [CmdletBinding(DefaultParameterSetName="File")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(ParameterSetName="File",Mandatory=$true,Position=0)]
        [string]$OutFile,
        [Parameter(ParameterSetName="StdOut",Mandatory=$false)]
        [switch]$StdOut
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($StdOut)
    {
        $OutFile = $null
    }
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance GET DiagnosticPackage/Log -OutFile $OutFile
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
