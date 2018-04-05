# Helper
function Test-SupportForClusterPatch
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Version = (Get-SafeguardVersion -Appliance $Appliance -Insecure:$Insecure)
    if ($local:Version.Major -gt 2 -or ($local:Version.Major -eq 2 -and $local:Version.Minor -gt 0))
    {
        $true
    }
    else
    {
        $false
    }
}

<#
.SYNOPSIS
Get the current status of Safeguard appliance via the Web API.

.DESCRIPTION
Get the current status of Safeguard appliance which will include version
information, current state, previous state, maintenance status, cluster
status, and primary appliance IP address.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardStatus

.EXAMPLE
Get-SafeguardStatus -Appliance 10.5.32.54 -Insecure
#>
function Get-SafeguardStatus
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -Anonymous -Appliance $Appliance -Insecure:$Insecure Notification GET Status
}

<#
.SYNOPSIS
Get the version of a Safeguard appliance via the Web API.

.DESCRIPTION
Get the version information from a Safeguard appliance which will 
be returned as an object containing major.minor.revision.build
portions separated into different properties.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardVersion

.EXAMPLE
Get-SafeguardVersion -Appliance 10.5.32.54 -Insecure
#>
function Get-SafeguardVersion
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -Anonymous -Appliance $Appliance -Insecure:$Insecure Appliance GET Version
}

<#
.SYNOPSIS
Get the system verification information on a Safeguard appliance via the Web API.

.DESCRIPTION
System verification information about a Safeguard appliance used during
manufacturing.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardApplianceVerification

.EXAMPLE
Get-SafeguardApplianceVerification -Appliance 10.5.32.54 -Insecure
#>
function Get-SafeguardApplianceVerification
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -Anonymous -Appliance $Appliance -Insecure:$Insecure Notification GET SystemVerification/Manufacturing
}

<#
.SYNOPSIS
Get the current time on a Safeguard appliance via the Web API.

.DESCRIPTION
Get the current time on a Safeguard appliance which will be returned in
UTC format, e.g. 2017-09-07T19:11:37.2995203Z

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardTime

.EXAMPLE
Get-SafeguardTime -Appliance 10.5.32.54 -Insecure
#>
function Get-SafeguardTime
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -Anonymous -Appliance $Appliance -Insecure:$Insecure Appliance GET SystemTime
}

<#
.SYNOPSIS
Get the current health of Safeguard appliance via the Web API.

.DESCRIPTION
Get the current health of Safeguard appliance which will include several
components: AuditLog, ClusterCommunication, ClusterConnectivity, AccessWorkflow,
PolicyData.  Additional information is provided about NetworkInformation,
ResourceUsage, Uptime, Version, and ApplianceState.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER ForceUpdate
Force health checks to run and wait to get up-to-date information.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardHealth

.EXAMPLE
Get-SafeguardHealth -Appliance 10.5.32.54 -AccessToken $token -Insecure
#>
function Get-SafeguardHealth
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
        [switch]$ForceUpdate
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($ForceUpdate)
    {
        (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET ClusterMembers/Self).Health
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance GET ApplianceStatus/Health
    }
}

<#
.SYNOPSIS
Get user-defined name of a Safeguard appliance via the Web API.

.DESCRIPTION
Get user-defined name of a Safeguard appliance. This name can be specified
using the Set-SafeguardName cmdlet. Each appliance in a cluster can have a
unique name.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardName

.EXAMPLE
Get-SafeguardName -Appliance 10.5.32.54 -Insecure
#>
function Get-SafeguardApplianceName
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

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    (Invoke-SafeguardMethod -Anonymous -Appliance $Appliance -Insecure:$Insecure Notification GET Status).ApplianceName
}

<#
.SYNOPSIS
Set user-defined name of a Safeguard appliance via the Web API.

.DESCRIPTION
Set user-defined name of a Safeguard appliance. Each appliance in a
cluster can have a unique name.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate

.PARAMETER Name
A string containing the name to give the appliance.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardName

.EXAMPLE
Get-SafeguardName -Appliance 10.5.32.54 -AccessToken $token -Insecure
#>
function Set-SafeguardApplianceName
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
        [string]$Name
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance PUT ApplianceStatus/Name -Body $Name
}

<#
.SYNOPSIS
Send a command to a Safeguard appliance to shut down via the Web API.

.DESCRIPTION
This command will shut down the Safeguard appliance.  The only way to
get Safeguard running again is to manually turn the power back on.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate

.PARAMETER Reason
A string containing the name to give the appliance.

.PARAMETER Force
Do not prompt for confirmation.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Invoke-SafeguardApplianceShutdown -Reason "Because I said so."

.EXAMPLE
Get-SafeguardName -Appliance 10.5.32.54 -AccessToken $token -Insecure -Force "Because I said so."
#>
function Invoke-SafeguardApplianceShutdown
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
        [string]$Reason,
        [Parameter(Mandatory=$false)]
        [switch]$Force
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local

    if ($Force)
    {
        $Confirmed = $true
    }
    else
    {
        Write-Host -ForegroundColor Yellow "You will be required to MANUALLY power the appliance on again!"
        $local:Confirmed = (Get-Confirmation "Safeguard Appliance Shutdown" "Do you want to initiate shutdown on this Safeguard appliance?"`
                                             "Initiates shutdown immediately." "Cancels this operation.")
    }

    if ($local:Confirmed)
    {
        Write-Host "Sending shutdown command..."
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance POST ApplianceStatus/Shutdown -Body $Reason
    }
    else
    {
        Write-Host -ForegroundColor Yellow "Operation canceled."
    }
}

<#
.SYNOPSIS
Send a command to a Safeguard appliance to reboot via the Web API.

.DESCRIPTION
This command will reboot the Safeguard appliance.  Safeguard will be
unavailable via the API for a period of time.  To determine if Safeguard
is back online you may poll the appliance status using Get-SafeguardStatus.
Look at the ApplianceCurrentState property.  When it says Online then
Safeguard is completely rebooted.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate

.PARAMETER Reason
A string containing the name to give the appliance.

.PARAMETER Force
Do not prompt for confirmation.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Invoke-SafeguardApplianceShutdown -Reason "Because I said so."

.EXAMPLE
Get-SafeguardName -Appliance 10.5.32.54 -AccessToken $token -Insecure -Force "Because I said so."
#>
function Invoke-SafeguardApplianceReboot
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
        [string]$Reason,
        [Parameter(Mandatory=$false)]
        [switch]$Force
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local

    if ($Force)
    {
        $local:Confirmed = $true
    }
    else
    {
        Write-Host -ForegroundColor Yellow "There will be a period of time when Safeguard is unavailable via the API while it reboots."
        $local:Confirmed = (Get-Confirmation "Safeguard Appliance Reboot" "Do you want to initiate reboot on this Safeguard appliance?"`
                                             "Initiates reboot immediately." "Cancels this operation.")
    }

    if ($local:Confirmed)
    {
        Write-Host "Sending reboot command..."
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance POST ApplianceStatus/Reboot -Body $Reason
    }
    else
    {
        Write-Host -ForegroundColor Yellow "Operation canceled."
    }
}

<#
.SYNOPSIS
Send a command to a Safeguard appliance to factory reset via the Web API.

.DESCRIPTION
This command will revert the Safeguard appliance to its initial factory
state.  This will drop all data stored on the appliance.  This should
generally only be done as a last resort.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate

.PARAMETER Reason
A string containing the name to give the appliance.

.PARAMETER Force
Do not prompt for confirmation.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Invoke-SafeguardApplianceShutdown -Reason "Because I said so."

.EXAMPLE
Get-SafeguardName -Appliance 10.5.32.54 -AccessToken $token -Insecure -Force "Because I said so."
#>
function Invoke-SafeguardApplianceFactoryReset
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
        [string]$Reason,
        [Parameter(Mandatory=$false)]
        [switch]$Force
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local

    if ($Force)
    {
        $Confirmed = $true
    }
    else
    {
        Write-Host -ForegroundColor Red "This operation will remove existing data stored on this appliance."
        Write-Host -ForegroundColor Red "In order to not lose data, you must have an existing replica or a backup you can restore."
        Write-Host -ForegroundColor Yellow "As Safeguard is performing the factory reset, progress information is only available via the LCD."
        Write-Host -ForegroundColor Yellow "The factory reset process can take up to an hour."
        Write-Host -ForegroundColor Yellow "Please do not touch any of the LCD buttons during factory reset!"
        Write-Host -ForegroundColor Magenta "When Safeguard completes the factory reset process it will have the default IP address."
        Write-Host -ForegroundColor Magenta "You will have to set the X0 IP address just as if you had just purchased the appliance."
        $local:Confirmed = (Get-Confirmation "Safeguard Appliance Factory Reset" "Do you want to initiate factory reset on this Safeguard appliance?"`
                                             "Initiates factory reset immediately." "Cancels this operation.")
    }

    if ($local:Confirmed)
    {
        Write-Host "Sending factory reset command..."
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance POST ApplianceStatus/FactoryReset -Body $Reason
    }
    else
    {
        Write-Host -ForegroundColor Yellow "Operation canceled."
    }
}

<#
.SYNOPSIS
Get a support bundle from a Safeguard appliance via the Web API.

.DESCRIPTION
Save a support bundle from the Safeguard appliance as a ZIP file to the
file system. If a file path is not specified, one will be generated in
the current directory.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate

.PARAMETER OutFile
A string containing the path to store the support bundle (default: SG-<id>-<date>.zip).

.PARAMETER Version
Version of the Web API you are using (default: 2).

.PARAMETER Timeout
A timeout value in seconds (default timeout depends on options specified).

.PARAMETER IncludeExtendedEventLog
Whether to include extended event logs (increases size and generation time).

.PARAMETER IncludeExtendedSessionsLog
Whether to include extended sessions logs (dramatically increases generation time).

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardSupportBundle -Appliance 10.5.32.54 -AccessToken $token
#>
function Get-SafeguardSupportBundle
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [string]$OutFile,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [int]$Version = 2,
        [Parameter(Mandatory=$false)]
        [int]$Timeout,
        [Parameter(Mandatory=$false)]
        [switch]$IncludeExtendedEventLog,
        [Parameter(Mandatory=$false)]
        [switch]$IncludeExtendedSessionsLog
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    Import-Module -Name "$PSScriptRoot\sslhandling.psm1" -Scope Local

    if ($SafeguardSession)
    {
        $Insecure = $SafeguardSession["Insecure"]
    }
    if (-not $Appliance -and $SafeguardSession)
    {
        $Appliance = $SafeguardSession["Appliance"]
    }
    if (-not $AccessToken -and $SafeguardSession)
    {
        $AccessToken = $SafeguardSession["AccessToken"]
    }
    if (-not $Appliance)
    {
        $Appliance = (Read-Host "Appliance")
    }
    if (-not $AccessToken)
    {
        $AccessToken = (Connect-Safeguard -Appliance $Appliance -Insecure:$Insecure -NoSessionVariable)
    }
    if (-not $OutFile)
    {
        $OutFile = (Join-Path (Get-Location) "SG-$Appliance-$((Get-Date).ToString("MMddTHHmmssZz")).zip")
    }

    # Handle options and timeout
    $DefaultTimeout = 600
    $Url = "https://$Appliance/service/appliance/v$Version/SupportBundle"
    if ($IncludeExtendedEventLog)
    {
        $DefaultTimeout = 900
        $Url += "?includeEventLogs=true"
    }
    else
    {
        $Url += "?includeEventLogs=false"
    }
    if ($IncludeExtendedSessionsLog)
    {
        $DefaultTimeout = 1800
        $Url += "&IncludeSessions=true"
    }
    else
    {
        $Url += "&IncludeSessions=false"
    }
    if (-not $Timeout)
    {
        $Timeout = $DefaultTimeout
    }

    try
    {
        Edit-SslVersionSupport
        if ($Insecure)
        {
            Disable-SslVerification
            if ($global:PSDefaultParameterValues) { $PSDefaultParameterValues = $global:PSDefaultParameterValues.Clone() }
        }
        # Use the WebClient class to avoid the content scraping slow down from Invoke-RestMethod as well as timeout issues
        Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local
        Add-ExWebClientExType

        $WebClient = (New-Object Ex.WebClientEx -ArgumentList @($Timeout))
        $WebClient.Headers.Add("Accept", "application/octet-stream")
        $WebClient.Headers.Add("Content-type", "application/json")
        $WebClient.Headers.Add("Authorization", "Bearer $AccessToken")
        Write-Host "This operation may take several minutes..."
        Write-Host "Downloading support bundle to: $OutFile"
        $WebClient.DownloadFile($Url, $OutFile)
    }
    catch [System.Net.WebException]
    {
        if ($_.Exception.Response)
        {
            $Response = $_.Exception.Response
            $Reader = New-Object System.IO.StreamReader -ArgumentList @($Response.GetResponseStream())
            Write-Error $Reader.ReadToEnd()
        }
        else
        {
            Write-Error $_
        }
        throw "Failure returned from downloading support bundle from Safeguard"
    }
    catch
    {
        Write-Error $_
        throw "Failed to GET support bundle from Safeguard"
    }
    finally
    {
        if ($Insecure)
        {
            Enable-SslVerification
            if ($global:PSDefaultParameterValues) { $PSDefaultParameterValues = $global:PSDefaultParameterValues.Clone() }
        }
    }
}

<#
.SYNOPSIS
Get patch that is currently staged on an appliance via the Web API.

.DESCRIPTION
Get the patch that is currently staged on the Safeguard appliance if there
is one.  This cmdlet returns the metadata associated with the patch.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.INPUTS
None.

.OUTPUTS
Script output as strings.

.EXAMPLE
Get-SafeguardPatch

.EXAMPLE
Get-SafeguardPatch -AccessToken $token -Appliance 10.5.32.54.
#>
function Get-SafeguardPatch
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

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance GET Patch).Metadata
}

<#
.SYNOPSIS
Remove patch that is currently staged on an appliance via the Web API.

.DESCRIPTION
Remove the patch that is currently staged on the Safeguard appliance if there
is one.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.INPUTS
None.

.OUTPUTS
Script output as strings.

.EXAMPLE
Clear-SafeguardPatch

.EXAMPLE
Clear-SafeguardPatch -AccessToken $token -Appliance 10.5.32.54.
#>
function Clear-SafeguardPatch
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

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (Test-SupportForClusterPatch -Appliance $Appliance -Insecure:$Insecure)
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance DELETE Patch/Distribute
    }
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance DELETE Patch
}

<#
.SYNOPSIS
Install patch on Safeguard appliance via the Web API.

.DESCRIPTION
Upload a patch to a Safeguard appliance via the Web API, and then call
the POST action to install it.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Version
Version of the Web API you are using (default: 2).

.PARAMETER Patch
A string containing the path to a patch file.

.PARAMETER Timeout
A timeout value in seconds for uploading; also used to wait for installation (default: 1800s or 30m)

.PARAMETER UseStagedPatch
Use the currently staged patch rather than uploading a new one.

.PARAMETER NoWait
Specify this flag to continue immediately without waiting for the patch to install to the connected appliance.

.INPUTS
None.

.OUTPUTS
Script output as strings.

.EXAMPLE
Install-SafeguardPatch -AccessToken $token -Patch XX.sgp -Appliance 10.5.32.54.
#>
function Install-SafeguardPatch
{
    [CmdletBinding(DefaultParameterSetName="NewPatch")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [int]$Version = 2,
        [Parameter(ParameterSetName="NewPatch",Mandatory=$true,Position=0)]
        [string]$Patch,
        [Parameter(ParameterSetName="NewPatch",Mandatory=$false)]
        [int]$Timeout = 1800,
        [Parameter(ParameterSetName="UseExisting",Mandatory=$false)]
        [switch]$UseStagedPatch = $false,
        [Parameter(Mandatory=$false)]
        [switch]$NoWait
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    
    if ($SafeguardSession)
    {
        $Insecure = $SafeguardSession["Insecure"]
    }
    if (-not $Appliance -and $SafeguardSession)
    {
        $Appliance = $SafeguardSession["Appliance"]
    }
    if (-not $AccessToken -and $SafeguardSession)
    {
        $AccessToken = $SafeguardSession["AccessToken"]
    }
    if (-not $Appliance)
    {
        $Appliance = (Read-Host "Appliance")
    }
    if (-not $AccessToken)
    {
        $AccessToken = (Connect-Safeguard -Appliance $Appliance -Insecure:$Insecure -NoSessionVariable)
    }

    if (-not $UseStagedPatch)
    {
        $Response = (Get-SafeguardPatch -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure)
        if ($Response)
        {
            Write-Host "Removing currently staged patch..."
            Clear-SafeguardPatch -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure
            $Response = (Get-SafeguardPatch -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure)
            if ($Response)
            {
                throw "Failed to delete existing patch"
            }
        }

        try
        {
            Import-Module -Name "$PSScriptRoot\sslhandling.psm1" -Scope Local
            Edit-SslVersionSupport
            if ($Insecure)
            {
                Disable-SslVerification
                if ($global:PSDefaultParameterValues) { $PSDefaultParameterValues = $global:PSDefaultParameterValues.Clone() }
            }
            # Use the WebClient class to avoid the content scraping slow down from Invoke-RestMethod as well as timeout issues
            Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local
            Add-ExWebClientExType

            $WebClient = (New-Object Ex.WebClientEx -ArgumentList @($Timeout))
            $WebClient.Headers.Add("Accept", "application/json")
            $WebClient.Headers.Add("Content-type", "application/octet-stream")
            $WebClient.Headers.Add("Authorization", "Bearer $AccessToken")
            Write-Host "Uploading patch to Safeguard. This operation may take several minutes..."

            $Bytes = [System.IO.File]::ReadAllBytes($Patch);
            $ResponseBytes = $WebClient.UploadData("https://$Appliance/service/appliance/v$Version/Patch", "POST", $Bytes) | Out-Null
            if ($ResponseBytes)
            {
                [System.Text.Encoding]::UTF8.GetString($ResponseBytes)
            }
        }
        catch [System.Net.WebException]
        {
            if ($_.Exception.Response)
            {
                $Response = $_.Exception.Response
                $Reader = New-Object System.IO.StreamReader -ArgumentList @($Response.GetResponseStream())
                Write-Error $Reader.ReadToEnd()
            }
            else
            {
                Write-Error $_
            }
            throw "Failure returned from POSTing patch to Safeguard"
        }
        catch
        {
            Write-Error $_
            throw "Failed to POST patch to Safeguard"
        }
        finally
        {
            if ($Insecure)
            {
                Enable-SslVerification
                if ($global:PSDefaultParameterValues) { $PSDefaultParameterValues = $global:PSDefaultParameterValues.Clone() }
            }
        }
    }

    $local:StagedPatch = (Get-SafeguardPatch -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure)

    if (Test-SupportForClusterPatch -Appliance $Appliance -Insecure:$Insecure)
    {
        Write-Host "Distributing patch to cluster..."
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance POST Patch/Distribute

        Import-Module -Name "$PSScriptRoot\sg-utilities.psm1" -Scope Local
        Wait-ForPatchDistribution -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure
    }

    Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local
    $local:Confirmed = (Get-Confirmation "Install Safeguard Patch" `
                                         "Do you want to install $($local:StagedPatch.Title) on this cluster?" `
                                         "Starts cluster patch immediately." `
                                         "Cancels this operation.")
    if ($local:Confirmed)
    {
        Write-Host "Starting patch install..."
        $local:MetaData = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance POST Patch/Install)
        if ($? -ne 0 -or $LastExitCode -eq 0)
        {
            Write-Host "Patch is currently installing..."
            if ($local:MetaData.Metadata)
            {
                $local:MetaData.Metadata
            }
            if ($NoWait)
            {
                Write-Host "Use Get-SafeguardStatus to monitor patching progress."
            }
            else
            {
                Wait-ForSafeguardOnlineStatus -Appliance $Appliance -Insecure:$Insecure -Timeout $Timeout
            }
        }
    }
    else
    {
        Write-Host "Patch installation canceled."
    }
}


<#
.SYNOPSIS
Create a new backup on a Safeguard appliance via the Web API.

.DESCRIPTION
This cmdlet will initiate the creation of a new backup on a Safeguard
appliance.  The backup can be downloaded using the Export-SafeguardBackup
cmdlet or archived using the Save-SafeguardBackupToArchive cmdlet. The
Import-SafeguardBackup cmdlet can be used to upload the backup later
to a Safeguard appliance. The Restore-SafeguardBackup cmdlet can be used
to restore a backup that has been uploaded.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
New-SafeguardBackup

.EXAMPLE
New-SafeguardBackup -Appliance 10.5.32.54 -AccessToken $token -Insecure
#>
function New-SafeguardBackup
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

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Write-Host "Starting a backup operation..."
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance POST Backups
}

<#
.SYNOPSIS
Delete a backup from a Safeguard appliance via the Web API.

.DESCRIPTION
This cmdlet will delete a backup stored on a Safeguard appliance.  Only
delete backups that you have either downloaded or archived.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER BackupId
A string containing a backup ID, which is a GUID.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardBackup -BackupId "c6f9a3b4-7a75-406d-ba5a-830e44c1c94d"

.EXAMPLE
Remove-SafeguardBackup -Appliance 10.5.32.54 -AccessToken $token -Insecure
#>
function Remove-SafeguardBackup
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
        [string]$BackupId
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $BackupId)
    {
        $CurrentBackupIds = (Get-SafeguardBackup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure).Id -join ", "
        Write-Host "Available Backups: [ $CurrentBackupIds ]"
        $BackupId = (Read-Host "BackupId")
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance DELETE "Backups/$BackupId"
}

<#
.SYNOPSIS
Download signed, encrypted backup from Safeguard appliance via the Web API.

.DESCRIPTION
Download signed, encrypted backup for safe storage offline so that it can be
uploaded to this appliance or another appliance in the future to recover data.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Version
Version of the Web API you are using (default: 2).

.PARAMETER BackupId
A string containing a backup ID, which is a GUID.

.PARAMETER OutFile
A string containing the path to store the backup (default: SG-<id>-backup-<backup date>.sgb)

.PARAMETER Timeout
A timeout value in seconds for uploading (default: 600s or 10m)

.INPUTS
None.

.OUTPUTS
Script output as strings.

.EXAMPLE
Export-SafeguardBackup -AccessToken $token -Appliance 10.5.32.54 f1f42734-e0ea-4edb-80f3-9f018b1b8afd sg-backup.sgb
#>
function Export-SafeguardBackup
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
        [int]$Version = 2,
        [Parameter(Mandatory=$false,Position=0)]
        [string]$BackupId,
        [Parameter(Mandatory=$false,Position=1)]
        [string]$OutFile,
        [Parameter(Mandatory=$false)]
        [int]$Timeout = 600
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    Import-Module -Name "$PSScriptRoot\sslhandling.psm1" -Scope Local

    if ($SafeguardSession)
    {
        $Insecure = $SafeguardSession["Insecure"]
    }
    if (-not $Appliance -and $SafeguardSession)
    {
        $Appliance = $SafeguardSession["Appliance"]
    }
    if (-not $AccessToken -and $SafeguardSession)
    {
        $AccessToken = $SafeguardSession["AccessToken"]
    }
    if (-not $Appliance)
    {
        $Appliance = (Read-Host "Appliance")
    }
    if (-not $AccessToken)
    {
        $AccessToken = (Connect-Safeguard -Appliance $Appliance -Insecure:$Insecure -NoSessionVariable)
    }

    if (-not $BackupId)
    {
        $CurrentBackupIds = (Get-SafeguardBackup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure).Id -join ", "
        Write-Host "Available Backups: [ $CurrentBackupIds ]"
        $BackupId = (Read-Host "BackupId")
    }
    if (-not $OutFile)
    {
        $CreatedOn = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance GET Backups/$BackupId).CreatedOn
        $FileName = "SG-$Appliance-backup-$((Get-Date $CreatedOn).ToString("MMddyyyyTHHmmZ")).sgb"
        $OutFile = (Join-Path (Get-Location) $FileName)
    }

    try
    {
        Edit-SslVersionSupport
        if ($Insecure)
        {
            Disable-SslVerification
            if ($global:PSDefaultParameterValues) { $PSDefaultParameterValues = $global:PSDefaultParameterValues.Clone() }
        }
        # Use the WebClient class to avoid the content scraping slow down from Invoke-RestMethod as well as timeout issues
        Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local
        Add-ExWebClientExType

        $WebClient = (New-Object Ex.WebClientEx -ArgumentList @($Timeout))
        $WebClient.Headers.Add("Accept", "application/octet-stream")
        $WebClient.Headers.Add("Content-type", "application/json")
        $WebClient.Headers.Add("Authorization", "Bearer $AccessToken")
        Write-Host "This operation may take several minutes..."
        Write-Host "Downloading Safeguard backup to: $OutFile"
        $WebClient.DownloadFile("https://$Appliance/service/appliance/v$Version/Backups/$BackupId/Download", $OutFile)
    }
    catch [System.Net.WebException]
    {
        if ($_.Exception.Response)
        {
            $Response = $_.Exception.Response
            $Reader = New-Object System.IO.StreamReader -ArgumentList @($Response.GetResponseStream())
            Write-Error $Reader.ReadToEnd()
        }
        else
        {
            Write-Error $_
        }
        throw "Failure returned from downloading backup from Safeguard"
    }
    catch
    {
        Write-Error $_
        throw "Failed to GET backup to Safeguard"
    }
    finally
    {
        if ($Insecure)
        {
            Enable-SslVerification
            if ($global:PSDefaultParameterValues) { $PSDefaultParameterValues = $global:PSDefaultParameterValues.Clone() }
        }
    }

}

<#
.SYNOPSIS
Upload backup file to Safeguard appliance via the Web API.

.DESCRIPTION
Upload a backup to a Safeguard appliance via the Web API.  Once it is
uploaded, you can call the Restore-SafeguardBackup cmdlet to restore it.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate

.PARAMETER Version
Version of the Web API you are using (default: 2).

.PARAMETER BackupFile
A string containing the path to a backup file.

.PARAMETER Timeout
A timeout value in seconds for uploading (default: 600s or 10m)

.INPUTS
None.

.OUTPUTS
Script output as strings.

.EXAMPLE
Import-SafeguardBackup -AccessToken $token -Appliance 10.5.32.54 sg-backup.sgb
#>
function Import-SafeguardBackup
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
        [int]$Version = 2,
        [Parameter(Mandatory=$true,Position=0)]
        [string]$BackupFile,
        [Parameter(Mandatory=$false)]
        [int]$Timeout = 600
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    Import-Module -Name "$PSScriptRoot\sslhandling.psm1" -Scope Local

    if ($SafeguardSession)
    {
        $Insecure = $SafeguardSession["Insecure"]
    }
    if (-not $Appliance -and $SafeguardSession)
    {
        $Appliance = $SafeguardSession["Appliance"]
    }
    if (-not $AccessToken -and $SafeguardSession)
    {
        $AccessToken = $SafeguardSession["AccessToken"]
    }
    if (-not $Appliance)
    {
        $Appliance = (Read-Host "Appliance")
    }
    if (-not $AccessToken)
    {
        $AccessToken = (Connect-Safeguard -Appliance $Appliance -Insecure:$Insecure -NoSessionVariable)
    }

    try
    {
        Edit-SslVersionSupport
        if ($Insecure)
        {
            Disable-SslVerification
            if ($global:PSDefaultParameterValues) { $PSDefaultParameterValues = $global:PSDefaultParameterValues.Clone() }
        }
        # Use the WebClient class to avoid the content scraping slow down from Invoke-RestMethod as well as timeout issues
        Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local
        Add-ExWebClientExType

        $WebClient = (New-Object Ex.WebClientEx -ArgumentList @($Timeout))
        $WebClient.Headers.Add("Accept", "application/json")
        $WebClient.Headers.Add("Content-type", "application/octet-stream")
        $WebClient.Headers.Add("Authorization", "Bearer $AccessToken")
        Write-Host "POSTing backup to Safeguard. This operation may take several minutes..."

        $Bytes = [System.IO.File]::ReadAllBytes($BackupFile);
        $ResponseBytes = $WebClient.UploadData("https://$Appliance/service/appliance/v$Version/Backups/Upload", "POST", $Bytes) | Out-Null
        if ($ResponseBytes)
        {
            [System.Text.Encoding]::UTF8.GetString($ResponseBytes)
        }
    }
    catch [System.Net.WebException]
    {
        if ($_.Exception.Response)
        {
            $Response = $_.Exception.Response
            $Reader = New-Object System.IO.StreamReader -ArgumentList @($Response.GetResponseStream())
            Write-Error $Reader.ReadToEnd()
        }
        else
        {
            Write-Error $_
        }
        throw "Failure returned from uploading backup to Safeguard"
    }
    catch
    {
        Write-Error $_
        throw "Failed to POST backup to Safeguard"
    }
    finally
    {
        if ($Insecure)
        {
            Enable-SslVerification
            if ($global:PSDefaultParameterValues) { $PSDefaultParameterValues = $global:PSDefaultParameterValues.Clone() }
        }
    }
}

<#
.SYNOPSIS
Restore a backup that was created on or uploaded to a Safeguard appliance via the Web API.

.DESCRIPTION
This cmdlet will restore a backup stored on a Safeguard appliance. The backup
needs to already be on the appliance

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER BackupId
A string containing a backup ID, which is a GUID.

.PARAMETER NoWait
Specify this flag to continue immediately without waiting for the restore to complete.

.PARAMETER Timeout
A timeout value in seconds for restore (default: 1800s or 30m)

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Restore-SafeguardBackup -BackupId "c6f9a3b4-7a75-406d-ba5a-830e44c1c94d"

.EXAMPLE
Restore-SafeguardBackup -Appliance 10.5.32.54 -AccessToken $SafeguardSession.AccessToken -Insecure -NoWait
#>
function Restore-SafeguardBackup
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
        [string]$BackupId,
        [Parameter(Mandatory=$false)]
        [switch]$NoWait,
        [Parameter(ParameterSetName="NewPatch",Mandatory=$false)]
        [int]$Timeout = 1800
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $BackupId)
    {
        $CurrentBackupIds = (Get-SafeguardBackup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure).Id -join ", "
        Write-Host "Available Backups: [ $CurrentBackupIds ]"
        $BackupId = (Read-Host "BackupId")
    }

    Write-Host "Starting restore operation for backup..."
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance POST "Backups/$BackupId/Restore"

    if (-not $NoWait)
    {
        Wait-ForSafeguardOnlineStatus -Appliance $Appliance -Insecure:$Insecure -Timeout $Timeout
    }
}

<#
.SYNOPSIS
Delete a backup from a Safeguard appliance via the Web API.

.DESCRIPTION
This cmdlet will delete a backup stored on a Safeguard appliance.  Only
delete backups that you have either downloaded or archived.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER BackupId
A string containing a backup ID, which is a GUID.

.PARAMETER ArchiveServerId
An integer containing the archive server ID.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Save-SafeguardBackupToArchive -BackupId "c6f9a3b4-7a75-406d-ba5a-830e44c1c94d"

.EXAMPLE
Save-SafeguardBackupToArchive -Appliance 10.5.32.54 -AccessToken $token -Insecure "c6f9a3b4-7a75-406d-ba5a-830e44c1c94d" 12
#>
function Save-SafeguardBackupToArchive
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
        [string]$BackupId,
        [Parameter(Mandatory=$false,Position=1)]
        [int]$ArchiveServerId
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $BackupId)
    {
        $CurrentBackupIds = (Get-SafeguardBackup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure).Id -join ", "
        Write-Host "Available Backups: [ $CurrentBackupIds ]"
        $BackupId = (Read-Host "BackupId")
    }

    if (-not $ArchiveServerId)
    {
        $ArchiveServerIds = ((Get-SafeguardArchiveServer -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure) | ForEach-Object { "$($_.Id): $($_.Name)" }) -join ", "
        Write-Host "Archive servers: [ $ArchiveServerIds ]"
        $ArchiveServerId = (Read-Host "ArchiveServerId")
    }

    Write-Host "Moving backup to archive server..."
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance POST "Backups/$BackupId/Archive" -Body @{
            ArchiveServerId = $ArchiveServerId
    }
}

<#
.SYNOPSIS
Get backups on a Safeguard appliance via the Web API.

.DESCRIPTION
This cmdlet will return information about backups that have occurred on
the appliance. Backups that are archived are no longer stored on Safeguard.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardBackup "c6f9a3b4-7a75-406d-ba5a-830e44c1c94d"

.EXAMPLE
Get-SafeguardBackup -Appliance 10.5.32.54 -AccessToken $token -Insecure
#>
function Get-SafeguardBackup
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
        [string]$BackupId
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($BackupId)
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance GET "Backups/$BackupId"
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance GET Backups
    }
}

<#
.SYNOPSIS
Get BMC configuration of a Safeguard appliance via the Web API.

.DESCRIPTION
Get the BMC network settings and enable state.  The AdminPassword field
returned will always be blank.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardBmcConfiguration -Appliance 10.5.32.54 -AccessToken $token -Insecure
#>
function Get-SafeguardBmcConfiguration
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

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance GET BmcConfiguration
}

<#
.SYNOPSIS
Enable BMC configuration of a Safeguard appliance via the Web API.

.DESCRIPTION
Set the BMC to enabled and provide network settings and ADMIN password.  The AdminPassword field
in the object returned will always be blank.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate

.PARAMETER Ipv4Address
A string containing the new address.

.PARAMETER Ipv4NetMask
A string containing the netmask (e.g. 255.255.255.0).

.PARAMETER Ipv4Gateway
A string containing the address of a gateway.

.PARAMETER Password
SecureString containing the password for the ADMIN account.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Enable-SafeguardBmcConfiguration 10.10.10.233 255.255.255.0 10.10.10.1

.EXAMPLE
Enable-SafeguardBmcConfiguration 10.10.10.233 255.255.255.0 10.10.10.1 -Password (ConvertTo-SecureString -AsPlainText -Force "reallylongpass")
#>
function Enable-SafeguardBmcConfiguration
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
        [string]$Ipv4Address,
        [Parameter(Mandatory=$false,Position=1)]
        [string]$Ipv4NetMask,
        [Parameter(Mandatory=$false,Position=2)]
        [string]$Ipv4Gateway,
        [Parameter(Mandatory=$false,Position=3)]
        [SecureString]$Password
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Body = @{
        Enabled = $true
    }
    if ($PSBoundParameters.ContainsKey("Ipv4Address") `
        -or $PSBoundParameters.ContainsKey("Ipv4NetMask") `
        -or $PSBoundParameters.ContainsKey("Ipv4Gateway"))
    {
        $local:Body.NetworkConfiguration = @{}
        if ($PSBoundParameters.ContainsKey("Ipv4Address")) { $local:Body.NetworkConfiguration.Ipv4Address = $Ipv4Address }
        if ($PSBoundParameters.ContainsKey("Ipv4NetMask")) { $local:Body.NetworkConfiguration.Netmask = $Ipv4NetMask }
        if ($PSBoundParameters.ContainsKey("Ipv4Gateway")) { $local:Body.NetworkConfiguration.DefaultGateway = $Ipv4Gateway }
    }
    if ($PSBoundParameters.ContainsKey("Password"))
    {
        $local:PasswordPlainText = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
        $local:Body.AdminPassword = $local:PasswordPlainText
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance PUT BmcConfiguration -Body $local:Body
}

<#
.SYNOPSIS
Disable BMC configuration of a Safeguard appliance via the Web API.

.DESCRIPTION
Disable the BMC by returning network settings to default and scrambling the password.
The AdminPassword field in the object returned will always be blank.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Disable-SafeguardBmcConfiguration -Appliance 10.5.32.54 -AccessToken $token -Insecure
#>
function Disable-SafeguardBmcConfiguration
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

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance PUT BmcConfiguration -Body @{
        Enabled = $false
    }
}

<#
.SYNOPSIS
Set password for BMC configuration of a Safeguard appliance via the Web API.

.DESCRIPTION
Set the BMC ADMIN password. The AdminPassword field in the object returned will always be blank.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate

.PARAMETER Password
SecureString containing the password for the ADMIN account.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Set-SafeguardBmcAdminPassword -Appliance 10.5.32.54 -AccessToken $token -Insecure

.EXAMPLE
Set-SafeguardBmcAdminPassword (ConvertTo-SecureString -AsPlainText -Force "reallylongpass")
#>
function Set-SafeguardBmcAdminPassword
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
        [SecureString]$Password
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Body = (Get-SafeguardBmcConfiguration -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure)
    if (-not $local:Body.Enabled)
    {
        throw "Unable to set admin password, this appliance does not have BMC enabled."
    }

    if (-not $Password)
    {
        $Password = Read-Host -AsSecureString "Password"
    }

    $local:PasswordPlainText = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
    $local:Body.AdminPassword = $local:PasswordPlainText

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance PUT BmcConfiguration -Body $local:Body
}
