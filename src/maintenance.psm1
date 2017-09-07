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
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure
    )

    $ErrorActionPreference = "Stop"

    Invoke-SafeguardMethod -Anonymous -Appliance $Appliance -Insecure:$Insecure Notification GET Status
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
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure
    )

    $ErrorActionPreference = "Stop"

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
Ignore verification of Safeguard appliance SSL certificate

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
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure
    )

    $ErrorActionPreference = "Stop"

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance GET ApplianceStatus/Health
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
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure
    )

    $ErrorActionPreference = "Stop"

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
    Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local

    if ($Force)
    {
        $Confirmed = $true
    }
    else
    {
        Write-Host -ForegroundColor Yellow "You will be required to MANUALLY power the appliance on again!"
        $Confirmed = (Get-Confirmation "Safeguard Appliance Shutdown" "Do you want to initiate shutdown on this Safeguard appliance?"`
                        "Initiates shutdown immediately." "Cancels this operation.")
    }

    if ($Confirmed)
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
    Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local

    if ($Force)
    {
        $Confirmed = $true
    }
    else
    {
        Write-Host -ForegroundColor Yellow "There will be a period of time when Safeguard is unavailable via the API while it reboots."
        $Confirmed = (Get-Confirmation "Safeguard Appliance Reboot" "Do you want to initiate reboot on this Safeguard appliance?"`
                        "Initiates reboot immediately." "Cancels this operation.")
    }

    if ($Confirmed)
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
        $Confirmed = (Get-Confirmation "Safeguard Appliance Factory Reset" "Do you want to initiate factory reset on this Safeguard appliance?"`
                        "Initiates factory reset immediately." "Cancels this operation.")
    }

    if ($Confirmed)
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
A string containing the path to store the support bundle.

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