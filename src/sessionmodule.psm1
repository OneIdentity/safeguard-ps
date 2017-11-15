# Helpers
function Resolve-CertificateTypeParameter
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Type
    )

    $ErrorActionPreference = "Stop"

    if (-not $Type)
    {
        Write-Host "Certificate Types: SessionRecording, TimeStamping, RdpSigning"
        $Type = Read-Host "Type"
    }
    switch ($Type.ToLower())
    {
        "timestamping" { $Type = "TimeStamping"; break }
        "rdpsigning" { $Type = "RdpSigning"; break }
        "sessionrecording" { $Type = "SessionRecording"; break }
    }
    $Type
}

<#
.SYNOPSIS
Get status of session module container running in Safeguard.

.DESCRIPTION
Get the execution status of the session module container and whether there
are active sessions or whether debug logging is enabled.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Component
Optionally get only a single component of the status.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardSessionContainerStatus -AccessToken $token -Appliance 10.5.32.54 -Insecure -Component ContainerState

.EXAMPLE
Get-SafeguardSessionContainerStatus
#>
function Get-SafeguardSessionContainerStatus
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false, Position=0)]
        [ValidateSet("ActiveSessions", "ContainerState", "DebugLogging", "ModuleState", IgnoreCase=$true)]
        [string]$Component
    )

    $ErrorActionPreference = "Stop"

    $local:RelativeUrl = "SessionModuleConfig"
    if ($PSBoundParameters.ContainsKey("Component"))
    {
        # Allow case insensitive actions to translate to appropriate case sensitive URL path
        switch ($Component)
        {
            "activesessions" { $Component = "ActiveSessions"; break }
            "containerstate" { $Component = "ContainerState"; break }
            "debuglogging" { $Component = "DebugLogging"; break }
            "modulestate" { $Component = "ModuleState"; break }
        }
        $local:RelativeUrl = "$($local:RelativeUrl)/$Component"
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance GET $local:RelativeUrl
}

<#
.SYNOPSIS
Get status of session module of Safeguard.

.DESCRIPTION
Get the status of the session module including components such as CPU, disk, memory, load,
network adapters, and network switches.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Component
Optionally get only a single component of the status.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardSessionModuleStatus -AccessToken $token -Appliance 10.5.32.54 -Insecure -Component Memory

.EXAMPLE
Get-SafeguardSessionModuleStatus
#>
function Get-SafeguardSessionModuleStatus
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false, Position=0)]
        [ValidateSet("Cpu", "Disk", "Load", "Memory", "NetworkAdapters", "NetworkSwitches", IgnoreCase=$true)]
        [string]$Component
    )

    $ErrorActionPreference = "Stop"

    $local:RelativeUrl = "SessionModuleConfig/Status"
    if ($PSBoundParameters.ContainsKey("Component"))
    {
        # Allow case insensitive actions to translate to appropriate case sensitive URL path
        switch ($Component.ToLower())
        {
            "cpu" { $Component = "Cpu"; break }
            "disk" { $Component = "Disk"; break }
            "load" { $Component = "Load"; break }
            "memory" { $Component = "Memory"; break }
            "networkadapters" { $Component = "NetworkAdapters"; break }
            "networkswitches" { $Component = "NetworkSwitches"; break }
        }
        $local:RelativeUrl = "$($local:RelativeUrl)/$Component"
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance GET $local:RelativeUrl
}

<#
.SYNOPSIS
Get version of session module of Safeguard.

.DESCRIPTION
Get the version of the session module firmware.

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
Get-SafeguardSessionModuleVersion -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardSessionModuleVersion
#>
function Get-SafeguardSessionModuleVersion
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

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance GET "SessionModuleConfig/Version"
}

<#
.SYNOPSIS
Reset the session module running inside Safeguard.

.DESCRIPTION
Reboot the session module components to attempt to restore proper functionality.

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
Reset-SafeguardSessionModule -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Reset-SafeguardSessionModule
#>
function Reset-SafeguardSessionModule
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
    Import-Module -name "$PSScriptRoot\sg-utilities.psm1" -Scope Local

    Write-Host "Stopping Safeguard Session Module"
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance POST "SessionModuleConfig/ContainerTurnOff" | Out-Null
    Wait-ForSessionModuleState -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure "Off" "" 30

    Write-Host "Starting Safeguard Session Module "
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance POST "SessionModuleConfig/ContainerStart" | Out-Null
    Wait-ForSessionModuleState -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure "Running" "Running" 120

    Write-Host "Safeguard Sessions are available again."
}

<#
.SYNOPSIS
Repair the session module running inside Safeguard.

.DESCRIPTION
Reinstall the session module components to attempt to restore proper functionality.

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
Repair-SafeguardSessionModule -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Repair-SafeguardSessionModule
#>
function Repair-SafeguardSessionModule
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
    Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local
    Import-Module -name "$PSScriptRoot\sg-utilities.psm1" -Scope Local

    $Confirmed = (Get-Confirmation "Repair Safeguard Session Module" `
                                   "Repairing the Safeguard Session Module will delete any session recordings that`n" + `
                                   "have not been securely stored on Safeguard or sent to an archive server." `
                                   "Initiates Safeguard redeploy immediately." "Cancels this operation.")
    if ($Confirmed)
    {
        Write-Host "Redeploying the Safeguard Session Module"
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance POST "SessionModuleConfig/Redeploy" | Out-Null
        Wait-ForSessionModuleState -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure "Running" "Running" 360

        Write-Host "Safeguard Sessions are available again."
    }
}

<#
.SYNOPSIS
Get the session-specific certificate of the given type from Safeguard via the Web API.

.DESCRIPTION
Safeguard has three session-specific certificates.  One for signing session recordings,
one for timestamping session recordings, and one for signing certificates used in
authenticating proxied RDP connections.  This cmdlet gets them individually from the Web API.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Type
A string representing the type of session certificate to get.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardSessionCertificate -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardSessionCertificate TimeStamping
#>
function Get-SafeguardSessionCertificate
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false, Position=0)]
        [ValidateSet("TimeStamping", "RdpSigning", "SessionRecording", IgnoreCase=$true)]
        [string]$Type
    )

    $ErrorActionPreference = "Stop"

    $Type = (Resolve-CertificateTypeParameter -Type $Type)
    $local:RelativeUrl = "SessionCertificates/$Type"

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET $local:RelativeUrl
}

<#
.SYNOPSIS
Install a session-specific certificate of the given type into Safeguard via the Web API.

.DESCRIPTION
Safeguard has three session-specific certificates.  One for signing session recordings,
one for timestamping session recordings, and one for signing certificates used in
authenticating proxied RDP connections.  This cmdlet sets them individually through the Web API.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Type
A string representing the type of session certificate to get.

.PARAMETER CertificateFile
A string containing the path to a certificate PFX file.

.PARAMETER Password
A secure string to be used as a passphrase for the certificate PFX file.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Install-SafeguardSessionCertificate -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Install-SafeguardSessionCertificate TimeStamping C:\file.pfx
#>
function Install-SafeguardSessionCertificate
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false, Position=0)]
        [ValidateSet("TimeStamping", "RdpSigning", "SessionRecording", IgnoreCase=$true)]
        [string]$Type,
        [Parameter(Mandatory=$false, Position=1)]
        [string]$CertificateFile,
        [Parameter(Mandatory=$false, Position=2)]
        [SecureString]$Password
    )

    $ErrorActionPreference = "Stop"
    Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local

    $Type = (Resolve-CertificateTypeParameter -Type $Type)
    $local:RelativeUrl = "SessionCertificates/$Type"

    if (-not $PSBoundParameters.ContainsKey("CertificateFile"))
    {
        $CertificateFile = (Read-Host "CertificateFile")
    }
    $local:CertificateContents = (Get-CertificateFileContents $CertificateFile)
    if (-not $CertificateContents)
    {
        throw "No valid certificate to upload"
    }

    if (-not $Password)
    {
        Write-Host "For no password just press enter..."
        $Password = (Read-host "Password" -AsSecureString)
    }
    $local:PasswordPlainText = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT $local:RelativeUrl -Body @{
            Base64CertificateData = "$($local:CertificateContents)";
            Passphrase = "$($local:PasswordPlainText)"
        }
}

<#
.SYNOPSIS
Reset a session-specific certificate of the given type to the default in Safeguard via the Web API.

.DESCRIPTION
Safeguard has three session-specific certificates.  One for signing session recordings,
one for timestamping session recordings, and one for signing certificates used in
authenticating proxied RDP connections.  This cmdlet resets them individually to the
default through the Web API.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Type
A string representing the type of session certificate to get.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Reset-SafeguardSessionCertificate -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Reset-SafeguardSessionCertificate TimeStamping
#>
function Reset-SafeguardSessionCertificate
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false, Position=0)]
        [ValidateSet("TimeStamping", "RdpSigning", "SessionRecording", IgnoreCase=$true)]
        [string]$Type
    )

    $ErrorActionPreference = "Stop"

    $Type = (Resolve-CertificateTypeParameter -Type $Type)
    $local:RelativeUrl = "SessionCertificates/$Type"

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE $local:RelativeUrl
}
