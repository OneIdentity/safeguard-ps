# Helpers
function Resolve-CertificateTypeParameter
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Type
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

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
    [CmdletBinding()]
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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

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
    [CmdletBinding()]
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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

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
    Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local
    Import-Module -name "$PSScriptRoot\sg-utilities.psm1" -Scope Local

    $local:Confirmed = (Get-Confirmation "Repair Safeguard Session Module" `
                                         ("Repairing the Safeguard Session Module will delete any session recordings that`n" + `
                                          "have not been securely stored on Safeguard or sent to an archive server.") `
                                         "Initiates Safeguard redeploy immediately." "Cancels this operation.")
    if ($local:Confirmed)
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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
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
    [CmdletBinding()]
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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $Type = (Resolve-CertificateTypeParameter -Type $Type)
    $local:RelativeUrl = "SessionCertificates/$Type"

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE $local:RelativeUrl
}

<#
.SYNOPSIS
Get session-specific SSH algorithms configured for Safeguard via the Web API.

.DESCRIPTION
Safeguard session functionality supports client-side and server-side SSH algorithms
for cipher, key exchange (Kex), compression, and message authentication code (Mac).
Enabling the proper algorithms will allow Safeguard to communicate with target
systems for privileged session management.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Endpoint
A string representing the endpoint (client-side or server-side) to get.

.PARAMETER AlgorithmType
A string representing the algorithm type to get.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardSessionSshAlgorithms -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardSessionSshAlgorithms ServerSide Cipher
#>
function Get-SafeguardSessionSshAlgorithms
{
    [CmdletBinding(DefaultParameterSetName="None")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, ParameterSetName="Args", Position=0)]
        [ValidateSet("ClientSide", "ServerSide", IgnoreCase=$true)]
        [string]$Endpoint,
        [Parameter(Mandatory=$false, ParameterSetName="Args", Position=1)]
        [ValidateSet("Cipher", "Compression", "Kex", "Mac", IgnoreCase=$true)]
        [string]$AlgorithmType
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Response = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET SessionSshAlgorithms)
    if ($Endpoint)
    {
        $local:EndpointResponse = $local:Response."$($Endpoint)Algorithms"
        if ($AlgorithmType)
        {
            $local:EndpointResponse.$AlgorithmType
        }
        else
        {
            $local:EndpointResponse
        }
    }
    else
    {
        $local:Response
    }
}

<#
.SYNOPSIS
Set session-specific SSH algorithms configured for Safeguard via the Web API.

.DESCRIPTION
Safeguard session functionality supports client-side and server-side SSH algorithms
for cipher, key exchange (Kex), compression, and message authentication code (Mac).
Enabling the proper algorithms will allow Safeguard to communicate with target
systems for privileged session management.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Endpoint
A string representing the endpoint (client-side or server-side) to set.

.PARAMETER AlgorithmType
A string representing the algorithm type to set.

.PARAMETER NewValue
An array of strings containing the new algorithm identifiers to set.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Set-SafeguardSessionSshAlgorithms -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Set-SafeguardSessionSshAlgorithms ServerSide Cipher

.EXAMPLE
Set-SafeguardSessionSshAlgorithms ServerSide Cipher 3des-cbc,arcfour,aes128-ctr,aes192-ctr,aes256-ctr
#>
function Set-SafeguardSessionSshAlgorithms
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
        [ValidateSet("ClientSide", "ServerSide", IgnoreCase=$true)]
        [string]$Endpoint,
        [Parameter(Mandatory=$true, Position=1)]
        [ValidateSet("Cipher", "Compression", "Kex", "Mac", IgnoreCase=$true)]
        [string]$AlgorithmType,
        [Parameter(Mandatory=$false, Position=2)]
        [string[]]$NewValue
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Current = (Get-SafeguardSessionSshAlgorithms -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure)
    if (-not $PSBoundParameters.ContainsKey("NewValue"))
    {
        $local:CurrentValue = $local:Current."$($Endpoint)Algorithms".$AlgorithmType
        Write-Host "$Endpoint $($AlgorithmType): $($local:CurrentValue -join ',')"
        $local:NewValueString = (Read-Host "NewValue")
        $local:NewValue = ($local:NewValueString -split ',')
    }
    $local:Current."$($Endpoint)Algorithms".$AlgorithmType = $local:NewValue

    $local:Response = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT SessionSshAlgorithms -Body $local:Current)
    $local:Response."$($Endpoint)Algorithms".$AlgorithmType
}

<#
.SYNOPSIS
Add a session-specific SSH algorithm configured for Safeguard via the Web API.

.DESCRIPTION
Safeguard session functionality supports client-side and server-side SSH algorithms
for cipher, key exchange (Kex), compression, and message authentication code (Mac).
Enabling the proper algorithms will allow Safeguard to communicate with target
systems for privileged session management.  This cmdlet will add a single algorithm
to the specified endpoint of the specified algorithm type.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Endpoint
A string representing the endpoint (client-side or server-side) to set.

.PARAMETER AlgorithmType
A string representing the algorithm type to set.

.PARAMETER AlgorithmToAdd
A string containing the new algorithm identifier to add.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Add-SafeguardSessionSshAlgorithm -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Add-SafeguardSessionSshAlgorithm ServerSide Cipher

.EXAMPLE
Add-SafeguardSessionSshAlgorithm ServerSide Cipher 3des-cbc
#>
function Add-SafeguardSessionSshAlgorithm
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
        [ValidateSet("ClientSide", "ServerSide", IgnoreCase=$true)]
        [string]$Endpoint,
        [Parameter(Mandatory=$true, Position=1)]
        [ValidateSet("Cipher", "Compression", "Kex", "Mac", IgnoreCase=$true)]
        [string]$AlgorithmType,
        [Parameter(Mandatory=$true, Position=2)]
        [string]$AlgorithmToAdd
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Algs = (Get-SafeguardSessionSshAlgorithms -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Endpoint $AlgorithmType)
    if ($local:Algs -contains $AlgorithmToAdd)
    {
        Write-Verbose "$AlgorithmToAdd is already in the list ($($local:Algs -join ","))"
        $local:Algs
    }
    else
    {
        $local:Algs += $AlgorithmToAdd
        Set-SafeguardSessionSshAlgorithms -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Endpoint $AlgorithmType $local:Algs
    }
}

<#
.SYNOPSIS
Add a session-specific SSH algorithm configured for Safeguard via the Web API.

.DESCRIPTION
Safeguard session functionality supports client-side and server-side SSH algorithms
for cipher, key exchange (Kex), compression, and message authentication code (Mac).
Enabling the proper algorithms will allow Safeguard to communicate with target
systems for privileged session management.  This cmdlet will remove a single algorithm
from the specified endpoint of the specified algorithm type.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Endpoint
A string representing the endpoint (client-side or server-side) to set.

.PARAMETER AlgorithmType
A string representing the algorithm type to set.

.PARAMETER AlgorithmToRemove
A string containing the new algorithm identifier to remove.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardSessionSshAlgorithm -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Remove-SafeguardSessionSshAlgorithm ServerSide Cipher

.EXAMPLE
Remove-SafeguardSessionSshAlgorithm ServerSide Cipher 3des-cbc
#>
function Remove-SafeguardSessionSshAlgorithm
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
        [ValidateSet("ClientSide", "ServerSide", IgnoreCase=$true)]
        [string]$Endpoint,
        [Parameter(Mandatory=$true, Position=1)]
        [ValidateSet("Cipher", "Compression", "Kex", "Mac", IgnoreCase=$true)]
        [string]$AlgorithmType,
        [Parameter(Mandatory=$true, Position=2)]
        [string]$AlgorithmToRemove
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Algs = (Get-SafeguardSessionSshAlgorithms -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Endpoint $AlgorithmType)
    if ($local:Algs -notcontains $AlgorithmToRemove)
    {
        Write-Verbose "$AlgorithmToRemove is not in the list ($($local:Algs -join ","))"
        $local:Algs
    }
    else
    {
        # $local:Algs.Remove($AlgorithmToRemove)
        # 'Collection was of a fixed size' error
        $local:AlgsNew = @()
        foreach ($local:Alg in $local:Algs)
        {
            if ($local:Alg -ine $AlgorithmToRemove)
            {
                $local:AlgsNew += $local:Alg
            }
        }
        Set-SafeguardSessionSshAlgorithms -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Endpoint $AlgorithmType $local:AlgsNew
    }
}