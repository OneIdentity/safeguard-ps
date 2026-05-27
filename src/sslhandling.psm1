<# Copyright (c) 2026 One Identity LLC. All rights reserved. #>
# SSL handling helpers
# Nothing is exported from here.

# Tracks whether -Insecure is active. Defaults to $false (verification on).
$script:SkipCertificateCheck = $false

function Disable-SslVerification
{
    [CmdletBinding()]
    Param(
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $script:SkipCertificateCheck = $true

    if ($PSVersionTable.PSEdition -eq "Core")
    {
        if ($PSVersionTable.PSVersion.Major -lt 6)
        {
            Write-Verbose "Unable to disable SSL on PowerShell Core version less than 6"
        }
        else
        {
            Write-Verbose "Disabling SSL on cross-platform PowerShell (module-scoped; non-Safeguard cmdlets are unaffected)"
        }
    }
    else
    {
        Write-Verbose "Disabling SSL on Windows platform"
        if (-not ([System.Management.Automation.PSTypeName]"TrustEverything").Type)
        {
            Write-Verbose "Adding the PSType for SSL trust override"
            Add-Type -TypeDefinition  @"
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public static class TrustEverything
{
private static bool ValidationCallback(object sender, X509Certificate certificate, X509Chain chain,
    SslPolicyErrors sslPolicyErrors) { return true; }
public static void SetCallback() { System.Net.ServicePointManager.ServerCertificateValidationCallback = ValidationCallback; }
public static void UnsetCallback() { System.Net.ServicePointManager.ServerCertificateValidationCallback = null; }
}
"@
        }
        Write-Verbose "Adding the trust everything callback"
        [TrustEverything]::SetCallback()
    }
}
function Enable-SslVerification
{
    [CmdletBinding()]
    Param(
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $script:SkipCertificateCheck = $false

    if ($PSVersionTable.PSEdition -eq "Core")
    {
        if ($PSVersionTable.PSVersion.Major -lt 6)
        {
            Write-Verbose "Unable to enable SSL on PowerShell Core version less than 6"
        }
        else
        {
            Write-Verbose "Enabling SSL on cross-platform PowerShell"
        }
    }
    else
    {
        Write-Verbose "Enabling SSL on Windows platform"
        if (([System.Management.Automation.PSTypeName]"TrustEverything").Type)
    {
        Write-Verbose "Removing the trust everything callback"
        [TrustEverything]::UnsetCallback()
    }
    }
}
# Returns a hashtable suitable for assignment to a function-scoped
# $PSDefaultParameterValues so that Invoke-RestMethod and Invoke-WebRequest
# calls within the *current function* honour the module-scoped TLS bypass.
# This replaces the prior pattern of cloning $global:PSDefaultParameterValues
# (which only worked because Disable-SslVerification was polluting it).
#
# On Windows PowerShell 5.1 the [TrustEverything] callback handles the bypass
# process-wide, so this helper returns an empty hashtable on that edition.
function Get-SafeguardSslPreferences
{
    [CmdletBinding()]
    [OutputType([hashtable])]
    Param(
    )

    if (-not $script:SkipCertificateCheck)
    {
        return @{}
    }

    if ($PSVersionTable.PSEdition -ne "Core" -or $PSVersionTable.PSVersion.Major -lt 6)
    {
        return @{}
    }

    return @{
        'Invoke-RestMethod:SkipCertificateCheck' = $true
        'Invoke-WebRequest:SkipCertificateCheck' = $true
    }
}
function Edit-SslVersionSupport
{
    [CmdletBinding()]
    Param(
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Write-Verbose "Configuring SSL version support to be secure"
    # Remove SSLv3, if present
    if ([bool]([System.Net.ServicePointManager]::SecurityProtocol -band [System.Net.SecurityProtocolType]::Ssl3))
    {
        [System.Net.ServicePointManager]::SecurityProtocol = `
            [System.Net.ServicePointManager]::SecurityProtocol -band (-bnot [System.Net.SecurityProtocolType]::Ssl3)
    }
    # Add TLS 1.2, if missing
    if (-not ([bool]([System.Net.ServicePointManager]::SecurityProtocol -band [System.Net.SecurityProtocolType]::Tls12)))
    {
        [System.Net.ServicePointManager]::SecurityProtocol = `
            [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
    }
    # Add TLS 1.3 if the runtime supports it
    $local:Tls13 = ([System.Net.SecurityProtocolType].GetEnumNames() -contains 'Tls13')
    if ($local:Tls13)
    {
        $local:Tls13Value = [System.Enum]::Parse([System.Net.SecurityProtocolType], 'Tls13')
        if (-not ([bool]([System.Net.ServicePointManager]::SecurityProtocol -band $local:Tls13Value)))
        {
            [System.Net.ServicePointManager]::SecurityProtocol = `
                [System.Net.ServicePointManager]::SecurityProtocol -bor $local:Tls13Value
        }
    }
}
