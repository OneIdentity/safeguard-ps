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
# Maps a caller-facing TLS version string ("1.2", "1.3") to the corresponding
# .NET enum member name ("Tls12", "Tls13") used by both SecurityProtocolType
# (Windows PowerShell) and WebSslProtocol (PowerShell 7 -SslProtocol).
function Get-SafeguardTlsEnumName
{
    [CmdletBinding()]
    [OutputType([string])]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$TlsVersion
    )

    switch ($TlsVersion)
    {
        "1.2" { "Tls12" }
        "1.3" { "Tls13" }
        default { throw "Unsupported TLS version '$TlsVersion'. Supported values are 1.2 and 1.3." }
    }
}
# Resolves an optional [MinimumTlsVersion, MaximumTlsVersion] range into the
# ordered set of secure TLS versions the module should enable. Only TLS 1.2 and
# TLS 1.3 are ever enabled (1.0/1.1 are intentionally excluded). Returns $null
# when neither bound is specified, meaning "negotiate normally" (the default).
function Get-SafeguardTlsVersionSet
{
    [CmdletBinding()]
    [OutputType([object[]])]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$MinimumTlsVersion,
        [Parameter(Mandatory=$false)]
        [string]$MaximumTlsVersion
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ([string]::IsNullOrEmpty($MinimumTlsVersion) -and [string]::IsNullOrEmpty($MaximumTlsVersion))
    {
        return $null
    }
    if ((-not [string]::IsNullOrEmpty($MinimumTlsVersion)) -and (-not [string]::IsNullOrEmpty($MaximumTlsVersion)) -and `
        ([System.Version]$MinimumTlsVersion -gt [System.Version]$MaximumTlsVersion))
    {
        throw "MinimumTlsVersion ($MinimumTlsVersion) cannot be greater than MaximumTlsVersion ($MaximumTlsVersion)."
    }

    # Secure TLS versions this module is willing to enable, in ascending order.
    $local:Known = @("1.2", "1.3")
    $local:Selected = @($local:Known | Where-Object {
        (([string]::IsNullOrEmpty($MinimumTlsVersion)) -or ([System.Version]$_ -ge [System.Version]$MinimumTlsVersion)) -and
        (([string]::IsNullOrEmpty($MaximumTlsVersion)) -or ([System.Version]$_ -le [System.Version]$MaximumTlsVersion))
    })
    if ((-not $local:Selected) -or ($local:Selected.Count -eq 0))
    {
        throw "The requested TLS version range (min='$MinimumTlsVersion', max='$MaximumTlsVersion') does not include any supported TLS version (1.2 or 1.3)."
    }
    return ,([string[]]$local:Selected)
}
function Edit-SslVersionSupport
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$MinimumTlsVersion,
        [Parameter(Mandatory=$false)]
        [string]$MaximumTlsVersion
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:VersionSet = (Get-SafeguardTlsVersionSet -MinimumTlsVersion $MinimumTlsVersion -MaximumTlsVersion $MaximumTlsVersion)
    if (($null -ne $local:VersionSet) -and ($PSVersionTable.PSEdition -ne "Core"))
    {
        # Windows PowerShell negotiates TLS through ServicePointManager, so an explicit
        # TLS version range means enabling *only* the requested versions (fail closed
        # outside the range). On PowerShell 7+ this is done per-request via the
        # -SslProtocol parameter instead (see Get-SafeguardWebRequestPreference).
        Write-Verbose "Restricting TLS to ($($local:VersionSet -join ', ')) for Windows PowerShell"
        $local:Protocol = 0
        foreach ($local:Version in $local:VersionSet)
        {
            $local:Name = (Get-SafeguardTlsEnumName $local:Version)
            if (-not ([System.Net.SecurityProtocolType].GetEnumNames() -contains $local:Name))
            {
                throw "TLS $local:Version was requested, but this Windows PowerShell runtime does not support it. Upgrade the operating system/.NET Framework or use PowerShell 7."
            }
            $local:Protocol = $local:Protocol -bor [int][System.Enum]::Parse([System.Net.SecurityProtocolType], $local:Name)
        }
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]$local:Protocol
        return
    }

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
# Returns a hashtable of extra parameters that should be splatted onto every
# Invoke-RestMethod / Invoke-WebRequest call that talks to Safeguard so that the
# module's HTTP/TLS behavior is explicit:
#
#   * HttpVersion = '1.1' -- SPP 9.0 exposes an HTTP/2-capable Standard binding.
#     HTTP/2 disallows the post-handshake TLS certificate request that client
#     certificate authentication relies on, so pin HTTP/1.1 to keep cert-auth
#     working regardless of the ingress in front of the appliance. The
#     -HttpVersion parameter only exists on PowerShell 7.3+, so it is omitted
#     where unavailable (older PowerShell 7 and Windows PowerShell 5.1 already
#     default to HTTP/1.1).
#
#   * SslProtocol -- only when an explicit -MinimumTlsVersion/-MaximumTlsVersion
#     range is supplied. This makes PowerShell 7 negotiate exclusively within the
#     requested TLS version range, failing closed outside it. Windows PowerShell
#     5.1 has no -SslProtocol parameter; there the range is enforced process-wide
#     by Edit-SslVersionSupport.
#
# By default (no -AsDefaultParameterValues) the keys are bare parameter names
# suitable for splatting directly onto an Invoke-RestMethod call. With
# -AsDefaultParameterValues the keys are qualified (e.g.
# 'Invoke-RestMethod:HttpVersion') for assignment to $PSDefaultParameterValues.
function Get-SafeguardWebRequestPreference
{
    [CmdletBinding()]
    [OutputType([hashtable])]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$MinimumTlsVersion,
        [Parameter(Mandatory=$false)]
        [string]$MaximumTlsVersion,
        [Parameter(Mandatory=$false)]
        [switch]$AsDefaultParameterValues
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Splat = @{}
    $local:VersionSet = (Get-SafeguardTlsVersionSet -MinimumTlsVersion $MinimumTlsVersion -MaximumTlsVersion $MaximumTlsVersion)

    if ($PSVersionTable.PSEdition -eq "Core")
    {
        $local:WebParameters = (Get-Command Invoke-RestMethod).Parameters
        if ($local:WebParameters.ContainsKey("HttpVersion"))
        {
            $local:Splat["HttpVersion"] = "1.1"
        }
        if ($null -ne $local:VersionSet)
        {
            if (-not ($local:WebParameters.ContainsKey("SslProtocol")))
            {
                throw "A TLS version range was requested, but this PowerShell runtime does not support the -SslProtocol parameter."
            }
            $local:ProtocolInt = 0
            foreach ($local:Version in $local:VersionSet)
            {
                $local:Name = (Get-SafeguardTlsEnumName $local:Version)
                if (-not ([System.Enum]::GetNames([Microsoft.PowerShell.Commands.WebSslProtocol]) -contains $local:Name))
                {
                    throw "TLS $local:Version was requested, but this PowerShell runtime does not support the $local:Name SSL protocol."
                }
                $local:ProtocolInt = $local:ProtocolInt -bor [int][Microsoft.PowerShell.Commands.WebSslProtocol]$local:Name
            }
            $local:Splat["SslProtocol"] = [Microsoft.PowerShell.Commands.WebSslProtocol]$local:ProtocolInt
        }
    }
    # Windows PowerShell 5.1: -HttpVersion does not exist (HTTP/1.1 is the default)
    # and the TLS version range is enforced by Edit-SslVersionSupport.

    if (-not $AsDefaultParameterValues)
    {
        return $local:Splat
    }

    $local:Defaults = @{}
    foreach ($local:Key in $local:Splat.Keys)
    {
        $local:Defaults["Invoke-RestMethod:$($local:Key)"] = $local:Splat[$local:Key]
        $local:Defaults["Invoke-WebRequest:$($local:Key)"] = $local:Splat[$local:Key]
    }
    return $local:Defaults
}
