# SSL handling helpers
# Nothing is exported from here
function Disable-SslVerification
{
    [CmdletBinding()]
    Param(
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = $PSCmdlet.GetVariableValue("ErrorAction") }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSVersionTable.PSEdition -eq "Core")
    {
        if ($PSVersionTable.PSVersion.Major -lt 6)
        {
            Write-Verbose "Unable to disable SSL on PowerShell Core version less than 6"
        }
        else
        {
            Write-Verbose "Disabling SSL on non-Windows platform"
            $global:PSDefaultParameterValues.Add("Invoke-RestMethod:SkipCertificateCheck",$true)
            $global:PSDefaultParameterValues.Add("Invoke-WebRequest:SkipCertificateCheck",$true)
        }
    }
    else
    {
        Write-Verbose "Disabling SSL on Windows platform"
    }
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
function Enable-SslVerification
{
    [CmdletBinding()]
    Param(
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = $PSCmdlet.GetVariableValue("ErrorAction") }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSVersionTable.PSEdition -eq "Core")
    {
        if ($PSVersionTable.PSVersion.Major -lt 6)
        {
            Write-Verbose "Unable to enable SSL on PowerShell Core version less than 6"
        }
        else
        {
            Write-Verbose "Enabling SSL on non-Windows platform"
            $global:PSDefaultParameterValues.Remove("Invoke-RestMethod:SkipCertificateCheck")
            $global:PSDefaultParameterValues.Remove("Invoke-WebRequest:SkipCertificateCheck")
        }
    }
    else
    {
        Write-Verbose "Enabling SSL on Windows platform"
    }
    if (([System.Management.Automation.PSTypeName]"TrustEverything").Type)
    {
        Write-Verbose "Removing the trust everything callback"
        [TrustEverything]::UnsetCallback()
    }
}
function Edit-SslVersionSupport
{
    [CmdletBinding()]
    Param(
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = $PSCmdlet.GetVariableValue("ErrorAction") }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Write-Verbose "Configuring SSL version support to be secure"
    # Remove SSLv3, if present
    if ([bool]([System.Net.ServicePointManager]::SecurityProtocol -band [System.Net.SecurityProtocolType]::Ssl3))
    {
        [System.Net.ServicePointManager]::SecurityProtocol = `
            [System.Net.ServicePointManager]::SecurityProtocol -band (-bnot [System.Net.SecurityProtocolType]::Ssl3)
    }
    # Add TLS 1.0, if missing
    if (-not ([bool]([System.Net.ServicePointManager]::SecurityProtocol -band [System.Net.SecurityProtocolType]::Tls)))
    {
        [System.Net.ServicePointManager]::SecurityProtocol = `
            [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls
    }
    # Add TLS 1.1, if missing
    if (-not ([bool]([System.Net.ServicePointManager]::SecurityProtocol -band [System.Net.SecurityProtocolType]::Tls11)))
    {
        [System.Net.ServicePointManager]::SecurityProtocol = `
            [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls11
    }
    # Add TLS 1.2, if missing
    if (-not ([bool]([System.Net.ServicePointManager]::SecurityProtocol -band [System.Net.SecurityProtocolType]::Tls12)))
    {
        [System.Net.ServicePointManager]::SecurityProtocol = `
            [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
    }
}
