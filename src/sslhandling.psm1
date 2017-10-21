# SSL handling helpers
# Nothing is exported from here
function Disable-SslVerification
{
    if (-not ([System.Management.Automation.PSTypeName]"TrustEverything").Type)
    {
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
    [TrustEverything]::SetCallback()
}
function Enable-SslVerification
{
    if (([System.Management.Automation.PSTypeName]"TrustEverything").Type)
    {
        [TrustEverything]::UnsetCallback()
    }
}
function Edit-SslVersionSupport
{
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