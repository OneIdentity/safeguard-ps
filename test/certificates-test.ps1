# This script assumes that the bootstrap admin account has the default password
# It also uses some test data underneath this directory
Param(
    [Parameter(Mandatory=$true)]
    [string]$Appliance
)

$ErrorActionPreference = "Stop"

$local:Password = (ConvertTo-SecureString -AsPlainText "Admin123" -Force)
$local:AccessToken = (Connect-Safeguard -Appliance $Appliance -IdentityProvider Local -Username Admin -Password $local:Password -Insecure -NoSessionVariable)

$local:CertificateData = (Join-Path $PSScriptRoot (Join-Path "data" "CERTS-2017-09-25T11-31-42"))
$local:RootCAFile = (Join-Path $local:CertificateData "RootCA.cer")
$local:IntermediateCAFile = (Join-Path $local:CertificateData "IntermediateCA.cer")
$local:SslCertFile = (Join-Path $local:CertificateData "10.5.32.162.pfx")
$local:UserCertFile = (Join-Path $local:CertificateData "UserCert.pfx")

Write-Host -ForegroundColor Yellow "Installing Root CA"
$local:RootCA = (Install-SafeguardTrustedCertificate -Appliance $Appliance -AccessToken $local:AccessToken -Insecure $local:RootCAFile)
Write-Host -ForegroundColor Yellow "Installing Intermediate CA"
$local:IntermediateCA = (Install-SafeguardTrustedCertificate -Appliance $Appliance -AccessToken $local:AccessToken -Insecure $local:IntermediateCAFile)
Write-Host -ForegroundColor Yellow "Installing SSL Certificate"
$local:SslCert = (Install-SafeguardSslCertificate -Appliance $Appliance -AccessToken $local:AccessToken -Insecure $local:SslCertFile -Password (ConvertTo-SecureString -AsPlainText "a" -Force))

Write-Host -ForegroundColor Yellow "Assigning SSL Certificate to this Appliance"
Set-SafeguardSslCertificateForAppliance -Appliance $Appliance -AccessToken $local:AccessToken -Insecure $local:SslCert.Thumbprint
Write-Host -ForegroundColor Yellow "Clearing SSL Certificate for this Appliance"
Clear-SafeguardSslCertificateForAppliance -Appliance $Appliance -AccessToken $local:AccessToken -Insecure $local:SslCert.Thumbprint
Write-Host -ForegroundColor Yellow "Uninstalling SSL Certificate"
Uninstall-SafeguardSslCertificate -Appliance $Appliance -AccessToken $local:AccessToken -Insecure $local:SslCert.Thumbprint

Write-Host -ForegroundColor Yellow "Adding SSL Certificate and Assigning (one call)"
$local:SslCert = (Install-SafeguardSslCertificate -Appliance $Appliance -AccessToken $local:AccessToken -Insecure $local:SslCertFile -Password (ConvertTo-SecureString -AsPlainText "a" -Force) -Assign)

Write-Host -ForegroundColor Yellow "Testing Get Root CA '$($local:RootCA.Thumbprint)'"
if (-not (Get-SafeguardTrustedCertificate -Appliance $Appliance -AccessToken $local:AccessToken -Insecure "$($local:RootCA.Thumbprint)"))
{
    throw "Unable to get root CA by thumbprint '$($local:RootCA.Thumbprint)'"
}
Write-Host -ForegroundColor Yellow "Testing Get Intermediate CA '$($local:IntermediateCA.Thumbprint)'"
if (-not (Get-SafeguardTrustedCertificate -Appliance $Appliance -AccessToken $local:AccessToken -Insecure "$($local:IntermediateCA.Thumbprint)"))
{
    throw "Unable to get intermediate CA by thumbprint '$($local:IntermediateCA.Thumbprint)'"
}
Write-Host -ForegroundColor Yellow "Testing Get SSL Cert '$($local:SslCert.Thumbprint)'"
if (-not (Get-SafeguardSslCertificate -Appliance $Appliance -AccessToken $local:AccessToken -Insecure "$($local:SslCert.Thumbprint)"))
{
    throw "Unable to get SSL cert by thumbprint '$($local:SslCert.Thumbprint)'"
}

Write-Host -ForegroundColor Yellow "Clean Up"
Write-Host -ForegroundColor Yellow "Clearing SSL Certificate for this Appliance"
Clear-SafeguardSslCertificateForAppliance -Appliance $Appliance -AccessToken $local:AccessToken -Insecure "$($local:SslCert.Thumbprint)"
Write-Host -ForegroundColor Yellow "Uninstalling SSL Certificate"
Uninstall-SafeguardSslCertificate -Appliance $Appliance -AccessToken $local:AccessToken -Insecure "$($local:SslCert.Thumbprint)"
Write-Host -ForegroundColor Yellow "Uninstalling Intermediate CA"
Uninstall-SafeguardTrustedCertificate -Appliance $Appliance -AccessToken $local:AccessToken -Insecure "$($local:IntermediateCA.Thumbprint)"
Write-Host -ForegroundColor Yellow "Uninstalling Root CA"
Uninstall-SafeguardTrustedCertificate -Appliance $Appliance -AccessToken $local:AccessToken -Insecure "$($local:RootCA.Thumbprint)"