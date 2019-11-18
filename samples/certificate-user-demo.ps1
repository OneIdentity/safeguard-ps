# This script assumes that the bootstrap admin account has the default password
# It also uses some test data underneath this directory
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$Appliance
)

if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }

$local:Password = (ConvertTo-SecureString -AsPlainText "Admin123" -Force)
$local:AccessToken = (Connect-Safeguard -Appliance $Appliance -IdentityProvider Local -Username Admin -Password $local:Password -Insecure -NoSessionVariable)

$local:CertificateData = (Join-Path $PSScriptRoot (Join-Path "data" "CERTS"))
$local:RootCAFile = (Join-Path $local:CertificateData "RootCA.cer")
$local:IntermediateCAFile = (Join-Path $local:CertificateData "IntermediateCA.cer")
$local:UserCertFile = (Join-Path $local:CertificateData "UserCert.pfx")

Write-Host -ForegroundColor Yellow "Installing Root CA"
$local:RootCA = (Install-SafeguardTrustedCertificate -Appliance $Appliance -AccessToken $local:AccessToken -Insecure $local:RootCAFile)
Write-Host -ForegroundColor Yellow "Installing Intermediate CA"
$local:IntermediateCA = (Install-SafeguardTrustedCertificate -Appliance $Appliance -AccessToken $local:AccessToken -Insecure $local:IntermediateCAFile)

Write-Host -ForegroundColor Yellow "Creating certificate user--need password for PFX (just the single letter 'a')"
New-SafeguardUser -Appliance $Appliance -AccessToken $local:AccessToken -Insecure "certificate" "CertyMcCertface" -Thumbprint (Get-PfxCertificate $local:UserCertFile).Thumbprint
if ($PSVersionTable.Platform -ne "Unix")
{
    Write-Host -ForegroundColor Yellow "Trying to authenticate as certificate user--need password for PFX (just the single letter 'a')"
    Write-Host -ForegroundColor Magenta "As a hack you have to have the issuing cert in your intermediate CA store on certain Windows platforms"
    Write-Host -ForegroundColor Magenta "It seems to be due to a Microsoft SChannel negotiation bug--this ought to be removed when fixed!"

    Import-Certificate -CertStoreLocation Cert:\CurrentUser\CA -FilePath $local:IntermediateCAFile
}
$local:CertUserToken = (Connect-Safeguard -Insecure $Appliance -CertificateFile $local:UserCertFile -NoSessionVariable)

Write-Host -ForegroundColor Yellow "Printing out the information about the certificate user that just logged in"
Get-SafeguardLoggedInUser -Insecure $Appliance -AccessToken $local:AccessToken

if ($PSVersionTable.Platform -ne "Unix")
{
    Remove-Item "Cert:\CurrentUser\CA\$($local:IntermediateCA.Thumbprint)"
}
Disconnect-Safeguard -Insecure $Appliance $local:CertUserToken

Write-Host -ForegroundColor Yellow "Clean Up"
Write-Host -ForegroundColor Yellow "Deleting certificate user"
Remove-SafeguardUser -Appliance $Appliance -AccessToken $local:AccessToken -Insecure "CertyMcCertface"
Write-Host -ForegroundColor Yellow "Uninstalling Intermediate CA"
Uninstall-SafeguardTrustedCertificate -Appliance $Appliance -AccessToken $local:AccessToken -Insecure "$($local:IntermediateCA.Thumbprint)"
Write-Host -ForegroundColor Yellow "Uninstalling Root CA"
Uninstall-SafeguardTrustedCertificate -Appliance $Appliance -AccessToken $local:AccessToken -Insecure "$($local:RootCA.Thumbprint)"

Disconnect-Safeguard -Insecure $Appliance $local:AccessToken
Write-Host "Test completed successfully"
