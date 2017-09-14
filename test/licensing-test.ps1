# This script assumes that the bootstrap admin account has the default password

Param(
    [Parameter(Mandatory=$true)]
    [string]$Appliance,
    [Parameter(Mandatory=$true)]
    [string]$PasswordLicenseFile,
    [Parameter(Mandatory=$true)]
    [string]$SessionsLicenseFile
)

$ErrorActionPreference = "Stop"

$local:Password = (ConvertTo-SecureString -AsPlainText "Admin123" -Force)
$local:AccessToken = (Connect-Safeguard -Appliance $Appliance -IdentityProvider Local -Username Admin -Password $local:Password -Insecure -NoSessionVariable)

$local:PasswordLicense = (Install-SafeguardLicense -Appliance $local:Appliance -AccessToken $local:AccessToken -Insecure $PasswordLicenseFile)
$local:SessionsLicense = (Install-SafeguardLicense -Appliance $local:Appliance -AccessToken $local:AccessToken -Insecure $SessionsLicenseFile)

$local:Licenses = (Get-SafeguardLicense -Appliance $Appliance -AccessToken $AccessToken -Insecure)
if ($local:Licenses.Count -lt 2)
{
    throw "Expected to see at least 2 licenses installed"
}
if (-not ($local:Licenses | Where-Object { $_.Key -eq $local:PasswordLicense.Key }))
{
    throw "Could not find password license key '$($local:PasswordLicense.Key)'"
}
if (-not ($local:Licenses | Where-Object { $_.Key -eq $local:SessionsLicense.Key }))
{
    throw "Could not find sessions license key '$($local:SessionsLicense.Key)'"
}
$local:PasswordLicense = (Get-SafeguardLicense -Appliance $Appliance -AccessToken $AccessToken -Insecure $local:PasswordLicense.Key)
if (-not $local:PasswordLicense)
{
    throw "Could not get password license by key '$($local:PasswordLicense.Key)'"
}
$local:SessionsLicense = (Get-SafeguardLicense -Appliance $Appliance -AccessToken $AccessToken -Insecure $local:SessionsLicense.Key)
if (-not $local:SessionsLicense)
{
    throw "Could not get sessions license by key '$($local:SessionsLicense.Key)'"
}

Uninstall-SafeguardLicense -Appliance $Appliance -AccessToken $AccessToken -Insecure $local:PasswordLicense.Key | Out-Null
Uninstall-SafeguardLicense -Appliance $Appliance -AccessToken $AccessToken -Insecure $local:SessionsLicense.Key | Out-Null

Write-Host "Test completed successfully"
