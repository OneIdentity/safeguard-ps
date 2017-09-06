# Certificate helper function
function Get-CertificateFileContents
{
    Param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$CertificateFile
    )

    try 
    {
        $CertificateFullPath = (Resolve-Path $CertificateFile).ToString()
        if ((Get-Item $CertificateFullPath).Length -gt 100kb)
        {
            throw "'$CertificateFile' appears to be too large to be a certificate"
        }
    }
    catch
    {
        throw "'$CertificateFile' does not exist"
    }
    $CertificateContents = [string](Get-Content $CertificateFullPath)
    if (-not ($CertificateContents.StartsWith("-----BEGIN CERTIFICATE-----")))
    {
        Write-Host "Converting to Base64..."
        $CertificateContents = [System.IO.File]::ReadAllBytes($CertificateFullPath)
        $CertificateContents = [System.Convert]::ToBase64String($CertificateContents)
    }

    $CertificateContents
}

<#
.SYNOPSIS
Upload trusted certificate to Safeguard via the Web API.

.DESCRIPTION
Upload a certificate to serve as a new trusted root certificate for
Safeguard. You use this same method to upload an intermediate 
certificate that is part of the chain of trust.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER CertificateFile
A string containing the path to a certificate in DER or Base64 format.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Install-SafeguardTrustedCertificate -AccessToken $token 10.5.32.54
#>
function Install-SafeguardTrustedCertificate
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$true,Position=0)]
        [string]$CertificateFile
    )

    $ErrorActionPreference = "Stop"

    $CertificateContents = (Get-CertificateFileContents $CertificateFile)
    if (-not $CertificateContents)
    {
        throw "No valid certificate to upload"
    }

    Write-Host "Uploading Certificate..."
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance Core `
        POST TrustedCertificates -Body @{
            Base64CertificateData = "$CertificateContents" 
        }
}

<#
.SYNOPSIS
Remove trusted certificate from Safeguard via the Web API.

.DESCRIPTION
Remove a trusted certificate that was previously added to Safeguard via
the Web API.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Thumbprint
A string containing the thumbprint of the certificate.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Uninstall-SafeguardTrustedCertificate -AccessToken $token 10.5.32.54

.EXAMPLE
Uninstall-SafeguardTrustedCertificate -Thumbprint 3E1A99AE7ACFB163DEE3CCAC00A437D675937FCA 
#>
function Uninstall-SafeguardTrustedCertificate
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false,Position=0)]
        [string]$Thumbprint
    )

    $ErrorActionPreference = "Stop"

    if (-not $Thumbprint)
    {
        $CurrentThumbprints = (Get-SafeguardTrustedCertificate -AccessToken $AccessToken -Appliance $Appliance).Thumbprint -join ", "
        Write-Host "Currently Installed Trusted Certificates: [ $CurrentThumbprints ]"
        $Thumbprint = (Read-Host "Thumbprint")
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance Core DELETE "TrustedCertificates/$Thumbprint"
}

<#
.SYNOPSIS
Get all trusted certificate from Safeguard via the Web API.

.DESCRIPTION
Retrieve all trusted certificates that were previously added to Safeguard via
the Web API.  These will be only the user-added trusted certificates.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Thumbprint
A string containing the thumbprint of the certificate.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Uninstall-SafeguardTrustedCertificate -AccessToken $token 10.5.32.54

.EXAMPLE
Uninstall-SafeguardTrustedCertificate -Thumbprint 3E1A99AE7ACFB163DEE3CCAC00A437D675937FCA 
#>
function Get-SafeguardTrustedCertificate
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken
    )

    $ErrorActionPreference = "Stop"

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance Core GET TrustedCertificates
}

