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
Install-SafeguardTrustedCertificate -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
Install-SafeguardTrustedCertificate "\\someserver.corp\share\Cert Root CA.cer"
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
Uninstall-SafeguardTrustedCertificate -AccessToken $token -Appliance 10.5.32.54

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

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardTrustedCertificate -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
Get-SafeguardTrustedCertificate
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

<#
.SYNOPSIS
Upload SSL certificate to Safeguard appliance via the Web API.

.DESCRIPTION
Upload a certificate for use with SSL server authentication. A separate
action is required to assign an SSL certificate to a particular appliance if
you do not use the -Assign parameter. A certificate can be assigned using
the Set-SafeguardSslCertificateForAppliance cmdlet.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER CertificateFile
A string containing the path to a certificate PFX file.

.PARAMETER Password
A secure string to be used as a passphrase for the certificate PFX file.

.PARAMETER Assign
Install the certificate to this server immediately.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Install-SafeguardSslCertificate -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
Install-SafeguardSslCertificate -CertificateFile C:\cert.pfx
#>
function Install-SafeguardSslCertificate
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$true,Position=0)]
        [string]$CertificateFile,
        [Parameter(Mandatory=$false,Position=1)]
        [SecureString]$Password
    )

    $ErrorActionPreference = "Stop"

    $CertificateContents = (Get-CertificateFileContents $CertificateFile)
    if (-not $CertificateContents)
    {
        throw "No valid certificate to upload"
    }

    if (-not $Password)
    {
        Write-Host "For no password just press enter..."
        $Password = (Read-host "Password" -AsSecureString)
        $PasswordPlainText = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
    }

    Write-Host "Uploading Certificate..."
    if ($PasswordPlainText)
    {
        $NewCertificate = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance Core `
            POST SslCertificates -Body @{
                Base64CertificateData = "$CertificateContents";
                Passphrase = "$PasswordPlainText"
            })
    }
    else
    {
        $NewCertificate = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance Core `
            POST SslCertificates -Body @{
                Base64CertificateData = "$CertificateContents" 
            })
    }

    $NewCertificate

    if ($Assign -and $NewCertificate.Thumbprint)
    {
        Set-SafeguardSslCertificate -AccessToken $AccessToken -Appliance $Appliance $NewCertificate.Thumbprint
    }
}

<#
.SYNOPSIS
Remove SSL certificate from Safeguard via the Web API.

.DESCRIPTION
Remove an SSL certificate that was previously added to Safeguard via
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
Uninstall-SafeguardSslCertificate -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
Uninstall-SafeguardSslCertificate -Thumbprint 3E1A99AE7ACFB163DEE3CCAC00A437D675937FCA 
#>
function Uninstall-SafeguardSslCertificate
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
        $CurrentThumbprints = (Get-SafeguardSslCertificate -AccessToken $AccessToken -Appliance $Appliance).Thumbprint -join ", "
        Write-Host "Currently Installed SSL Certificates: [ $CurrentThumbprints ]"
        $Thumbprint = (Read-Host "Thumbprint")
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance Core DELETE "SslCertificates/$Thumbprint"
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

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardSslCertificate -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
Get-SafeguardSslCertificate
#>
function Get-SafeguardSslCertificate
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken
    )

    $ErrorActionPreference = "Stop"

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance Core GET SslCertificates
}

<#
.SYNOPSIS
Assign an SSL certificate to a specific Safeguard appliance via the Web API.

.DESCRIPTION
Assign a previously added SSL certificate to a specific Safeguard appliance via
the Web API.  If an appliance ID is not specified this cmdlet will use the appliance
that you are communicating with.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Thumbprint
A string containing the thumbprint of the SSL certificate.

.PARAMETER ApplianceId
A string containing the ID of the appliance to assign the SSL certificate to.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Set-SafeguardTrustedCertificateForAppliance -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
Set-SafeguardTrustedCertificateForAppliance -Thumbprint 3E1A99AE7ACFB163DEE3CCAC00A437D675937FCA -ApplianceId 00155D26E342
#>
function Set-SafeguardSslCertificateForAppliance
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false,Position=0)]
        [string]$Thumbprint,
        [Parameter(Mandatory=$false,Position=1)]
        [string]$ApplianceId
    )

    $ErrorActionPreference = "Stop"

    if (-not $Thumbprint)
    {
        $CurrentThumbprints = (Get-SafeguardSslCertificate -AccessToken $AccessToken -Appliance $Appliance).Thumbprint -join ", "
        Write-Host "Currently Installed SSL Certificates: [ $CurrentThumbprints ]"
        $Thumbprint = (Read-Host "Thumbprint")
    }

    if ($ApplianceId)
    {
        $ApplianceId = (Invoke-SafeguardMethod -Anonymous -Appliance $Appliance Notification GET Status).ApplianceId
    }

    Write-Host "Setting $Thumbprint as current SSL Certificate for $ApplianceId..."
    $CurrentIds = @(Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance Core GET "SslCertificates/$Thumbprint/Appliances")
    $CurrentIds += @{ Id = $ApplianceId }
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance Core PUT "SslCertificates/$Thumbprint/Appliances" -Body $CurrentIds
}

<#
.SYNOPSIS
Unassign SSL certificate from a Safeguard appliance via the Web API.

.DESCRIPTION
Unassign SSL certificate from a Safeguard appliance that was previously
configured via the Web API.  If an appliance ID is not specified to this
cmdlet will use the appliance that you are communicating with.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Thumbprint
A string containing the thumbprint of the SSL certificate.

.PARAMETER ApplianceId
A string containing the ID of the appliance to unassign the SSL certificate from.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Clear-SafeguardTrustedCertificateForAppliance -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
Clear-SafeguardTrustedCertificateForAppliance -Thumbprint 3E1A99AE7ACFB163DEE3CCAC00A437D675937FCA -ApplianceId 00155D26E342
#>
function Clear-SafeguardSslCertificateForAppliance
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false,Position=0)]
        [string]$Thumbprint,
        [Parameter(Mandatory=$false,Position=1)]
        [string]$ApplianceId
    )

    $ErrorActionPreference = "Stop"

    if (-not $Thumbprint)
    {
        $CurrentThumbprints = (Get-SafeguardSslCertificate -AccessToken $AccessToken -Appliance $Appliance).Thumbprint -join ", "
        Write-Host "Currently Installed SSL Certificates: [ $CurrentThumbprints ]"
        $Thumbprint = (Read-Host "Thumbprint")
    }

    if (-not $ApplianceId)
    {
        $ApplianceId = (Invoke-SafeguardMethod -Anonymous -Appliance $Appliance Notification GET Status).ApplianceId
    }

    Write-Host "Clearing $Thumbprint as current SSL Certificate for $ApplianceId..."
    $CurrentIds = @(Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance Core GET "SslCertificates/$Thumbprint/Appliances")
    $NewIds = $CurrentIds | Where-Object { $_.Id -ne $ApplianceId }
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance Core PUT "SslCertificates/$Thumbprint/Appliances" -Body $NewIds
}

<#
.SYNOPSIS
Get SSL certificate assigned to a specific Safeguard via the Web API.

.DESCRIPTION
Get the SSL certificate that has been previously assigned to a specific
Safeguard appliance.  If an appliance ID is not specified to this cmdlet
will use the appliance that you are communicating with.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER ApplianceId
A string containing the ID of the appliance to assign the SSL certificate to.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardTrustedCertificateForAppliance -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
Get-SafeguardTrustedCertificateForAppliance -ApplianceId 00155D26E342
#>

function Get-SafeguardSslCertificateForAppliance
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false,Position=1)]
        [string]$ApplianceId
    )

    $ErrorActionPreference = "Stop"

    if (-not $ApplianceId)
    {
        $ApplianceId = (Invoke-SafeguardMethod -Anonymous -Appliance $Appliance Notification GET Status).ApplianceId
    }

    $Certificates = (Get-SafeguardSslCertificate -AccessToken $AccessToken -Appliance $Appliance)
    $Certificates | ForEach-Object {
        if (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance Core GET "SslCertificates/$($_.Thumbprint)/Appliances" | Where-Object {
            $_.Id -eq $ApplianceId
        })
        {
            $_
        }
    }
}