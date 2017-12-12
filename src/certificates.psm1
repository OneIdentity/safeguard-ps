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

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

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
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [string]$CertificateFile
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local

    $local:CertificateContents = (Get-CertificateFileContents $CertificateFile)
    if (-not $CertificateContents)
    {
        throw "No valid certificate to upload"
    }

    Write-Host "Uploading Certificate..."
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
        POST TrustedCertificates -Body @{
            Base64CertificateData = "$($local:CertificateContents)"
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

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

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
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [string]$Thumbprint
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $Thumbprint)
    {
        $local:CurrentThumbprints = (Get-SafeguardTrustedCertificate -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure).Thumbprint -join ", "
        Write-Host "Currently Installed Trusted Certificates: [ $($local:CurrentThumbprints) ]"
        $Thumbprint = (Read-Host "Thumbprint")
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "TrustedCertificates/$Thumbprint"
}

<#
.SYNOPSIS
Get trusted certificates from Safeguard via the Web API.

.DESCRIPTION
Retrieve trusted certificates that were previously added to Safeguard via
the Web API.  These will be only the user-added trusted certificates.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Thumbprint
A string containing the thumbprint of the certificate.

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
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [string]$Thumbprint
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSBoundParameters.ContainsKey("Thumbprint"))
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "TrustedCertificates/$Thumbprint"
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET TrustedCertificates
    }
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

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

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
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [string]$CertificateFile,
        [Parameter(Mandatory=$false,Position=1)]
        [SecureString]$Password,
        [Parameter(Mandatory=$false)]
        [switch]$Assign
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local

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

    Write-Host "Uploading Certificate..."
    if ($local:PasswordPlainText)
    {
        $local:NewCertificate = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            POST SslCertificates -Body @{
                Base64CertificateData = "$($local:CertificateContents)";
                Passphrase = "$($local:PasswordPlainText)"
            })
    }
    else
    {
        $local:NewCertificate = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            POST SslCertificates -Body @{
                Base64CertificateData = "$($local:CertificateContents)" 
            })
    }

    $local:NewCertificate

    if ($Assign -and $local:NewCertificate.Thumbprint)
    {
        Set-SafeguardSslCertificateForAppliance -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $local:NewCertificate.Thumbprint
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

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

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
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [string]$Thumbprint
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $Thumbprint)
    {
        $local:CurrentThumbprints = (Get-SafeguardSslCertificate -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure).Thumbprint -join ", "
        Write-Host "Currently Installed SSL Certificates: [ $($local:CurrentThumbprints) ]"
        $Thumbprint = (Read-Host "Thumbprint")
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "SslCertificates/$Thumbprint"
}

<#
.SYNOPSIS
Get SSL certificates from Safeguard via the Web API.

.DESCRIPTION
Retrieve SSL certificates that were previously added to Safeguard via
the Web API.  These will also include the default SSL certificates.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Thumbprint
A string containing the thumbprint of the certificate.

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
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [string]$Thumbprint
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSBoundParameters.ContainsKey("Thumbprint"))
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "SslCertificates/$Thumbprint"
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET SslCertificates
    }
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

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Thumbprint
A string containing the thumbprint of the SSL certificate.

.PARAMETER ApplianceId
A string containing the ID of the appliance to assign the SSL certificate to.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Set-SafeguardSslCertificateForAppliance -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
Set-SafeguardSslCertificateForAppliance -Thumbprint 3E1A99AE7ACFB163DEE3CCAC00A437D675937FCA -ApplianceId 00155D26E342
#>
function Set-SafeguardSslCertificateForAppliance
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [string]$Thumbprint,
        [Parameter(Mandatory=$false,Position=1)]
        [string]$ApplianceId
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $Thumbprint)
    {
        $local:CurrentThumbprints = (Get-SafeguardSslCertificate -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure).Thumbprint -join ", "
        Write-Host "Currently Installed SSL Certificates: [ $($local:CurrentThumbprints) ]"
        $Thumbprint = (Read-Host "Thumbprint")
    }

    if (-not $ApplianceId)
    {
        $ApplianceId = (Invoke-SafeguardMethod -Anonymous -Appliance $Appliance -Insecure:$Insecure Notification GET Status).ApplianceId
    }

    Write-Host "Setting $Thumbprint as current SSL Certificate for $ApplianceId..."
    $local:CurrentIds = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "SslCertificates/$Thumbprint/Appliances")
    if (-not $local:CurrentIds)
    {
        $local:CurrentIds = @()
    }
    $local:CurrentIds += @{ "Id" = "$ApplianceId" }
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "SslCertificates/$Thumbprint/Appliances" -Body $local:CurrentIds
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

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Thumbprint
A string containing the thumbprint of the SSL certificate.

.PARAMETER ApplianceId
A string containing the ID of the appliance to unassign the SSL certificate from.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Clear-SafeguardSslCertificateForAppliance -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
Clear-SafeguardSslCertificateForAppliance -Thumbprint 3E1A99AE7ACFB163DEE3CCAC00A437D675937FCA -ApplianceId 00155D26E342
#>
function Clear-SafeguardSslCertificateForAppliance
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [string]$Thumbprint,
        [Parameter(Mandatory=$false,Position=1)]
        [string]$ApplianceId
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $Thumbprint)
    {
        $local:CurrentThumbprints = (Get-SafeguardSslCertificate -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure).Thumbprint -join ", "
        Write-Host "Currently Installed SSL Certificates: [ $($local:CurrentThumbprints) ]"
        $Thumbprint = (Read-Host "Thumbprint")
    }

    if (-not $ApplianceId)
    {
        $ApplianceId = (Invoke-SafeguardMethod -Anonymous -Appliance $Appliance -Insecure:$Insecure Notification GET Status).ApplianceId
    }

    Write-Host "Clearing $Thumbprint as current SSL Certificate for $ApplianceId..."
    $local:CurrentIds = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "SslCertificates/$Thumbprint/Appliances")
    $local:NewIds = $local:CurrentIds | Where-Object { $_.Id -ne $ApplianceId }
    if (-not $local:NewIds)
    {
        $local:NewIds = @()
    }
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "SslCertificates/$Thumbprint/Appliances" -Body $local:NewIds
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

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER ApplianceId
A string containing the ID of the appliance to assign the SSL certificate to.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardSslCertificateForAppliance -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
Get-SafeguardSslCertificateForAppliance -ApplianceId 00155D26E342
#>
function Get-SafeguardSslCertificateForAppliance
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=1)]
        [string]$ApplianceId
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $ApplianceId)
    {
        $ApplianceId = (Invoke-SafeguardMethod -Anonymous -Appliance $Appliance -Insecure:$Insecure Notification GET Status).ApplianceId
    }

    $local:Certificates = (Get-SafeguardSslCertificate -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure)
    $local:Certificates | ForEach-Object {
        if (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "SslCertificates/$($_.Thumbprint)/Appliances" | Where-Object {
            $_.Id -eq $ApplianceId
        })
        {
            $_
        }
    }
}

<#
.SYNOPSIS
Create test certificates for use with Safeguard.

.DESCRIPTION
Creates test certificates for use with Safeguard.  This cmdlet will create
a new root CA, an intermediate CA, a user certificate, and a server SSL
certificate.  The user certificate can be used for login.  The SSL certificate
can be used to secure Safeguard.

.PARAMETER SubjectBaseDn
A string containing the subject base Dn (e.g. "").

.PARAMETER KeySize
An integer with the RSA key size.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate--will be ignored for entire session.

.INPUTS
None.

.OUTPUTS
None.  Just host messages describing what has been created.

.EXAMPLE
New-SafeguardTestCertificates -SubjectBaseDn "OU=petrsnd,O=OneIdentityInc,C=US"

.EXAMPLE
New-SafeguardTestCertificates 
#>
function New-SafeguardTestCertificatePki
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$SubjectBaseDn,
        [Parameter(Mandatory=$false)]
        [int]$KeySize = 2048,
        [Parameter(Mandatory=$false)]
        $OutputDirectory
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local

    if (-not $OutputDirectory)
    {
        $OutputDirectory = (Join-Path (Get-Location) ("CERTS-{0}" -f (Get-Date -format s) -replace ':','-'))
    }
    else
    {
        $OutputDirectory = (Join-Path $OutputDirectory ("CERTS-{0}" -f (Get-Date -format s) -replace ':','-'))
    }

    Write-Host -ForegroundColor Yellow "Locating tools"
    $local:MakeCert = (Get-Tool @("C:\Program Files (x86)\Windows Kits", "C:\Program Files (x86)\Microsoft SDKs\Windows") "makecert.exe")
    $local:Pvk2Pfx = (Get-Tool @("C:\Program Files (x86)\Windows Kits", "C:\Program Files (x86)\Microsoft SDKs\Windows") "pvk2pfx.exe")
    $local:CertUtil = (Join-Path $env:windir "system32\certutil.exe")

    Write-Host "Creating Directory: $OutputDirectory"
    New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

    Write-Host -ForegroundColor Yellow "Generating Certificates"
    Write-Host "This cmdlet can be annoying because you have to type your password a lot... this is a limitation of the underlying tools"
    Write-Host -ForegroundColor Yellow "Just type the same password at all of the prompts!!! It can be as simple as one letter."
    $local:PasswordSecure = (Read-Host "Password" -AsSecureString)
    $local:Password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($local:PasswordSecure))

    $local:Name = "RootCA"
    $local:Subject = "CN=$($local:Name),$($local:SubjectBaseDn)"
    Write-Host "Creating Root CA Certificate as $($local:Subject)"
    Invoke-Expression ("& '$($local:MakeCert)' -n '$($local:Subject)' -r -a sha256 -len $($local:KeySize) -m 240 -cy authority -sky signature -sv '$OutputDirectory\$($local:Name).pvk' '$OutputDirectory\$($local:Name).cer'")
    Invoke-Expression ("& '$($local:CertUtil)' -encode '$OutputDirectory\$($local:Name).cer' '$OutputDirectory\$($local:Name).pem'")
    Invoke-Expression ("& '$($local:Pvk2Pfx)' -pvk '$OutputDirectory\$($local:Name).pvk' -spc '$OutputDirectory\$($local:Name).cer' -pfx '$OutputDirectory\$($local:Name).pfx' -pi $($local:Password)")

    $local:Issuer = "RootCA"
    $local:Name = "IntermediateCA"
    $local:Subject = "CN=$($local:Name),$SubjectBaseDn"
    Write-Host "Creating Intermediate CA Certificate as $($local:Subject)"
    Invoke-Expression ("& '$($local:MakeCert)' -n '$($local:Subject)' -a sha256 -len $KeySize -m 240 -cy authority -sky signature -iv '$OutputDirectory\$($local:Issuer).pvk' -ic '$OutputDirectory\$($local:Issuer).cer' -sv '$OutputDirectory\$($local:Name).pvk' '$OutputDirectory\$($local:Name).cer'")
    Invoke-Expression ("& '$($local:CertUtil)' -encode '$OutputDirectory\$($local:Name).cer' '$OutputDirectory\$($local:Name).pem'")
    Invoke-Expression ("& '$($local:Pvk2Pfx)' -pvk '$OutputDirectory\$($local:Name).pvk' -spc '$OutputDirectory\$($local:Name).cer' -pfx '$OutputDirectory\$($local:Name).pfx' -pi $($local:Password)")

    $local:Issuer = "IntermediateCA"
    $local:Name = "UserCert"
    $local:Subject = "CN=$($local:Name),$SubjectBaseDn"
    Write-Host "Creating User Certificate as $($local:Subject)"
    Invoke-Expression ("& '$($local:MakeCert)' -n '$($local:Subject)' -a sha256 -len $KeySize -m 120 -cy end -sky exchange -eku '1.3.6.1.4.1.311.10.3.4,1.3.6.1.5.5.7.3.4,1.3.6.1.5.5.7.3.2' -iv '$OutputDirectory\$($local:Issuer).pvk' -ic '$OutputDirectory\$($local:Issuer).cer' -sv '$OutputDirectory\$($local:Name).pvk' '$OutputDirectory\$($local:Name).cer'")
    Invoke-Expression ("& '$($local:CertUtil)' -encode '$OutputDirectory\$($local:Name).cer' '$OutputDirectory\$($local:Name).pem'")
    Invoke-Expression ("& '$($local:Pvk2Pfx)' -pvk '$OutputDirectory\$($local:Name).pvk' -spc '$OutputDirectory\$($local:Name).cer' -pfx '$OutputDirectory\$($local:Name).pfx' -pi $($local:Password)")

    $local:Issuer = "IntermediateCA"
    Write-Host "The IP address of your host is necessary to define the SSL Certificate subject name"
    $local:Name = Read-Host "IPAddress"
    $local:Subject = "CN=$($local:Name),$SubjectBaseDn"
    Write-Host "Creating User Certificate as $($local:Subject)"
    Invoke-Expression ("& '$($local:MakeCert)' -n '$($local:Subject)' -a sha256 -len $KeySize -m 120 -cy end -sky exchange -eku '1.3.6.1.5.5.7.3.1' -iv '$OutputDirectory\$($local:Issuer).pvk' -ic '$OutputDirectory\$($local:Issuer).cer' -sv '$OutputDirectory\$($local:Name).pvk' '$OutputDirectory\$($local:Name).cer'")
    Invoke-Expression ("& '$($local:CertUtil)' -encode '$OutputDirectory\$($local:Name).cer' '$OutputDirectory\$($local:Name).pem'")
    Invoke-Expression ("& '$($local:Pvk2Pfx)' -pvk '$OutputDirectory\$($local:Name).pvk' -spc '$OutputDirectory\$($local:Name).cer' -pfx '$OutputDirectory\$($local:Name).pfx' -pi $($local:Password)")

    Write-Host -ForegroundColor Yellow "You now have four certificates in $OutputDirectory."
    Write-Host -ForegroundColor Green "To setup Safeguard SSL:"
    Write-Host "- Upload both RootCA and IntermediateCA to Safeguard using Install-SafeguardTrustedCertificate cmdlet"
    Write-Host "- Upload the certificate with the IP address to Safeguard using Install-SafeguardSSlCertificate cmdlet"
    Write-Host "- Import RootCA into your trusted root store using 'Run -> certmgr.msc'"
    Write-Host "- Import IntermediateCA into your intermediate store using 'Run -> certmgr.msc'"
    Write-Host "- Then, open a browser to Safeguard... if the IP address matches the subject you gave it should work"
    Write-Host -ForegroundColor Green "To setup client certificate user login:"
    Write-Host "- Upload both RootCA and IntermediateCA if you haven't already using Install-SafeguardTrustedCertificate cmdlet"
    Write-Host "- Import UserCert into your personal user store"
    Write-Host "- Create a user with the PrimaryAuthenticationIdentity set to the thumbprint of UserCert"
    Write-Host "   - You can see your installed certificate thumbprints with: gci Cert:\CurrentUser\My\"
    Write-Host "   - The POST to create the user will need a body like this: -Body @{`n" `
    "                `"PrimaryAuthenticationProviderId`" = -2;`n" `
    "                `"UserName`" = `"CertBoy`";`n" `
    "                `"PrimaryAuthenticationIdentity`" = `"<thumbprint>`" }"
    Write-Host "- Test it by getting a token: Connect-Safeguard -Thumbprint `"<thumbprint>`""
}