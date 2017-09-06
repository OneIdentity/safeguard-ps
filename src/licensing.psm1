<#
.SYNOPSIS
Upload Safeguard license file and install it via the Web API.

.DESCRIPTION
Upload a Safeguard license file to the staging area and install it. In
the Web API this is a two stage process. This cmdlet performs both
staging and installation.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER LicenseFile
A string containing the path to a Safeguard license file.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Install-SafeguardLicense -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
Install-SafeguardLicense C:\license.dlv
#>
function Install-SafeguardLicense
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$true,Position=0)]
        [string]$LicenseFile
    )

    $ErrorActionPreference = "Stop"

    $LicenseContents = (Get-Content $LicenseFile)
    $LicenseBase64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($LicenseContents))
    
    Write-Host "Uploading License File..."
    $StagedLicense = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance Core POST Licenses -Body @{
            Base64Data = "$LicenseBase64" 
        })
    $StagedLicense

    Write-Host "Installing License $($StagedLicense.Key)..."
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance Core POST "Licenses/$($StagedLicense.Key)/Install"
}

<#
.SYNOPSIS
Uninstall Safeguard license file using the Web API.

.DESCRIPTION
Uninstall Safeguard license file that was previously installed on the
appliance.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Key
A string containing the license key (e.g. 123-123-123)

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Uninstall-SafeguardLicense -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
Uninstall-SafeguardLicense -Key "123-123-123"

#>
function Uninstall-SafeguardLicense
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false,Position=0)]
        [string]$Key
    )

    $ErrorActionPreference = "Stop"

    if (-not $Key)
    {
        $CurrentKeys = (Get-SafeguardLicense -AccessToken $AccessToken -Appliance $Appliance).Key -join ", "
        Write-Host "Currently Installed Licenses: [ $CurrentKeys ]"
        $Key = (Read-Host "Key")
    }
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance Core DELETE "Licenses/$Key"
}

<#
.SYNOPSIS
Get Safeguard license file(s) from the Web API.

.DESCRIPTION
Show Safeguard license file(s) currently installed on the appliance.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardLicense -AccessToken $token -Appliance 10.5.32.54

#>
function Get-SafeguardLicense
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken
    )

    $ErrorActionPreference = "Stop"

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance Core GET Licenses
}