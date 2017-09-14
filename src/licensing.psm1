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

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER LicenseFile
A string containing the path to a Safeguard license file.

.PARAMETER StageOnly
A flag meaning to only stage the license, not installed it (only works with -LicenseFile)

.PARAMETER Key
A string containing the license key (e.g. 123-123-123)

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
    [CmdletBinding(DefaultParameterSetName="File")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(ParameterSetName="File",Mandatory=$true,Position=0)]
        [string]$LicenseFile,
        [Parameter(ParameterSetName="File",Mandatory=$false)]
        [switch]$StageOnly,
        [Parameter(ParameterSetName="Key",Mandatory=$true)]
        [string]$Key
    )

    $ErrorActionPreference = "Stop"

    if ($PSBoundParameters.ContainsKey("LicenseFile"))
    {
        $local:LicenseContents = (Get-Content $LicenseFile)
        $local:LicenseBase64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($local:LicenseContents))
        Write-Host "Uploading license file..."
        $local:StagedLicense = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST Licenses -Body @{
                Base64Data = "$($local:LicenseBase64)" 
            })

        if ($StageOnly)
        {
            $local:StagedLicense
        }
        else
        {
            $Key = ($local:StagedLicense.Key)
        }
    }

    try
    {
        if (-not $StageOnly)
        {
            Write-Host "Installing license with key '$Key'..."
            Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "Licenses/$Key/Install"
        }
    }
    catch
    {
        if ($PSBoundParameters.ContainsKey("LicenseFile"))
        {
            Write-Host "License was only staged..."
            $local:StagedLicense
        }
        throw
    }
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

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

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
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [string]$Key
    )

    $ErrorActionPreference = "Stop"

    if (-not $PSBoundParameters.ContainsKey("Key"))
    {
        $CurrentKeys = (Get-SafeguardLicense -AccessToken $AccessToken -Appliance $Appliance).Key -join ", "
        Write-Host "Currently Installed Licenses: [ $CurrentKeys ]"
        $Key = (Read-Host "Key")
    }
    Write-Host "Removing license with key '$Key'..."
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "Licenses/$Key"
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

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

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
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [string]$Key
    )

    $ErrorActionPreference = "Stop"

    if ($PSBoundParameters.ContainsKey("Key"))
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Licenses/$Key"
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Licenses
    }
}