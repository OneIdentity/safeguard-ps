# Global session variable for login information
try
{
    Get-Variable -Name "SafeguardSession" -Scope Global | Out-Null
}
catch
{
    New-Variable -Name "SafeguardSession" -Scope Global -Value $null
}

# SSL handling
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

# Helpers for calling Safeguard REST APIs
function New-SafeguardUrl
{
    $Url = "https://$Appliance/service/$($Service.ToLower())/v$Version/$RelativeUrl"
    if ($Parameters -and $Parameters.Length -gt 0)
    {
        $Url += "?"
        $Parameters.Keys | ForEach-Object {
            $Url += ($_ + "=" + $Parameters.Item($_) + "&")
        }
        $Url = $Url -replace ".$"
    }
    $Url
}
function Invoke-WithoutBody
{
    if ($InFile)
    {
        Invoke-RestMethod -Method $Method -Headers $Headers -Uri (New-SafeguardUrl) -InFile $InFile -OutFile $OutFile -TimeoutSec $Timeout
    }
    else
    {
        Invoke-RestMethod -Method $Method -Headers $Headers -Uri (New-SafeguardUrl) -OutFile $OutFile -TimeoutSec $Timeout
    }
}
function Invoke-WithBody
{
    Invoke-RestMethod -Method $Method -Headers $Headers -Uri (New-SafeguardUrl) -Body (ConvertTo-Json -InputObject $Body) -OutFile $OutFile -TimeoutSec $Timeout
}

<#
.SYNOPSIS
Call a method in the Safeguard Web API.

.DESCRIPTION
This utility is useful for calling the Safeguard Web API for testing or
scripting purposes. It provides  a couple benefits over using curl.exe or
Invoke-RestMethod by generating or reusing an access token and composing
the Url, parameters, and body for the request.

This script is meant to be used with the Login-Safeguard.ps1 script which
will generate and store a variable in the session so that it doesn't need
to be passed to each call to the API.  Call Logout=Safeguard.ps1 script
when finished.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER Service
Safeguard service you would like to call: Appliance or Core.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Method
REST method verb you would like to use: GET, PUT, POST, DELETE.

.PARAMETER RelativeUrl
Relative portion of the Url you would like to call starting after the version.

.PARAMETER Version
Version of the Web API you are using (default: 2).

.PARAMETER Accept
Specify the Accept header (default: application/json)

.PARAMETER ContentType
Specify the Content-type header (default: application/json)

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Body
A hash table containing an object to PUT or POST to the Url.

.PARAMETER Parameters
A hash table containing the HTTP query parameters to add to the Url.

.PARAMETER OutFile
A file to store the Web API response.

.PARAMETER InFile
A file to read for the body of a POST or PUT request.

.PARAMETER Timeout
A timeout value in seconds (default: 300s or 5m)

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Invoke-SafeguardMethod.ps1 -AccessToken $token -Appliance 10.5.32.54 Core GET Assets/16/Accounts

.EXAMPLE
.\Invoke-SafeguardMethod.ps1 -Appliance 10.5.32.54 -Anonymous notification GET SystemVerification/Manufacturing

.EXAMPLE
Invoke-SafeguardMethod.ps1 Appliance GET TrustedCertificates

.EXAMPLE
Invoke-SafeguardMethod.ps1 Core GET Users -Parameters @{ filter = "UserName eq 'admin'" }

.EXAMPLE
Invoke-SafeguardMethod.ps1 Core POST ReasonCodes -Body @{ Name = "RN12345"; Description = "Routine maintenance." }

.EXAMPLE
Invoke-SafeguardMethod.ps1 Core DELETE ReasonCodes/4

.EXAMPLE
Invoke-SafeguardMethod.ps1 PUT ReasonCodes/1 -Body @{ Name = "RN2233"; Description = "Service interrupted." }

#>
function Invoke-SafeguardMethod
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$true,Position=0)]
        [ValidateSet("Core","Appliance","Cluster","Notification",IgnoreCase=$true)]
        [string]$Service,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure = $false,
        [Parameter(Mandatory=$true,Position=1)]
        [ValidateSet("Get","Put","Post","Delete",IgnoreCase=$true)]
        [string]$Method,
        [Parameter(Mandatory=$true,Position=2)]
        [string]$RelativeUrl,
        [Parameter(Mandatory=$false)]
        [int]$Version = 2,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Anonymous = $false,
        [Parameter(Mandatory=$false)]
        [string]$Accept = "application/json",
        [Parameter(Mandatory=$false)]
        [string]$ContentType = "application/json",
        [Parameter(Mandatory=$false)]
        [object]$Body,
        [Parameter(Mandatory=$false)]
        [HashTable]$Parameters,
        [Parameter(Mandatory=$false)]
        [string]$OutFile = $null,
        [Parameter(Mandatory=$false)]
        [string]$InFile = $null,
        [Parameter(Mandatory=$false)]
        [int]$Timeout = 300
    )

    if (-not $AccessToken -and -not $Anonymous -and -not $SafeguardSession)
    {
        if (-not $Appliance)
        {
            $Appliance = (Read-Host "Appliance")
        }
        $AccessToken = (& $PsScriptRoot\Login-Safeguard.ps1 -Appliance $Appliance -NoSessionVariable)
    }
    elseif (-not $Anonymous)
    {
        if (-not $Appliance -and $SafeguardSession)
        {
            $Appliance = $SafeguardSession["Appliance"]
        }
        if (-not $AccessToken -and $SafeguardSession)
        {
            $AccessToken = $SafeguardSession["AccessToken"]
        }
        if (-not $Appliance)
        {
            $Appliance = (Read-Host "Appliance")
        }
        if (-not $AccessToken -and -not $Anonymous)
        {
            $AccessToken = (& $PsScriptRoot\Login-Safeguard.ps1 -Appliance $Appliance -NoSessionVariable)
        }
    }

    if ($Insecure)
    {
        Disable-SslVerification
    }

    $Headers = @{
            "Accept" = $Accept;
            "Content-type" = $ContentType;
        }
    
    if (-not $Anonymous)
    {
        $Headers["Authorization"] = "Bearer $AccessToken"
    }

    try {
        switch ($Method.ToLower())
        {
            {$_ -in "get","delete"} {
                Invoke-WithoutBody
                break
            }
            {$_ -in "put","post"} {
                if ($InFile)
                {
                    Invoke-WithoutBody
                }
                else
                {
                    Invoke-WithBody
                }
                break
            }
        }
    }
    finally {
        if ($Insecure)
        {
            Enable-SslVerification
        }
    }
}