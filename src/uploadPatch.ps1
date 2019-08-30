Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Patch,
        [Parameter(Mandatory=$false, Position=1)]
        [string]$Appliance,
        [Parameter(Mandatory=$false, Position=2)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false, Position=3)]
        [int]$Version,
        [Parameter(Mandatory=$false, Position=4)]
        [int]$Timeout,
        [Parameter(Mandatory=$false, Position=5)]
        [ValidateSet('True','False', IgnoreCase=$true)]
        [string]$Insecure
    )

try
{
    Import-Module -Name "$PSScriptRoot\sslhandling.psm1" -Scope Local
    Edit-SslVersionSupport

    [Boolean]$Insecure = [System.Convert]::ToBoolean($Insecure)

    if ($Insecure)
    {
        Disable-SslVerification
        if ($global:PSDefaultParameterValues) { $PSDefaultParameterValues = $global:PSDefaultParameterValues.Clone() }
    }
    # Use the WebClient class to avoid the content scraping slow down from Invoke-RestMethod as well as timeout issues
    Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local
    Add-ExWebClientExType

    $WebClient = (New-Object Ex.WebClientEx -ArgumentList @($Timeout))
    $WebClient.Headers.Add("Accept", "application/json")
    $WebClient.Headers.Add("Content-type", "application/octet-stream")
    $WebClient.Headers.Add("Authorization", "Bearer $AccessToken")
    Write-Host "Uploading patch to Safeguard ($Appliance). This operation may take several minutes..."
    $Bytes = [System.IO.File]::ReadAllBytes($Patch);

    $ResponseBytes = $WebClient.UploadData("https://$Appliance/service/appliance/v$Version/Patch", "POST", $Bytes) | Out-Null
    if ($ResponseBytes)
    {
        [System.Text.Encoding]::UTF8.GetString($ResponseBytes)
    }
}
catch [System.Net.WebException]
{
    Import-Module -Name "$PSScriptRoot\sg-utilities.psm1" -Scope Local
    Out-SafeguardExceptionIfPossible $_.Exception
}
