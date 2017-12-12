# This file contains random Powershell utilities required by some modules
# Nothing is exported from here

# Confirmation helper function
function Get-Confirmation
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Title,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$Message,
        [Parameter(Mandatory=$true,Position=2)]
        [string]$YesDescription,
        [Parameter(Mandatory=$true,Position=3)]
        [string]$NoDescription
    )

    $Yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", $YesDescription
    $No = New-Object System.Management.Automation.Host.ChoiceDescription "&No", $NoDescription
    $Options = [System.Management.Automation.Host.ChoiceDescription[]]($Yes, $No)
    $Result = $host.ui.PromptForChoice($Title, $Message, $Options, 0) 
    switch ($result)
    {
        0 {$true}
        1 {$false}
    }
}
# Show an SSH host key acceptance prompt
function Show-SshHostKeyPrompt
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$PublicKey,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$Fingerprint
    )
    Write-Host "SSH Host Key:"
    Write-Host "$PublicKey"
    Write-Host "Fingerprint:"
    Write-Host "$Fingerprint"
    Get-Confirmation "SSH Host Key" "Would you like to accept this SSH host key?" `
        "Accept SSH host key and add complete operation." "Deny SSH host key and revert operation."
}
# Add web client type with controllable timeout
function Add-ExWebClientExType
{
    [CmdletBinding()]
    Param(
    )

    if (-not ([System.Management.Automation.PSTypeName]"Ex.WebClientEx").Type)
    {
        Add-Type -WarningAction SilentlyContinue -TypeDefinition @"
using System;
using System.Net;

namespace Ex
{
    public class WebClientEx : WebClient
    {
        int _timeoutSeconds;

        public WebClientEx(int timeoutSeconds)
        {
            _timeoutSeconds = timeoutSeconds;
        }
        protected override WebRequest GetWebRequest(Uri uri)
        {
            var webRequest = base.GetWebRequest(uri);
            webRequest.Timeout = (int)TimeSpan.FromSeconds(_timeoutSeconds).TotalMilliseconds;
            return webRequest;
        }
    }
}
"@
    }
}
# Test whether a string is an IP address
function Test-IpAddress
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$IpAddress
    )

    [bool]($IpAddress -as [IPAddress])
}

# Certificate helper function
function Get-CertificateFileContents
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$CertificateFile
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    try 
    {
        $local:CertificateFullPath = (Resolve-Path $CertificateFile).ToString()
        if ((Get-Item $local:CertificateFullPath).Length -gt 100kb)
        {
            throw "'$CertificateFile' appears to be too large to be a certificate"
        }
    }
    catch
    {
        throw "'$CertificateFile' does not exist"
    }
    $local:CertificateContents = [string](Get-Content $local:CertificateFullPath)
    if (-not ($CertificateContents.StartsWith("-----BEGIN CERTIFICATE-----")))
    {
        Write-Host "Converting to Base64..."
        $local:CertificateContents = [System.IO.File]::ReadAllBytes($local:CertificateFullPath)
        $local:CertificateContents = [System.Convert]::ToBase64String($local:CertificateContents)
    }

    $local:CertificateContents
}
# Helper function for finding tools to generate certificates
function Get-Tool
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, Position=0)]
        [string[]]$Paths,
        [Parameter(Mandatory=$true, Position=1)]
        [string]$Tool
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    foreach ($local:SearchPath in $Paths)
    {
        Write-Host "Searching $($local:SearchPath) for $Tool"
        $local:ToolPath = (Get-ChildItem -Recurse -EA SilentlyContinue $local:SearchPath | Where-Object { $_.Name -eq $Tool })
        if ($local:ToolPath.Length -gt 0) 
        {
            $local:ToolPath[-1].Fullname
            return
        }
    }
    throw "Unable to find $Tool"
}
