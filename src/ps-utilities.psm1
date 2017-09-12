# This file contains random Powershell utilities required by some modules
# Nothing is exported from here

function Get-Confirmation
{
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

function Show-SshHostKeyPrompt
{
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

function Add-ExWebClientExType
{
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

function Test-IpAddress
{
    Param(
        [Parameter(Mandatory=$true)]
        [string]$IpAddress
    )

    [bool]($IpAddress -as [IPAddress])
}