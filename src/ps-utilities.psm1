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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
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
# Helper function for getting a client certificate from either the system store or from a PFX file
function Use-CertificateFile
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$CertificateFile,
        [Parameter(Mandatory=$false,Position=1)]
        [SecureString]$Password
    )

    if (-not $Password)
    {
        Get-PfxCertificate -FilePath $CertificateFile
    }
    else
    {
        $local:X509KeyStorageFlag = 0
        $local:Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $local:Cert.Import([string]($CertificateFile), [SecureString]($Password), $local:X509KeyStorageFlag)
        $local:Cert
    }
}
