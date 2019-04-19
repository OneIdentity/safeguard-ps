# Global session variable for login information
Remove-Variable -Name "SafeguardSession" -Scope Global -ErrorAction "SilentlyContinue"
New-Variable -Name "SafeguardSession" -Scope Global -Value $null
$MyInvocation.MyCommand.ScriptBlock.Module.OnRemove = {
    Set-Variable -Name "SafeguardSession" -Scope Global -Value $null -ErrorAction "SilentlyContinue"
}
Edit-SslVersionSupport

function Get-SessionConnectionIdentifier
{
    [CmdletBinding()]
    Param(
    )

    if (-not $SafeguardSession)
    {
        "Not Connected"
    }
    else
    {
        if ($SafeguardSession["Gui"])
        {
            "$($SafeguardSession["Appliance"]) (GUI)"
        }
        else
        {
            $local:Identifier = "$($SafeguardSession["Appliance"]) ($($SafeguardSession["IdentityProvider"])"
            if (($SafeguardSession["IdentityProvider"]) -ieq "certificate")
            {
                if ($SafeguardSession["Thumbprint"])
                {
                    $local:Identifier = "$($local:Identifier)\$($SafeguardSession["Thumbprint"]))"
                }
                else
                {
                    $local:Identifier = "$($local:Identifier)\$($SafeguardSession["CertificateFile"]))"
                }
            }
            else
            {
                $local:Identifier = "$($local:Identifier)\$($SafeguardSession["Username"]))"
            }
            $local:Identifier
        }
    }

}
function Show-RstsWindow
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Appliance,
        [Parameter(Mandatory=$false,Position=1)]
        [string]$PrimaryProviderId = "",
        [Parameter(Mandatory=$false,Position=2)]
        [string]$SecondaryProviderId = ""
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not ([System.Management.Automation.PSTypeName]"RstsWindow").Type)
    {
        Write-Verbose "Adding the PSType for rSTS Web form interaction"
        Add-Type -TypeDefinition  @"
        using System;
        using System.Text.RegularExpressions;
        using System.Web;
        using System.Windows.Forms;
        public class RstsWindow {
            private const string ClientId = "00000000-0000-0000-0000-000000000000";
            private const string RedirectUri = "urn%3AInstalledApplication";
            private readonly string _appliance;
            private System.Windows.Forms.Form _form;
            private WebBrowser _browser;
            public RstsWindow(string appliance) {
                _appliance = appliance;
                _form = new Form() { Text = string.Format("{0} - Safeguard Login", _appliance),
                                     Width = 640, Height = 720, StartPosition = FormStartPosition.CenterParent };
                _browser = new WebBrowser() { Dock = DockStyle.Fill, AllowNavigation = true };
                _form.Controls.Add(_browser);
                _browser.DocumentTitleChanged += (sender, args) => {
                    var b = (WebBrowser)sender;
                    if (Regex.IsMatch(b.DocumentTitle, "error=[^&]*|code=[^&]*")) {
                        AuthorizationCode = b.DocumentTitle.Substring(5);
                        _form.DialogResult = DialogResult.OK;
                        _form.Hide(); }
                };
            }
            public string AuthorizationCode { get; set; }
            public bool Show(string primaryProviderId = "", string secondaryProviderId = "") {
                try {
                    string url;
                    if (!string.IsNullOrEmpty(primaryProviderId) && !string.IsNullOrEmpty(secondaryProviderId))
                        url = string.Format("https://{0}/RSTS/Login?response_type=code&client_id={1}&redirect_uri={2}&primaryproviderid={3}&secondaryproviderid={4}",
                            _appliance, ClientId, RedirectUri, HttpUtility.UrlEncode(primaryProviderId), HttpUtility.UrlEncode(secondaryProviderId));
                    else
                        url = string.Format("https://{0}/RSTS/Login?response_type=code&client_id={1}&redirect_uri={2}", _appliance, ClientId, RedirectUri);
                    _browser.Stop();
                    _browser.Navigate(url);
                    if (_form.ShowDialog() == DialogResult.OK) { return true; }
                    return false;
                } catch (Exception e) {
                    var color = Console.ForegroundColor; Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine(e); Console.ForegroundColor = color;
                    return false;
                }
            }
        }
"@ -ReferencedAssemblies System.Windows.Forms,System.Web
    }

    if (-not $global:Browser)
    {
        $local:Browser = New-Object -TypeName RstsWindow -ArgumentList $Appliance
    }
    if (!$local:Browser.Show($PrimaryProviderId, $SecondaryProviderId))
    {
        throw "Unable to correctly manipulate browser"
    }
    $global:AuthorizationCode = $local:Browser.AuthorizationCode
    $local:Browser = $null
}
function Get-RstsTokenFromGui
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Appliance,
        [Parameter(Mandatory=$false,Position=1)]
        [string]$PrimaryProviderId = "",
        [Parameter(Mandatory=$false,Position=2)]
        [string]$SecondaryProviderId = ""
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSVersionTable.PSEdition -eq "Core")
    {
        throw "This -Gui parameter is not supported in PowerShell Core"
    }

    Show-RstsWindow $Appliance $PrimaryProviderId $SecondaryProviderId
    $local:Code = $global:AuthorizationCode
    Remove-Variable -Name AuthorizationCode -Scope Global -Force -ErrorAction "SilentlyContinue"
    if (-not $local:Code)
    {
        throw "Unable to obtain authorization code"
    }
    Invoke-RestMethod -Method POST -Headers @{
        "Accept" = "application/json";
        "Content-type" = "application/json"
    } -Uri "https://$Appliance/RSTS/oauth2/token" -Body @"
{
"grant_type": "authorization_code",
"client_id": "$($script:ClientId)",
"redirect_uri": "$($script:RedirectUri)",
"code": "$($local:Code)"
}
"@
}
function New-SafeguardUrl
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Appliance,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$Service,
        [Parameter(Mandatory=$true,Position=2)]
        [int]$Version,
        [Parameter(Mandatory=$true,Position=3)]
        [string]$RelativeUrl,
        [Parameter(Mandatory=$false)]
        [object]$Parameters
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Url = "https://$Appliance/service/$($Service.ToLower())/v$Version/$RelativeUrl"
    if ($Parameters -and $Parameters.Length -gt 0)
    {
        $local:Url += "?"
        $Parameters.Keys | ForEach-Object {
            $local:Url += ($_ + "=" + $Parameters.Item($_) + "&")
        }
        $local:Url = $local:Url -replace ".$"
    }
    $local:Url
}
function Wait-LongRunningTask
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [object]$Response,
        [Parameter(Mandatory=$true,Position=1)]
        [object]$Headers,
        [Parameter(Mandatory=$true,Position=2)]
        [int]$Timeout
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $Response.Headers.Location)
    {
        throw "Trying to track long running task, but response did not include a Location header"
    }

    $local:StartTime = (Get-Date)
    $local:TaskResult = $null
    $local:TaskToPoll = $Response.Headers.Location
    do {
        $local:TaskResponse = (Invoke-RestMethod -Method GET -Headers $Headers -Uri $local:TaskToPoll)
        Write-Verbose $local:TaskResponse
        Write-Verbose $local:TaskResponse.RequestStatus
        if (-not $local:TaskResponse.RequestStatus)
        {
            throw "Trying to track long running task, but Location URL did not return a long running task"
        }
        $local:TaskStatus = $local:TaskResponse.RequestStatus
        if ($local:TaskStatus.PercentComplete -eq 100)
        {
            Write-Progress -Activity "Waiting for long-running task" -Status "Step: $($local:TaskStatus.Message)" -PercentComplete $local:TaskStatus.PercentComplete
            $local:TaskResult = $local:TaskStatus.Message
        }
        else
        {
            $local:Percent = 0
            if ($local:TaskStatus.PercentComplete)
            {
                $local:Percent = $local:TaskStatus.PercentComplete
            }
            Write-Progress -Activity "Waiting for long-running task" -Status "Step: $($local:TaskStatus.Message)" -PercentComplete $local:Percent
            if ((((Get-Date) - $local:StartTime).TotalSeconds) -gt $Timeout)
            {
                throw "Timed out waiting for long-running task, timeout was $Timeout seconds"
            }
        }
        Start-Sleep 1
    } until ($local:TaskResult)
    if ($local:TaskStatus.State -ieq "Failure")
    {
        throw $local:TaskResult
    }
    $local:TaskResult
}
function Invoke-WithoutBody
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Appliance,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$Service,
        [Parameter(Mandatory=$true,Position=2)]
        [string]$Method,
        [Parameter(Mandatory=$true,Position=3)]
        [int]$Version,
        [Parameter(Mandatory=$true,Position=4)]
        [string]$RelativeUrl,
        [Parameter(Mandatory=$true,Position=5)]
        [object]$Headers,
        [Parameter(Mandatory=$false)]
        [object]$Parameters,
        [Parameter(Mandatory=$false)]
        [string]$InFile,
        [Parameter(Mandatory=$false)]
        [string]$OutFile,
        [Parameter(Mandatory=$false)]
        [switch]$LongRunningTask,
        [Parameter(Mandatory=$false)]
        [int]$Timeout
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Url = (New-SafeguardUrl $Appliance $Service $Version $RelativeUrl -Parameters $Parameters)
    Write-Verbose "Url=$($local:Url)"
    Write-Verbose "Parameters=$(ConvertTo-Json -InputObject $Parameters)"
    if ($InFile)
    {
        if ($LongRunningTask)
        {
            $local:Response = (Invoke-WebRequest -Method $Method -Headers $Headers -Uri $local:Url `
                                   -InFile $InFile -OutFile $OutFile -TimeoutSec $Timeout)
            Wait-LongRunningTask $local:Response $Headers $Timeout
        }
        else
        {
            Invoke-RestMethod -Method $Method -Headers $Headers -Uri $local:Url -InFile $InFile -OutFile $OutFile -TimeoutSec $Timeout
        }
    }
    else
    {
        if ($LongRunningTask)
        {
            $local:Response = $(Invoke-RestMethod -Method $Method -Headers $Headers -Uri $local:Url `
                                    -InFile $InFile -OutFile $OutFile -TimeoutSec $Timeout)
            Wait-LongRunningTask $local:Response $Headers $Timeout
        }
        else
        {
            Invoke-RestMethod -Method $Method -Headers $Headers -Uri $local:Url -OutFile $OutFile -TimeoutSec $Timeout
        }
    }
}
function Invoke-WithBody
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Appliance,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$Service,
        [Parameter(Mandatory=$true,Position=2)]
        [string]$Method,
        [Parameter(Mandatory=$true,Position=3)]
        [int]$Version,
        [Parameter(Mandatory=$true,Position=4)]
        [string]$RelativeUrl,
        [Parameter(Mandatory=$true,Position=5)]
        [object]$Headers,
        [Parameter(Mandatory=$false)]
        [object]$Body,
        [Parameter(Mandatory=$false)]
        [object]$JsonBody,
        [Parameter(Mandatory=$false)]
        [object]$Parameters,
        [Parameter(Mandatory=$false)]
        [string]$OutFile,
        [Parameter(Mandatory=$false)]
        [switch]$LongRunningTask,
        [Parameter(Mandatory=$false)]
        [int]$Timeout
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:BodyInternal = $JsonBody
    if ($Body)
    {
        $local:BodyInternal = (ConvertTo-Json -Depth 5 -InputObject $Body)
    }
    $local:Url = (New-SafeguardUrl $Appliance $Service $Version $RelativeUrl -Parameters $Parameters)
    Write-Verbose "Url=$($local:Url)"
    Write-Verbose "Parameters=$(ConvertTo-Json -InputObject $Parameters)"
    Write-Verbose "---Request Body---"
    Write-Verbose "$($local:BodyInternal)"
    if ($LongRunningTask)
    {
        $local:Response = (Invoke-WebRequest -Method $Method -Headers $Headers -Uri $local:Url `
                           -Body ([System.Text.Encoding]::UTF8.GetBytes($local:BodyInternal)) `
                           -OutFile $OutFile -TimeoutSec $Timeout)
        Wait-LongRunningTask $local:Response $Headers $Timeout
    }
    else
    {
        Invoke-RestMethod -Method $Method -Headers $Headers -Uri $local:Url `
            -Body ([System.Text.Encoding]::UTF8.GetBytes($local:BodyInternal)) `
            -OutFile $OutFile -TimeoutSec $Timeout
    }
}

function Invoke-Internal
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Appliance,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$Service,
        [Parameter(Mandatory=$true,Position=2)]
        [string]$Method,
        [Parameter(Mandatory=$true,Position=3)]
        [int]$Version,
        [Parameter(Mandatory=$true,Position=4)]
        [string]$RelativeUrl,
        [Parameter(Mandatory=$true,Position=5)]
        [object]$Headers,
        [Parameter(Mandatory=$false)]
        [object]$Body,
        [Parameter(Mandatory=$false)]
        [object]$JsonBody,
        [Parameter(Mandatory=$false)]
        [object]$Parameters,
        [Parameter(Mandatory=$false)]
        [string]$InFile,
        [Parameter(Mandatory=$false)]
        [string]$OutFile,
        [Parameter(Mandatory=$false)]
        [switch]$LongRunningTask,
        [Parameter(Mandatory=$false)]
        [int]$Timeout
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    try
    {
        switch ($Method.ToLower())
        {
            {$_ -in "get","delete"} {
                Invoke-WithoutBody $Appliance $Service $Method $Version $RelativeUrl $Headers `
                    -Parameters $Parameters -InFile $InFile -OutFile $OutFile -LongRunningTask:$LongRunningTask -Timeout $Timeout 
                break
            }
            {$_ -in "put","post"} {
                if ($InFile)
                {
                    Invoke-WithoutBody $Appliance $Service $Method $Version $RelativeUrl $Headers `
                        -Parameters $Parameters -InFile $InFile -OutFile $OutFile -LongRunningTask:$LongRunningTask -Timeout $Timeout
                }
                else
                {
                    Invoke-WithBody $Appliance $Service $Method $Version $RelativeUrl $Headers `
                        -Body $Body -JsonBody $JsonBody `
                        -Parameters $Parameters -OutFile $OutFile -LongRunningTask:$LongRunningTask -Timeout $Timeout
                }
                break
            }
        }
    }
    catch
    {
        Import-Module -Name "$PSScriptRoot\sg-utilities.psm1" -Scope Local
        Out-SafeguardExceptionIfPossible $_.Exception
    }
}

<#
.SYNOPSIS
Log into a Safeguard appliance in this Powershell session for the purposes
of using the Web API.

.DESCRIPTION
This utility can help you securely obtain an access token from a Safeguard
appliance and save it as a global variable. Optionally, the token can be
returned to standard out and not saved in the session.

The password may be passed in as a SecureString or a Powershell
credential can be used for both username and password. By default, this
script will securely prompt for the password. Client certificate
authentication is also supported. Two-factor authentication is not supported.

First this script retrieves an access token from the embedded redistributable
secure token service. Then, it exchanges this token for a Safeguard user token.

You must use the -Gui parameter for 2FA login support.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate--will be ignored for entire session.

.PARAMETER IdentityProvider
Identity provider to use for RSTS authentication (e.g. local, certificate, ad<int>-<domain>)

.PARAMETER Credential
Powershell credential to be used for username and password.

.PARAMETER Username
The username to authenticate as when not using Powershell credential.

.PARAMETER Password
SecureString containing the password.

.PARAMETER CertificateFile
Path to a PFX (PKCS12) file containing the client certificate to use to connect to the RSTS.

.PARAMETER Thumbprint
Client certificate thumbprint to use to authenticate the connection to the RSTS.

.PARAMETER Version
Version of the Web API you are using (default: 3).

.PARAMETER Gui
Display redistributable STS login window in a browser.  Supports 2FA.

.PARAMETER NoSessionVariable
If this switch is sent the access token will be returned and a login session context variable will not be created.

.INPUTS
None.

.OUTPUTS
None (with LoginSession variable filled out) or AccessToken for calling Web API.


.EXAMPLE
Connect-Safeguard 10.5.32.54 local -Credential (Get-Credential)

Login Successful.

.EXAMPLE
Connect-Safeguard 10.5.32.54 -Gui -Insecure

[Opens browser window for normal Safeguard login experience, including 2FA]


.EXAMPLE
Connect-Safeguard 10.5.32.54 -Username admin -Insecure
(certificate, local)
IdentityProvider: local
Password: ********

Login Successful.


.EXAMPLE
Connect-Safeguard 10.5.32.162 -Thumbprint "AB40BF0AD5647C9A8E0431DA5F473F44910D8975"

Login Successful.


.EXAMPLE
Connect-Safeguard 10.5.32.162 ad18-green.vas
Username: petrsnd
Password: **********

Login Successful.


.EXAMPLE
Connect-Safeguard 10.5.32.162 local Admin Admin123 -NoSessionVariable
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1Ni...

#>
function Connect-Safeguard
{
    [CmdletBinding(DefaultParameterSetName="Username")]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure = $false,
        [Parameter(Mandatory=$false,Position=1)]
        [string]$IdentityProvider,
        [Parameter(ParameterSetName="PSCredential",Position=2)]
        [PSCredential]$Credential,
        [Parameter(ParameterSetName="Username",Mandatory=$false,Position=2)]
        [string]$Username,
        [Parameter(ParameterSetName="Username",Position=3)]
        [SecureString]$Password,
        [Parameter(ParameterSetName="Certificate",Mandatory=$false)]
        [string]$CertificateFile,
        [Parameter(ParameterSetName="Certificate",Mandatory=$false)]
        [string]$Thumbprint,
        [Parameter(Mandatory=$false)]
        [switch]$Gui,
        [Parameter(Mandatory=$false)]
        [int]$Version = 3,
        [Parameter(Mandatory=$false)]
        [switch]$NoSessionVariable = $false
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    try
    {
        Edit-SslVersionSupport
        if ($Insecure)
        {
            Disable-SslVerification
            if ($global:PSDefaultParameterValues) { $PSDefaultParameterValues = $global:PSDefaultParameterValues.Clone() }
        }

        if ($Gui)
        {
            $local:RstsResponse = (Get-RstsTokenFromGui $Appliance)
        }
        else
        {
            Write-Verbose "Getting configured identity providers from RSTS service (using POST)..."
            $local:GetPrimaryProvidersRelativeURL = "RSTS/UserLogin/LoginController?response_type=token&redirect_uri=urn:InstalledApplication&loginRequestStep=1"
            try
            {
                $local:ConfiguredProvidersRaw = (Invoke-RestMethod -Method POST -Uri "https://$Appliance/$($local:GetPrimaryProvidersRelativeURL)" `
                                              -Headers @{ "Content-type" = "application/x-www-form-urlencoded" } `
                                              -Body "RelayState=" `
                                              -ErrorAction SilentlyContinue).Providers
            }
            catch [Net.WebException]
            {
                Write-Verbose "Initial attempt returned WebException: $($_.Exception.Status)"
                if ($_.Exception.Status -eq "ConnectFailure")
                {
                    throw "Unable to connect to $Appliance, bad appliance network address?"
                }
            }
            catch
            {
                Write-Verbose "Initial attempt threw unknown exception"
            }
            if (-not $local:ConfiguredProvidersRaw)
            {
                try
                {
                    Write-Verbose "Getting configured identity providers from RSTS service (using GET)..."
                    $local:ConfiguredProvidersRaw = (Invoke-RestMethod -Method GET -Uri "https://$Appliance/$($local:GetPrimaryProvidersRelativeURL)" `
                                                  -ErrorAction SilentlyContinue).Providers
                }
                catch
                {
                    Write-Verbose "Also threw an unknown exception"
                }
            }

            # Built-in providers
            $local:ConfiguredProviders = ,(New-Object -TypeName PSObject -Property @{
                Id = "certificate";
                DisplayName = "certificate"
            }),(New-Object -TypeName PSObject -Property @{
                Id = "local";
                DisplayName = "Local"
            })
            $local:ConfiguredProvidersRaw | Sort-Object DisplayName | ForEach-Object {
                # Trim out local so we can control order
                if ($_.Id -ine "local")
                {
                    $local:ConfiguredProviders += (New-Object -TypeName PSObject -Property @{
                        Id = $_.Id;
                        DisplayName = $_.DisplayName
                    })
                }
            }

            $local:IdentityProviders = ($local:ConfiguredProviders | ForEach-Object {
                if ($_.Id -ieq "certificate" -or $_.Id -ieq "local")
                {
                    "$($_.Id)"
                }
                else
                {
                    "$($_.Id) [$($_.DisplayName)]"
                }
            })
            if (-not $IdentityProvider)
            {
                Write-Verbose "Identity provider not passed in"
                if ($Thumbprint -or $CertificateFile)
                {
                    $IdentityProvider = "certificate"
                }
                else
                {
                    if ($local:ConfiguredProviders)
                    {
                        Write-Host "($($local:IdentityProviders -join ", "))"
                    }
                    else 
                    {
                        Write-Warning "Unable to detect identity providers -- report this as an issue"
                    }
                    $IdentityProvider = (Read-Host "Provider")
                }
            }
            if ($local:ConfiguredProviders -and ($local:ConfiguredProviders.Id.ToLower() -notcontains $IdentityProvider.ToLower() `
                -and $local:ConfiguredProviders.DisplayName.ToLower() -notcontains $IdentityProvider.ToLower()))
            {
                throw "IdentityProvider '$($local:IdentityProvider)' not found in ($($local:IdentityProviders -join ", "))"
            }

            # Allow the caller to specify the domain name for AD
            $local:ConfiguredProviders | ForEach-Object {
                if ($_.DisplayName.ToLower() -ieq $IdentityProvider)
                {
                    $IdentityProvider = $_.Id
                }
            }
    
            if ($IdentityProvider -ieq "certificate")
            {
                if (-not $Thumbprint -and -not $CertificateFile)
                {
                    $Thumbprint = (Read-Host "Thumbprint")
                }
                $local:Scope = "rsts:sts:primaryproviderid:certificate"
            }
            else
            {
                switch ($PsCmdlet.ParameterSetName)
                {
                    "Username" {
                        if (-not $Username)
                        {
                            $Username = (Read-Host "Username")
                        }
                        if (-not $Password)
                        { 
                            $Password = (Read-Host "Password" -AsSecureString)
                        }
                        $local:PasswordPlainText = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
                        break
                    }
                    "PSCredential" {
                        $Username = $Credential.UserName
                        $local:PasswordPlainText = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password))
                        break
                    }
                    "Certificate" {
                        $IdentityProvider = "certificate"
                        $local:Scope = "rsts:sts:primaryproviderid:certificate"
                    }
                }
            }
        
            if ($Username)
            {
                try
                {
                    Write-Verbose "Calling RSTS token service for password authentication..."
                    $local:Scope = "rsts:sts:primaryproviderid:$($IdentityProvider.ToLower())"
                    $RstsResponse = (Invoke-RestMethod -Method POST -Headers @{
                        "Accept" = "application/json";
                        "Content-type" = "application/json"
                    } -Uri "https://$Appliance/RSTS/oauth2/token" -Body @"
{
    "grant_type": "password",
    "username": "$Username",
    "password": "$($local:PasswordPlainText)",
    "scope": "$($local:Scope)"
}
"@)
                }
                catch
                {
                    Import-Module -Name "$PSScriptRoot\sg-utilities.psm1" -Scope Local
                    Out-SafeguardExceptionIfPossible $_.Exception
                }
            }
            else # Assume Client Certificate Authentication
            {
                try
                {
                    if (-not $Thumbprint)
                    {
                        Write-Verbose "Calling RSTS token service for client certificate authentication (PKCS#12 file)..."
                        # From PFX file
                        $local:ClientCertificate = (Get-PfxCertificate -FilePath $CertificateFile)
                        $local:RstsResponse = (Invoke-RestMethod -Certificate $local:ClientCertificate -Method POST -Headers @{
                            "Accept" = "application/json";
                            "Content-type" = "application/json"
                        } -Uri "https://$Appliance/RSTS/oauth2/token" -Body @"
{
    "grant_type": "client_credentials",
    "scope": "$($local:Scope)"
}
"@)
                    }
                    else
                    {
                        Write-Verbose "Calling RSTS token service for client certificate authentication (Windows cert store)..."
                        # From thumbprint in Windows Certificate Store
                        $local:RstsResponse = (Invoke-RestMethod -CertificateThumbprint $Thumbprint -Method POST -Headers @{
                            "Accept" = "application/json";
                            "Content-type" = "application/json"
                        } -Uri "https://$Appliance/RSTS/oauth2/token" -Body @"
{
    "grant_type": "client_credentials",
    "scope": "$($local:Scope)"
}
"@)
                    }
                }
                catch
                {
                    Write-Verbose "An exception was caught trying to authenticate to RSTS using a certificate."
                    Write-Verbose "Your problem may be an quirk on Windows where the low-level HTTPS client requires that you have the Issuing CA"
                    Write-Verbose "in your 'Intermediate Certificate Authorities' store, otherwise Windows doesn't think you have a matching"
                    Write-Verbose "certificate to send in the initial client connection. This occurs even if you pass in a PFX file specifying"
                    Write-Verbose "exactly which certificate to use."
                    Import-Module -Name "$PSScriptRoot\sg-utilities.psm1" -Scope Local
                    Out-SafeguardExceptionIfPossible $_.Exception
                }
            }
        }

        if (-not $local:RstsResponse)
        {
            throw "Failed to get RSTS token response"
        }

        Write-Verbose "Calling Safeguard LoginResponse service..."
        try
        {
            $local:LoginResponse = (Invoke-RestMethod -Method POST -Headers @{
                "Accept" = "application/json";
                "Content-type" = "application/json"
            } -Uri "https://$Appliance/service/core/v$Version/Token/LoginResponse" -Body @"
{
    "StsAccessToken": "$($local:RstsResponse.access_token)"
}
"@)
        }
        catch
        {
            if ([int]($_.Exception.Response.StatusCode) -eq 404)
            {
                $Version -= 1
                $local:LoginResponse = (Invoke-RestMethod -Method POST -Headers @{
                    "Accept" = "application/json";
                    "Content-type" = "application/json"
                } -Uri "https://$Appliance/service/core/v$Version/Token/LoginResponse" -Body @"
{
    "StsAccessToken": "$($local:RstsResponse.access_token)"
}
"@)
            }
            else
            {
                throw
            }
        }
        if ($local:LoginResponse.Status -eq "Needs2FA" -and $Gui)
        {
            $local:RstsResponse = (Get-RstsTokenFromGui $Appliance $local:LoginResponse.PrimaryProviderId $local:LoginResponse.SecondaryProviderId)
            Write-Verbose "Re-calling Safeguard LoginResponse service..."
            $local:LoginResponse = (Invoke-RestMethod -Method POST -Headers @{
                "Accept" = "application/json";
                "Content-type" = "application/json"
            } -Uri "https://$Appliance/service/core/v$Version/Token/LoginResponse" -Body @"
{
    "StsAccessToken": "$($local:RstsResponse.access_token)"
}
"@)
        }
        if ($local:LoginResponse.Status -ine "Success")
        {
            throw $local:LoginResponse
        }

        if ($NoSessionVariable)
        {
            $local:LoginResponse.UserToken
        }
        else
        {
            Write-Verbose "Setting up the SafeguardSession variable"
            if ($CertificateFile)
            {
                try { $CertificateFile = (Resolve-Path $CertificateFile).Path } catch {}
            }
            Set-Variable -Name "SafeguardSession" -Scope Global -Value @{
                "Appliance" = $Appliance;
                "Version" = $Version
                "IdentityProvider" = $IdentityProvider;
                "Username" = $Username;
                "AccessToken" = $local:LoginResponse.UserToken;
                "Thumbprint" = $Thumbprint;
                "CertificateFile" = $CertificateFile;
                "Insecure" = $Insecure;
                "Gui" = $Gui;
            }
            $Host.UI.RawUI.WindowTitle = "Windows PowerShell -- Safeguard Connection: $(Get-SessionConnectionIdentifier)"
            Write-Host "Login Successful."
        }
    }
    finally
    {
        if ($Insecure)
        {
            Enable-SslVerification
            if ($global:PSDefaultParameterValues) { $PSDefaultParameterValues = $global:PSDefaultParameterValues.Clone() }
        }
    }
}

<#
.SYNOPSIS
Log out of a Safeguard appliance in this Powershell session when finished
using the Web API.

.DESCRIPTION
This utility will invalidate your token and remove the session variable
that was created by the Connect-Safeguard cmdlet.

.PARAMETER Appliance
Which appliance to contact when not using session variable.

.PARAMETER AccessToken
Invalidate specific access token rather than the session variable.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Version
Version of the Web API you are using (default: 3).

.INPUTS
None.

.OUTPUTS
None.

.EXAMPLE
Disconnect-Safeguard

Log out Successful.

#>
function Disconnect-Safeguard
{
    [CmdletBinding(DefaultParameterSetName='None')]
    Param(
        [Parameter(ParameterSetName="AccessToken",Mandatory=$true,Position=0)]
        [string]$Appliance,
        [Parameter(ParameterSetName="AccessToken",Mandatory=$true,Position=1)]
        [object]$AccessToken,
        [Parameter(ParameterSetName="AccessToken",Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(ParameterSetName="AccessToken",Mandatory=$false)]
        [int]$Version = 3
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PsCmdlet.ParameterSetName -eq "AccessToken")
    {
        try
        {
            Edit-SslVersionSupport
            if ($Insecure)
            {
                Disable-SslVerification
                if ($global:PSDefaultParameterValues) { $PSDefaultParameterValues = $global:PSDefaultParameterValues.Clone() }
            }
            Write-Verbose "Calling Safeguard Logout service..."
            $local:Headers = @{
                "Accept" = "application/json";
                "Content-type" = "application/json";
                "Authorization" = "Bearer $AccessToken"
            }
            Invoke-RestMethod -Method POST -Headers $local:Headers -Uri "https://$Appliance/service/core/v$Version/Token/Logout"
            Write-Host "Log out Successful."
        }
        finally
        {
            if ($Insecure)
            {
                Enable-SslVerification
                if ($global:PSDefaultParameterValues) { $PSDefaultParameterValues = $global:PSDefaultParameterValues.Clone() }
            }
        }
    }
    else
    {
        try
        {
            if (-not $SafeguardSession)
            {
                Write-Host "Not logged in."
            }
            else
            {
                $Appliance = $SafeguardSession["Appliance"]
                $Version = $SafeguardSession["Version"]
                $AccessToken = $SafeguardSession["AccessToken"]
                $Insecure = $SafeguardSession["Insecure"]
                Edit-SslVersionSupport
                if ($Insecure)
                {
                    Disable-SslVerification
                    if ($global:PSDefaultParameterValues) { $PSDefaultParameterValues = $global:PSDefaultParameterValues.Clone() }
                }
                Write-Host "Logging out $(Get-SessionConnectionIdentifier)"
                Write-Verbose "Calling Safeguard Logout service..."
                $local:Headers = @{
                    "Accept" = "application/json";
                    "Content-type" = "application/json";
                    "Authorization" = "Bearer $AccessToken"
                }
                Invoke-RestMethod -Method POST -Headers $local:Headers -Uri "https://$Appliance/service/core/v$Version/Token/Logout"
            }
            $Host.UI.RawUI.WindowTitle = "Windows PowerShell"
            Write-Host "Log out Successful."
        }
        finally
        {
            Write-Host "Session variable removed."
            Set-Variable -Name "SafeguardSession" -Scope Global -Value $null
            if ($Insecure)
            {
                Enable-SslVerification
                if ($global:PSDefaultParameterValues) { $PSDefaultParameterValues = $global:PSDefaultParameterValues.Clone() }
            }
        }
    }
}

<#
.SYNOPSIS
Call a method in the Safeguard Web API.

.DESCRIPTION
This utility is useful for calling the Safeguard Web API for testing or
scripting purposes. It provides  a couple benefits over using curl.exe or
Invoke-RestMethod by generating or reusing an access token and composing
the Url, parameters, and body for the request.

This script is meant to be used with the Connect-Safeguard cmdlet which
will generate and store a variable in the session so that it doesn't need
to be passed to each call to the API.  Call Disconnect-Safeguard when
finished.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER Service
Safeguard service you would like to call: Appliance or Core.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate--will be ignored for entire session.

.PARAMETER Method
HTTP method verb you would like to use: GET, PUT, POST, DELETE.

.PARAMETER RelativeUrl
Relative portion of the Url you would like to call starting after the version.

.PARAMETER Version
Version of the Web API you are using (default: 3).

.PARAMETER RetryUrl
Relative portion of the Url to retry if the initial call returns 404 (for backwards compatibility).
Retry will only occur if this parameter is included.  If the retry needs to differ only by version,
you must specify this anyway (even if it is the same value) along with RetryVersion.

.PARAMETER RetryVersion
Version of the Web API to retry if the initial call returns 404 (for backwards compatibility).

.PARAMETER Accept
Specify the Accept header (default: application/json), Use text/csv to request CSV output.

.PARAMETER ContentType
Specify the Content-type header (default: application/json).

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Body
A hash table containing an object to PUT or POST to the Url.

.PARAMETER JsonBody
A pre-formatted JSON string to PUT or Post to the URl.  If -Body is also specified, this is ignored.
It can sometimes be difficult to get arrays of objects to behave properly with hashtables in Powershell.

.PARAMETER Parameters
A hash table containing the HTTP query parameters to add to the Url.

.PARAMETER OutFile
A file to store the Web API response.

.PARAMETER InFile
A file to read for the body of a POST or PUT request.

.PARAMETER Timeout
A timeout value in seconds (default: 300s or 5m)

.PARAMETER LongRunningTask
A switch to specify that this method call should be handled synchronously as a long-running task.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Invoke-SafeguardMethod -AccessToken $token -Appliance 10.5.32.54 Core GET Assets/16/Accounts

.EXAMPLE
Invoke-SafeguardMethod Core GET Users -Accept "text/csv" -OutFile sg-users.csv

.EXAMPLE
Invoke-SafeguardMethod -Appliance 10.5.32.54 -Anonymous notification GET SystemVerification/Manufacturing

.EXAMPLE
Invoke-SafeguardMethod Appliance GET TrustedCertificates

.EXAMPLE
Invoke-SafeguardMethod Core GET Users -Parameters @{ filter = "UserName eq 'admin'" }

.EXAMPLE
Invoke-SafeguardMethod Core POST ReasonCodes -Body @{ Name = "RN12345"; Description = "Routine maintenance." }

.EXAMPLE
Invoke-SafeguardMethod Core DELETE ReasonCodes/4

.EXAMPLE
Invoke-SafeguardMethod PUT ReasonCodes/1 -Body @{ Name = "RN2233"; Description = "Service interrupted." }

#>
function Invoke-SafeguardMethod
{
    [CmdletBinding()]
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
        [int]$Version = 3,
        [Parameter(Mandatory=$false)]
        [string]$RetryUrl,
        [Parameter(Mandatory=$false)]
        [int]$RetryVersion = $Version,
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
        [string]$JsonBody,
        [Parameter(Mandatory=$false)]
        [HashTable]$Parameters,
        [Parameter(Mandatory=$false)]
        [string]$OutFile = $null,
        [Parameter(Mandatory=$false)]
        [string]$InFile = $null,
        [Parameter(Mandatory=$false)]
        [int]$Timeout = 300,
        [Parameter(Mandatory=$false)]
        [switch]$LongRunningTask,
        [Parameter(Mandatory=$false)]
        [HashTable]$ExtraHeaders
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not ($PSBoundParameters.ContainsKey("Version") -and $SafeguardSession))
    {
        # Use version from the connection if included in the session
        # Connect-Safeguard will automatically downgrade if v2 was required to call LoginResponse
        $Version = $SafeguardSession["Version"]
    }
    if (-not ($PSBoundParameters.ContainsKey("Insecure")) -and $SafeguardSession)
    {
        # This only covers the case where Invoke-SafeguardMethod is called directly.
        # All script callers in the module will specify the flag, e.g. -Insecure:$Insecure
        # which will not hit this code.
        $Insecure = $SafeguardSession["Insecure"]
    }
    if (-not $AccessToken -and -not $Anonymous -and -not $SafeguardSession)
    {
        if (-not $Appliance)
        {
            $Appliance = (Read-Host "Appliance")
        }
        Write-Verbose "Not using existing session, calling Connect-Safeguard [1]..."
        $AccessToken = (Connect-Safeguard -Appliance $Appliance -Insecure:$Insecure -NoSessionVariable)
    }
    elseif (-not $Anonymous)
    {
        if (-not $Appliance -and $SafeguardSession)
        {
            $Appliance = $SafeguardSession["Appliance"]
            # if using session variable also inherit trust status
            $Insecure = $SafeguardSession["Insecure"]
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
            Write-Verbose "Not using existing session, calling Connect-Safeguard [2]..."
            $AccessToken = (Connect-Safeguard -Appliance $Appliance -Insecure:$Insecure -NoSessionVariable)
        }
    }
    else
    {
        if (-not $Appliance -and $SafeguardSession)
        {
            $Appliance = $SafeguardSession["Appliance"]
            # if using session variable also inherit trust status
            $Insecure = $SafeguardSession["Insecure"]
        }
        elseif (-not $Appliance)
        {
            $Appliance = (Read-Host "Appliance")
        }
    }

    Write-Verbose "Insecure=$Insecure"
    Edit-SslVersionSupport
    if ($Insecure)
    {
        Disable-SslVerification
        if ($global:PSDefaultParameterValues) { $PSDefaultParameterValues = $global:PSDefaultParameterValues.Clone() }
    }

    $local:Headers = @{
            "Accept" = $Accept;
            "Content-type" = $ContentType;
        }

    ForEach ($key in $ExtraHeaders.Keys)
    {
        $local:Headers[$key] = $ExtraHeaders[$key]
    }

    Write-Verbose "---Request---"
    Write-Verbose "Headers=$(ConvertTo-Json -InputObject $local:Headers)"

    if (-not $Anonymous)
    {
        $local:Headers["Authorization"] = "Bearer $AccessToken"
    }

    try
    {
        Invoke-Internal $Appliance $Service $Method $Version $RelativeUrl $local:Headers `
                        -Body $Body -JsonBody $JsonBody `
                        -Parameters $Parameters -InFile $InFile -OutFile $OutFile -LongRunningTask:$LongRunningTask -Timeout $Timeout
    }
    catch
    {
        if ($_.Exception.HttpStatusCode -eq 404 -and $RetryUrl)
        {
            Write-Verbose "Trying to use RetryVersion: $RetryVersion, and RetryUrl: $RetryUrl"
            Invoke-Internal $Appliance $Service $Method $RetryVersion $RetryUrl $local:Headers `
                            -Body $Body -JsonBody $JsonBody `
                            -Parameters $Parameters -InFile $InFile -OutFile $OutFile -LongRunningTask:$LongRunningTask -Timeout $Timeout
        }
        else
        {
            throw
        }
    }
    finally
    {
        if ($Insecure)
        {
            Enable-SslVerification
            if ($global:PSDefaultParameterValues) { $PSDefaultParameterValues = $global:PSDefaultParameterValues.Clone() }
        }
    }
}

<#
.SYNOPSIS
Get the time remaining on your current Safeguard session via the Web API.

.DESCRIPTION
This utility calls the Safeguard Web API and looks at the headers to determine
the remaining lifetime of the current access token.  If the access token is
already expired, it will throw an error.

By default, this cmdlet uses the Safeguard session variable, but it may be
used to check any access token by passing in the Appliance and AccessToken
parameters.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Raw
When provided this cmdlet returns a Timespan object rather than a message.

.INPUTS
None.

.OUTPUTS
Text or Timespan object for Raw option.

.EXAMPLE
Get-SafeguardAccessTokenStatus

.EXAMPLE
Get-SafeguardAccessTokenStatus -Raw
#>
function Get-SafeguardAccessTokenStatus
{
    [CmdletBinding(DefaultParameterSetName="None")]
    Param(
        [Parameter(ParameterSetName="Token",Mandatory=$true,Position=0)]
        [string]$Appliance,
        [Parameter(ParameterSetName="Token",Mandatory=$true,Position=1)]
        [object]$AccessToken,
        [Parameter(ParameterSetName="Token",Mandatory=$false)]
        [switch]$Insecure = $false,
        [Parameter(Mandatory=$false)]
        [switch]$Raw
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSCmdlet.ParameterSetName -ne "Token")
    {
        if (-not $SafeguardSession)
        {
            throw "No current Safeguard login session."
        }
        $Appliance = $SafeguardSession.Appliance
        $AccessToken = $SafeguardSession.AccessToken
        $Insecure = $SafeguardSession.Insecure
    }

    try
    {
        Edit-SslVersionSupport
        if ($Insecure)
        {
            Disable-SslVerification
            if ($global:PSDefaultParameterValues) { $PSDefaultParameterValues = $global:PSDefaultParameterValues.Clone() }
        }
        $local:Response = (Invoke-WebRequest -Method GET -Headers @{ 
                "Authorization" = "Bearer $AccessToken"
            } -Uri "https://$Appliance/service/core/v3/Me")
        $local:TimeRemaining = (New-TimeSpan -Minutes $local:Response.Headers["X-TokenLifetimeRemaining"])
        if ($Raw)
        {
            $local:TimeRemaining
        }
        else
        {
            Write-Host ("Token lifetime remaining: {0} hours {1} minutes" -f [Math]::Floor($local:TimeRemaining.TotalHours),$local:TimeRemaining.Minutes)
        }
    }
    catch
    {
        Write-Warning "Your token may be expired."
        throw $_
    }
    finally
    {
        if ($Insecure)
        {
            Enable-SslVerification
            if ($global:PSDefaultParameterValues) { $PSDefaultParameterValues = $global:PSDefaultParameterValues.Clone() }
        }
    }
}

<#
.SYNOPSIS
Refresh the access token in your current Safeguard session via the Web API.

.DESCRIPTION
This utility calls the Safeguard Web API using the information in your Safeguard
session variable to refresh your access token.  It can be made completely
non-interactive when using the certificate provider.

.PARAMETER Raw
When provided this cmdlet returns a Timespan object rather than a message.

.INPUTS
None.

.OUTPUTS
Text or Timespan object for Raw option.

.EXAMPLE
Update-SafeguardAccessToken
#>
function Update-SafeguardAccessToken
{
    [CmdletBinding()]
    Param(
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $SafeguardSession)
    {
        throw "No current Safeguard login session."
    }

    if ($SafeguardSession.Gui)
    {
        Connect-Safeguard -Appliance $SafeguardSession.Appliance -Insecure:$SafeguardSession.Insecure -Gui -Version $SafeguardSession.Version
    }
    elseif ($SafeguardSession.IdentityProvider -ieq "certificate")
    {
        if ($SafeguardSession.CertificateFile)
        {
            Connect-Safeguard -Appliance $SafeguardSession.Appliance -Insecure:$SafeguardSession.Insecure -Version $SafeguardSession.Version `
                -IdentityProvider $SafeguardSession.IdentityProvider -CertificateFile $SafeguardSession.CertificateFile
        }
        else
        {
            Connect-Safeguard -Appliance $SafeguardSession.Appliance -Insecure:$SafeguardSession.Insecure -Version $SafeguardSession.Version `
                -IdentityProvider $SafeguardSession.IdentityProvider -CertificateFile $SafeguardSession.Thumbprint
        }
    }
    else
    {
        Connect-Safeguard -Appliance $SafeguardSession.Appliance -Insecure:$SafeguardSession.Insecure -Version $SafeguardSession.Version `
            -IdentityProvider $SafeguardSession.IdentityProvider -Username $SafeguardSession.Username
    }
}

<#
.SYNOPSIS
Get information about logged in user via the Safeguard Web API.

.DESCRIPTION
Get information about the user currently logged into Safeguard.  By default this
gets the information based on the SafeguardSession variable, or else you can pass
an access token in to override it or to specify a user other than the one in the
current session.

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
Get-SafeguardLoggedInUser -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardLoggedInUser
#>
function Get-SafeguardLoggedInUser
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Me
}

<#
.SYNOPSIS
Simple utility for opening CSV files in Excel from the command line.

.DESCRIPTION
Sometimes a CSV file will not open properly in Microsoft Excel, because Excel doesn't
properly identify the delimiters and attributes of the plain text file.  This cmdlet
tells Excel how to interpret the file so that it is properly loaded as a spreadsheet.

This cmdlet can be used in conjunction with Invoke-SafeguardMethod.  Passing the
-Accept "text/csv" parameter to Invoke-SafeguardMethod will cause it to request CSV
rather than JSON from the API.  This CSV can be saved to a file using the -OutFile
parameter.

.PARAMETER FilePath
IP address or hostname of a Safeguard appliance.

.INPUTS
None.

.OUTPUTS
None.

.EXAMPLE
Open-CsvInExcel .\test.csv

.EXAMPLE
Open-CsvInExcel C:\Temp\my-sg-users.csv
#>
function Open-CsvInExcel
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $global:SgExcel)
    {
        if (-not ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_ -match "Microsoft.Office.Interop.Excel" }))
        {
            try
            {
                Add-Type -AssemblyName Microsoft.Office.Interop.Excel
            }
            catch
            {
                throw "Unable to load Microsoft Excel interop, is Excel installed?"
            }
            $global:SgExcel = (New-Object -ComObject Excel.Application)
        }
    }

    $local:FullPath = (Resolve-Path $FilePath)

    $global:SgExcel.Workbooks.OpenText(
        $local:FullPath,
        [Microsoft.Office.Interop.Excel.XlPlatform]::xlWindows,
        1, # start from row 1
        [Microsoft.Office.Interop.Excel.XlTextParsingType]::xlDelimited,
        [Microsoft.Office.Interop.Excel.XlTextQualifier]::xlTextQualifierDoubleQuote,
        $false, # consecutive delimiters not merged
        $false, # no tab delimiter
        $false, # no semicolon delimiter
        $true) # yes, comma delimiter
    $global:SgExcel.Visible = $true
}
