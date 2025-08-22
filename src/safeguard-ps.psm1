# Global session variable for login information, including SPS
Remove-Variable -Name "SafeguardSession" -Scope Global -ErrorAction "SilentlyContinue"
New-Variable -Name "SafeguardSession" -Scope Global -Value $null
Remove-Variable -Name "SafeguardSpsSession" -Scope Global -ErrorAction "SilentlyContinue"
New-Variable -Name "SafeguardSpsSession" -Scope Global -Value $null
$MyInvocation.MyCommand.ScriptBlock.Module.OnRemove = {
    Set-Variable -Name "SafeguardSession" -Scope Global -Value $null -ErrorAction "SilentlyContinue"
    Set-Variable -Name "SafeguardSpsSession" -Scope Global -Value $null -ErrorAction "SilentlyContinue"
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
function Get-RstsTokenFromBrowser
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Appliance,
        [Parameter(Mandatory=$false,Position=1)]
        [string]$Username = "",
        [Parameter(Mandatory=$false,Position=2)]
        [string]$IdentityProvider,
        [Parameter(Mandatory=$false,Position=3)]
        [int]$Port = 8400
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not ([System.Management.Automation.PSTypeName]"RstsAccessTokenExtractor").Type)
    {
        Write-Verbose "Adding the PSType for RstsAccessTokenExtractor"
        if ($PSVersionTable.PSEdition -eq "Core")
        {
            $local:Assemblies = ("System.Web.dll","System.Net.Primitives.dll","System.Net.Sockets.dll","System.Text.RegularExpressions.dll",
                                 "System.Web.HttpUtility.dll","System.Diagnostics.Process.dll","System.ComponentModel.Primitives.dll",
                                 "System.Runtime.InteropServices.RuntimeInformation.dll","System.Collections.Specialized","System.Console.dll","System.Security.Cryptography.dll")
        }
        else
        {
            $local:Assemblies = ("System.Web.dll","System.Net.Primitives.dll","System.Net.Sockets.dll","System.Text.RegularExpressions.dll",
                                 "System.Diagnostics.Process.dll","System.ComponentModel.Primitives.dll",
                                 "System.Runtime.InteropServices.RuntimeInformation.dll","System.Collections.Specialized")
        }
        Add-Type -ReferencedAssemblies $local:Assemblies -TypeDefinition @"
        using System;
        using System.Diagnostics;
        using System.Net;
        using System.Net.Sockets;
        using System.Runtime.InteropServices;
        using System.Security.Cryptography;
        using System.Text;
        using System.Text.RegularExpressions;
        using System.Threading;
        using System.Threading.Tasks;
        using System.Web;
        public class RstsAccessTokenExtractor {
            private readonly string _appliance;
            private static readonly string ResponseHtml = "<!doctype html><html><head><title>Authentication Complete</title><meta name=\"color-scheme\" content=\"dark\"><script>var prefDark = window.matchMedia(\"(prefers-color-scheme: dark)\");if (!prefDark.matches){{document.head.querySelector('meta[name=\"color-scheme\"]').setAttribute(\"content\", \"light\");}}</script></head><body><h2>Authentication complete.</h2><p>You can return to PowerShell.</p><p>Feel free to close this browser tab.</p></body></html>";

            public RstsAccessTokenExtractor(string appliance) { _appliance = appliance; }
            public string AuthorizationCode { get; set; }
            public string CodeVerifier { get; set; }
            public string Error { get; set; }
            public bool Show(string username = "", int port = 8400, string authProvider = "") {
                var tcpListener = new TcpListener(IPAddress.Loopback, port);
                tcpListener.Start();
                try {
                    CodeVerifier = OAuthCodeVerifier();
                    string redirectUri = "urn:InstalledApplicationTcpListener";
                    if (!string.IsNullOrEmpty(username)) redirectUri += string.Format("&login_hint={0}", Uri.EscapeDataString(username));
                    if (!string.IsNullOrEmpty(authProvider)) redirectUri += string.Format("&primaryProviderId={0}", Uri.EscapeDataString(authProvider));
                    string accessTokenUri = string.Format("https://{0}/RSTS/Login?response_type=code&code_challenge_method=S256&code_challenge={1}&redirect_uri={2}&port={3}", _appliance, OAuthCodeChallenge(CodeVerifier), redirectUri, port);
                    try {
                        var psi = new ProcessStartInfo { FileName = accessTokenUri, UseShellExecute = true };
                        Process.Start(psi);
                    }
                    catch {
                        // hack because of this: https://github.com/dotnet/corefx/issues/10361
                        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) {
                            accessTokenUri = accessTokenUri.Replace("&", "^&");
                            Process.Start(new ProcessStartInfo("cmd", "/c start " + accessTokenUri) { CreateNoWindow = true });
                        } else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux)) {
                            Process.Start("xdg-open", accessTokenUri);
                        } else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX)) {
                            Process.Start("open", accessTokenUri);
                        }
                        else { throw; }
                    }
                }
                catch (System.Exception) {
                    throw;
                }
                var source = new CancellationTokenSource();
                Console.CancelKeyPress += (object sender, ConsoleCancelEventArgs e) => {
                    source.Cancel();
                };
                try {
                    var listenTask = tcpListener.AcceptTcpClientAsync().ContinueWith<Task<string>>(async t => {
                        if (t.IsFaulted || t.IsCanceled) return null;
                        var tcpClient = t.Result;
                        using (var networkStream = tcpClient.GetStream())
                        {
                            var readBuffer = new byte[1024];
                            var sb = new StringBuilder();
                            do {
                                var numberOfBytesRead = await networkStream.ReadAsync(readBuffer, 0, readBuffer.Length, source.Token).ConfigureAwait(false);
                                var s = Encoding.ASCII.GetString(readBuffer, 0, numberOfBytesRead);
                                sb.Append(s);
                            } while (networkStream.DataAvailable);
                            var fullResponse = "HTTP/1.1 200 OK\r\n\r\n" + ResponseHtml + "\r\n";
                            var response = Encoding.ASCII.GetBytes(fullResponse);
                            await networkStream.WriteAsync(response, 0, response.Length, source.Token);
                            await networkStream.FlushAsync();
                            return sb.ToString();
                        }
                    });
                    listenTask.Wait(source.Token);
                    var innerTask = listenTask.Result;
                    if (innerTask != null) {
                        innerTask.Wait(source.Token);
                        if (!innerTask.IsFaulted && innerTask.Result != null)
                            AuthorizationCode = HttpUtility.ParseQueryString(ExtractUriFromHttpRequest(innerTask.Result)).Get("oauth");
                        else if (innerTask.Result != null)
                            Error = innerTask.Result;
                        else
                            Error = "No HTTP redirect";
                    }
                    return true;
                }
                finally {
                    tcpListener.Stop();
                }
            }
            private string OAuthCodeVerifier()
            {
                var bytes = new byte[60];
                RandomNumberGenerator.Create().GetBytes(bytes);
                return ToBase64Url(bytes);
            }
            private string OAuthCodeChallenge(string codeVerifier)
            {
                using (var sha = SHA256.Create())
                {
                    var hash = sha.ComputeHash(Encoding.ASCII.GetBytes(codeVerifier));
                    return ToBase64Url(hash);
                }
            }
            // https://172.21.21.1/RSTS/Login?
            // response_type=code&
            // redirect_uri=https%3a%2f%2flocalhost%3a7035%2f%3fserver%3d172.21.21.1%26auth%3dresume&
            // code_challenge=Ullteua8nkpbqkCUpKSxqPfTqrZvZfnmpV3YTGEPUfQ&
            // code_challenge_method=S256&
            // state=w5mtmJUPPMhHEW-qo4PyyX4pGDsevgTN2QNRC0aWiaxd8weEQdgiHoieLe4NDeuAkL63Q6-ipG1nIOwY

            /// <summary>Creates a Base64 string with the trailing equal signs removed and any plus signs replaced with
            /// minus signs and any forward slashes replaced with underscores.</summary>
            /// <param name="data">Any byte array to be Base64 encoded.</param>
            /// <returns>A special Base64 string that is URL safe. Used in JWTs, OAuth2.0 and other things.</returns>
            private string ToBase64Url(byte[] data)
            {
                return Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            }
            private string ExtractUriFromHttpRequest(string httpRequest) {
                string regexp = @"GET \/\?(.*) HTTP";
                Regex r1 = new Regex(regexp);
                Match match = r1.Match(httpRequest);
                if (!match.Success) { throw new InvalidOperationException("Not a GET query"); }
                return match.Groups[1].Value;
            }
        }
"@
    }
    if (-not $global:Browser)
    {
        $local:Browser = New-Object -TypeName RstsAccessTokenExtractor -ArgumentList $Appliance
    }
    if (!$local:Browser.Show($Username, $Port, $IdentityProvider))
    {
        throw "Unable to correctly manipulate browser"
    }
    if (-not $local:Browser.AuthorizationCode)
    {
        throw "Unable to obtain authorization code"
    }

    try
    {
        Write-Verbose "Redeeming RSTS authorization code..."
        $local:RstsResponse = (Invoke-RestMethod -Method POST -Headers @{
            "Accept" = "application/json";
            "Content-type" = "application/json"
        } -Uri "https://$Appliance/RSTS/oauth2/token" -Body ([System.Text.Encoding]::UTF8.GetBytes(@"
{
"grant_type": "authorization_code",
"redirect_uri": "urn:InstalledApplication",
"code": "$($local:Browser.AuthorizationCode)",
"code_verifier": "$($local:Browser.CodeVerifier)"
}
"@)))
    }
    catch
    {
        throw "Unable to obtain access token"
    }

    # Return as a hashtable object because other parts of the code later on will expect it.
    @{access_token=$local:RstsResponse.access_token}
}
function Submit-RstsMultifactorPost
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Appliance,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$PrimaryProviderId,
        [Parameter(Mandatory=$true,Position=2)]
        [string]$Username,
        [Parameter(Mandatory=$true,Position=3)]
        [securestring]$Password,
        [Parameter(Mandatory=$true,Position=4)]
        [object]$CsrfToken,
        [Parameter(Mandatory=$false,Position=5)]
        [string]$SecondaryAuthState,
        [Parameter(Mandatory=$false,Position=6)]
        [string]$SecondaryLogin
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:PasswordPlainText = [System.Net.NetworkCredential]::new("", $Password).Password
    $local:Response = (Invoke-RestMethod -Method POST "https://$Appliance/RSTS/UserLogin/LoginController?response_type=token&redirect_uri=urn%3aInstalledApplication&loginRequestStep=5" `
        -WebSession $HttpSession -Headers @{ "Accept" = "application/json"; "Content-type" = "application/x-www-form-urlencoded" } -Body @{
            directoryComboBox = "$PrimaryProviderId";
            usernameTextbox = "$Username";
            passwordTextbox = "$($local:PasswordPlainText)";
            csrfTokenTextbox = "$CsrfToken";
            secondaryAuthenticationStateTextbox = "$SecondaryAuthState";
            secondaryLoginTextbox = "$SecondaryLogin"
        })

    $local:Response
}
function Submit-RstsMultiFactorCredential
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Appliance,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$PrimaryProviderId,
        [Parameter(Mandatory=$true,Position=2)]
        [string]$Username,
        [Parameter(Mandatory=$true,Position=3)]
        [securestring]$Password,
        [Parameter(Mandatory=$true,Position=4)]
        [object]$CsrfToken
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local

    # MFA preauthenticate
    $local:PasswordPlainText = [System.Net.NetworkCredential]::new("", $Password).Password
    $local:Response = (Invoke-RestMethod -Method POST "https://$Appliance/RSTS/UserLogin/LoginController?response_type=token&redirect_uri=urn%3aInstalledApplication&loginRequestStep=7" `
        -WebSession $HttpSession -Headers @{ "Accept" = "application/json"; "Content-type" = "application/x-www-form-urlencoded" } -Body @{
            directoryComboBox = "$PrimaryProviderId";
            usernameTextbox = "$Username";
            passwordTextbox = "$($local:PasswordPlainText)";
            csrfTokenTextbox = "$CsrfToken"
        })
    $local:SecondaryAuthState = $local:Response.State
    $local:Message = $local:Response.Message
    $local:ShouldEcho = $local:Response.Echo
    if ($local:ShouldEcho)
    {
        Write-Host $local:Message
    }

    # Looping is to handle push to authenticate
    while ($local:SecondaryAuthState -or $local:SecondaryLogin)
    {
        $local:Response = (Submit-RstsMultifactorPost $Appliance $PrimaryProviderId $Username $Password $CsrfToken $local:SecondaryAuthState $local:SecondaryLogin)
        $local:SecondaryAuthState = $local:Response.State
        $local:Message = $local:Response.Message
        $local:ShouldEcho = $local:Response.Echo
        $local:SecondaryLogin = ""
        if ($local:ShouldEcho)
        {
            Write-Host $local:Message
        }
        if ($local:SecondaryAuthState)
        {
            if ($local:SecondaryAuthState.StartsWith("DefenderCloudOneTouch:"))
            {
                Write-Host -NoNewline "  Press any key to use OTP instead... "
                Start-Sleep -Milliseconds 100;
                $Host.UI.RawUI.FlushInputBuffer()
                $local:i = 0;
                while (-not $Host.UI.RawUI.KeyAvailable -and $local:i -lt 25)
                {
                    Write-Host -NoNewline ("`r{0}" -f '/-\|'[($local:i++ % 4)]);
                    Start-Sleep -Milliseconds 200
                }
                if ($Host.UI.RawUI.KeyAvailable)
                {
                    Write-Host "" # line feed to to not write prompt over top of previous message
                    $local:SecondaryAuthState = "UseOtpInstead"
                    $Host.UI.RawUI.FlushInputBuffer()
                    Start-Sleep -Milliseconds 100
                }
                else
                {
                    Write-Host ""
                }
            }
            elseif ($local:SecondaryAuthState -eq "ShowDefenderCloud")
            {
                $local:SecondaryAuthState = ""
                $local:SecondaryLogin = (Read-Host ":")
            }
            elseif ($local:SecondaryAuthState -eq "OneTouchExpired")
            {
                throw "The OneTouch push notification has expired."
            }
            elseif ($local:SecondaryAuthState.StartsWith("Fido2:"))
            {
                throw "FIDO2 is not supported."
            }
            else
            {
                $local:SecondaryAuthState = ""
                $local:SecondaryLogin = (Read-Host ":")
            }
        }
    }

    # Get final response
    $local:Response = (Invoke-RestMethod -Method POST "https://$Appliance/RSTS/UserLogin/LoginController?response_type=token&redirect_uri=urn%3aInstalledApplication&loginRequestStep=6" `
        -WebSession $HttpSession -Headers @{ "Accept" = "application/json"; "Content-type" = "application/x-www-form-urlencoded" } -Body @{
            directoryComboBox = "$PrimaryProviderId";
            usernameTextbox = "$Username";
            passwordTextbox = "$($local:PasswordPlainText)";
            csrfTokenTextbox = "$CsrfToken"
        })

    $local:Uri = ([Uri]$local:Response.RelyingPartyUrl)
    $local:Fragment = ($local:Uri.Fragment.SubString(1))
    $local:Parts = [System.Web.HttpUtility]::ParseQueryString($local:Fragment)

    (New-Object -TypeName PSObject -Property @{
            access_token = $local:Parts["access_token"];
            token_type = $local:Parts["token_type"];
            expires_in = $local:Parts["expires_in"];
            scope = $local:Parts["scope"]
        })
}
function Submit-RstsPrimaryCredential
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Appliance,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$PrimaryProviderId,
        [Parameter(Mandatory=$true,Position=2)]
        [string]$Username,
        [Parameter(Mandatory=$true,Position=3)]
        [securestring]$Password,
        [Parameter(Mandatory=$true,Position=4)]
        [object]$CsrfToken
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:PasswordPlainText = [System.Net.NetworkCredential]::new("", $Password).Password
    $local:Response = (Invoke-RestMethod -Method POST "https://$Appliance/RSTS/UserLogin/LoginController?response_type=token&redirect_uri=urn%3aInstalledApplication&loginRequestStep=3" `
        -WebSession $HttpSession -Headers @{ "Accept" = "application/json"; "Content-type" = "application/x-www-form-urlencoded" } -Body @{
            directoryComboBox = "$PrimaryProviderId";
            usernameTextbox = "$Username";
            passwordTextbox = "$($local:PasswordPlainText)";
            csrfTokenTextbox = "$CsrfToken"
        })

    $local:stsIdentity0 = ((($HttpSession).Cookies).GetCookies("https://$Appliance/RSTS") | Where-Object { $_.Name -eq "stsIdentity0" })[0]
    if (-not $local:stsIdentity0)
    {
        throw "Unable to find primary identity cookie"
    }

    if ($local:Response.SecondaryProviderID)
    {
        $local:Response = (Submit-RstsMultiFactorCredential $Appliance $PrimaryProviderId $Username $Password $CsrfToken)
        $local:Response
    }
    else
    {
        Write-Verbose "No 2FA configured for $Username"
        if (-not $local:Response.access_token)
        {
            throw "No access token found in RSTS response"
        }
        $local:Response.access_token
    }
}
function Get-RstsCsrfTokenAndSession
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Appliance
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Response = (Invoke-RestMethod -Method POST "https://$Appliance/RSTS/UserLogin/LoginController?response_type=token&redirect_uri=urn%3aInstalledApplication&loginRequestStep=1" `
        -SessionVariable LocalHttpSession -Headers @{ "Accept" = "application/json"; "Content-type" = "application/x-www-form-urlencoded" } -Body @{})
    $local:CsrfToken = ((($LocalHttpSession).Cookies).GetCookies("https://$Appliance/RSTS") | Where-Object { $_.Name -eq "CsrfToken" })[0]
    Add-Type -AssemblyName System.Web
    $local:CsrfToken = ([System.Web.HttpUtility]::UrlDecode($local:CsrfToken.Value))
    if ($local:CsrfToken -ne $local:Response.AntiCsrfToken)
    {
        throw "Anti-CSRF token in response does not match CSRF in cookie"
    }

    Set-Variable -Name HttpSession -Scope Script -Value $LocalHttpSession
    $local:CsrfToken
}
function Get-RstsTokenWith2fa
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Appliance,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$PrimaryProviderId,
        [Parameter(Mandatory=$true,Position=2)]
        [string]$Username,
        [Parameter(Mandatory=$true,Position=3)]
        [SecureString]$Password
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    try
    {
        New-Variable -Name "HttpSession" -Scope Script -Value $null -Force
        $local:CsrfToken = (Get-RstsCsrfTokenAndSession $Appliance)
        $local:RstsResponse = (Submit-RstsPrimaryCredential $Appliance $PrimaryProviderId $Username $Password $local:CsrfToken)
        $local:RstsResponse
    }
    finally
    {
        Clear-Variable -Name HttpSession
    }
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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Url = "https://$Appliance/service/$($Service.ToLower())/v$Version/$RelativeUrl"
    if ($Parameters -and $Parameters.Length -gt 0)
    {
        $local:Url += "?"
        $Parameters.Keys | ForEach-Object {
            $local:Url += ($_ + "=" + [uri]::EscapeDataString($Parameters.Item($_)) + "&")
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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $Response.Headers.Location)
    {
        throw "Trying to track long running task, but response did not include a Location header"
    }

    $local:StartTime = (Get-Date)
    $local:TaskResult = $null
    $local:TaskToPoll = $($Response.Headers.Location)
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
            $local:TaskResult = $local:TaskStatus.Message + "`n " + ($local:TaskResponse.Log | ForEach-Object { "{0,-26} {1,-12} {2}`n" -f $_.Timestamp,$_.Status,$_.Message })
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
        Import-Module -Name "$PSScriptRoot\sg-utilities.psm1" -Scope Local
        throw (New-LongRunningTaskException $local:TaskResult $local:TaskResponse)
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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Url = (New-SafeguardUrl $Appliance $Service $Version $RelativeUrl -Parameters $Parameters)
    Write-Verbose "Url=$($local:Url)"
    Write-Verbose "Parameters=$(ConvertTo-Json -InputObject $Parameters)"
    $arguments = @{
        Method = $Method;
        Headers = $Headers;
        Uri = $local:Url;
        TimeoutSec = $Timeout
    }
    if ($InFile)
    {
        Write-Verbose "InFile=$InFile"
        $arguments = $arguments + @{ InFile = $InFile }
    }
    if ($OutFile)
    {
        Write-Verbose "OutFile=$OutFile"
        $arguments = $arguments + @{ OutFile = $OutFile }
    }

    if ($LongRunningTask)
    {
        $local:Response = (Invoke-WebRequest @arguments)
        Wait-LongRunningTask $local:Response $Headers $Timeout
    }
    else
    {
        Invoke-RestMethod @arguments
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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:BodyInternal = $JsonBody
    if ($Body)
    {
        $local:BodyInternal = (ConvertTo-Json -Depth 100 -InputObject $Body)
    }
    $local:Url = (New-SafeguardUrl $Appliance $Service $Version $RelativeUrl -Parameters $Parameters)
    Write-Verbose "Url=$($local:Url)"
    Write-Verbose "Parameters=$(ConvertTo-Json -InputObject $Parameters)"
    Write-Verbose "---Request Body---"
    Write-Verbose "$($local:BodyInternal)"
    $arguments = @{
        Method = $Method;
        Headers = $Headers;
        Uri = $local:Url;
        Body = ([System.Text.Encoding]::UTF8.GetBytes($local:BodyInternal));
        TimeoutSec = $Timeout
    }
    if ($OutFile)
    {
        Write-Verbose "OutFile=$OutFile"
        $arguments = $arguments + @{ OutFile = $OutFile }
    }


    if ($LongRunningTask)
    {
        $local:Response = (Invoke-WebRequest @arguments)
        Wait-LongRunningTask $local:Response $Headers $Timeout
    }
    else
    {
        Invoke-RestMethod @arguments
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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
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
        Out-SafeguardExceptionIfPossible $_
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
authentication is also supported.

First this script retrieves an access token from the embedded redistributable
secure token service. Then, it exchanges this token for a Safeguard user token.

You must use the -Browser parameter for 2FA login support.

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
Version of the Web API you are using (default: 4).

.PARAMETER Gui (Deprecated)
Use -Browser instead.

.PARAMETER Browser
Launch redistributable STS login window in a native system browser.  Supports 2FA.

If neither the -Gui nor -Browser switches are specified, then the OAuth2 Resource Owner Password Credential grant type
will be used to programmatically submit the provided credentials. Ensure that Safeguard has been configured to allow
this grant type by checking the Safeguard Access settings in Appliance Management.

.PARAMETER TwoFactor
Attempt to authenticate using multiple factors via the command line.  Supports Starling 2FA.

.PARAMETER NoSessionVariable
If this switch is sent the access token will be returned and a login session context variable will not be created.

.PARAMETER NoWindowTitle
If this switch is sent safeguard-ps won't try to set the window title, which can cause failures when the PowerShell
runtime doesn't allow user interaction; for example, when running safeguard-ps from C#.

.INPUTS
None.

.OUTPUTS
None (with LoginSession variable filled out) or AccessToken for calling Web API.


.EXAMPLE
Connect-Safeguard 10.5.32.54 local -Credential (Get-Credential)

Login Successful.

.EXAMPLE
Connect-Safeguard 10.5.32.54 -Browser

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

.EXAMPLE
Connect-Safeguard 10.5.32.162 -Browser -IdentityProvider extf14 -Username floyd.smith@acme.com

[Opens browser window for normal Safeguard login experience, including 2FA, using the specified
identity provider. Which may automatically redirect if it is to an external federation provider.]

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
        [Parameter(ParameterSetName="Username",Mandatory=$false,Position=2)][Parameter(ParameterSetName="Browser",Mandatory=$false)]
        [string]$Username,
        [Parameter(ParameterSetName="Username",Position=3)]
        [SecureString]$Password,
        [Parameter(ParameterSetName="Certificate",Mandatory=$false)]
        [string]$CertificateFile,
        [Parameter(ParameterSetName="Certificate",Mandatory=$false)]
        [string]$Thumbprint,
        [Parameter(ParameterSetName="Gui",Mandatory=$false)]
        [switch]$Gui,
        [Parameter(ParameterSetName="Browser",Mandatory=$false)]
        [switch]$Browser,
        [Parameter(ParameterSetName="Username",Mandatory=$false)]
        [switch]$TwoFactor,
        [Parameter(Mandatory=$false)]
        [int]$Version = 4,
        [Parameter(Mandatory=$false)]
        [switch]$NoSessionVariable = $false,
        [Parameter(Mandatory=$false)]
        [switch]$NoWindowTitle = $false
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    try
    {
        Edit-SslVersionSupport
        if ($Insecure)
        {
            Disable-SslVerification
            if ($global:PSDefaultParameterValues) { $PSDefaultParameterValues = $global:PSDefaultParameterValues.Clone() }
        }

        if ($Browser -Or $Gui)
        {
            $local:RstsResponse = (Get-RstsTokenFromBrowser $Appliance $Username $IdentityProvider)
        }
        else
        {
            Write-Verbose "Getting configured identity providers from CORE service (using GET)..."
            try
            {
                $local:ConfiguredProvidersRaw = (Invoke-RestMethod -Method GET -Uri "https://$Appliance/service/core/v$Version/AuthenticationProviders" `
                                            -Headers @{ "Accept" = "application/json" } `
                                            -ErrorAction SilentlyContinue)
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

            # Built-in providers
            $local:ConfiguredProviders = ,(New-Object -TypeName PSObject -Property @{
                RstsProviderId = "certificate";
                Name = "certificate"
            }),(New-Object -TypeName PSObject -Property @{
                RstsProviderId = "local";
                Name = "Local"
            })
            $local:ConfiguredProvidersRaw | Sort-Object Name | ForEach-Object {
                # Trim out local so we can control order
                if ($_.RstsProviderId -ine "local")
                {
                    $local:ConfiguredProviders += (New-Object -TypeName PSObject -Property @{
                        RstsProviderId = $_.RstsProviderId;
                        Name = $_.Name
                    })
                }
            }

            $local:IdentityProviders = ($local:ConfiguredProviders | ForEach-Object {
                if ($_.RstsProviderId -ieq "certificate" -or $_.RstsProviderId -ieq "local")
                {
                    "$($_.RstsProviderId)"
                }
                else
                {
                    "$($_.RstsProviderId) [$($_.Name)]"
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
            if ($local:ConfiguredProviders -and ($local:ConfiguredProviders.RstsProviderId.ToLower() -notcontains $IdentityProvider.ToLower() `
                -and $local:ConfiguredProviders.Name.ToLower() -notcontains $IdentityProvider.ToLower()))
            {
                throw "IdentityProvider '$($local:IdentityProvider)' not found in ($($local:IdentityProviders -join ", "))"
            }

            # Allow the caller to specify the domain name for AD
            $local:ConfiguredProviders | ForEach-Object {
                if ($_.Name.ToLower() -ieq $IdentityProvider)
                {
                    $IdentityProvider = $_.RstsProviderId
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
                        $local:PasswordPlainText = [System.Net.NetworkCredential]::new("", $Password).Password
                        break
                    }
                    "PSCredential" {
                        $Username = $Credential.UserName
                        $local:PasswordPlainText = [System.Net.NetworkCredential]::new("", $Credential.Password).Password
                        break
                    }
                    "Certificate" {
                        # If the user manually entered an Identity Provider ID, use it.
                        # Otherwise, we'll default to the built-in Certificate provider.
                        if ($IdentityProvider)
                        {
                            $local:Scope = "rsts:sts:primaryproviderid:$($IdentityProvider)"
                        }
                        else
                        {
                            $IdentityProvider = "certificate"
                            $local:Scope = "rsts:sts:primaryproviderid:certificate"
                        }
                    }
                }
            }

            if ($Username)
            {
                if ($TwoFactor)
                {
                    $local:RstsResponse = (Get-RstsTokenWith2fa $Appliance $IdentityProvider $Username (ConvertTo-SecureString -AsPlainText -Force $local:PasswordPlainText))
                }
                else
                {
                    try
                    {
                        Write-Verbose "Calling RSTS token service for password authentication..."
                        $local:Scope = "rsts:sts:primaryproviderid:$($IdentityProvider.ToLower())"
                        $local:RstsResponse = (Invoke-RestMethod -Method POST -Headers @{
                            "Accept" = "application/json";
                            "Content-type" = "application/json"
                        } -Uri "https://$Appliance/RSTS/oauth2/token" -Body ([System.Text.Encoding]::UTF8.GetBytes(@"
{
    "grant_type": "password",
    "username": "$Username",
    "password": "$($local:PasswordPlainText)",
    "scope": "$($local:Scope)"
}
"@)))
                    }
                    catch
                    {
                        Import-Module -Name "$PSScriptRoot\sg-utilities.psm1" -Scope Local
                        Out-SafeguardExceptionIfPossible $_
                    }
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
                    Out-SafeguardExceptionIfPossible $_
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
                "Gui" = $Gui -Or $Browser;
                "NoWindowTitle" = $NoWindowTitle;
                "AssetPartitionId" = $null
            }
            if (-not $NoWindowTitle)
            {
                $Host.UI.RawUI.WindowTitle = "PowerShell -- Safeguard Connection: $(Get-SessionConnectionIdentifier)"
            }
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
Version of the Web API you are using (default: 4).

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
        [int]$Version = 4
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
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
                $NoWindowTitle = $false
                if ($SafeguardSession.ContainsKey("NoWindowTitle"))
                {
                    $NoWindowTitle = $SafeguardSession["NoWindowTitle"]
                }
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
            if (-not $NoWindowTitle)
            {
                $Host.UI.RawUI.WindowTitle = "PowerShell"
            }
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
Safeguard service you would like to call: Appliance, Core, Notification, Management.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate--will be ignored for entire session.

.PARAMETER Method
HTTP method verb you would like to use: GET, PUT, POST, DELETE.

.PARAMETER RelativeUrl
Relative portion of the Url you would like to call starting after the version.

.PARAMETER Version
Version of the Web API you are using (default: 4).

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
A timeout value in seconds (default: 300s or 5m).

.PARAMETER LongRunningTask
A switch to specify that this method call should be handled synchronously as a long-running task.

.PARAMETER JsonOutput
A switch to return data as pretty JSON string.

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
Invoke-SafeguardMethod Core GET TrustedCertificates -JsonOutput

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
        [ValidateSet("Core","Appliance","Notification","Management",IgnoreCase=$true)]
        [string]$Service,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure = $false,
        [Parameter(Mandatory=$true,Position=1)]
        [ValidateSet("Get","Put","Post","Delete",IgnoreCase=$true)]
        [string]$Method,
        [Parameter(Mandatory=$true,Position=2)]
        [string]$RelativeUrl,
        [Parameter(Mandatory=$false)]
        [int]$Version = 4,
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
        [HashTable]$ExtraHeaders,
        [Parameter(Mandatory=$false)]
        [switch]$JsonOutput
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ((-not ($PSBoundParameters.ContainsKey("Version")) -or $Version -eq 0) -and $SafeguardSession)
    {
        # Use version from the connection if included in the session
        $Version = $SafeguardSession["Version"]
        if (-not ($PSBoundParameters.ContainsKey("RetryVersion")))
        {
            $RetryVersion = $Version;
        }
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
        if ($JsonOutput)
        {
            (Invoke-Internal $Appliance $Service $Method $Version $RelativeUrl $local:Headers `
                             -Body $Body -JsonBody $JsonBody -Parameters $Parameters -InFile $InFile -OutFile $OutFile `
                             -LongRunningTask:$LongRunningTask -Timeout $Timeout) | ConvertTo-Json -Depth 100
        }
        else
        {
            Invoke-Internal $Appliance $Service $Method $Version $RelativeUrl $local:Headers `
                            -Body $Body -JsonBody $JsonBody -Parameters $Parameters -InFile $InFile -OutFile $OutFile `
                            -LongRunningTask:$LongRunningTask -Timeout $Timeout
        }
    }
    catch
    {
        if ($_.Exception -and ($_.Exception.HttpStatusCode -eq 404 -and ($RetryUrl -or ($RetryVersion -ne $Version))))
        {
            if (-not $RetryVersion) { $RetryVersion = $Version}
            if (-not $RetryUrl) { $RetryUrl = $RelativeUrl}
            Write-Verbose "Trying to use RetryVersion: $RetryVersion, and RetryUrl: $RetryUrl"
            if ($JsonOutput)
            {
                (Invoke-Internal $Appliance $Service $Method $RetryVersion $RetryUrl $local:Headers `
                                 -Body $Body -JsonBody $JsonBody -Parameters $Parameters -InFile $InFile -OutFile $OutFile `
                                 -LongRunningTask:$LongRunningTask -Timeout $Timeout) | ConvertTo-Json -Depth 100
            }
            else
            {
                Invoke-Internal $Appliance $Service $Method $RetryVersion $RetryUrl $local:Headers `
                                -Body $Body -JsonBody $JsonBody -Parameters $Parameters -InFile $InFile -OutFile $OutFile `
                                -LongRunningTask:$LongRunningTask -Timeout $Timeout
            }
        }
        else
        {
            Write-Verbose "NOT FOUND: YOU MAY BE TRYING TO USE A DIFFERENT VERSION OF SAFEGUARD API:"
            Write-Verbose "    TRY CONNECTING WITH THE Version PARAMETER SET SOMETHING OTHER THAN $Version, OR"
            Write-Verbose "    DOWNLOAD THE VERSION OF safeguard-ps MATCHING YOUR VERSION OF SAFEGUARD"
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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
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
        $local:minutes = $local:Response.Headers["X-TokenLifetimeRemaining"]
        $local:TimeRemaining = (New-TimeSpan -Minutes $(if ($local:minutes.GetType() -eq "string") { $local:minutes } else { $local:minutes[0] }))
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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $SafeguardSession)
    {
        throw "No current Safeguard login session."
    }

    if ($SafeguardSession.Gui)
    {
        Connect-Safeguard -Appliance $SafeguardSession.Appliance -Insecure:$SafeguardSession.Insecure -Browser -Version $SafeguardSession.Version
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

.PARAMETER Fields
An array of the user property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardLoggedInUser -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardLoggedInUser -Fields Id
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
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Parameters = $null
    if ($Fields)
    {
        $local:Parameters = @{ fields = ($Fields -join ",")}
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Me -Parameters $local:Parameters
}

<#
.SYNOPSIS
Accept the Safeguard Software Transaction Agreement (STA) via the Safeguard Web API.

.DESCRIPTION
All Safeguard customers must accept the STA before using the software.  This cmdlet
provides a programmatic means for customers to accept the agreement as displayed on
One Identity's website: https://www.oneidentity.com/legal/sta.aspx.  The agreement
applies to customers based on their geographic region.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Confirm-SafeguardStaAcceptance
#>
function Confirm-SafeguardStaAcceptance
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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:StaStatus = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Licenses/Sta")
    if ($local:StaStatus.Accepted)
    {
        Write-Host "Safeguard STA agreement (https://www.oneidentity.com/legal/sta.aspx) already accepted."
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "Licenses/Sta"
        Write-Host "The Safeguard STA agreement (https://www.oneidentity.com/legal/sta.aspx) has been accepted."
    }
}

<#
.SYNOPSIS
Simple utility to switch the API version in your connected session.

.DESCRIPTION
Connect-Safeguard stores version information in your connected session.  By default
this will be API version 4.  If you want to call a version 3 API for certain cmdlets,
then you can use this cmdlet to switch the API version stored in your connect session.
Just remember to switch it back!

.PARAMETER Version
Version of the Web API you are using (default: 4).

.INPUTS
None.

.OUTPUTS
None.

.EXAMPLE
Switch-SafeguardConnectionVersion -Version 3

.EXAMPLE
Switch-SafeguardConnectionVersion
#>
function Switch-SafeguardConnectionVersion
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false, Position=0)]
        [int]$Version = 4
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $SafeguardSession)
    {
        throw "This cmdlet requires that you log in with the Connect-Safeguard cmdlet"
    }

    $SafeguardSession.Version = $Version
    Write-Host "API Version set to v$Version"
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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
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
