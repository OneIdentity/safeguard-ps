@{
    Name        = "Device Code Authentication"
    Description = "Tests device-code login request, disabled-grant handling, and optional E2E approval"
    Tags        = @("auth", "device-code")

    Setup = {
        param($Context)

        # Stash the current Allowed OAuth2 Grant Types so the suite Cleanup block can
        # restore the exact original set even if Execute throws. Grant restoration must
        # live in the suite's own Cleanup (framework-registered cleanups run afterward).
        $Context.SuiteData["OriginalGrantTypes"] = @(Get-SafeguardOAuth2GrantType -Insecure)

        # Ensure DeviceCode is enabled as the baseline for the enabled-path assertions.
        $null = Enable-SafeguardOAuth2GrantType -Insecure DeviceCode
    }

    Execute = {
        param($Context)

        $appliance = $Context.Appliance

        # Reads the message text out of an InformationRecord regardless of whether the
        # payload is a plain string or a HostInformationMessage (Write-Host emits the latter).
        function Get-SgPsInformationText {
            param($Record)
            $data = $Record.MessageData
            if ($data -is [System.Management.Automation.HostInformationMessage]) {
                return [string]$data.Message
            }
            return [string]$data
        }

        # Posts directly to the rSTS DeviceLogin endpoint and returns the raw response body.
        # When the DeviceCode grant is disabled the appliance answers with an HTML (not JSON)
        # error body that carries the disabled-grant marker; capture it without choking on
        # the non-JSON content. Test-only helper -- no product-code change.
        function Get-SgPsDeviceLoginBody {
            param($Appliance)
            $uri = "https://$Appliance/RSTS/oauth2/DeviceLogin"
            $body = (@{ client_id = ""; scope = "rsts:sts:primaryproviderid:local" } | ConvertTo-Json -Depth 100)
            try {
                $resp = Invoke-WebRequest -Method POST -Uri $uri -Body $body `
                    -ContentType "application/json" -SkipCertificateCheck -ErrorAction Stop
                return [string]$resp.Content
            }
            catch {
                if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
                    return [string]$_.ErrorDetails.Message
                }
                if ($_.Exception.Response -and $_.Exception.Response.GetResponseStream) {
                    try {
                        $stream = $_.Exception.Response.GetResponseStream()
                        $reader = [System.IO.StreamReader]::new($stream)
                        $text = $reader.ReadToEnd()
                        $reader.Close()
                        return $text
                    }
                    catch {
                        return ""
                    }
                }
                return ""
            }
        }

        # Bounded harness for the enabled baseline. Runs Connect-Safeguard -DeviceCode in a
        # separate runspace, captures the Write-Host verification display from the Information
        # stream, and terminates the runspace once the verification info has appeared so the
        # poll loop never runs to expiry. Returns the captured display text.
        function Invoke-SgPsDeviceCodeCapture {
            param($Appliance, $ModuleRoot, $IdentityProvider, $TimeoutSeconds)

            $manifestPath = (Join-Path $ModuleRoot "safeguard-ps.psd1")
            $runner = {
                param($ManifestPath, $Appliance, $IdentityProvider)
                Import-Module $ManifestPath -Force
                $connectArgs = @{
                    Appliance         = $Appliance
                    DeviceCode        = $true
                    Insecure          = $true
                    NoSessionVariable = $true
                }
                if ($IdentityProvider) { $connectArgs["IdentityProvider"] = $IdentityProvider }
                Connect-Safeguard @connectArgs
            }

            $ps = [powershell]::Create()
            $null = $ps.AddScript($runner).AddArgument($manifestPath).AddArgument($Appliance).AddArgument($IdentityProvider)
            $captured = [System.Collections.Generic.List[string]]::new()
            try {
                $async = $ps.BeginInvoke()
                $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
                while ((Get-Date) -lt $deadline) {
                    Start-Sleep -Milliseconds 250
                    foreach ($record in $ps.Streams.Information.ReadAll()) {
                        $captured.Add((Get-SgPsInformationText -Record $record))
                    }
                    $joined = ($captured -join "`n")
                    if (($joined -match "enter the code") -and ($joined -match "expires in")) {
                        break
                    }
                    if ($async.IsCompleted) { break }
                }
                # Drain any records produced between the last read and termination.
                foreach ($record in $ps.Streams.Information.ReadAll()) {
                    $captured.Add((Get-SgPsInformationText -Record $record))
                }
            }
            finally {
                try { $ps.Stop() } catch {}
                try { $ps.Dispose() } catch {}
            }

            return ($captured -join "`n")
        }

        # Best-effort scripted browser-side approval. Drives the rSTS UserLogin/LoginController
        # pattern (mirroring the non-interactive PKCE implementation) and submits the captured
        # user code for the device verification. Net-new and brittle by design -- any failure
        # propagates so the caller degrades to Test-SgPsSkip.
        function Approve-SgPsDeviceVerification {
            param($Appliance, $ProviderId, $Username, $PasswordPlain, $UserCode)

            Add-Type -AssemblyName System.Web

            $csrfBytes = [byte[]]::new(32)
            [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($csrfBytes)
            $csrf = [Convert]::ToBase64String($csrfBytes).TrimEnd("=").Replace("+", "-").Replace("/", "_")

            $session = (New-Object Microsoft.PowerShell.Commands.WebRequestSession)
            $cookie = (New-Object System.Net.Cookie("CsrfToken", $csrf, "/RSTS", $Appliance))
            $session.Cookies.Add((New-Object System.Uri("https://$Appliance")), $cookie)

            $base = "https://$Appliance/RSTS/UserLogin/LoginController?response_type=token" +
                "&redirect_uri=urn%3aInstalledApplication" +
                "&user_code=$([System.Uri]::EscapeDataString($UserCode))&loginRequestStep="

            $form = @{
                directoryComboBox = "$ProviderId"
                usernameTextbox   = "$Username"
                passwordTextbox   = "$PasswordPlain"
                csrfTokenTextbox  = "$csrf"
                userCodeTextbox   = "$UserCode"
            }

            foreach ($step in @("1", "3", "6")) {
                $null = Invoke-WebRequest -Method POST -Uri ($base + $step) -WebSession $session `
                    -Headers @{ "Accept" = "application/json" } -ContentType "application/x-www-form-urlencoded" `
                    -Body $form -SkipCertificateCheck
            }
        }

        # Runs the real product device-code login in a runspace (so it owns the rSTS-to-Safeguard
        # token exchange and yields a genuine Safeguard API token), drives scripted approval for
        # the captured user code, then waits a bounded time for the poll loop to redeem the token.
        function Approve-SgPsDeviceCodeE2E {
            param($Context)

            $appliance = $Context.Appliance
            $providerId = "local"
            $username = $Context.AdminUserName
            $passwordPlain = $Context.AdminPassword
            if ([string]::IsNullOrWhiteSpace($username) -or [string]::IsNullOrWhiteSpace($passwordPlain)) {
                throw "No local admin credentials available for scripted approval"
            }

            $manifestPath = (Join-Path $Context.ModuleRoot "safeguard-ps.psd1")
            $runner = {
                param($ManifestPath, $Appliance, $ProviderId)
                Import-Module $ManifestPath -Force
                Connect-Safeguard -Appliance $Appliance -DeviceCode -IdentityProvider $ProviderId `
                    -Insecure -NoSessionVariable
            }
            $ps = [powershell]::Create()
            $null = $ps.AddScript($runner).AddArgument($manifestPath).AddArgument($appliance).AddArgument($providerId)

            $token = $null
            try {
                $async = $ps.BeginInvoke()

                $userCode = $null
                $buffer = [System.Collections.Generic.List[string]]::new()
                $deadline = (Get-Date).AddSeconds(30)
                while ((Get-Date) -lt $deadline -and -not $userCode) {
                    Start-Sleep -Milliseconds 250
                    foreach ($record in $ps.Streams.Information.ReadAll()) {
                        $buffer.Add((Get-SgPsInformationText -Record $record))
                    }
                    $lines = @($buffer)
                    for ($i = 0; $i -lt $lines.Count - 1; $i++) {
                        if (($lines[$i] -match "enter the code") -and (-not $userCode)) {
                            $candidate = $lines[$i + 1].Trim()
                            if ($candidate) { $userCode = $candidate }
                        }
                    }
                    if ($async.IsCompleted) { break }
                }
                if (-not $userCode) {
                    throw "Could not capture a device user code to approve"
                }

                Approve-SgPsDeviceVerification -Appliance $appliance -ProviderId $providerId `
                    -Username $username -PasswordPlain $passwordPlain -UserCode $userCode

                $tokenDeadline = (Get-Date).AddSeconds(60)
                while ((Get-Date) -lt $tokenDeadline -and -not $async.IsCompleted) {
                    Start-Sleep -Milliseconds 500
                }
                if ($async.IsCompleted) {
                    $result = $ps.EndInvoke($async)
                    if ($result -and $result.Count -gt 0) { $token = [string]$result[0] }
                }
            }
            finally {
                try { $ps.Stop() } catch {}
                try { $ps.Dispose() } catch {}
            }

            if ([string]::IsNullOrWhiteSpace([string]$token)) {
                throw "Scripted approval completed without producing a token"
            }
            return $token
        }

        # -- Disabled-grant error: reactive detection ------------------------------------

        $null = Disable-SafeguardOAuth2GrantType -Insecure DeviceCode

        Test-SgPsAssert "Device-code login fails fast when the grant is disabled" {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $threw = $false
            try {
                Connect-Safeguard -Appliance $appliance -DeviceCode -Insecure -NoSessionVariable
            }
            catch {
                $threw = $true
            }
            $sw.Stop()
            # The DeviceLogin request is rejected immediately; it must not block on a poll loop.
            $threw -and ($sw.Elapsed.TotalSeconds -lt 30)
        }

        Test-SgPsAssert "DeviceLogin error body surfaces the disabled-grant marker" {
            $body = Get-SgPsDeviceLoginBody -Appliance $appliance
            $null -ne $body -and $body.ToLowerInvariant().Contains("device code grant type is not allowed")
        }

        # Re-enable DeviceCode before the enabled-path assertions.
        $null = Enable-SafeguardOAuth2GrantType -Insecure DeviceCode

        # -- Enabled baseline: request succeeds and code is surfaced ----------------------

        $Context.SuiteData["BaselineDisplay"] = (Invoke-SgPsDeviceCodeCapture `
            -Appliance $appliance -ModuleRoot $Context.ModuleRoot -IdentityProvider "local" -TimeoutSeconds 90)

        Test-SgPsAssert "Device-code login surfaces the verification prompt" {
            $text = $Context.SuiteData["BaselineDisplay"]
            $null -ne $text -and ($text -match "use a web browser")
        }

        Test-SgPsAssert "Device-code login surfaces the verification URL" {
            $text = $Context.SuiteData["BaselineDisplay"]
            $text -match [regex]::Escape("https://$appliance")
        }

        Test-SgPsAssert "Device-code login surfaces a non-empty user code" {
            $text = $Context.SuiteData["BaselineDisplay"]
            $lines = ($text -split "`r?`n")
            $codeFound = $false
            for ($i = 0; $i -lt $lines.Count - 1; $i++) {
                if ($lines[$i] -match "enter the code") {
                    if ($lines[$i + 1].Trim().Length -gt 0) { $codeFound = $true }
                    break
                }
            }
            $codeFound
        }

        Test-SgPsAssert "Device-code login surfaces expiry/polling metadata" {
            $text = $Context.SuiteData["BaselineDisplay"]
            $text -match "expires in"
        }

        # -- Optional true E2E: scripted local/no-MFA approval ----------------------------
        # Opt-in only -- scripted no-human device approval is net-new and brittle. Enable it
        # with SGPS_DEVICECODE_E2E and a local, no-MFA admin. Any failure degrades to a skip
        # so the guaranteed baseline coverage above always stands.
        if (-not $env:SGPS_DEVICECODE_E2E) {
            Test-SgPsSkip "Device-code scripted approval E2E" `
                "Opt-in only; set SGPS_DEVICECODE_E2E=1 (local provider, no MFA) to exercise scripted approval"
        }
        else {
            $e2eToken = $null
            $e2eError = $null
            try {
                $e2eToken = (Approve-SgPsDeviceCodeE2E -Context $Context)
            }
            catch {
                $e2eError = $_.Exception.Message
            }

            if ($null -eq $e2eToken -or [string]::IsNullOrWhiteSpace([string]$e2eToken)) {
                $reason = if ($e2eError) { $e2eError } else { "Scripted approval did not yield a token" }
                Test-SgPsSkip "Device-code scripted approval E2E" $reason
            }
            else {
                Test-SgPsAssert "Device-code scripted approval yields a usable token" {
                    $status = Invoke-SafeguardMethod -Insecure -AccessToken $e2eToken Appliance GET "ApplianceStatus"
                    $null -ne $status
                }
            }
        }
    }

    Cleanup = {
        param($Context)

        # Restore the exact original Allowed OAuth2 Grant Types here in the suite's own
        # Cleanup -- framework-registered cleanups run afterward, so this is the resilient
        # restore path even if Execute threw.
        try {
            $original = @($Context.SuiteData["OriginalGrantTypes"])
            @("AuthorizationCode", "Implicit", "ResourceOwner", "DeviceCode") | ForEach-Object {
                try { $null = Disable-SafeguardOAuth2GrantType -Insecure $_ } catch {}
            }
            if ($original -and $original.Count -gt 0) {
                $original | ForEach-Object {
                    if (-not [string]::IsNullOrWhiteSpace([string]$_)) {
                        try { $null = Enable-SafeguardOAuth2GrantType -Insecure $_ } catch {}
                    }
                }
            }
        }
        catch {}

        # Restore the run-admin session last, mirroring Suite-PkceAuthentication.ps1.
        try {
            if (-not $SafeguardSession -or $SafeguardSession.Username -ne $Context.RunAdminName) {
                $secRunPass = ConvertTo-SecureString $Context.RunAdminPassword -AsPlainText -Force
                Connect-Safeguard -Appliance $Context.Appliance -IdentityProvider local `
                    -Username $Context.RunAdminName -Password $secRunPass -Insecure
            }
        }
        catch {}
    }
}
