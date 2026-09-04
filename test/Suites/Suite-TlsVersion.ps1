@{
    Name        = "TLS Version"
    Description = "Tests -MinimumTlsVersion/-MaximumTlsVersion pinning on Connect-Safeguard: client-side range validation, downgrade to TLS 1.2, and TLS 1.3 negotiation that adapts to the appliance's capability (connects where 1.3 is supported, fails closed where it is not)."
    Tags        = @("core", "auth", "tls")

    Setup = {
        param($Context)

        # Detect whether this appliance can negotiate TLS 1.3. The runner has already
        # connected successfully, so credentials and network are known-good; a failure
        # to connect with a TLS 1.3 floor therefore reflects the appliance's TLS
        # capability (8.x caps at 1.2, 9.0+ supports 1.3), not an environment problem.
        # Use -NoSessionVariable throughout so the global runner session is never disturbed.
        $secPwd = ConvertTo-SecureString $Context.AdminPassword -AsPlainText -Force
        $supports13 = $false
        try {
            $probeToken = Connect-Safeguard -Appliance $Context.Appliance -IdentityProvider "Local" `
                -Username $Context.AdminUserName -Password $secPwd -Insecure -NoSessionVariable `
                -MinimumTlsVersion 1.3
            if ($probeToken) {
                $supports13 = $true
                try { Disconnect-Safeguard -Appliance $Context.Appliance -AccessToken $probeToken -Insecure } catch {}
            }
        }
        catch {
            $supports13 = $false
        }
        $Context.SuiteData["SupportsTls13"] = $supports13
    }

    Execute = {
        param($Context)

        $secPwd = ConvertTo-SecureString $Context.AdminPassword -AsPlainText -Force

        # --- Client-side range validation (appliance-independent, never hits the network) ---
        Test-SgPsAssertThrows "Connect-Safeguard rejects MinimumTlsVersion > MaximumTlsVersion" {
            Connect-Safeguard -Appliance $Context.Appliance -IdentityProvider "Local" `
                -Username $Context.AdminUserName -Password $secPwd -Insecure -NoSessionVariable `
                -MinimumTlsVersion 1.3 -MaximumTlsVersion 1.2
        } -ExpectedMessage "cannot be greater than"

        # --- Downgrade to TLS 1.2 (supported by every Safeguard version) ---
        Test-SgPsAssert "Connect-Safeguard with -MaximumTlsVersion 1.2 connects" {
            $token = Connect-Safeguard -Appliance $Context.Appliance -IdentityProvider "Local" `
                -Username $Context.AdminUserName -Password $secPwd -Insecure -NoSessionVariable `
                -MaximumTlsVersion 1.2
            $result = ($null -ne $token -and $token.Length -gt 0)
            if ($token) { try { Disconnect-Safeguard -Appliance $Context.Appliance -AccessToken $token -Insecure } catch {} }
            $result
        }

        # --- Explicit 1.2..1.3 range: negotiates the highest common version on any appliance ---
        Test-SgPsAssert "Connect-Safeguard with 1.2-1.3 range connects and can call the API" {
            $token = Connect-Safeguard -Appliance $Context.Appliance -IdentityProvider "Local" `
                -Username $Context.AdminUserName -Password $secPwd -Insecure -NoSessionVariable `
                -MinimumTlsVersion 1.2 -MaximumTlsVersion 1.3
            $me = Invoke-SafeguardMethod -Appliance $Context.Appliance -AccessToken $token -Insecure `
                -Service Core -Method Get -RelativeUrl "Me"
            $result = ($null -ne $me -and $null -ne $me.Id)
            if ($token) { try { Disconnect-Safeguard -Appliance $Context.Appliance -AccessToken $token -Insecure } catch {} }
            $result
        }

        # --- TLS 1.3 floor: behavior depends on appliance capability ---
        if ($Context.SuiteData["SupportsTls13"]) {
            Test-SgPsAssert "Connect-Safeguard with -MinimumTlsVersion 1.3 connects and can call the API" {
                $token = Connect-Safeguard -Appliance $Context.Appliance -IdentityProvider "Local" `
                    -Username $Context.AdminUserName -Password $secPwd -Insecure -NoSessionVariable `
                    -MinimumTlsVersion 1.3
                $me = Invoke-SafeguardMethod -Appliance $Context.Appliance -AccessToken $token -Insecure `
                    -Service Core -Method Get -RelativeUrl "Me"
                $result = ($null -ne $me -and $null -ne $me.Id)
                if ($token) { try { Disconnect-Safeguard -Appliance $Context.Appliance -AccessToken $token -Insecure } catch {} }
                $result
            }

            Test-SgPsAssert "Connect-Safeguard pinned to exactly TLS 1.3 (min=max=1.3) connects" {
                $token = Connect-Safeguard -Appliance $Context.Appliance -IdentityProvider "Local" `
                    -Username $Context.AdminUserName -Password $secPwd -Insecure -NoSessionVariable `
                    -MinimumTlsVersion 1.3 -MaximumTlsVersion 1.3
                $result = ($null -ne $token -and $token.Length -gt 0)
                if ($token) { try { Disconnect-Safeguard -Appliance $Context.Appliance -AccessToken $token -Insecure } catch {} }
                $result
            }
        }
        else {
            # Appliance does not support TLS 1.3 (e.g. Safeguard 8.x): a TLS 1.3 floor
            # must fail to negotiate rather than silently downgrade.
            Test-SgPsAssertThrows "Connect-Safeguard with -MinimumTlsVersion 1.3 fails closed on a non-TLS-1.3 appliance" {
                Connect-Safeguard -Appliance $Context.Appliance -IdentityProvider "Local" `
                    -Username $Context.AdminUserName -Password $secPwd -Insecure -NoSessionVariable `
                    -MinimumTlsVersion 1.3
            }

            # The failed attempt must not have disturbed the runner's live session.
            Test-SgPsAssert "Runner session is intact after a failed TLS 1.3 connection attempt" {
                $me = Get-SafeguardLoggedInUser -Insecure
                $null -ne $me -and $null -ne $me.Id
            }
        }
    }

    Cleanup = {
        param($Context)
        # This suite only uses -NoSessionVariable and never mutates the global
        # $SafeguardSession, so there is nothing to restore.
    }
}
