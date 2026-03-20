@{
    Name        = "PKCE Authentication"
    Description = "Tests PKCE non-interactive login and error handling"
    Tags        = @("auth", "pkce")

    Setup = {
        param($Context)
        # No setup needed -- uses pre-existing admin user
    }

    Execute = {
        param($Context)

        $appliance = $Context.Appliance
        $user = $Context.AdminUserName
        $pass = $Context.AdminPassword

        # -- Successful login (run first to avoid rate limiter penalties from error tests) --

        Test-SgPsAssert "PKCE non-interactive login succeeds" {
            $secPass = ConvertTo-SecureString $pass -AsPlainText -Force
            $token = Connect-Safeguard $appliance local $user -Pkce -Password $secPass -Insecure -NoSessionVariable
            $null -ne $token -and $token.Length -gt 0
        }

        Test-SgPsAssert "PKCE login sets session variable" {
            $secPass = ConvertTo-SecureString $pass -AsPlainText -Force
            Connect-Safeguard $appliance local $user -Pkce -Password $secPass -Insecure
            $connected = $null -ne $SafeguardSession -and $SafeguardSession.Appliance -eq $appliance
            try { Disconnect-Safeguard } catch {}
            # Reconnect as the run admin for subsequent tests
            $secRunPass = ConvertTo-SecureString $Context.RunAdminPassword -AsPlainText -Force
            Connect-Safeguard $appliance local $Context.RunAdminName -Password $secRunPass -Insecure
            $connected
        }

        Test-SgPsAssert "PKCE login can call API" {
            $secPass = ConvertTo-SecureString $pass -AsPlainText -Force
            $token = Connect-Safeguard $appliance local $user -Pkce -Password $secPass -Insecure -NoSessionVariable
            $status = Invoke-SafeguardMethod -Insecure -AccessToken $token Appliance GET "ApplianceStatus"
            $null -ne $status
        }

        # -- Error handling --

        Test-SgPsAssert "PKCE login with wrong password returns error" {
            try {
                $badPass = ConvertTo-SecureString "WRONGPASSWORD" -AsPlainText -Force
                Connect-Safeguard $appliance local $user -Pkce -Password $badPass -Insecure -NoSessionVariable
                $false # Should not reach here
            }
            catch {
                # rSTS returns 400 for bad credentials
                $true
            }
        }

        Test-SgPsAssert "PKCE login with unknown user returns error" {
            try {
                $secPass = ConvertTo-SecureString "anypassword" -AsPlainText -Force
                Connect-Safeguard $appliance local "NoSuchUser_ZZZZZ" -Pkce -Password $secPass -Insecure -NoSessionVariable
                $false
            }
            catch {
                # rSTS returns 400 for unknown user
                $true
            }
        }

        Test-SgPsAssert "PKCE login with unknown provider returns error" {
            try {
                $secPass = ConvertTo-SecureString $pass -AsPlainText -Force
                Connect-Safeguard $appliance "nonexistent_provider" $user -Pkce -Password $secPass -Insecure -NoSessionVariable
                $false
            }
            catch {
                $_.Exception.Message -like "*not found*"
            }
        }
    }

    Cleanup = {
        param($Context)
        # Ensure the run admin session is restored if PKCE tests disrupted it
        try {
            if (-not $SafeguardSession -or $SafeguardSession.Username -ne $Context.RunAdminName) {
                $secRunPass = ConvertTo-SecureString $Context.RunAdminPassword -AsPlainText -Force
                Connect-Safeguard $Context.Appliance local $Context.RunAdminName -Password $secRunPass -Insecure
            }
        } catch {}
    }
}
