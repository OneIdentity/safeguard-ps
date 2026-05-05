@{
    Name        = "Connect & Core"
    Description = "Tests Connect-Safeguard, Disconnect-Safeguard, Invoke-SafeguardMethod, token status, and logged-in user"
    Tags        = @("core", "auth")

    Setup = {
        param($Context)

        $prefix = $Context.TestPrefix

        # Set up certificate infrastructure for CertificateObject tests
        $certDir = Join-Path $Context.TestRoot "TestData\CERTS"
        if (-not (Test-Path $certDir)) {
            throw "Test certificate directory not found: $certDir"
        }
        $Context.SuiteData["CertDir"] = $certDir
        $Context.SuiteData["UserCertPfx"] = Join-Path $certDir "CertAuthUser.pfx"
        $Context.SuiteData["CaCertPem"] = Join-Path $certDir "CertAuthCA.pem"
        $Context.SuiteData["PfxPassword"] = "a"

        # Read thumbprints
        $pfxPwd = ConvertTo-SecureString $Context.SuiteData["PfxPassword"] -AsPlainText -Force
        $userCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            $Context.SuiteData["UserCertPfx"], $pfxPwd)
        $Context.SuiteData["UserCertThumbprint"] = $userCert.Thumbprint

        $caCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            $Context.SuiteData["CaCertPem"])
        $Context.SuiteData["CaThumbprint"] = $caCert.Thumbprint

        # Pre-cleanup: remove stale objects from prior runs
        $certUserName = "${prefix}_ConnCertUser"
        $Context.SuiteData["CertUserName"] = $certUserName
        try { Uninstall-SafeguardTrustedCertificate -Insecure $Context.SuiteData["CaThumbprint"] } catch {}
        try {
            $staleUser = Find-SafeguardUser -Insecure $certUserName
            if ($staleUser) { Remove-SafeguardUser -Insecure $staleUser.Id }
        } catch {}

        # Install CA as trusted so the appliance accepts the user cert
        Install-SafeguardTrustedCertificate -Insecure $Context.SuiteData["CaCertPem"] | Out-Null
        Register-SgPsTestCleanup -Description "Uninstall Connect CA cert" -Action {
            param($Ctx)
            try { Uninstall-SafeguardTrustedCertificate -Insecure $Ctx.SuiteData['CaThumbprint'] } catch {}
        }

        # Create certificate-authenticated user
        $user = New-SafeguardUser -Insecure -Provider certificate `
            -NewUserName $certUserName `
            -Thumbprint $Context.SuiteData["UserCertThumbprint"] `
            -NoPassword `
            -AdminRoles @("Auditor")
        $Context.SuiteData["CertUserId"] = $user.Id
        Register-SgPsTestCleanup -Description "Remove Connect cert user" -Action {
            param($Ctx)
            try { Remove-SafeguardUser -Insecure $Ctx.SuiteData['CertUserId'] } catch {}
        }
    }

    Execute = {
        param($Context)

        # --- Connect-Safeguard with -NoSessionVariable (returns access token) ---
        Test-SgPsAssert "Connect-Safeguard -NoSessionVariable returns access token" {
            $secPwd = ConvertTo-SecureString $Context.AdminPassword -AsPlainText -Force
            $token = Connect-Safeguard -Appliance $Context.Appliance -IdentityProvider "Local" `
                -Username $Context.AdminUserName -Password $secPwd -Insecure -NoSessionVariable
            $Context.SuiteData["ExplicitToken"] = $token
            $null -ne $token -and $token.Length -gt 0
        }

        # --- Disconnect explicit token ---
        Test-SgPsAssert "Disconnect-Safeguard with explicit token" {
            Disconnect-Safeguard -Appliance $Context.Appliance `
                -AccessToken $Context.SuiteData["ExplicitToken"] -Insecure
            # Verify token is invalidated by trying to use it
            try {
                $null = Invoke-SafeguardMethod -Appliance $Context.Appliance `
                    -AccessToken $Context.SuiteData["ExplicitToken"] -Insecure `
                    -Service Core -Method Get -RelativeUrl "Me"
                $false  # Should have thrown
            } catch {
                $true   # Expected: token is no longer valid
            }
        }

        # --- Connect-Safeguard sets $SafeguardSession ---
        Test-SgPsAssert "Connect-Safeguard sets SafeguardSession global" {
            # Reconnect using session variable (runner already connected, but let's verify behavior)
            $secPwd = ConvertTo-SecureString $Context.AdminPassword -AsPlainText -Force
            Connect-Safeguard -Appliance $Context.Appliance -IdentityProvider "Local" `
                -Username $Context.AdminUserName -Password $secPwd -Insecure
            $null -ne $SafeguardSession -and $SafeguardSession.Appliance -eq $Context.Appliance
        }

        # --- Get-SafeguardAccessTokenStatus (session-based, no -Insecure) ---
        Test-SgPsAssert "Get-SafeguardAccessTokenStatus returns valid timespan" {
            $remaining = Get-SafeguardAccessTokenStatus -Raw
            $remaining -is [TimeSpan] -and $remaining.TotalMinutes -gt 0
        }

        # --- Get-SafeguardAccessTokenStatus with explicit token ---
        Test-SgPsAssert "Get-SafeguardAccessTokenStatus with explicit token" {
            $secPwd = ConvertTo-SecureString $Context.AdminPassword -AsPlainText -Force
            $token = Connect-Safeguard -Appliance $Context.Appliance -IdentityProvider "Local" `
                -Username $Context.AdminUserName -Password $secPwd -Insecure -NoSessionVariable
            $remaining = Get-SafeguardAccessTokenStatus -Appliance $Context.Appliance `
                -AccessToken $token -Insecure -Raw
            Disconnect-Safeguard -Appliance $Context.Appliance -AccessToken $token -Insecure
            $remaining -is [TimeSpan] -and $remaining.TotalMinutes -gt 0
        }

        # --- Get-SafeguardLoggedInUser ---
        Test-SgPsAssert "Get-SafeguardLoggedInUser returns current user" {
            $me = Get-SafeguardLoggedInUser -Insecure
            $null -ne $me -and $null -ne $me.Id -and $null -ne $me.Name
        }

        Test-SgPsAssert "Get-SafeguardLoggedInUser with Fields parameter" {
            $me = Get-SafeguardLoggedInUser -Insecure -Fields "Id","Name","AdminRoles"
            $null -ne $me.Id -and $null -ne $me.Name -and $null -ne $me.AdminRoles
        }

        # --- Invoke-SafeguardMethod ---
        Test-SgPsAssert "Invoke-SafeguardMethod GET on Core service" {
            $result = Invoke-SafeguardMethod -Insecure -Service Core -Method Get -RelativeUrl "Me"
            $null -ne $result -and $null -ne $result.Id
        }

        Test-SgPsAssert "Invoke-SafeguardMethod GET on Appliance service" {
            $result = Invoke-SafeguardMethod -Insecure -Service Appliance -Method Get -RelativeUrl "ApplianceStatus"
            $null -ne $result
        }

        Test-SgPsAssert "Invoke-SafeguardMethod GET on Notification service" {
            $result = Invoke-SafeguardMethod -Insecure -Service Notification -Method Get -RelativeUrl "Status"
            $null -ne $result
        }

        Test-SgPsAssert "Invoke-SafeguardMethod with explicit token" {
            $secPwd = ConvertTo-SecureString $Context.AdminPassword -AsPlainText -Force
            $token = Connect-Safeguard -Appliance $Context.Appliance -IdentityProvider "Local" `
                -Username $Context.AdminUserName -Password $secPwd -Insecure -NoSessionVariable
            $result = Invoke-SafeguardMethod -Appliance $Context.Appliance `
                -AccessToken $token -Insecure -Service Core -Method Get -RelativeUrl "Me"
            Disconnect-Safeguard -Appliance $Context.Appliance -AccessToken $token -Insecure
            $null -ne $result -and $null -ne $result.Id
        }

        Test-SgPsAssert "Invoke-SafeguardMethod with Parameters" {
            $result = Invoke-SafeguardMethod -Insecure -Service Core -Method Get `
                -RelativeUrl "Users" -Parameters @{ fields = "Id,Name"; filter = "Name eq 'Admin'" }
            $null -ne $result
        }

        Test-SgPsAssert "Invoke-SafeguardMethod Anonymous GET on status" {
            $result = Invoke-SafeguardMethod -Appliance $Context.Appliance -Insecure `
                -Service Notification -Method Get -RelativeUrl "Status" -Anonymous
            $null -ne $result
        }

        # --- Update-SafeguardAccessToken ---
        Test-SgPsAssert "Update-SafeguardAccessToken refreshes the token" {
            $oldToken = $SafeguardSession.AccessToken
            # We're connected as bootstrap Admin at this point in the suite
            $secPwd = ConvertTo-SecureString $Context.AdminPassword -AsPlainText -Force
            Update-SafeguardAccessToken -Password $secPwd
            $newToken = $SafeguardSession.AccessToken
            # New token should be valid (may or may not differ depending on timing)
            $null -ne $newToken -and $newToken.Length -gt 0 -and $newToken -ne $oldToken
        }

        # --- Connect-Safeguard with -CertificateObject ---
        Test-SgPsAssert "Connect-Safeguard with -CertificateObject returns access token" {
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
                $Context.SuiteData["UserCertPfx"],
                $Context.SuiteData["PfxPassword"])
            $token = Connect-Safeguard -Appliance $Context.Appliance `
                -CertificateObject $cert -Insecure -NoSessionVariable
            $null -ne $token -and $token.Length -gt 0
        }

        Test-SgPsAssert "Connect-Safeguard with -CertificateObject stores in session" {
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
                $Context.SuiteData["UserCertPfx"],
                $Context.SuiteData["PfxPassword"])
            Connect-Safeguard -Appliance $Context.Appliance `
                -CertificateObject $cert -Insecure
            $stored = $SafeguardSession.CertificateObject
            $result = $null -ne $stored -and $stored.Thumbprint -eq $cert.Thumbprint
            # Reconnect as original user for remaining tests
            $secPwd = ConvertTo-SecureString $Context.AdminPassword -AsPlainText -Force
            Connect-Safeguard -Appliance $Context.Appliance -IdentityProvider "Local" `
                -Username $Context.AdminUserName -Password $secPwd -Insecure
            $result
        }

        Test-SgPsAssert "Connect-Safeguard with -CertificateObject can call API" {
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
                $Context.SuiteData["UserCertPfx"],
                $Context.SuiteData["PfxPassword"])
            Connect-Safeguard -Appliance $Context.Appliance `
                -CertificateObject $cert -Insecure
            $me = Get-SafeguardLoggedInUser -Insecure
            $result = $null -ne $me -and $me.Name -eq $Context.SuiteData["CertUserName"]
            # Reconnect as admin
            $secPwd = ConvertTo-SecureString $Context.AdminPassword -AsPlainText -Force
            Connect-Safeguard -Appliance $Context.Appliance -IdentityProvider "Local" `
                -Username $Context.AdminUserName -Password $secPwd -Insecure
            $result
        }

        Test-SgPsAssert "Update-SafeguardAccessToken works with CertificateObject session" {
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
                $Context.SuiteData["UserCertPfx"],
                $Context.SuiteData["PfxPassword"])
            Connect-Safeguard -Appliance $Context.Appliance `
                -CertificateObject $cert -Insecure
            $oldToken = $SafeguardSession.AccessToken
            Update-SafeguardAccessToken
            $newToken = $SafeguardSession.AccessToken
            $result = $null -ne $newToken -and $newToken.Length -gt 0 -and $newToken -ne $oldToken
            # Reconnect as admin
            $secPwd = ConvertTo-SecureString $Context.AdminPassword -AsPlainText -Force
            Connect-Safeguard -Appliance $Context.Appliance -IdentityProvider "Local" `
                -Username $Context.AdminUserName -Password $secPwd -Insecure
            $result
        }
    }

    Cleanup = {
        param($Context)
        # The Connect suite reconnects as bootstrap Admin during tests.
        # Reconnect as RunAdmin (if used) so subsequent suites have full privileges.
        if ($Context.RunAdminName) {
            try { Disconnect-Safeguard } catch {}
            $secPwd = ConvertTo-SecureString $Context.RunAdminPassword -AsPlainText -Force
            Connect-Safeguard -Appliance $Context.Appliance -IdentityProvider "Local" `
                -Username $Context.RunAdminName -Password $secPwd -Insecure
        } else {
            # Not using RunAdmin -- just ensure we're still connected
            try {
                $null = Get-SafeguardLoggedInUser -Insecure -ErrorAction Stop
            }
            catch {
                $secPwd = ConvertTo-SecureString $Context.AdminPassword -AsPlainText -Force
                Connect-Safeguard -Appliance $Context.Appliance -IdentityProvider "Local" `
                    -Username $Context.AdminUserName -Password $secPwd -Insecure
            }
        }
    }
}
