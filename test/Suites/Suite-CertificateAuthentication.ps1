@{
    Name        = "Certificate Authentication"
    Description = "Tests Connect-Safeguard with -CertificateFile and -CertificatePassword, including Update-SafeguardAccessToken"
    Tags        = @("auth", "certificate")

    Setup = {
        param($Context)

        # Locate test certificate files (dedicated certs for this suite)
        $certDir = Join-Path $Context.TestRoot "TestData\CERTS"
        if (-not (Test-Path $certDir)) {
            throw "Test certificate directory not found: $certDir"
        }
        $Context.SuiteData["CertDir"] = $certDir
        $Context.SuiteData["CaCertPem"] = Join-Path $certDir "CertAuthCA.pem"
        $Context.SuiteData["UserCertPfx"] = Join-Path $certDir "CertAuthUser.pfx"
        $Context.SuiteData["PfxPassword"] = "a"  # documented in TestData/CERTS/README.md

        # Read the user certificate thumbprint
        $pfxPwd = ConvertTo-SecureString $Context.SuiteData["PfxPassword"] -AsPlainText -Force
        $userCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            $Context.SuiteData["UserCertPfx"], $pfxPwd)
        $Context.SuiteData["UserCertThumbprint"] = $userCert.Thumbprint

        # Read the CA thumbprint for cleanup
        $caCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
            $Context.SuiteData["CaCertPem"])
        $Context.SuiteData["CaThumbprint"] = $caCert.Thumbprint

        # Pre-cleanup: remove stale objects from previous runs
        try { Uninstall-SafeguardTrustedCertificate -Insecure $Context.SuiteData["CaThumbprint"] } catch {}
        $certUserName = "$($Context.TestPrefix)_CertAuthUser"
        $Context.SuiteData["CertUserName"] = $certUserName
        try {
            $staleUser = Find-SafeguardUser -Insecure $certUserName
            if ($staleUser) { Remove-SafeguardUser -Insecure $staleUser.Id }
        } catch {}
        # Also remove any user mapped to the same thumbprint (from prior failed runs)
        try {
            $allUsers = Invoke-SafeguardMethod -Insecure -Service Core -Method Get -RelativeUrl "Users"
            $thumbprintUser = @($allUsers) | Where-Object {
                $_.PrimaryAuthenticationProvider.Identity -eq $Context.SuiteData["UserCertThumbprint"]
            }
            if ($thumbprintUser) { Remove-SafeguardUser -Insecure $thumbprintUser.Id }
        } catch {}

        # Install the CA cert as trusted so the appliance trusts the user cert
        Install-SafeguardTrustedCertificate -Insecure $Context.SuiteData["CaCertPem"] | Out-Null
        Register-SgPsTestCleanup -Description "Uninstall CertAuth CA trusted cert" -Action {
            param($Ctx)
            try { Uninstall-SafeguardTrustedCertificate -Insecure $Ctx.SuiteData['CaThumbprint'] } catch {}
        }

        # Create a certificate-authenticated user linked to the user cert thumbprint
        $user = New-SafeguardUser -Insecure -Provider certificate `
            -NewUserName $certUserName `
            -Thumbprint $Context.SuiteData["UserCertThumbprint"] `
            -NoPassword `
            -AdminRoles @("Auditor")
        $Context.SuiteData["CertUserId"] = $user.Id
        Register-SgPsTestCleanup -Description "Remove certificate auth test user" -Action {
            param($Ctx)
            try { Remove-SafeguardUser -Insecure $Ctx.SuiteData['CertUserId'] } catch {}
        }
    }

    Execute = {
        param($Context)

        $appliance = $Context.Appliance
        $pfxFile = $Context.SuiteData["UserCertPfx"]
        $pfxPlainPassword = $Context.SuiteData["PfxPassword"]
        $pfxSecurePassword = ConvertTo-SecureString $pfxPlainPassword -AsPlainText -Force

        # --- Connect-Safeguard with -CertificateFile and -CertificatePassword ---
        Test-SgPsAssert "Connect-Safeguard with CertificateFile and CertificatePassword returns token" {
            $token = Connect-Safeguard -Appliance $appliance -Insecure `
                -IdentityProvider certificate `
                -CertificateFile $pfxFile `
                -CertificatePassword $pfxSecurePassword `
                -NoSessionVariable
            $null -ne $token -and $token.Length -gt 0
        }

        # --- Connect-Safeguard with -CertificateFile and -CertificatePassword sets session ---
        Test-SgPsAssert "Connect-Safeguard with CertificateFile and CertificatePassword sets session" {
            Connect-Safeguard -Appliance $appliance -Insecure `
                -IdentityProvider certificate `
                -CertificateFile $pfxFile `
                -CertificatePassword $pfxSecurePassword
            $hasSession = $null -ne $SafeguardSession -and $SafeguardSession.Appliance -eq $appliance
            $hasCertFile = $null -ne $SafeguardSession.CertificateFile
            $hasCertPwd = $null -ne $SafeguardSession.CertificatePassword
            $hasSession -and $hasCertFile -and $hasCertPwd
        }

        # --- Session stores CertificatePassword for reconnection ---
        Test-SgPsAssert "Session variable stores CertificatePassword" {
            $SafeguardSession.CertificatePassword -is [SecureString]
        }

        # --- API call works with certificate session ---
        Test-SgPsAssert "Certificate session can call API" {
            $me = Get-SafeguardLoggedInUser -Insecure
            $null -ne $me -and $null -ne $me.Id
        }

        # --- Update-SafeguardAccessToken refreshes certificate session without prompting ---
        Test-SgPsAssert "Update-SafeguardAccessToken refreshes certificate session non-interactively" {
            $oldToken = $SafeguardSession.AccessToken
            Update-SafeguardAccessToken
            $newToken = $SafeguardSession.AccessToken
            $null -ne $newToken -and $newToken.Length -gt 0 -and $newToken -ne $oldToken
        }

        # --- API call still works after token refresh ---
        Test-SgPsAssert "API call succeeds after Update-SafeguardAccessToken" {
            $me = Get-SafeguardLoggedInUser -Insecure
            $null -ne $me -and $null -ne $me.Id
        }

        # --- Disconnect certificate session ---
        Test-SgPsAssert "Disconnect-Safeguard clears certificate session" {
            Disconnect-Safeguard
            $null -eq $SafeguardSession
        }
    }

    Cleanup = {
        param($Context)
        # Reconnect as the run admin (or bootstrap admin) for subsequent suites
        try { Disconnect-Safeguard } catch {}
        if ($Context.RunAdminName) {
            $secPwd = ConvertTo-SecureString $Context.RunAdminPassword -AsPlainText -Force
            Connect-Safeguard -Appliance $Context.Appliance -IdentityProvider "Local" `
                -Username $Context.RunAdminName -Password $secPwd -Insecure
        } else {
            $secPwd = ConvertTo-SecureString $Context.AdminPassword -AsPlainText -Force
            Connect-Safeguard -Appliance $Context.Appliance -IdentityProvider "Local" `
                -Username $Context.AdminUserName -Password $secPwd -Insecure
        }
    }
}
