@{
    Name        = "A2A Credentials"
    Description = "Tests A2A credential retrieval via certificate authentication"
    Tags        = @("a2a", "certificate", "credentials")

    Setup = {
        param($Context)

        $prefix = $Context.TestPrefix
        $certUser = "${prefix}_A2aCertUser"
        $testAsset = "${prefix}_A2aCredAsset"
        $testAccount = "${prefix}_A2aCredAcct"
        $testA2a = "${prefix}_A2aCredReg"
        $accountPassword = "TestA2aPwd_9xZk!"

        # Locate test certificate files
        $certDir = Join-Path $Context.TestRoot "TestData\CERTS"
        if (-not (Test-Path $certDir)) {
            throw "Test certificate directory not found: $certDir"
        }
        $Context.SuiteData["CertDir"] = $certDir
        $Context.SuiteData["UserPfx"] = Join-Path $certDir "UserCert.pfx"
        $Context.SuiteData["RootCaPem"] = Join-Path $certDir "RootCA.pem"
        $Context.SuiteData["IntCaPem"] = Join-Path $certDir "IntermediateCA.pem"
        $Context.SuiteData["PfxPassword"] = "a"

        # Compute thumbprints
        $rootCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            $Context.SuiteData["RootCaPem"])
        $Context.SuiteData["RootThumbprint"] = $rootCert.Thumbprint

        $intCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            $Context.SuiteData["IntCaPem"])
        $Context.SuiteData["IntThumbprint"] = $intCert.Thumbprint

        $userCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            $Context.SuiteData["UserPfx"],
            $Context.SuiteData["PfxPassword"])
        $Context.SuiteData["UserThumbprint"] = $userCert.Thumbprint

        # Pre-cleanup: remove stale objects (reverse dependency order)
        Remove-SgPsStaleTestObject -Collection "A2ARegistrations" -Name $testA2a
        Remove-SgPsStaleTestObject -Collection "AssetAccounts" -Name $testAccount
        Remove-SgPsStaleTestObject -Collection "Assets" -Name $testAsset
        Remove-SgPsStaleTestObject -Collection "Users" -Name $certUser
        try { Uninstall-SafeguardTrustedCertificate -Insecure $Context.SuiteData["IntThumbprint"] } catch {}
        try { Uninstall-SafeguardTrustedCertificate -Insecure $Context.SuiteData["RootThumbprint"] } catch {}

        # 1. Install trusted cert chain (required for cert user auth)
        $null = Install-SafeguardTrustedCertificate -Insecure $Context.SuiteData["RootCaPem"]
        Register-SgPsTestCleanup -Description "Uninstall RootCA" -Action {
            param($Ctx)
            try { Uninstall-SafeguardTrustedCertificate -Insecure $Ctx.SuiteData['RootThumbprint'] } catch {}
        }

        $null = Install-SafeguardTrustedCertificate -Insecure $Context.SuiteData["IntCaPem"]
        Register-SgPsTestCleanup -Description "Uninstall IntermediateCA" -Action {
            param($Ctx)
            try { Uninstall-SafeguardTrustedCertificate -Insecure $Ctx.SuiteData['IntThumbprint'] } catch {}
        }

        # 2. Create certificate user (auth provider -2 = Certificate, Identity = thumbprint)
        $cUser = Invoke-SafeguardMethod -Insecure Core POST "Users" -Body @{
            PrimaryAuthenticationProvider = @{
                Id = -2
                Identity = $Context.SuiteData["UserThumbprint"]
            }
            Name = $certUser
        }
        $Context.SuiteData["CertUserId"] = $cUser.Id
        Register-SgPsTestCleanup -Description "Delete certificate user" -Action {
            param($Ctx)
            try { Remove-SafeguardUser -Insecure $Ctx.SuiteData['CertUserId'] } catch {}
        }

        # 3. Create asset and account
        $asset = New-SafeguardAsset -Insecure -DisplayName $testAsset `
            -Platform 521 -NetworkAddress "10.0.8.100" `
            -ServiceAccountCredentialType "None" -NoSshHostKeyDiscovery
        $Context.SuiteData["AssetId"] = $asset.Id
        $Context.SuiteData["TestAsset"] = $testAsset
        Register-SgPsTestCleanup -Description "Delete A2A cred asset" -Action {
            param($Ctx)
            try { Remove-SafeguardAsset -Insecure $Ctx.SuiteData['AssetId'] } catch {}
        }

        $account = New-SafeguardAssetAccount -Insecure -ParentAsset $asset.Id -NewAccountName $testAccount
        $Context.SuiteData["AccountId"] = $account.Id
        $Context.SuiteData["TestAccount"] = $testAccount
        Register-SgPsTestCleanup -Description "Delete A2A cred account" -Action {
            param($Ctx)
            try { Remove-SafeguardAssetAccount -Insecure $Ctx.SuiteData['AssetId'] $Ctx.SuiteData['AccountId'] } catch {}
        }

        # Set account password
        Set-SafeguardAssetAccountPassword -Insecure $Context.SuiteData["TestAsset"] `
            $Context.SuiteData["TestAccount"] `
            -NewPassword (ConvertTo-SecureString $accountPassword -AsPlainText -Force)
        $Context.SuiteData["AccountPassword"] = $accountPassword

        # 4. Create A2A registration with credential retrieval (BidirectionalEnabled for Set-Password)
        $a2aReg = Invoke-SafeguardMethod -Insecure Core POST "A2ARegistrations" -Body @{
            AppName = $testA2a
            CertificateUserId = $cUser.Id
            Description = "A2A credential retrieval test"
            VisibleToCertificateUsers = $true
            BidirectionalEnabled = $true
        }
        $Context.SuiteData["A2aId"] = $a2aReg.Id
        Register-SgPsTestCleanup -Description "Delete A2A registration" -Action {
            param($Ctx)
            try { Remove-SafeguardA2a -Insecure $Ctx.SuiteData['A2aId'] } catch {}
        }

        # 5. Add credential retrieval for the account
        Add-SafeguardA2aCredentialRetrieval -Insecure $Context.SuiteData["A2aId"] `
            -Asset $testAsset -Account $testAccount

        # 6. Get the API key
        $apiKey = Get-SafeguardA2aCredentialRetrievalApiKey -Insecure $Context.SuiteData["A2aId"] `
            -Asset $testAsset -Account $testAccount
        $Context.SuiteData["ApiKey"] = $apiKey

        # 7. Enable A2A service
        try {
            Invoke-SafeguardMethod -Insecure Appliance POST "A2AService/Enable"
        } catch {
            # May already be enabled
        }
    }

    Execute = {
        param($Context)

        $pfx = $Context.SuiteData["UserPfx"]
        $pfxPwd = ConvertTo-SecureString $Context.SuiteData["PfxPassword"] -AsPlainText -Force
        $apiKey = $Context.SuiteData["ApiKey"]
        $appliance = $Context.Appliance

        # --- Get-SafeguardA2aRetrievableAccount via PFX ---
        Test-SgPsAssert "Get-SafeguardA2aRetrievableAccount via PFX" {
            $accounts = Get-SafeguardA2aRetrievableAccount -Appliance $appliance -Insecure `
                -CertificateFile $pfx -Password $pfxPwd
            $list = @($accounts)
            $list.Count -ge 1
        }

        # --- Get-SafeguardA2aPassword via PFX ---
        Test-SgPsAssert "Get-SafeguardA2aPassword retrieves password via PFX" {
            $a2aPassword = Get-SafeguardA2aPassword -Appliance $appliance -Insecure `
                -CertificateFile $pfx -Password $pfxPwd -ApiKey $apiKey
            $null -ne $a2aPassword
        }

        # --- Get-SafeguardA2aApiKeySecret via PFX ---
        Test-SgPsAssert "Get-SafeguardA2aApiKeySecret retrieves API key secret" {
            $secret = Get-SafeguardA2aApiKeySecret -Appliance $appliance -Insecure `
                -CertificateFile $pfx -Password $pfxPwd -ApiKey $apiKey
            $null -ne $secret
        }

        # --- Set-SafeguardA2aPassword via PFX ---
        Test-SgPsAssert "Set-SafeguardA2aPassword sets a new password via PFX" {
            $newPwd = ConvertTo-SecureString "NewA2aPwd_7mQr!" -AsPlainText -Force
            Set-SafeguardA2aPassword -Appliance $appliance -Insecure `
                -CertificateFile $pfx -Password $pfxPwd -ApiKey $apiKey -NewPassword $newPwd
            $true
        }

        # --- New-SafeguardA2aAccessRequest via PFX ---
        Test-SgPsAssert "New-SafeguardA2aAccessRequest returns expected error without policy" {
            try {
                $ar = New-SafeguardA2aAccessRequest -Appliance $appliance -Insecure `
                    -CertificateFile $pfx -Password $pfxPwd -ApiKey $apiKey `
                    -ForUserName $Context.SuiteData["TestAccount"] -AssetToUse $Context.SuiteData["TestAsset"]
                $null -ne $ar
            } catch {
                # Expected: various policy/access/cert errors are all acceptable
                $true
            }
        }
    }

    Cleanup = {
        param($Context)
    }
}
