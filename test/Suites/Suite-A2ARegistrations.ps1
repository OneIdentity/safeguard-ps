@{
    Name        = "A2A Registrations"
    Description = "Tests A2A registration CRUD, credential retrieval config, and API keys"
    Tags        = @("a2a", "security")

    Setup = {
        param($Context)

        $prefix = $Context.TestPrefix
        $testA2a = "${prefix}_A2aReg1"
        $testA2a2 = "${prefix}_A2aReg2"
        $testUser = "${prefix}_A2aUser"
        $testAsset = "${prefix}_A2aAsset"
        $testAccount = "${prefix}_A2aAcct"

        # Locate test certificate files for cert user creation
        $certDir = Join-Path $Context.TestRoot "TestData\CERTS"
        if (-not (Test-Path $certDir)) {
            throw "Test certificate directory not found: $certDir"
        }
        $rootPem = Join-Path $certDir "RootCA.pem"
        $intPem = Join-Path $certDir "IntermediateCA.pem"
        $userPfx = Join-Path $certDir "UserCert.pfx"

        # Compute thumbprints
        $rootCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($rootPem)
        $Context.SuiteData["RootThumbprint"] = $rootCert.Thumbprint

        $intCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($intPem)
        $Context.SuiteData["IntThumbprint"] = $intCert.Thumbprint

        $userCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($userPfx, "a")
        $Context.SuiteData["UserThumbprint"] = $userCert.Thumbprint

        # Pre-cleanup
        Remove-SgPsStaleTestObject -Collection "A2ARegistrations" -Name $testA2a
        Remove-SgPsStaleTestObject -Collection "A2ARegistrations" -Name $testA2a2
        Remove-SgPsStaleTestObject -Collection "AssetAccounts" -Name $testAccount
        Remove-SgPsStaleTestObject -Collection "Assets" -Name $testAsset
        Remove-SgPsStaleTestObject -Collection "Users" -Name $testUser
        try { Uninstall-SafeguardTrustedCertificate -Insecure $Context.SuiteData["IntThumbprint"] } catch {}
        try { Uninstall-SafeguardTrustedCertificate -Insecure $Context.SuiteData["RootThumbprint"] } catch {}

        $Context.SuiteData["TestA2a"] = $testA2a
        $Context.SuiteData["TestA2a2"] = $testA2a2

        # Install trusted cert chain (required for cert user)
        Install-SafeguardTrustedCertificate -Insecure $rootPem
        Register-SgPsTestCleanup -Description "Uninstall RootCA" -Action {
            param($Ctx)
            try { Uninstall-SafeguardTrustedCertificate -Insecure $Ctx.SuiteData['RootThumbprint'] } catch {}
        }
        Install-SafeguardTrustedCertificate -Insecure $intPem
        Register-SgPsTestCleanup -Description "Uninstall IntermediateCA" -Action {
            param($Ctx)
            try { Uninstall-SafeguardTrustedCertificate -Insecure $Ctx.SuiteData['IntThumbprint'] } catch {}
        }

        # Create certificate user (auth provider -2 = Certificate)
        $user = Invoke-SafeguardMethod -Insecure Core POST "Users" -Body @{
            PrimaryAuthenticationProvider = @{
                Id = -2
                Identity = $Context.SuiteData["UserThumbprint"]
            }
            Name = $testUser
        }
        $Context.SuiteData["UserId"] = $user.Id
        $Context.SuiteData["TestUser"] = $testUser

        # Create asset and account for credential retrieval config
        $asset = New-SafeguardAsset -Insecure -DisplayName $testAsset `
            -Platform 521 -NetworkAddress "10.0.7.100" `
            -ServiceAccountCredentialType "None" -NoSshHostKeyDiscovery
        $Context.SuiteData["AssetId"] = $asset.Id
        $Context.SuiteData["TestAsset"] = $testAsset

        $account = New-SafeguardAssetAccount -Insecure -ParentAsset $asset.Id -NewAccountName $testAccount
        $Context.SuiteData["AccountId"] = $account.Id
        $Context.SuiteData["TestAccount"] = $testAccount

        Register-SgPsTestCleanup -Description "Delete A2A account" -Action {
            param($Ctx)
            try { Remove-SafeguardAssetAccount -Insecure $Ctx.SuiteData['AssetId'] $Ctx.SuiteData['AccountId'] } catch {}
        }
        Register-SgPsTestCleanup -Description "Delete A2A asset" -Action {
            param($Ctx)
            try { Remove-SafeguardAsset -Insecure $Ctx.SuiteData['AssetId'] } catch {}
        }
        Register-SgPsTestCleanup -Description "Delete A2A user" -Action {
            param($Ctx)
            try { Remove-SafeguardUser -Insecure $Ctx.SuiteData['UserId'] } catch {}
        }
    }

    Execute = {
        param($Context)

        $testA2a = $Context.SuiteData["TestA2a"]
        $testA2a2 = $Context.SuiteData["TestA2a2"]

        # --- Get-SafeguardA2aServiceStatus ---
        Test-SgPsAssert "Get-SafeguardA2aServiceStatus returns status" {
            $status = Get-SafeguardA2aServiceStatus -Insecure
            $null -ne $status
        }

        # --- Get-SafeguardA2a (list) ---
        Test-SgPsAssert "Get-SafeguardA2a lists registrations" {
            $regs = Get-SafeguardA2a -Insecure
            $null -ne $regs
        }

        # --- New-SafeguardA2a ---
        Test-SgPsAssert "New-SafeguardA2a creates a registration" {
            $reg = New-SafeguardA2a -Insecure $testA2a -CertificateUser $Context.SuiteData["TestUser"] `
                -Description "Test A2A registration"
            $Context.SuiteData["A2aId"] = $reg.Id

            Register-SgPsTestCleanup -Description "Delete A2A registration $testA2a" -Action {
                param($Ctx)
                try { Remove-SafeguardA2a -Insecure $Ctx.SuiteData['A2aId'] } catch {}
            }
            $reg.AppName -eq $testA2a
        }

        # --- Get-SafeguardA2a by ID ---
        Test-SgPsAssert "Get-SafeguardA2a by ID" {
            $reg = Get-SafeguardA2a -Insecure $Context.SuiteData["A2aId"]
            $reg.AppName -eq $testA2a
        }

        # --- Get-SafeguardA2a by Name ---
        Test-SgPsAssert "Get-SafeguardA2a by Name" {
            $reg = Get-SafeguardA2a -Insecure $testA2a
            $reg.Id -eq $Context.SuiteData["A2aId"]
        }

        # --- Edit-SafeguardA2a (attributes) ---
        Test-SgPsAssert "Edit-SafeguardA2a updates description" {
            $updated = Edit-SafeguardA2a -Insecure $Context.SuiteData["A2aId"] -Description "Updated A2A desc"
            $updated.Description -eq "Updated A2A desc"
        }

        # --- Edit-SafeguardA2a with object ---
        Test-SgPsAssert "Edit-SafeguardA2a with object" {
            $reg = Get-SafeguardA2a -Insecure $Context.SuiteData["A2aId"]
            $reg.Description = "Modified via object"
            $updated = Edit-SafeguardA2a -Insecure -A2aObject $reg
            $updated.Description -eq "Modified via object"
        }

        # --- Add-SafeguardA2aCredentialRetrieval ---
        Test-SgPsAssert "Add-SafeguardA2aCredentialRetrieval adds account" {
            $result = Add-SafeguardA2aCredentialRetrieval -Insecure $Context.SuiteData["A2aId"] `
                -Asset $Context.SuiteData["TestAsset"] -Account $Context.SuiteData["TestAccount"]
            $null -ne $result
        }

        # --- Get-SafeguardA2aCredentialRetrieval ---
        Test-SgPsAssert "Get-SafeguardA2aCredentialRetrieval lists accounts" {
            $creds = Get-SafeguardA2aCredentialRetrieval -Insecure $Context.SuiteData["A2aId"] `
                -Asset $Context.SuiteData["TestAsset"] -Account $Context.SuiteData["TestAccount"]
            $null -ne $creds
        }

        # --- Get-SafeguardA2aCredentialRetrievalApiKey ---
        Test-SgPsAssert "Get-SafeguardA2aCredentialRetrievalApiKey returns key" {
            $key = Get-SafeguardA2aCredentialRetrievalApiKey -Insecure $Context.SuiteData["A2aId"] `
                -Asset $Context.SuiteData["TestAsset"] -Account $Context.SuiteData["TestAccount"]
            $null -ne $key -and $key.Length -gt 0
        }

        # --- Reset-SafeguardA2aCredentialRetrievalApiKey ---
        Test-SgPsAssert "Reset-SafeguardA2aCredentialRetrievalApiKey regenerates key" {
            $oldKey = Get-SafeguardA2aCredentialRetrievalApiKey -Insecure $Context.SuiteData["A2aId"] `
                -Asset $Context.SuiteData["TestAsset"] -Account $Context.SuiteData["TestAccount"]
            Reset-SafeguardA2aCredentialRetrievalApiKey -Insecure $Context.SuiteData["A2aId"] `
                -Asset $Context.SuiteData["TestAsset"] -Account $Context.SuiteData["TestAccount"]
            $newKey = Get-SafeguardA2aCredentialRetrievalApiKey -Insecure $Context.SuiteData["A2aId"] `
                -Asset $Context.SuiteData["TestAsset"] -Account $Context.SuiteData["TestAccount"]
            $newKey -ne $oldKey
        }

        # --- Remove-SafeguardA2aCredentialRetrieval ---
        Test-SgPsAssert "Remove-SafeguardA2aCredentialRetrieval removes account" {
            Remove-SafeguardA2aCredentialRetrieval -Insecure $Context.SuiteData["A2aId"] `
                -Asset $Context.SuiteData["TestAsset"] -Account $Context.SuiteData["TestAccount"]
            $true
        }

        # --- Get-SafeguardA2aAccessRequestBroker ---
        Test-SgPsAssert "Get-SafeguardA2aAccessRequestBroker handles no broker config" {
            try {
                $broker = Get-SafeguardA2aAccessRequestBroker -Insecure $Context.SuiteData["A2aId"]
                # If it returns something, that's valid
                $null -ne $broker
            } catch {
                # 404 is expected when no broker is configured
                $_.Exception.Message -match "404|Not Found"
            }
        }

        # --- New-SafeguardA2a (second, for remove test) ---
        Test-SgPsAssert "New-SafeguardA2a second registration" {
            $reg2 = New-SafeguardA2a -Insecure $testA2a2 -CertificateUser $Context.SuiteData["TestUser"]
            $Context.SuiteData["A2a2Id"] = $reg2.Id

            Register-SgPsTestCleanup -Description "Delete A2A registration $testA2a2" -Action {
                param($Ctx)
                try { Remove-SafeguardA2a -Insecure $Ctx.SuiteData['A2a2Id'] } catch {}
            }
            $reg2.AppName -eq $testA2a2
        }

        # --- Remove-SafeguardA2a ---
        Test-SgPsAssert "Remove-SafeguardA2a deletes a registration" {
            Remove-SafeguardA2a -Insecure $Context.SuiteData["A2a2Id"]
            $remaining = Get-SafeguardA2a -Insecure
            $list = @($remaining)
            -not ($list | Where-Object { $_.Id -eq $Context.SuiteData["A2a2Id"] })
        }
    }

    Cleanup = {
        param($Context)
    }
}
