@{
    Name        = "Asset Account Management"
    Description = "Tests asset account CRUD, password management, enable/disable operations"
    Tags        = @("accounts", "core")

    Setup = {
        param($Context)

        $prefix = $Context.TestPrefix
        $testAsset = "${prefix}_AcctAsset"
        $testAccount = "${prefix}_Account1"
        $testAccount2 = "${prefix}_Account2"
        $testPassword = "AcctTest1234!abcXYZ"

        # Pre-cleanup (accounts before assets due to dependency)
        Remove-SgPsStaleTestObject -Collection "AssetAccounts" -Name $testAccount
        Remove-SgPsStaleTestObject -Collection "AssetAccounts" -Name $testAccount2
        Remove-SgPsStaleTestObject -Collection "Assets" -Name $testAsset

        # Create a parent asset for account tests
        $asset = New-SafeguardAsset -Insecure -DisplayName $testAsset `
            -Platform 521 -NetworkAddress "10.0.1.100" `
            -ServiceAccountCredentialType "None" -NoSshHostKeyDiscovery
        $Context.SuiteData["AssetId"] = $asset.Id
        $Context.SuiteData["AssetName"] = $testAsset

        Register-SgPsTestCleanup -Description "Delete parent asset $testAsset" -Action {
            param($Ctx)
            try { Remove-SafeguardAsset -Insecure $Ctx.SuiteData['AssetId'] } catch {}
        }

        $Context.SuiteData["TestAccount"] = $testAccount
        $Context.SuiteData["TestAccount2"] = $testAccount2
        $Context.SuiteData["TestPassword"] = $testPassword
    }

    Execute = {
        param($Context)

        $assetId = $Context.SuiteData["AssetId"]
        $testAccount = $Context.SuiteData["TestAccount"]
        $testAccount2 = $Context.SuiteData["TestAccount2"]
        $testPassword = $Context.SuiteData["TestPassword"]

        # --- Get-SafeguardAssetAccount (list all) ---
        Test-SgPsAssert "Get-SafeguardAssetAccount lists accounts" {
            $list = @(Get-SafeguardAssetAccount -Insecure)
            $list -is [Array]
        }

        # --- New-SafeguardAssetAccount ---
        Test-SgPsAssert "New-SafeguardAssetAccount creates an account" {
            $account = New-SafeguardAssetAccount -Insecure -ParentAsset $assetId `
                -NewAccountName $testAccount
            $Context.SuiteData["AccountId"] = $account.Id

            Register-SgPsTestCleanup -Description "Delete test account $testAccount" -Action {
                param($Ctx)
                try { Remove-SafeguardAssetAccount -Insecure -AccountToDelete $Ctx.SuiteData['AccountId'] } catch {}
            }

            $null -ne $account.Id -and $account.Name -eq $testAccount
        }

        # --- Get-SafeguardAssetAccount by asset and account ---
        Test-SgPsAssert "Get-SafeguardAssetAccount by asset and account ID" {
            $account = Get-SafeguardAssetAccount -Insecure $assetId $Context.SuiteData["AccountId"]
            $account.Name -eq $testAccount
        }

        # --- Get-SafeguardAssetAccount for specific asset ---
        Test-SgPsAssert "Get-SafeguardAssetAccount for specific asset" {
            $accounts = Get-SafeguardAssetAccount -Insecure $assetId
            $found = @($accounts) | Where-Object { $_.Name -eq $testAccount }
            $null -ne $found
        }

        # --- Get-SafeguardAssetAccount with Fields ---
        Test-SgPsAssert "Get-SafeguardAssetAccount with Fields" {
            $account = Get-SafeguardAssetAccount -Insecure $assetId $Context.SuiteData["AccountId"] `
                -Fields "Id","Name","Asset"
            $null -ne $account.Id -and $null -ne $account.Asset
        }

        # --- Edit-SafeguardAssetAccount (attributes) ---
        Test-SgPsAssert "Edit-SafeguardAssetAccount updates description" {
            $updated = Edit-SafeguardAssetAccount -Insecure $assetId $Context.SuiteData["AccountId"] `
                -Description "Updated by integration test"
            $updated.Description -eq "Updated by integration test"
        }

        # --- Edit-SafeguardAssetAccount (object) ---
        Test-SgPsAssert "Edit-SafeguardAssetAccount with AccountObject" {
            $account = Get-SafeguardAssetAccount -Insecure $assetId $Context.SuiteData["AccountId"]
            $account.Description = "Modified via object"
            $edited = Edit-SafeguardAssetAccount -Insecure -AccountObject $account
            $edited.Description -eq "Modified via object"
        }
        Test-SgPsAssert "Edit-SafeguardAssetAccount changes persisted" {
            $readback = Get-SafeguardAssetAccount -Insecure $assetId $Context.SuiteData["AccountId"]
            $readback.Description -eq "Modified via object"
        }

        # --- Find-SafeguardAssetAccount (search string) ---
        Test-SgPsAssert "Find-SafeguardAssetAccount by search string" {
            $results = Find-SafeguardAssetAccount -Insecure $testAccount
            $found = @($results) | Where-Object { $_.Name -eq $testAccount }
            $null -ne $found
        }

        # --- Find-SafeguardAssetAccount (query filter) ---
        Test-SgPsAssert "Find-SafeguardAssetAccount with QueryFilter" {
            $results = Find-SafeguardAssetAccount -Insecure -QueryFilter "Name eq '$testAccount'"
            $found = @($results) | Where-Object { $_.Name -eq $testAccount }
            $null -ne $found
        }

        # --- Set-SafeguardAssetAccountPassword ---
        Test-SgPsAssert "Set-SafeguardAssetAccountPassword sets password in vault" {
            $secPwd = ConvertTo-SecureString $testPassword -AsPlainText -Force
            Set-SafeguardAssetAccountPassword -Insecure $assetId $Context.SuiteData["AccountId"] `
                -NewPassword $secPwd
            # Verify account has password set
            $account = Get-SafeguardAssetAccount -Insecure $assetId $Context.SuiteData["AccountId"]
            $account.HasPassword -eq $true
        }

        # --- Disable-SafeguardAssetAccount ---
        Test-SgPsAssert "Disable-SafeguardAssetAccount disables account" {
            Disable-SafeguardAssetAccount -Insecure $assetId $Context.SuiteData["AccountId"]
            $account = Get-SafeguardAssetAccount -Insecure $assetId $Context.SuiteData["AccountId"]
            $account.Disabled -eq $true
        }

        # --- Enable-SafeguardAssetAccount ---
        Test-SgPsAssert "Enable-SafeguardAssetAccount re-enables account" {
            Enable-SafeguardAssetAccount -Insecure $assetId $Context.SuiteData["AccountId"]
            $account = Get-SafeguardAssetAccount -Insecure $assetId $Context.SuiteData["AccountId"]
            $account.Disabled -eq $false
        }

        # --- New-SafeguardAssetAccount (second, for remove test) ---
        Test-SgPsAssert "New-SafeguardAssetAccount second account" {
            $account2 = New-SafeguardAssetAccount -Insecure -ParentAsset $assetId `
                -NewAccountName $testAccount2 -Description "For removal test"
            $Context.SuiteData["Account2Id"] = $account2.Id

            Register-SgPsTestCleanup -Description "Delete test account $testAccount2" -Action {
                param($Ctx)
                try { Remove-SafeguardAssetAccount -Insecure -AccountToDelete $Ctx.SuiteData['Account2Id'] } catch {}
            }

            $null -ne $account2.Id
        }

        # --- Remove-SafeguardAssetAccount ---
        Test-SgPsAssert "Remove-SafeguardAssetAccount deletes account" {
            Remove-SafeguardAssetAccount -Insecure -AccountToDelete $Context.SuiteData["Account2Id"]
            $found = $false
            try {
                $null = Get-SafeguardAssetAccount -Insecure $assetId $Context.SuiteData["Account2Id"]
                $found = $true
            } catch {}
            -not $found
        }
    }

    Cleanup = {
        param($Context)
        # Registered cleanups handle deletion in LIFO order (accounts before asset)
    }
}
