@{
    Name        = "Account Groups"
    Description = "Tests account group CRUD and member management"
    Tags        = @("groups", "accounts")

    Setup = {
        param($Context)

        $prefix = $Context.TestPrefix
        $testGroup = "${prefix}_AcctGrp1"
        $testGroup2 = "${prefix}_AcctGrp2"
        $testAsset = "${prefix}_AcctGAsset"
        $testAccount = "${prefix}_AcctGAcct"

        # Pre-cleanup
        Remove-SgPsStaleTestObject -Collection "AccountGroups" -Name $testGroup
        Remove-SgPsStaleTestObject -Collection "AccountGroups" -Name $testGroup2
        Remove-SgPsStaleTestObject -Collection "AssetAccounts" -Name $testAccount
        Remove-SgPsStaleTestObject -Collection "Assets" -Name $testAsset

        $Context.SuiteData["TestGroup"] = $testGroup
        $Context.SuiteData["TestGroup2"] = $testGroup2

        # Create an asset and account for group membership tests
        $asset = New-SafeguardAsset -Insecure -DisplayName $testAsset `
            -Platform 521 -NetworkAddress "10.0.4.100" `
            -ServiceAccountCredentialType "None" -NoSshHostKeyDiscovery
        $Context.SuiteData["AssetId"] = $asset.Id

        $account = New-SafeguardAssetAccount -Insecure -ParentAsset $asset.Id -NewAccountName $testAccount
        $Context.SuiteData["AccountId"] = $account.Id
        $Context.SuiteData["TestAccount"] = $testAccount

        Register-SgPsTestCleanup -Description "Delete test account" -Action {
            param($Ctx)
            try { Remove-SafeguardAssetAccount -Insecure $Ctx.SuiteData['AssetId'] $Ctx.SuiteData['AccountId'] } catch {}
        }
        Register-SgPsTestCleanup -Description "Delete test asset" -Action {
            param($Ctx)
            try { Remove-SafeguardAsset -Insecure $Ctx.SuiteData['AssetId'] } catch {}
        }
    }

    Execute = {
        param($Context)

        $testGroup = $Context.SuiteData["TestGroup"]
        $testGroup2 = $Context.SuiteData["TestGroup2"]

        # --- Get-SafeguardAccountGroup (list) ---
        Test-SgPsAssert "Get-SafeguardAccountGroup lists groups" {
            $groups = Get-SafeguardAccountGroup -Insecure
            $null -ne $groups
        }

        # --- New-SafeguardAccountGroup ---
        Test-SgPsAssert "New-SafeguardAccountGroup creates a group" {
            $group = New-SafeguardAccountGroup -Insecure $testGroup -Description "Test account group"
            $Context.SuiteData["GroupId"] = $group.Id

            Register-SgPsTestCleanup -Description "Delete account group $testGroup" -Action {
                param($Ctx)
                try { Remove-SafeguardAccountGroup -Insecure $Ctx.SuiteData['GroupId'] } catch {}
            }
            $group.Name -eq $testGroup
        }

        # --- Get-SafeguardAccountGroup by ID ---
        Test-SgPsAssert "Get-SafeguardAccountGroup by ID" {
            $group = Get-SafeguardAccountGroup -Insecure $Context.SuiteData["GroupId"]
            $group.Name -eq $testGroup
        }

        # --- Get-SafeguardAccountGroup by Name ---
        Test-SgPsAssert "Get-SafeguardAccountGroup by Name" {
            $group = Get-SafeguardAccountGroup -Insecure $testGroup
            $group.Id -eq $Context.SuiteData["GroupId"]
        }

        # --- Edit-SafeguardAccountGroup (description) ---
        Test-SgPsAssert "Edit-SafeguardAccountGroup updates description" {
            $updated = Edit-SafeguardAccountGroup -Insecure $Context.SuiteData["GroupId"] -Description "Updated description"
            $updated.Description -eq "Updated description"
        }

        # --- Add-SafeguardAccountGroupMember ---
        Test-SgPsAssert "Add-SafeguardAccountGroupMember adds a member" {
            $acctRef = "$($Context.SuiteData['TestAsset'])\$($Context.SuiteData['TestAccount'])"
            Add-SafeguardAccountGroupMember -Insecure $testGroup -AccountList $acctRef
            $true
        }

        # --- Get-SafeguardAccountGroupMember ---
        Test-SgPsAssert "Get-SafeguardAccountGroupMember lists members" {
            $members = Get-SafeguardAccountGroupMember -Insecure $testGroup
            $list = @($members)
            $list.Count -ge 1 -and ($list | Where-Object { $_.Id -eq $Context.SuiteData["AccountId"] })
        }

        # --- Remove-SafeguardAccountGroupMember ---
        Test-SgPsAssert "Remove-SafeguardAccountGroupMember removes a member" {
            $acctRef = "$($Context.SuiteData['TestAsset'])\$($Context.SuiteData['TestAccount'])"
            Remove-SafeguardAccountGroupMember -Insecure $testGroup -AccountList $acctRef
            $members = Get-SafeguardAccountGroupMember -Insecure $testGroup
            $list = @($members)
            -not ($list | Where-Object { $_.Id -eq $Context.SuiteData["AccountId"] })
        }

        # --- New-SafeguardAccountGroup (second, for remove test) ---
        Test-SgPsAssert "New-SafeguardAccountGroup second group" {
            $group2 = New-SafeguardAccountGroup -Insecure $testGroup2
            $Context.SuiteData["Group2Id"] = $group2.Id

            Register-SgPsTestCleanup -Description "Delete account group $testGroup2" -Action {
                param($Ctx)
                try { Remove-SafeguardAccountGroup -Insecure $Ctx.SuiteData['Group2Id'] } catch {}
            }
            $group2.Name -eq $testGroup2
        }

        # --- Remove-SafeguardAccountGroup ---
        Test-SgPsAssert "Remove-SafeguardAccountGroup deletes a group" {
            Remove-SafeguardAccountGroup -Insecure $Context.SuiteData["Group2Id"]
            $remaining = Get-SafeguardAccountGroup -Insecure
            $list = @($remaining)
            -not ($list | Where-Object { $_.Id -eq $Context.SuiteData["Group2Id"] })
        }
    }

    Cleanup = {
        param($Context)
    }
}
