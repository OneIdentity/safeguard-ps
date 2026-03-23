@{
    Name        = "Asset Groups"
    Description = "Tests asset group CRUD and member management"
    Tags        = @("groups", "assets")

    Setup = {
        param($Context)

        $prefix = $Context.TestPrefix
        $testGroup = "${prefix}_AGroup1"
        $testGroup2 = "${prefix}_AGroup2"
        $testAsset = "${prefix}_AGAsset"

        # Pre-cleanup
        Remove-SgPsStaleTestObject -Collection "AssetGroups" -Name $testGroup
        Remove-SgPsStaleTestObject -Collection "AssetGroups" -Name $testGroup2
        Remove-SgPsStaleTestObject -Collection "Assets" -Name $testAsset

        $Context.SuiteData["TestGroup"] = $testGroup
        $Context.SuiteData["TestGroup2"] = $testGroup2
        $Context.SuiteData["TestAsset"] = $testAsset

        # Create an asset for group membership tests
        $asset = New-SafeguardAsset -Insecure -DisplayName $testAsset `
            -Platform 521 -NetworkAddress "10.0.3.100" `
            -ServiceAccountCredentialType "None" -NoSshHostKeyDiscovery
        $Context.SuiteData["AssetId"] = $asset.Id

        Register-SgPsTestCleanup -Description "Delete member asset" -Action {
            param($Ctx)
            try { Remove-SafeguardAsset -Insecure $Ctx.SuiteData['AssetId'] } catch {}
        }
    }

    Execute = {
        param($Context)

        $testGroup = $Context.SuiteData["TestGroup"]
        $testGroup2 = $Context.SuiteData["TestGroup2"]
        $testAsset = $Context.SuiteData["TestAsset"]

        # --- Get-SafeguardAssetGroup (list) ---
        Test-SgPsAssert "Get-SafeguardAssetGroup lists groups" {
            $groups = Get-SafeguardAssetGroup -Insecure
            $null -ne $groups
        }

        # --- New-SafeguardAssetGroup ---
        Test-SgPsAssert "New-SafeguardAssetGroup creates a group" {
            $group = New-SafeguardAssetGroup -Insecure $testGroup -Description "Test asset group"
            $Context.SuiteData["GroupId"] = $group.Id

            Register-SgPsTestCleanup -Description "Delete asset group $testGroup" -Action {
                param($Ctx)
                try { Remove-SafeguardAssetGroup -Insecure $Ctx.SuiteData['GroupId'] } catch {}
            }
            $group.Name -eq $testGroup
        }

        # --- Get-SafeguardAssetGroup by ID ---
        Test-SgPsAssert "Get-SafeguardAssetGroup by ID" {
            $group = Get-SafeguardAssetGroup -Insecure $Context.SuiteData["GroupId"]
            $group.Name -eq $testGroup
        }

        # --- Get-SafeguardAssetGroup by Name ---
        Test-SgPsAssert "Get-SafeguardAssetGroup by Name" {
            $group = Get-SafeguardAssetGroup -Insecure $testGroup
            $group.Id -eq $Context.SuiteData["GroupId"]
        }

        # --- Edit-SafeguardAssetGroup (description) ---
        Test-SgPsAssert "Edit-SafeguardAssetGroup updates description" {
            $updated = Edit-SafeguardAssetGroup -Insecure $Context.SuiteData["GroupId"] -Description "Updated description"
            $updated.Description -eq "Updated description"
        }
        Test-SgPsAssert "Edit-SafeguardAssetGroup changes persisted" {
            $readback = Get-SafeguardAssetGroup -Insecure $Context.SuiteData["GroupId"]
            $readback.Description -eq "Updated description"
        }

        # --- Add-SafeguardAssetGroupMember ---
        Test-SgPsAssert "Add-SafeguardAssetGroupMember adds a member" {
            Add-SafeguardAssetGroupMember -Insecure $testGroup -AssetList $testAsset
            $members = Get-SafeguardAssetGroupMember -Insecure $testGroup
            $list = @($members)
            ($list | Where-Object { $_.Id -eq $Context.SuiteData["AssetId"] }) -ne $null
        }

        # --- Get-SafeguardAssetGroupMember ---
        Test-SgPsAssert "Get-SafeguardAssetGroupMember lists members" {
            $members = Get-SafeguardAssetGroupMember -Insecure $testGroup
            $list = @($members)
            $list.Count -ge 1 -and ($list | Where-Object { $_.Id -eq $Context.SuiteData["AssetId"] })
        }

        # --- Remove-SafeguardAssetGroupMember ---
        Test-SgPsAssert "Remove-SafeguardAssetGroupMember removes a member" {
            Remove-SafeguardAssetGroupMember -Insecure $testGroup -AssetList $testAsset
            $members = Get-SafeguardAssetGroupMember -Insecure $testGroup
            $list = @($members)
            -not ($list | Where-Object { $_.Id -eq $Context.SuiteData["AssetId"] })
        }

        # --- New-SafeguardAssetGroup (second, for remove test) ---
        Test-SgPsAssert "New-SafeguardAssetGroup second group" {
            $group2 = New-SafeguardAssetGroup -Insecure $testGroup2
            $Context.SuiteData["Group2Id"] = $group2.Id

            Register-SgPsTestCleanup -Description "Delete asset group $testGroup2" -Action {
                param($Ctx)
                try { Remove-SafeguardAssetGroup -Insecure $Ctx.SuiteData['Group2Id'] } catch {}
            }
            $group2.Name -eq $testGroup2
        }

        # --- Remove-SafeguardAssetGroup ---
        Test-SgPsAssert "Remove-SafeguardAssetGroup deletes a group" {
            Remove-SafeguardAssetGroup -Insecure $Context.SuiteData["Group2Id"]
            $remaining = Get-SafeguardAssetGroup -Insecure
            $list = @($remaining)
            -not ($list | Where-Object { $_.Id -eq $Context.SuiteData["Group2Id"] })
        }
    }

    Cleanup = {
        param($Context)
    }
}
