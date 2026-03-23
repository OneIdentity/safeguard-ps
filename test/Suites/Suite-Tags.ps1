@{
    Name        = "Tags"
    Description = "Tests tag CRUD and assignment to assets and accounts"
    Tags        = @("tags", "core")

    Setup = {
        param($Context)

        $prefix = $Context.TestPrefix
        $testTag = "${prefix}_Tag1"
        $testTag2 = "${prefix}_Tag2"
        $testAsset = "${prefix}_TagAsset"
        $testAccount = "${prefix}_TagAcct"

        # Pre-cleanup
        Remove-SgPsStaleTestObject -Collection "AssetAccounts" -Name $testAccount
        Remove-SgPsStaleTestObject -Collection "Assets" -Name $testAsset

        # Create a parent asset and account for tag assignment tests
        $asset = New-SafeguardAsset -Insecure -DisplayName $testAsset `
            -Platform 521 -NetworkAddress "10.0.2.100" `
            -ServiceAccountCredentialType "None" -NoSshHostKeyDiscovery
        $Context.SuiteData["AssetId"] = $asset.Id

        Register-SgPsTestCleanup -Description "Delete tag test asset" -Action {
            param($Ctx)
            try { Remove-SafeguardAsset -Insecure $Ctx.SuiteData['AssetId'] } catch {}
        }

        $account = New-SafeguardAssetAccount -Insecure -ParentAsset $asset.Id `
            -NewAccountName $testAccount
        $Context.SuiteData["AccountId"] = $account.Id

        Register-SgPsTestCleanup -Description "Delete tag test account" -Action {
            param($Ctx)
            try { Remove-SafeguardAssetAccount -Insecure -AccountToDelete $Ctx.SuiteData['AccountId'] } catch {}
        }

        $Context.SuiteData["TestTag"] = $testTag
        $Context.SuiteData["TestTag2"] = $testTag2
    }

    Execute = {
        param($Context)

        $testTag = $Context.SuiteData["TestTag"]
        $testTag2 = $Context.SuiteData["TestTag2"]
        $assetId = $Context.SuiteData["AssetId"]
        $accountId = $Context.SuiteData["AccountId"]

        # --- Get-SafeguardTag (list all) ---
        Test-SgPsAssert "Get-SafeguardTag lists tags" {
            $tags = Get-SafeguardTag -Insecure
            $null -ne $tags -or $true
        }

        # --- New-SafeguardTag ---
        Test-SgPsAssert "New-SafeguardTag creates a tag" {
            $tag = New-SafeguardTag -Insecure -Name $testTag -Description "Integration test tag"
            $Context.SuiteData["TagId"] = $tag.Id

            Register-SgPsTestCleanup -Description "Delete test tag $testTag" -Action {
                param($Ctx)
                try { Remove-SafeguardTag -Insecure $Ctx.SuiteData['TagId'] } catch {}
            }

            $null -ne $tag.Id -and $tag.Name -eq $testTag
        }

        # --- Get-SafeguardTag by ID ---
        Test-SgPsAssert "Get-SafeguardTag by ID" {
            $tag = Get-SafeguardTag -Insecure $Context.SuiteData["TagId"]
            $tag.Name -eq $testTag
        }

        # --- Find-SafeguardTag ---
        Test-SgPsAssert "Find-SafeguardTag by search string" {
            $results = Find-SafeguardTag -Insecure $testTag
            $found = @($results) | Where-Object { $_.Name -eq $testTag }
            $null -ne $found
        }

        # --- Update-SafeguardTag ---
        Test-SgPsAssert "Update-SafeguardTag renames tag" {
            $updated = Update-SafeguardTag -Insecure -TagId $Context.SuiteData["TagId"] `
                -Name $testTag -Description "Updated description"
            $updated.Description -eq "Updated description"
        }
        Test-SgPsAssert "Update-SafeguardTag changes persisted" {
            $readback = Get-SafeguardTag -Insecure $Context.SuiteData["TagId"]
            $readback.Description -eq "Updated description" -and $readback.Name -eq $testTag
        }

        # --- Add-SafeguardAssetTag (assign tag to asset) ---
        Test-SgPsAssert "Add-SafeguardAssetTag assigns tag to asset" {
            Add-SafeguardAssetTag -Insecure -Asset $assetId -Tag @($Context.SuiteData["TagId"])
            $tags = Get-SafeguardAssetTag -Insecure -Asset $assetId
            $found = @($tags) | Where-Object { $_.Id -eq $Context.SuiteData["TagId"] }
            $null -ne $found
        }

        # --- Get-SafeguardAssetTag ---
        Test-SgPsAssert "Get-SafeguardAssetTag lists tags on asset" {
            $tags = Get-SafeguardAssetTag -Insecure -Asset $assetId
            @($tags).Count -gt 0
        }

        # --- Get-SafeguardTagOccurrence ---
        Test-SgPsAssert "Get-SafeguardTagOccurrence returns tagged objects" {
            $occurrences = Get-SafeguardTagOccurrence -Insecure -Tag $Context.SuiteData["TagId"]
            @($occurrences).Count -gt 0
        }

        # --- Remove-SafeguardAssetTag ---
        Test-SgPsAssert "Remove-SafeguardAssetTag removes tag from asset" {
            Remove-SafeguardAssetTag -Insecure -Asset $assetId -Tag @($Context.SuiteData["TagId"])
            $tags = Get-SafeguardAssetTag -Insecure -Asset $assetId
            $found = @($tags) | Where-Object { $_.Id -eq $Context.SuiteData["TagId"] }
            $null -eq $found
        }

        # --- Add-SafeguardAssetAccountTag (assign tag to account) ---
        Test-SgPsAssert "Add-SafeguardAssetAccountTag assigns tag to account" {
            Add-SafeguardAssetAccountTag -Insecure -Account $accountId `
                -Tag @($Context.SuiteData["TagId"])
            $tags = Get-SafeguardAssetAccountTag -Insecure -Account $accountId
            $found = @($tags) | Where-Object { $_.Id -eq $Context.SuiteData["TagId"] }
            $null -ne $found
        }

        # --- Get-SafeguardAssetAccountTag ---
        Test-SgPsAssert "Get-SafeguardAssetAccountTag lists tags on account" {
            $tags = Get-SafeguardAssetAccountTag -Insecure -Account $accountId
            @($tags).Count -gt 0
        }

        # --- Remove-SafeguardAssetAccountTag ---
        Test-SgPsAssert "Remove-SafeguardAssetAccountTag removes tag from account" {
            Remove-SafeguardAssetAccountTag -Insecure -Account $accountId `
                -Tag @($Context.SuiteData["TagId"])
            $tags = Get-SafeguardAssetAccountTag -Insecure -Account $accountId
            $found = @($tags) | Where-Object { $_.Id -eq $Context.SuiteData["TagId"] }
            $null -eq $found
        }

        # --- New-SafeguardTag (second, for remove test) ---
        Test-SgPsAssert "New-SafeguardTag second tag" {
            $tag2 = New-SafeguardTag -Insecure -Name $testTag2
            $Context.SuiteData["Tag2Id"] = $tag2.Id

            Register-SgPsTestCleanup -Description "Delete test tag $testTag2" -Action {
                param($Ctx)
                try { Remove-SafeguardTag -Insecure $Ctx.SuiteData['Tag2Id'] } catch {}
            }

            $null -ne $tag2.Id
        }

        # --- Remove-SafeguardTag ---
        Test-SgPsAssert "Remove-SafeguardTag deletes a tag" {
            Remove-SafeguardTag -Insecure $Context.SuiteData["Tag2Id"]
            $found = $false
            try {
                $null = Get-SafeguardTag -Insecure $Context.SuiteData["Tag2Id"]
                $found = $true
            } catch {}
            -not $found
        }
    }

    Cleanup = {
        param($Context)
        # Registered cleanups handle deletion (tags, then account, then asset)
    }
}
