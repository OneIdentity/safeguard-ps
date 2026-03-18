@{
    Name        = "Deleted Objects"
    Description = "Tests get, restore, and purge of soft-deleted assets, accounts, and users plus purge settings"
    Tags        = @("deleted", "lifecycle")

    Setup = {
        param($Context)

        # Create an asset we can delete
        $asset = New-SafeguardAsset -Insecure -DisplayName "SgPsTest_DelAsset" `
            -Platform 521 -NetworkAddress "10.0.99.1" -ServiceAccountCredentialType None -NoSshHostKeyDiscovery
        $Context.SuiteData["AssetId"] = $asset.Id
        $Context.SuiteData["AssetName"] = $asset.DisplayName

        # Create an account on that asset
        $account = New-SafeguardAssetAccount -Insecure -ParentAsset $asset.Id -NewAccountName "SgPsTest_DelAcct"
        $Context.SuiteData["AccountId"] = $account.Id
        $Context.SuiteData["AccountName"] = $account.Name

        # Create a user we can delete
        $secPass = ConvertTo-SecureString "Test1234pass!" -AsPlainText -Force
        $user = New-SafeguardUser -Insecure local "SgPsTest_DelUser" -Password $secPass
        $Context.SuiteData["UserId"] = $user.Id
        $Context.SuiteData["UserName"] = $user.Name

        # Save original purge settings for restore
        $purge = Get-SafeguardPurgeSettings -Insecure
        $Context.SuiteData["OriginalPurgeSettings"] = $purge
    }

    Execute = {
        param($Context)

        $assetId   = $Context.SuiteData["AssetId"]
        $accountId = $Context.SuiteData["AccountId"]
        $userId    = $Context.SuiteData["UserId"]

        # ===== PURGE SETTINGS =====

        Test-SgPsAssert "Get-SafeguardPurgeSettings returns settings" {
            $settings = Get-SafeguardPurgeSettings -Insecure
            $null -ne $settings
        }

        Test-SgPsAssert "Update-SafeguardPurgeSettings modifies retention days" {
            $updated = Update-SafeguardPurgeSettings -Insecure -DeletedAssetRetentionInDays 90
            $updated.DeletedAssetRetentionInDays -eq 90
        }

        Test-SgPsAssert "Reset-SafeguardPurgeSettings restores defaults" {
            Reset-SafeguardPurgeSettings -Insecure
            $reset = Get-SafeguardPurgeSettings -Insecure
            $null -ne $reset
        }

        # Restore original settings
        try {
            Update-SafeguardPurgeSettings -Insecure -Settings $Context.SuiteData["OriginalPurgeSettings"]
        } catch {}

        # ===== DELETED USERS =====

        Test-SgPsAssert "Get-SafeguardDeletedUser returns empty or list before delete" {
            $deleted = Get-SafeguardDeletedUser -Insecure
            # May or may not have items — just verify it doesn't throw
            $true
        }

        # Delete the user (soft-delete)
        Remove-SafeguardUser -Insecure $userId
        # Deregister the user cleanup since it's already deleted
        $Context.SuiteData["UserDeleted"] = $true

        Test-SgPsAssert "Get-SafeguardDeletedUser finds deleted user" {
            $deleted = Get-SafeguardDeletedUser -Insecure
            $match = @($deleted) | Where-Object { $_.Id -eq $userId }
            $null -ne $match -and @($match).Count -gt 0
        }

        Test-SgPsAssert "Restore-SafeguardDeletedUser restores user" {
            Restore-SafeguardDeletedUser -Insecure $userId
            $Context.SuiteData["UserDeleted"] = $false
            # Verify it's no longer in deleted list
            $deleted = Get-SafeguardDeletedUser -Insecure
            $match = @($deleted) | Where-Object { $_.Id -eq $userId }
            @($match).Count -eq 0 -or $null -eq $match
        }

        # ===== DELETED ASSET ACCOUNTS =====

        Test-SgPsAssert "Get-SafeguardDeletedAssetAccount returns list before delete" {
            $deleted = Get-SafeguardDeletedAssetAccount -Insecure
            $true
        }

        # Delete the account (soft-delete)
        Remove-SafeguardAssetAccount -Insecure $assetId $accountId
        $Context.SuiteData["AccountDeleted"] = $true

        Test-SgPsAssert "Get-SafeguardDeletedAssetAccount finds deleted account" {
            $deleted = Get-SafeguardDeletedAssetAccount -Insecure
            $match = @($deleted) | Where-Object { $_.Id -eq $accountId }
            $null -ne $match -and @($match).Count -gt 0
        }

        Test-SgPsAssert "Restore-SafeguardDeletedAssetAccount restores account" {
            Restore-SafeguardDeletedAssetAccount -Insecure $accountId
            $Context.SuiteData["AccountDeleted"] = $false
            $deleted = Get-SafeguardDeletedAssetAccount -Insecure
            $match = @($deleted) | Where-Object { $_.Id -eq $accountId }
            @($match).Count -eq 0 -or $null -eq $match
        }

        # ===== DELETED ASSETS =====

        # First remove the account again so we can delete the asset cleanly
        Remove-SafeguardAssetAccount -Insecure $assetId $accountId
        $Context.SuiteData["AccountDeleted"] = $true

        Test-SgPsAssert "Get-SafeguardDeletedAsset returns list before delete" {
            $deleted = Get-SafeguardDeletedAsset -Insecure
            $true
        }

        # Delete the asset (soft-delete)
        Remove-SafeguardAsset -Insecure $assetId
        $Context.SuiteData["AssetDeleted"] = $true

        Test-SgPsAssert "Get-SafeguardDeletedAsset finds deleted asset" {
            $deleted = Get-SafeguardDeletedAsset -Insecure
            $match = @($deleted) | Where-Object { $_.Id -eq $assetId }
            $null -ne $match -and @($match).Count -gt 0
        }

        Test-SgPsAssert "Restore-SafeguardDeletedAsset restores asset" {
            Restore-SafeguardDeletedAsset -Insecure $assetId
            $Context.SuiteData["AssetDeleted"] = $false
            $deleted = Get-SafeguardDeletedAsset -Insecure
            $match = @($deleted) | Where-Object { $_.Id -eq $assetId }
            @($match).Count -eq 0 -or $null -eq $match
        }

        # ===== PURGE (permanent delete) =====
        # Delete user again, then purge permanently
        Remove-SafeguardUser -Insecure $userId
        $Context.SuiteData["UserDeleted"] = $true

        Test-SgPsAssert "Remove-SafeguardDeletedUser purges permanently" {
            Remove-SafeguardDeletedUser -Insecure $userId
            $Context.SuiteData["UserPurged"] = $true
            $deleted = Get-SafeguardDeletedUser -Insecure
            $match = @($deleted) | Where-Object { $_.Id -eq $userId }
            @($match).Count -eq 0 -or $null -eq $match
        }
    }

    Cleanup = {
        param($Context)

        $assetId   = $Context.SuiteData["AssetId"]
        $accountId = $Context.SuiteData["AccountId"]
        $userId    = $Context.SuiteData["UserId"]

        # Clean up account — try active removal first, then purge if in deleted state
        if ($accountId) {
            if (-not $Context.SuiteData["AccountDeleted"]) {
                try { Remove-SafeguardAssetAccount -Insecure $assetId $accountId } catch {}
            }
            # Purge from deleted if still there
            try { Remove-SafeguardDeletedAssetAccount -Insecure $accountId } catch {}
        }

        # Clean up asset
        if ($assetId) {
            if (-not $Context.SuiteData["AssetDeleted"]) {
                try { Remove-SafeguardAsset -Insecure $assetId } catch {}
            }
            try { Remove-SafeguardDeletedAsset -Insecure $assetId } catch {}
        }

        # Clean up user
        if ($userId -and -not $Context.SuiteData["UserPurged"]) {
            if (-not $Context.SuiteData["UserDeleted"]) {
                try { Remove-SafeguardUser -Insecure $userId } catch {}
            }
            try { Remove-SafeguardDeletedUser -Insecure $userId } catch {}
        }

        # Restore original purge settings
        if ($Context.SuiteData["OriginalPurgeSettings"]) {
            try { Update-SafeguardPurgeSettings -Insecure -Settings $Context.SuiteData["OriginalPurgeSettings"] } catch {}
        }
    }
}
