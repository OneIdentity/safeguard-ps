@{
    Name        = "Asset Management"
    Description = "Tests asset CRUD, find, edit, and discovery operations"
    Tags        = @("assets", "core")

    Setup = {
        param($Context)

        $prefix = $Context.TestPrefix
        $testAsset = "${prefix}_Asset1"
        $testAsset2 = "${prefix}_Asset2"

        # Pre-cleanup
        Remove-SgPsStaleTestObject -Collection "Assets" -Name $testAsset
        Remove-SgPsStaleTestObject -Collection "Assets" -Name $testAsset2

        $Context.SuiteData["TestAsset"] = $testAsset
        $Context.SuiteData["TestAsset2"] = $testAsset2
    }

    Execute = {
        param($Context)

        $testAsset = $Context.SuiteData["TestAsset"]
        $testAsset2 = $Context.SuiteData["TestAsset2"]

        # --- Get-SafeguardAsset (list all) ---
        Test-SgPsAssert "Get-SafeguardAsset lists assets" {
            $list = @(Get-SafeguardAsset -Insecure)
            $list -is [Array]
        }

        # --- New-SafeguardAsset (Linux platform, no service account) ---
        Test-SgPsAssert "New-SafeguardAsset creates an asset" {
            $asset = New-SafeguardAsset -Insecure -DisplayName $testAsset `
                -Platform 521 -NetworkAddress "10.0.0.100" `
                -ServiceAccountCredentialType "None" -NoSshHostKeyDiscovery
            $Context.SuiteData["AssetId"] = $asset.Id

            Register-SgPsTestCleanup -Description "Delete test asset $testAsset" -Action {
                param($Ctx)
                try { Remove-SafeguardAsset -Insecure $Ctx.SuiteData['AssetId'] } catch {}
            }

            $null -ne $asset.Id -and $asset.Name -eq $testAsset
        }

        # --- Get-SafeguardAsset by ID ---
        Test-SgPsAssert "Get-SafeguardAsset by ID" {
            $asset = Get-SafeguardAsset -Insecure $Context.SuiteData["AssetId"]
            $asset.Name -eq $testAsset
        }

        # --- Get-SafeguardAsset by Name ---
        Test-SgPsAssert "Get-SafeguardAsset by Name" {
            $asset = Get-SafeguardAsset -Insecure $testAsset
            $asset.Name -eq $testAsset
        }

        # --- Get-SafeguardAsset with Fields ---
        Test-SgPsAssert "Get-SafeguardAsset with Fields" {
            $asset = Get-SafeguardAsset -Insecure $Context.SuiteData["AssetId"] `
                -Fields "Id","Name","NetworkAddress"
            $null -ne $asset.Id -and $asset.NetworkAddress -eq "10.0.0.100"
        }

        # --- Edit-SafeguardAsset (attributes) ---
        Test-SgPsAssert "Edit-SafeguardAsset updates attributes" {
            $updated = Edit-SafeguardAsset -Insecure $Context.SuiteData["AssetId"] `
                -Description "Updated by integration test" -NetworkAddress "10.0.0.101"
            $updated.Description -eq "Updated by integration test" -and $updated.NetworkAddress -eq "10.0.0.101"
        }

        # --- Edit-SafeguardAsset (object) ---
        Test-SgPsAssert "Edit-SafeguardAsset with AssetObject" {
            $asset = Get-SafeguardAsset -Insecure $Context.SuiteData["AssetId"]
            $asset.Description = "Modified via object"
            $edited = Edit-SafeguardAsset -Insecure -AssetObject $asset
            $edited.Description -eq "Modified via object"
        }
        Test-SgPsAssert "Edit-SafeguardAsset changes persisted" {
            $readback = Get-SafeguardAsset -Insecure $Context.SuiteData["AssetId"]
            $readback.Description -eq "Modified via object" -and $readback.NetworkAddress -eq "10.0.0.101"
        }

        # --- Find-SafeguardAsset (search string) ---
        Test-SgPsAssert "Find-SafeguardAsset by search string" {
            $results = Find-SafeguardAsset -Insecure $testAsset
            $found = @($results) | Where-Object { $_.Name -eq $testAsset }
            $null -ne $found
        }

        # --- Find-SafeguardAsset (query filter) ---
        Test-SgPsAssert "Find-SafeguardAsset with QueryFilter" {
            $results = Find-SafeguardAsset -Insecure -QueryFilter "Name eq '$testAsset'"
            $found = @($results) | Where-Object { $_.Name -eq $testAsset }
            $null -ne $found
        }

        # --- New-SafeguardAsset (second asset for remove test) ---
        Test-SgPsAssert "New-SafeguardAsset second asset" {
            $asset2 = New-SafeguardAsset -Insecure -DisplayName $testAsset2 `
                -Platform 521 -NetworkAddress "10.0.0.102" `
                -ServiceAccountCredentialType "None" -NoSshHostKeyDiscovery
            $Context.SuiteData["Asset2Id"] = $asset2.Id

            Register-SgPsTestCleanup -Description "Delete test asset $testAsset2" -Action {
                param($Ctx)
                try { Remove-SafeguardAsset -Insecure $Ctx.SuiteData['Asset2Id'] } catch {}
            }

            $null -ne $asset2.Id
        }

        # --- Remove-SafeguardAsset ---
        Test-SgPsAssert "Remove-SafeguardAsset deletes an asset" {
            Remove-SafeguardAsset -Insecure $Context.SuiteData["Asset2Id"]
            $found = $false
            try {
                $null = Get-SafeguardAsset -Insecure $Context.SuiteData["Asset2Id"]
                $found = $true
            } catch {}
            -not $found
        }
    }

    Cleanup = {
        param($Context)
        # Registered cleanups handle remaining asset deletion
    }
}
