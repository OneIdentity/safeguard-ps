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

        # --- New-SafeguardAsset with DirectoryPassword (issue #601 regression) ---
        # When the directory asset name does not match the domain name,
        # New-SafeguardAsset should still resolve the directory by domain name.
        Test-SgPsAssert "New-SafeguardAsset with DirectoryPassword resolves directory by domain name" {
            # Find a directory asset to use
            $directories = @(Invoke-SafeguardMethod -Insecure Core GET "Assets" `
                -Parameters @{ filter = "IsDirectory eq true" })
            if ($directories.Count -eq 0)
            {
                Write-Host "      SKIP: No directory assets on appliance" -ForegroundColor Yellow
                return $true
            }
            $dir = $directories[0]
            $dirId = $dir.Id
            $originalName = $dir.Name
            $domainName = ($dir.DirectoryAssetProperties.Domains |
                Where-Object { $_.DomainName -eq $dir.DirectoryAssetProperties.ForestRootDomain } |
                Select-Object -First 1).DomainName
            if (-not $domainName)
            {
                $domainName = $dir.DirectoryAssetProperties.Domains[0].DomainName
            }
            if (-not $domainName)
            {
                Write-Host "      SKIP: Cannot determine domain name for directory '$originalName'" -ForegroundColor Yellow
                return $true
            }

            # Find a service account under this directory
            $accounts = @(Invoke-SafeguardMethod -Insecure Core GET "Assets/$dirId/Accounts" `
                -Parameters @{ fields = "Id,Name" })
            if ($accounts.Count -eq 0)
            {
                Write-Host "      SKIP: No accounts under directory '$originalName'" -ForegroundColor Yellow
                return $true
            }
            $svcAccount = $accounts[0]

            # Rename the directory so Name no longer matches the domain name
            $prefix = $Context.TestPrefix
            $renamedName = "${prefix}_RenamedDir"
            $dirObj = Invoke-SafeguardMethod -Insecure Core GET "Assets/$dirId"
            $dirObj.Name = $renamedName
            Invoke-SafeguardMethod -Insecure Core PUT "Assets/$dirId" -Body $dirObj | Out-Null

            # Register cleanup to restore original name immediately
            $Context.SuiteData["DirId"] = $dirId
            $Context.SuiteData["OriginalDirName"] = $originalName
            Register-SgPsTestCleanup -Description "Restore directory name to '$originalName'" -Action {
                param($Ctx)
                try {
                    $d = Invoke-SafeguardMethod -Insecure Core GET "Assets/$($Ctx.SuiteData['DirId'])"
                    $d.Name = $Ctx.SuiteData['OriginalDirName']
                    Invoke-SafeguardMethod -Insecure Core PUT "Assets/$($Ctx.SuiteData['DirId'])" -Body $d | Out-Null
                } catch {}
            }

            $assetName = "${prefix}_DirPwdAsset"
            Remove-SgPsStaleTestObject -Collection "Assets" -Name $assetName
            try
            {
                $newAsset = New-SafeguardAsset -Insecure -DisplayName $assetName `
                    -Platform 521 -NetworkAddress "10.255.255.1" `
                    -ServiceAccountCredentialType "DirectoryPassword" `
                    -ServiceAccountDomainName $domainName `
                    -ServiceAccountName $svcAccount.Name `
                    -NoSshHostKeyDiscovery
                $Context.SuiteData["DirPwdAssetId"] = $newAsset.Id

                Register-SgPsTestCleanup -Description "Delete DirectoryPassword test asset" -Action {
                    param($Ctx)
                    try { Remove-SafeguardAsset -Insecure $Ctx.SuiteData['DirPwdAssetId'] } catch {}
                }

                $null -ne $newAsset.Id -and
                    $newAsset.ConnectionProperties.ServiceAccountId -eq $svcAccount.Id
            }
            finally
            {
                # Restore directory name inline so subsequent tests are not affected
                $dirObj2 = Invoke-SafeguardMethod -Insecure Core GET "Assets/$dirId"
                $dirObj2.Name = $originalName
                Invoke-SafeguardMethod -Insecure Core PUT "Assets/$dirId" -Body $dirObj2 | Out-Null
            }
        }

        Test-SgPsAssert "DirectoryPassword asset persisted with correct service account" {
            if (-not $Context.SuiteData.ContainsKey("DirPwdAssetId")) { return $true }
            $prefix = $Context.TestPrefix
            $readback = Get-SafeguardAsset -Insecure $Context.SuiteData["DirPwdAssetId"]
            $readback.Name -eq "${prefix}_DirPwdAsset" -and
                $null -ne $readback.ConnectionProperties.ServiceAccountId
        }
    }

    Cleanup = {
        param($Context)
        # Registered cleanups handle remaining asset deletion
    }
}
