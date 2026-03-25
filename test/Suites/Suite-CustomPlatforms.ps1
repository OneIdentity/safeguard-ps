@{
    Name        = "CustomPlatforms"
    Description = "Tests custom platform CRUD, script upload, and editing"
    Tags        = @("customplatforms", "core")

    Setup = {
        param($Context)

        $prefix = $Context.TestPrefix
        $testPlatform1 = "${prefix}_CustomPlat1"
        $testPlatform2 = "${prefix}_CustomPlat2"
        $testPlatform3 = "${prefix}_CustomPlat3"

        # Pre-cleanup any stale platforms from a previous failed run
        Remove-SgPsStaleTestObject -Collection "Platforms" -Name $testPlatform1
        Remove-SgPsStaleTestObject -Collection "Platforms" -Name $testPlatform2
        Remove-SgPsStaleTestObject -Collection "Platforms" -Name $testPlatform3

        $Context.SuiteData["TestPlatform1"] = $testPlatform1
        $Context.SuiteData["TestPlatform2"] = $testPlatform2
        $Context.SuiteData["TestPlatform3"] = $testPlatform3

        # Locate the test script file (relative to the test root directory)
        $scriptPath = Join-Path $PSScriptRoot "..\TestData\GenericLinuxWithSSHKeySupport.json"
        if (-not (Test-Path $scriptPath))
        {
            throw "Test data file not found: $scriptPath"
        }
        # The stock script uses Id "ExampleLinuxScript" which may conflict with pre-existing
        # platforms. Create a temp copy with a unique Id for the test run.
        $scriptContent = Get-Content -Path $scriptPath -Raw
        $uniqueScriptId = "${prefix}PlatScript"
        $modifiedScript = $scriptContent -replace '"ExampleLinuxScript"', "`"$uniqueScriptId`""
        $tempScriptFile = Join-Path ([System.IO.Path]::GetTempPath()) "${prefix}_TestScript.json"
        Set-Content -Path $tempScriptFile -Value $modifiedScript -NoNewline

        $Context.SuiteData["ScriptFile"] = $tempScriptFile
        $Context.SuiteData["ScriptId"] = $uniqueScriptId

        # Prepare a second script (Discovery variant) for script-change tests
        $scriptPath2 = Join-Path $PSScriptRoot "..\TestData\GenericLinuxWithDiscovery.json"
        if (-not (Test-Path $scriptPath2))
        {
            throw "Test data file not found: $scriptPath2"
        }
        $scriptContent2 = Get-Content -Path $scriptPath2 -Raw
        $uniqueScriptId2 = "${prefix}PlatScript2"
        $modifiedScript2 = $scriptContent2 -replace '"ExampleLinuxScriptWithDiscovery"', "`"$uniqueScriptId2`""
        $tempScriptFile2 = Join-Path ([System.IO.Path]::GetTempPath()) "${prefix}_TestScript2.json"
        Set-Content -Path $tempScriptFile2 -Value $modifiedScript2 -NoNewline

        $Context.SuiteData["ScriptFile2"] = $tempScriptFile2
        $Context.SuiteData["ScriptId2"] = $uniqueScriptId2

        # Asset test data
        $testAsset1 = "${prefix}_CustPlatAsset1"
        $testAsset2 = "${prefix}_CustPlatAsset2"
        $Context.SuiteData["TestAsset1"] = $testAsset1
        $Context.SuiteData["TestAsset2"] = $testAsset2

        # Pre-cleanup any stale test assets from a previous failed run
        Remove-SgPsStaleTestObject -Collection "Assets" -Name $testAsset1
        Remove-SgPsStaleTestObject -Collection "Assets" -Name $testAsset2

        Register-SgPsTestCleanup -Description "Remove temp script files" -Action {
            param($Ctx)
            foreach ($key in @('ScriptFile','ScriptFile2')) {
                $f = $Ctx.SuiteData[$key]
                if ($f -and (Test-Path $f)) { Remove-Item $f -Force }
            }
        }
    }

    Execute = {
        param($Context)

        $platform1Name = $Context.SuiteData["TestPlatform1"]
        $platform2Name = $Context.SuiteData["TestPlatform2"]
        $platform3Name = $Context.SuiteData["TestPlatform3"]
        $scriptFile = $Context.SuiteData["ScriptFile"]
        $scriptFile2 = $Context.SuiteData["ScriptFile2"]
        $scriptId = $Context.SuiteData["ScriptId"]
        $scriptId2 = $Context.SuiteData["ScriptId2"]

        # --- Get-SafeguardCustomPlatform (list all) ---
        Test-SgPsAssert "Get-SafeguardCustomPlatform lists custom platforms" {
            $list = @(Get-SafeguardCustomPlatform -Insecure)
            $list -is [Array]
        }

        # --- New-SafeguardCustomPlatform (without script) ---
        Test-SgPsAssert "New-SafeguardCustomPlatform creates platform without script" {
            $plat = New-SafeguardCustomPlatform -Insecure -Name $platform1Name
            $Context.SuiteData["Platform1Id"] = $plat.Id

            Register-SgPsTestCleanup -Description "Delete $platform1Name" -Action {
                param($Ctx)
                try { Remove-SafeguardCustomPlatform -Insecure $Ctx.SuiteData['Platform1Id'] -ForceDelete } catch {}
            }

            $null -ne $plat.Id -and
                $plat.Name -eq $platform1Name -and
                $plat.PlatformFamily -eq "Custom" -and
                $plat.PlatformType -eq "Custom"
        }

        Test-SgPsAssert "New-SafeguardCustomPlatform readback verifies creation" {
            $readback = Get-SafeguardCustomPlatform -Insecure $Context.SuiteData["Platform1Id"]
            $readback.Name -eq $platform1Name -and
                $readback.PlatformFamily -eq "Custom" -and
                $readback.CustomScriptProperties.HasScript -eq $false -and
                $readback.SessionFeatureProperties.SupportsSessionManagement -eq $false
        }

        # --- New-SafeguardCustomPlatform (with description and script) ---
        Test-SgPsAssert "New-SafeguardCustomPlatform creates platform with script" {
            $plat = New-SafeguardCustomPlatform -Insecure -Name $platform2Name `
                -Description "Test platform with script" -ScriptFile $scriptFile
            $Context.SuiteData["Platform2Id"] = $plat.Id

            Register-SgPsTestCleanup -Description "Delete $platform2Name" -Action {
                param($Ctx)
                try { Remove-SafeguardCustomPlatform -Insecure $Ctx.SuiteData['Platform2Id'] -ForceDelete } catch {}
            }

            $null -ne $plat.Id -and
                $plat.Name -eq $platform2Name -and
                $plat.Description -eq "Test platform with script" -and
                $plat.CustomScriptProperties.HasScript -eq $true
        }

        Test-SgPsAssert "New-SafeguardCustomPlatform with script readback has operations" {
            $readback = Get-SafeguardCustomPlatform -Insecure $Context.SuiteData["Platform2Id"]
            $readback.CustomScriptProperties.HasScript -eq $true -and
                $readback.SupportedOperations.Count -gt 0 -and
                $readback.Description -eq "Test platform with script"
        }

        # --- Get-SafeguardCustomPlatform (by ID) ---
        Test-SgPsAssert "Get-SafeguardCustomPlatform by ID returns correct platform" {
            $plat = Get-SafeguardCustomPlatform -Insecure $Context.SuiteData["Platform1Id"]
            $plat.Id -eq $Context.SuiteData["Platform1Id"] -and $plat.Name -eq $platform1Name
        }

        # --- Get-SafeguardCustomPlatform (by name) ---
        Test-SgPsAssert "Get-SafeguardCustomPlatform by name returns correct platform" {
            $plat = Get-SafeguardCustomPlatform -Insecure $platform2Name
            $plat.Id -eq $Context.SuiteData["Platform2Id"] -and $plat.Name -eq $platform2Name
        }

        # --- Get-SafeguardCustomPlatform rejects non-custom platform by ID ---
        Test-SgPsAssert "Get-SafeguardCustomPlatform rejects non-custom platform" {
            $threw = $false
            try {
                # Platform ID 521 is "Other Linux" (built-in, not Custom)
                $null = Get-SafeguardCustomPlatform -Insecure 521
            } catch {
                $threw = $true
            }
            $threw
        }

        # --- Edit-SafeguardCustomPlatform (by ID, change description) ---
        Test-SgPsAssert "Edit-SafeguardCustomPlatform updates description by ID" {
            $edited = Edit-SafeguardCustomPlatform -Insecure $Context.SuiteData["Platform1Id"] `
                -Description "Edited description"
            $edited.Description -eq "Edited description"
        }

        Test-SgPsAssert "Edit-SafeguardCustomPlatform description persisted" {
            $readback = Get-SafeguardCustomPlatform -Insecure $Context.SuiteData["Platform1Id"]
            $readback.Description -eq "Edited description"
        }

        # --- Edit-SafeguardCustomPlatform (by name) ---
        Test-SgPsAssert "Edit-SafeguardCustomPlatform updates by name" {
            $edited = Edit-SafeguardCustomPlatform -Insecure $platform1Name `
                -Description "Edited by name"
            $edited.Description -eq "Edited by name"
        }

        Test-SgPsAssert "Edit-SafeguardCustomPlatform by name persisted" {
            $readback = Get-SafeguardCustomPlatform -Insecure $Context.SuiteData["Platform1Id"]
            $readback.Description -eq "Edited by name"
        }

        # --- Edit-SafeguardCustomPlatform (piped object) ---
        Test-SgPsAssert "Edit-SafeguardCustomPlatform via pipeline" {
            $platObj = Get-SafeguardCustomPlatform -Insecure $Context.SuiteData["Platform2Id"]
            $platObj.Description = "Piped edit"
            $edited = $platObj | Edit-SafeguardCustomPlatform -Insecure
            $edited.Description -eq "Piped edit"
        }

        Test-SgPsAssert "Edit-SafeguardCustomPlatform piped edit persisted" {
            $readback = Get-SafeguardCustomPlatform -Insecure $Context.SuiteData["Platform2Id"]
            $readback.Description -eq "Piped edit"
        }

        # --- Session management: New-SafeguardCustomPlatform with -AllowSessionRequests ---
        Test-SgPsAssert "New-SafeguardCustomPlatform with -AllowSessionRequests enables sessions" {
            $plat = New-SafeguardCustomPlatform -Insecure -Name $platform3Name `
                -AllowSessionRequests -SshSessionPort 22 -RdpSessionPort 3389 -TelnetSessionPort 23
            $Context.SuiteData["Platform3Id"] = $plat.Id

            Register-SgPsTestCleanup -Description "Delete $platform3Name" -Action {
                param($Ctx)
                try { Remove-SafeguardCustomPlatform -Insecure $Ctx.SuiteData['Platform3Id'] -ForceDelete } catch {}
            }

            $plat.SessionFeatureProperties.SupportsSessionManagement -eq $true -and
                $plat.SessionFeatureProperties.DefaultSshSessionPort -eq 22 -and
                $plat.SessionFeatureProperties.DefaultRemoteDesktopSessionPort -eq 3389 -and
                $plat.SessionFeatureProperties.DefaultTelnetSessionPort -eq 23
        }

        Test-SgPsAssert "New-SafeguardCustomPlatform session settings persisted" {
            $readback = Get-SafeguardCustomPlatform -Insecure $Context.SuiteData["Platform3Id"]
            $readback.SessionFeatureProperties.SupportsSessionManagement -eq $true -and
                $readback.SessionFeatureProperties.DefaultSshSessionPort -eq 22 -and
                $readback.SessionFeatureProperties.DefaultRemoteDesktopSessionPort -eq 3389 -and
                $readback.SessionFeatureProperties.DefaultTelnetSessionPort -eq 23
        }

        # --- Session management: Edit to change session ports ---
        Test-SgPsAssert "Edit-SafeguardCustomPlatform changes session ports" {
            $edited = Edit-SafeguardCustomPlatform -Insecure $Context.SuiteData["Platform3Id"] `
                -SshSessionPort 2222 -RdpSessionPort 13389
            $edited.SessionFeatureProperties.DefaultSshSessionPort -eq 2222 -and
                $edited.SessionFeatureProperties.DefaultRemoteDesktopSessionPort -eq 13389 -and
                $edited.SessionFeatureProperties.SupportsSessionManagement -eq $true
        }

        Test-SgPsAssert "Edit-SafeguardCustomPlatform session port changes persisted" {
            $readback = Get-SafeguardCustomPlatform -Insecure $Context.SuiteData["Platform3Id"]
            $readback.SessionFeatureProperties.DefaultSshSessionPort -eq 2222 -and
                $readback.SessionFeatureProperties.DefaultRemoteDesktopSessionPort -eq 13389 -and
                $readback.SessionFeatureProperties.SupportsSessionManagement -eq $true
        }

        # --- Session management: Edit to disable sessions ---
        Test-SgPsAssert "Edit-SafeguardCustomPlatform -DenySessionRequests disables sessions" {
            $edited = Edit-SafeguardCustomPlatform -Insecure $Context.SuiteData["Platform3Id"] `
                -DenySessionRequests
            $edited.SessionFeatureProperties.SupportsSessionManagement -eq $false
        }

        Test-SgPsAssert "Edit-SafeguardCustomPlatform deny sessions persisted" {
            $readback = Get-SafeguardCustomPlatform -Insecure $Context.SuiteData["Platform3Id"]
            $readback.SessionFeatureProperties.SupportsSessionManagement -eq $false
        }

        # --- Session management: Edit to re-enable sessions ---
        Test-SgPsAssert "Edit-SafeguardCustomPlatform -AllowSessionRequests re-enables sessions" {
            $edited = Edit-SafeguardCustomPlatform -Insecure $Context.SuiteData["Platform3Id"] `
                -AllowSessionRequests
            $edited.SessionFeatureProperties.SupportsSessionManagement -eq $true
        }

        Test-SgPsAssert "Edit-SafeguardCustomPlatform re-enable sessions persisted" {
            $readback = Get-SafeguardCustomPlatform -Insecure $Context.SuiteData["Platform3Id"]
            $readback.SessionFeatureProperties.SupportsSessionManagement -eq $true
        }

        # --- Import-SafeguardCustomPlatformScript (add script to scriptless platform) ---
        Test-SgPsAssert "Import-SafeguardCustomPlatformScript adds script to scriptless platform" {
            # Platform1 was created without a script - use a unique script ID
            $scriptContent = Get-Content -Path $scriptFile -Raw
            $importId = "$($scriptId)Import"
            $modified = $scriptContent -replace [regex]::Escape($scriptId), $importId
            $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) "import_script.json"
            Set-Content -Path $tempFile -Value $modified -NoNewline

            $result = Import-SafeguardCustomPlatformScript -Insecure $Context.SuiteData["Platform1Id"] `
                -ScriptFile $tempFile
            Remove-Item $tempFile -Force

            $result.CustomScriptProperties.HasScript -eq $true -and
                $result.SupportedOperations.Count -gt 0
        }

        Test-SgPsAssert "Import-SafeguardCustomPlatformScript persisted with readback" {
            $readback = Get-SafeguardCustomPlatform -Insecure $Context.SuiteData["Platform1Id"]
            $readback.CustomScriptProperties.HasScript -eq $true -and
                $readback.SupportedOperations.Count -gt 0
        }

        # --- Export-SafeguardCustomPlatformScript (by ID) ---
        Test-SgPsAssert "Export-SafeguardCustomPlatformScript returns script content" {
            $exported = Export-SafeguardCustomPlatformScript -Insecure $Context.SuiteData["Platform2Id"]
            $null -ne $exported -and $null -ne $exported.Id -and
                $exported.Id -eq $scriptId -and $null -ne $exported.BackEnd
        }

        # --- Export-SafeguardCustomPlatformScript (by name) ---
        Test-SgPsAssert "Export-SafeguardCustomPlatformScript by name" {
            $exported = Export-SafeguardCustomPlatformScript -Insecure $platform2Name
            $null -ne $exported -and $exported.Id -eq $scriptId
        }

        # --- Export-SafeguardCustomPlatformScript (to file) ---
        Test-SgPsAssert "Export-SafeguardCustomPlatformScript writes to OutFile" {
            $outPath = Join-Path ([System.IO.Path]::GetTempPath()) "exported_script.json"
            Export-SafeguardCustomPlatformScript -Insecure $Context.SuiteData["Platform2Id"] `
                -OutFile $outPath
            $exists = Test-Path $outPath
            $content = ""
            if ($exists) {
                $content = Get-Content -Path $outPath -Raw
                Remove-Item $outPath -Force
            }
            $exists -and $content.Length -gt 100 -and $content -match $scriptId
        }

        # --- Export-SafeguardCustomPlatformScript (error on no script) ---
        Test-SgPsAssert "Export-SafeguardCustomPlatformScript errors on scriptless platform" {
            # Create a temp platform without script to test the error path
            $tempPlat = New-SafeguardCustomPlatform -Insecure -Name "${platform1Name}_NoScript"
            $threw = $false
            try {
                $null = Export-SafeguardCustomPlatformScript -Insecure $tempPlat.Id
            } catch {
                $threw = $_ -match "does not have a script"
            }
            Remove-SafeguardCustomPlatform -Insecure $tempPlat.Id
            $threw
        }

        # --- Import-SafeguardCustomPlatformScript (replace script with different one) ---
        Test-SgPsAssert "Import-SafeguardCustomPlatformScript replaces script with different one" {
            # Platform2 currently has script1 (SSHKeySupport). Replace with script2 (Discovery).
            $beforeExport = Export-SafeguardCustomPlatformScript -Insecure $Context.SuiteData["Platform2Id"]
            $hadOriginalId = $beforeExport.Id -eq $scriptId

            $result = Import-SafeguardCustomPlatformScript -Insecure $Context.SuiteData["Platform2Id"] `
                -ScriptFile $scriptFile2

            $result.CustomScriptProperties.HasScript -eq $true -and $hadOriginalId
        }

        Test-SgPsAssert "Import-SafeguardCustomPlatformScript script change verified via Export" {
            $afterExport = Export-SafeguardCustomPlatformScript -Insecure $Context.SuiteData["Platform2Id"]
            # The exported script should now contain the Discovery script ID, not the original
            $afterExport.Id -eq $scriptId2
        }

        # --- Edit-SafeguardCustomPlatform -ScriptFile (change script via Edit) ---
        Test-SgPsAssert "Edit-SafeguardCustomPlatform -ScriptFile changes script content" {
            # Platform2 now has Discovery script. Switch back to SSHKey via Edit -ScriptFile.
            $edited = Edit-SafeguardCustomPlatform -Insecure $Context.SuiteData["Platform2Id"] `
                -ScriptFile $scriptFile
            $edited.CustomScriptProperties.HasScript -eq $true
        }

        Test-SgPsAssert "Edit-SafeguardCustomPlatform -ScriptFile change verified via Export" {
            $afterExport = Export-SafeguardCustomPlatformScript -Insecure $Context.SuiteData["Platform2Id"]
            # Should be back to the original SSHKey script
            $afterExport.Id -eq $scriptId
        }

        # --- Test-SafeguardCustomPlatformScript (valid script) ---
        Test-SgPsAssert "Test-SafeguardCustomPlatformScript validates a well-formed script" {
            $result = Test-SafeguardCustomPlatformScript -Insecure $scriptFile
            $null -ne $result -and
                $result.PlatformType -eq "Custom" -and
                $result.PlatformFamily -eq "Custom" -and
                $result.CustomScriptProperties.HasScript -eq $true -and
                $result.SupportedOperations.Count -gt 0
        }

        Test-SgPsAssert "Test-SafeguardCustomPlatformScript returns expected operations" {
            $result = Test-SafeguardCustomPlatformScript -Insecure $scriptFile
            # The SSHKeySupport script defines 8 operations
            $ops = $result.SupportedOperations
            $ops -contains "TestConnection" -and
                $ops -contains "CheckPassword" -and
                $ops -contains "ChangePassword" -and
                $ops.Count -eq 8
        }

        Test-SgPsAssert "Test-SafeguardCustomPlatformScript rejects malformed script" {
            # Create a temp file with invalid JSON
            $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) "SgPsTest_BadScript.json"
            "{ invalid json content" | Out-File -FilePath $tempFile -Encoding utf8
            $threw = $false
            try {
                $null = Test-SafeguardCustomPlatformScript -Insecure $tempFile
            } catch {
                $threw = $_ -match "60020"
            }
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
            $threw
        }

        Test-SgPsAssert "Test-SafeguardCustomPlatformScript rejects structurally invalid script" {
            # Create a temp file with valid JSON but missing required fields
            $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) "SgPsTest_BadStructure.json"
            '{"Id": "test", "Operations": []}' | Out-File -FilePath $tempFile -Encoding utf8
            $threw = $false
            try {
                $null = Test-SafeguardCustomPlatformScript -Insecure $tempFile
            } catch {
                $threw = $_ -match "60020"
            }
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
            $threw
        }

        # --- Get-SafeguardCustomPlatformScriptParameter ---
        Test-SgPsAssert "Get-SafeguardCustomPlatformScriptParameter returns schema" {
            $params = @(Get-SafeguardCustomPlatformScriptParameter -Insecure $Context.SuiteData["Platform2Id"])
            # The SSHKeySupport script defines RequestTerminal for multiple operations
            $params.Count -gt 0 -and
                ($params | Where-Object { $_.Name -eq "RequestTerminal" }).Count -gt 0 -and
                $params[0].PSObject.Properties.Name -contains "Name" -and
                $params[0].PSObject.Properties.Name -contains "DefaultValue" -and
                $params[0].PSObject.Properties.Name -contains "Type" -and
                $params[0].PSObject.Properties.Name -contains "TaskName"
        }

        Test-SgPsAssert "Get-SafeguardCustomPlatformScriptParameter by name" {
            $params = @(Get-SafeguardCustomPlatformScriptParameter -Insecure $platform2Name)
            $params.Count -gt 0 -and
                ($params | Where-Object { $_.Name -eq "RequestTerminal" -and $_.Type -eq "Boolean" }).Count -gt 0
        }

        Test-SgPsAssert "Get-SafeguardCustomPlatformScriptParameter throws for scriptless platform" {
            # Platform1 may have had a script imported during import tests, so create a fresh one
            $local:tempPlat = New-SafeguardCustomPlatform -Insecure "${prefix}_ScriptlessTemp"
            $threw = $false
            try {
                $null = Get-SafeguardCustomPlatformScriptParameter -Insecure $local:tempPlat.Id
            } catch {
                $threw = $_ -match "does not have a script"
            }
            Remove-SafeguardCustomPlatform -Insecure $local:tempPlat.Id | Out-Null
            $threw
        }

        Test-SgPsAssert "Get-SafeguardCustomPlatformScriptParameter from script file" {
            $params = @(Get-SafeguardCustomPlatformScriptParameter -Insecure `
                -ScriptFile $Context.SuiteData["ScriptFile"])
            $params.Count -gt 0 -and
                ($params | Where-Object { $_.Name -eq "RequestTerminal" }).Count -gt 0 -and
                $params[0].PSObject.Properties.Name -contains "Name" -and
                $params[0].PSObject.Properties.Name -contains "DefaultValue" -and
                $params[0].PSObject.Properties.Name -contains "Type" -and
                $params[0].PSObject.Properties.Name -contains "TaskName"
        }

        # --- New-SafeguardCustomPlatformAsset ---
        $asset1Name = $Context.SuiteData["TestAsset1"]
        $asset2Name = $Context.SuiteData["TestAsset2"]

        Test-SgPsAssert "New-SafeguardCustomPlatformAsset creates asset with defaults" {
            $asset = New-SafeguardCustomPlatformAsset -Insecure $platform2Name "10.99.99.1" `
                -DisplayName $asset1Name -NoSshHostKeyDiscovery `
                -CustomScriptParameters @()
            $Context.SuiteData["Asset1Id"] = $asset.Id
            $asset.Name -eq $asset1Name -and
                $asset.NetworkAddress -eq "10.99.99.1" -and
                $asset.PlatformDisplayName -eq $platform2Name
        }

        Test-SgPsAssert "New-SafeguardCustomPlatformAsset asset has default custom params" {
            $readback = Invoke-SafeguardMethod -Insecure Core GET "Assets/$($Context.SuiteData['Asset1Id'])"
            $readback.CustomScriptParameters.Count -gt 0 -and
                ($readback.CustomScriptParameters | Where-Object {
                    $_.Name -eq "RequestTerminal" -and $_.Value -eq "True"
                }).Count -gt 0
        }

        Test-SgPsAssert "New-SafeguardCustomPlatformAsset with custom param overrides" {
            $overrides = @(
                @{ Name = "RequestTerminal"; Value = "False" }
            )
            $asset = New-SafeguardCustomPlatformAsset -Insecure $platform2Name "10.99.99.2" `
                -DisplayName $asset2Name -NoSshHostKeyDiscovery `
                -CustomScriptParameters $overrides
            $Context.SuiteData["Asset2Id"] = $asset.Id
            $asset.Name -eq $asset2Name -and
                $asset.NetworkAddress -eq "10.99.99.2"
        }

        Test-SgPsAssert "New-SafeguardCustomPlatformAsset overrides verified via GET readback" {
            $readback = Invoke-SafeguardMethod -Insecure Core GET "Assets/$($Context.SuiteData['Asset2Id'])"
            $rtParams = @($readback.CustomScriptParameters | Where-Object { $_.Name -eq "RequestTerminal" })
            # All operations should have Value=False since we didn't specify TaskName
            $allFalse = $true
            foreach ($p in $rtParams) {
                if ($p.Value -ne "False") { $allFalse = $false }
            }
            $rtParams.Count -gt 0 -and $allFalse
        }

        # --- Set-SafeguardCustomPlatformAssetParameter ---
        Test-SgPsAssert "Set-SafeguardCustomPlatformAssetParameter sets all operations" {
            $updated = Set-SafeguardCustomPlatformAssetParameter -Insecure $Context.SuiteData["Asset1Id"] `
                "RequestTerminal" "False"
            $rtParams = @($updated.CustomScriptParameters | Where-Object { $_.Name -eq "RequestTerminal" })
            $allFalse = $true
            foreach ($p in $rtParams) {
                if ($p.Value -ne "False") { $allFalse = $false }
            }
            $rtParams.Count -gt 0 -and $allFalse
        }

        Test-SgPsAssert "Set-SafeguardCustomPlatformAssetParameter verified via GET readback" {
            $readback = Invoke-SafeguardMethod -Insecure Core GET "Assets/$($Context.SuiteData['Asset1Id'])"
            $rtParams = @($readback.CustomScriptParameters | Where-Object { $_.Name -eq "RequestTerminal" })
            $allFalse = $true
            foreach ($p in $rtParams) {
                if ($p.Value -ne "False") { $allFalse = $false }
            }
            $rtParams.Count -gt 0 -and $allFalse
        }

        Test-SgPsAssert "Set-SafeguardCustomPlatformAssetParameter per-operation" {
            # Set only TestConnection back to True
            $updated = Set-SafeguardCustomPlatformAssetParameter -Insecure $Context.SuiteData["Asset1Id"] `
                "RequestTerminal" "True" -TaskName "TestConnection"
            $tcParam = $updated.CustomScriptParameters | Where-Object {
                $_.Name -eq "RequestTerminal" -and $_.TaskName -eq "TestConnection"
            }
            $otherParams = @($updated.CustomScriptParameters | Where-Object {
                $_.Name -eq "RequestTerminal" -and $_.TaskName -ne "TestConnection"
            })
            $othersStillFalse = $true
            foreach ($p in $otherParams) {
                if ($p.Value -ne "False") { $othersStillFalse = $false }
            }
            $tcParam.Value -eq "True" -and $othersStillFalse
        }

        Test-SgPsAssert "Set-SafeguardCustomPlatformAssetParameter per-operation verified via GET" {
            $readback = Invoke-SafeguardMethod -Insecure Core GET "Assets/$($Context.SuiteData['Asset1Id'])"
            $tcParam = $readback.CustomScriptParameters | Where-Object {
                $_.Name -eq "RequestTerminal" -and $_.TaskName -eq "TestConnection"
            }
            $cpParam = $readback.CustomScriptParameters | Where-Object {
                $_.Name -eq "RequestTerminal" -and $_.TaskName -eq "CheckPassword"
            }
            $tcParam.Value -eq "True" -and $cpParam.Value -eq "False"
        }

        Test-SgPsAssert "Set-SafeguardCustomPlatformAssetParameter by asset name" {
            $updated = Set-SafeguardCustomPlatformAssetParameter -Insecure $asset2Name `
                "RequestTerminal" "True"
            $rtParams = @($updated.CustomScriptParameters | Where-Object { $_.Name -eq "RequestTerminal" })
            $allTrue = $true
            foreach ($p in $rtParams) {
                if ($p.Value -ne "True") { $allTrue = $false }
            }
            $rtParams.Count -gt 0 -and $allTrue
        }

        Test-SgPsAssert "Set-SafeguardCustomPlatformAssetParameter throws for bad param name" {
            $threw = $false
            try {
                $null = Set-SafeguardCustomPlatformAssetParameter -Insecure $Context.SuiteData["Asset1Id"] `
                    "NonExistentParam" "SomeValue"
            } catch {
                $threw = $_ -match "Unable to find custom script parameter"
            }
            $threw
        }

        # --- Cleanup test assets before platform removal ---
        Test-SgPsAssert "Remove test asset 1" {
            Invoke-SafeguardMethod -Insecure Core DELETE "Assets/$($Context.SuiteData['Asset1Id'])" | Out-Null
            $found = $false
            try {
                $null = Invoke-SafeguardMethod -Insecure Core GET "Assets/$($Context.SuiteData['Asset1Id'])"
                $found = $true
            } catch {}
            -not $found
        }

        Test-SgPsAssert "Remove test asset 2" {
            Invoke-SafeguardMethod -Insecure Core DELETE "Assets/$($Context.SuiteData['Asset2Id'])" | Out-Null
            $found = $false
            try {
                $null = Invoke-SafeguardMethod -Insecure Core GET "Assets/$($Context.SuiteData['Asset2Id'])"
                $found = $true
            } catch {}
            -not $found
        }

        # --- Remove-SafeguardCustomPlatform (by ID) ---
        Test-SgPsAssert "Remove-SafeguardCustomPlatform deletes by ID" {
            Remove-SafeguardCustomPlatform -Insecure $Context.SuiteData["Platform1Id"]
            $found = $false
            try {
                $null = Get-SafeguardCustomPlatform -Insecure $Context.SuiteData["Platform1Id"]
                $found = $true
            } catch {}
            -not $found
        }

        # --- Remove-SafeguardCustomPlatform (by name) ---
        Test-SgPsAssert "Remove-SafeguardCustomPlatform deletes by name" {
            Remove-SafeguardCustomPlatform -Insecure $platform2Name
            $found = $false
            try {
                $null = Get-SafeguardCustomPlatform -Insecure $platform2Name
                $found = $true
            } catch {}
            -not $found
        }

        # --- Remove-SafeguardCustomPlatform (session platform by ID) ---
        Test-SgPsAssert "Remove-SafeguardCustomPlatform deletes session-enabled platform" {
            Remove-SafeguardCustomPlatform -Insecure $Context.SuiteData["Platform3Id"]
            $found = $false
            try {
                $null = Get-SafeguardCustomPlatform -Insecure $Context.SuiteData["Platform3Id"]
                $found = $true
            } catch {}
            -not $found
        }

        # --- Verify all test platforms gone ---
        Test-SgPsAssert "All test platforms cleaned up" {
            $remaining = @(Get-SafeguardCustomPlatform -Insecure)
            $stale = $remaining | Where-Object { $_.Name -like "$($Context.TestPrefix)*" }
            $null -eq $stale -or @($stale).Count -eq 0
        }
    }

    Cleanup = {
        param($Context)
        # Registered cleanups handle deletion of platforms and temp files
    }
}
