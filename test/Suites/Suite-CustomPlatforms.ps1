@{
    Name        = "CustomPlatforms"
    Description = "Tests custom platform CRUD, script upload, and editing"
    Tags        = @("customplatforms", "core")

    Setup = {
        param($Context)

        $prefix = $Context.TestPrefix
        $testPlatform1 = "${prefix}_CustomPlat1"
        $testPlatform2 = "${prefix}_CustomPlat2"

        # Pre-cleanup any stale platforms from a previous failed run
        Remove-SgPsStaleTestObject -Collection "Platforms" -Name $testPlatform1
        Remove-SgPsStaleTestObject -Collection "Platforms" -Name $testPlatform2

        $Context.SuiteData["TestPlatform1"] = $testPlatform1
        $Context.SuiteData["TestPlatform2"] = $testPlatform2

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

        Register-SgPsTestCleanup -Description "Remove temp script file" -Action {
            param($Ctx)
            $f = $Ctx.SuiteData['ScriptFile']
            if ($f -and (Test-Path $f)) { Remove-Item $f -Force }
        }
    }

    Execute = {
        param($Context)

        $platform1Name = $Context.SuiteData["TestPlatform1"]
        $platform2Name = $Context.SuiteData["TestPlatform2"]
        $scriptFile = $Context.SuiteData["ScriptFile"]

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
                $readback.CustomScriptProperties.HasScript -eq $false
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

        # --- Edit-SafeguardCustomPlatform (add script to platform without one) ---
        Test-SgPsAssert "Edit-SafeguardCustomPlatform adds script to scriptless platform" {
            # Platform1 was created without a script
            $before = Get-SafeguardCustomPlatform -Insecure $Context.SuiteData["Platform1Id"]
            $hadScript = $before.CustomScriptProperties.HasScript

            # We need a second unique script ID since Platform2 already has one
            $scriptContent = Get-Content -Path $scriptFile -Raw
            $secondId = "$($Context.SuiteData['ScriptId'])2"
            $modified = $scriptContent -replace [regex]::Escape($Context.SuiteData['ScriptId']), $secondId
            $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) "second_script.json"
            Set-Content -Path $tempFile -Value $modified -NoNewline

            $edited = Edit-SafeguardCustomPlatform -Insecure $Context.SuiteData["Platform1Id"] `
                -ScriptFile $tempFile
            Remove-Item $tempFile -Force

            $hadScript -eq $false -and $edited.CustomScriptProperties.HasScript -eq $true
        }

        Test-SgPsAssert "Edit-SafeguardCustomPlatform script upload persisted" {
            $readback = Get-SafeguardCustomPlatform -Insecure $Context.SuiteData["Platform1Id"]
            $readback.CustomScriptProperties.HasScript -eq $true -and
                $readback.SupportedOperations.Count -gt 0
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
