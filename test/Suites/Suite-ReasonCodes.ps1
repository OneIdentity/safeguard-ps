@{
    Name        = "ReasonCodes"
    Description = "Tests reason code CRUD operations"
    Tags        = @("reasoncodes", "core")

    Setup = {
        param($Context)

        $prefix = $Context.TestPrefix
        $rcName1 = "${prefix}_RC1"
        $rcName2 = "${prefix}_RC2"

        # Pre-cleanup stale objects from previous runs
        try {
            $stale = Get-SafeguardReasonCode -Insecure
            @($stale) | Where-Object { $_.Name -like "${prefix}_RC*" } | ForEach-Object {
                try { Remove-SafeguardReasonCode -Insecure $_.Id } catch {}
            }
        } catch {}

        $Context.SuiteData["RcName1"] = $rcName1
        $Context.SuiteData["RcName2"] = $rcName2
    }

    Execute = {
        param($Context)

        $rcName1 = $Context.SuiteData["RcName1"]
        $rcName2 = $Context.SuiteData["RcName2"]

        # --- Get-SafeguardReasonCode (list all) ---
        Test-SgPsAssert "Get-SafeguardReasonCode lists reason codes" {
            $list = @(Get-SafeguardReasonCode -Insecure)
            $list -is [Array]
        }

        # --- New-SafeguardReasonCode ---
        Test-SgPsAssert "New-SafeguardReasonCode creates a reason code" {
            $rc = New-SafeguardReasonCode -Insecure -Name $rcName1 -Description "Test reason code 1"
            $Context.SuiteData["RcId1"] = $rc.Id

            Register-SgPsTestCleanup -Description "Delete test reason code $rcName1" -Action {
                param($Ctx)
                try { Remove-SafeguardReasonCode -Insecure $Ctx.SuiteData['RcId1'] } catch {}
            }

            $null -ne $rc.Id -and $rc.Name -eq $rcName1 -and $rc.Description -eq "Test reason code 1"
        }

        # --- Get-SafeguardReasonCode by ID readback ---
        Test-SgPsAssert "Get-SafeguardReasonCode by ID returns correct object" {
            $rc = Get-SafeguardReasonCode -Insecure $Context.SuiteData["RcId1"]
            $rc.Name -eq $rcName1 -and $rc.Description -eq "Test reason code 1"
        }

        # --- Get-SafeguardReasonCode by Name ---
        Test-SgPsAssert "Get-SafeguardReasonCode by name" {
            $rc = Get-SafeguardReasonCode -Insecure $rcName1
            $rc.Id -eq $Context.SuiteData["RcId1"]
        }

        # --- Get-SafeguardReasonCode with Fields ---
        Test-SgPsAssert "Get-SafeguardReasonCode with Fields" {
            $rc = Get-SafeguardReasonCode -Insecure $Context.SuiteData["RcId1"] -Fields "Id","Name"
            $null -ne $rc.Id -and $rc.Name -eq $rcName1
        }

        # --- Find-SafeguardReasonCode ---
        Test-SgPsAssert "Find-SafeguardReasonCode by search string" {
            $results = Find-SafeguardReasonCode -Insecure $rcName1
            $found = @($results) | Where-Object { $_.Name -eq $rcName1 }
            $null -ne $found
        }

        # --- New second reason code for edit test ---
        Test-SgPsAssert "New-SafeguardReasonCode creates second reason code" {
            $rc2 = New-SafeguardReasonCode -Insecure -Name $rcName2 -Description "Test reason code 2"
            $Context.SuiteData["RcId2"] = $rc2.Id

            Register-SgPsTestCleanup -Description "Delete test reason code $rcName2" -Action {
                param($Ctx)
                try { Remove-SafeguardReasonCode -Insecure $Ctx.SuiteData['RcId2'] } catch {}
            }

            $rc2.Name -eq $rcName2
        }

        # --- Edit-SafeguardReasonCode ---
        Test-SgPsAssert "Edit-SafeguardReasonCode updates description" {
            $rc = Get-SafeguardReasonCode -Insecure $Context.SuiteData["RcId2"]
            $rc.Description = "Updated description"
            $edited = Edit-SafeguardReasonCode -Insecure $rc
            $edited.Description -eq "Updated description" -and $edited.Name -eq $rcName2
        }

        Test-SgPsAssert "Edit-SafeguardReasonCode change persisted" {
            $readback = Get-SafeguardReasonCode -Insecure $Context.SuiteData["RcId2"]
            $readback.Description -eq "Updated description" -and $readback.Name -eq $rcName2
        }

        # --- Edit-SafeguardReasonCode via pipeline ---
        Test-SgPsAssert "Edit-SafeguardReasonCode via pipeline" {
            $rc = Get-SafeguardReasonCode -Insecure $Context.SuiteData["RcId2"]
            $rc.Description = "Pipeline edit"
            $edited = $rc | Edit-SafeguardReasonCode -Insecure
            $edited.Description -eq "Pipeline edit"
        }

        Test-SgPsAssert "Edit-SafeguardReasonCode pipeline change persisted" {
            $readback = Get-SafeguardReasonCode -Insecure $Context.SuiteData["RcId2"]
            $readback.Description -eq "Pipeline edit"
        }

        # --- Remove-SafeguardReasonCode ---
        Test-SgPsAssert "Remove-SafeguardReasonCode removes by ID" {
            Remove-SafeguardReasonCode -Insecure $Context.SuiteData["RcId2"]
            $found = $false
            try {
                $null = Get-SafeguardReasonCode -Insecure $Context.SuiteData["RcId2"]
                $found = $true
            } catch {}
            -not $found
        }

        # --- Remove-SafeguardReasonCode by name ---
        Test-SgPsAssert "Remove-SafeguardReasonCode removes by name" {
            # Create a temporary one to delete by name
            $temp = New-SafeguardReasonCode -Insecure -Name "${rcName2}_temp" -Description "Temp for delete test"
            Remove-SafeguardReasonCode -Insecure "${rcName2}_temp"
            $found = $false
            try {
                $null = Get-SafeguardReasonCode -Insecure $temp.Id
                $found = $true
            } catch {}
            -not $found
        }
    }

    Cleanup = {
        param($Context)
    }
}
