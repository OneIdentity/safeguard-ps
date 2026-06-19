@{
    Name        = "SSH Key Profiles"
    Description = "Tests SSH key profile, check schedule, change schedule, and discovery schedule CRUD"
    Tags        = @("profiles", "sshkeys")

    Setup = {
        param($Context)

        $prefix = $Context.TestPrefix
        $profileName = "${prefix}_SshKeyProfile"
        $profileName2 = "${prefix}_SshKeyProfile2"
        $profileCopyName = "${prefix}_SshKeyProfileCopy"
        $checkName = "${prefix}_SshChkSched"
        $changeName = "${prefix}_SshChgSched"
        $discoveryName = "${prefix}_SshDiscSched"

        # Pre-cleanup
        try {
            $profiles = Get-SafeguardSshKeyProfile -Insecure
            @($profiles) | Where-Object { $_.Name -match $prefix } | ForEach-Object {
                try { Remove-SafeguardSshKeyProfile -Insecure $_.Id } catch {}
            }
        } catch {}
        try {
            $checks = Get-SafeguardSshKeyCheckSchedule -Insecure
            @($checks) | Where-Object { $_.Name -match $prefix } | ForEach-Object {
                try { Remove-SafeguardSshKeyCheckSchedule -Insecure $_.Id } catch {}
            }
        } catch {}
        try {
            $changes = Get-SafeguardSshKeyChangeSchedule -Insecure
            @($changes) | Where-Object { $_.Name -match $prefix } | ForEach-Object {
                try { Remove-SafeguardSshKeyChangeSchedule -Insecure $_.Id } catch {}
            }
        } catch {}
        try {
            $discoveries = Get-SafeguardSshKeyDiscoverySchedule -Insecure
            @($discoveries) | Where-Object { $_.Name -match $prefix } | ForEach-Object {
                try { Remove-SafeguardSshKeyDiscoverySchedule -Insecure $_.Id } catch {}
            }
        } catch {}

        $Context.SuiteData["ProfileName"] = $profileName
        $Context.SuiteData["ProfileName2"] = $profileName2
        $Context.SuiteData["ProfileCopyName"] = $profileCopyName
        $Context.SuiteData["CheckName"] = $checkName
        $Context.SuiteData["ChangeName"] = $changeName
        $Context.SuiteData["DiscoveryName"] = $discoveryName
    }

    Execute = {
        param($Context)

        # =========================================
        # SSH Key Check Schedules
        # =========================================

        # --- Get-SafeguardSshKeyCheckSchedule (list) ---
        Test-SgPsAssert "Get-SafeguardSshKeyCheckSchedule lists schedules" {
            $schedules = Get-SafeguardSshKeyCheckSchedule -Insecure
            $null -ne $schedules
        }

        # --- New-SafeguardSshKeyCheckSchedule ---
        Test-SgPsAssert "New-SafeguardSshKeyCheckSchedule creates a schedule" {
            $sched = New-SafeguardSshKeyCheckSchedule -Insecure $Context.SuiteData["CheckName"]
            $Context.SuiteData["CheckId"] = $sched.Id

            Register-SgPsTestCleanup -Description "Delete SSH key check schedule" -Action {
                param($Ctx)
                try { Remove-SafeguardSshKeyCheckSchedule -Insecure $Ctx.SuiteData['CheckId'] } catch {}
            }
            $sched.Name -eq $Context.SuiteData["CheckName"]
        }

        # --- Get-SafeguardSshKeyCheckSchedule by ID ---
        Test-SgPsAssert "Get-SafeguardSshKeyCheckSchedule by ID" {
            $sched = Get-SafeguardSshKeyCheckSchedule -Insecure $Context.SuiteData["CheckId"]
            $sched.Name -eq $Context.SuiteData["CheckName"]
        }

        # --- Edit-SafeguardSshKeyCheckSchedule ---
        Test-SgPsAssert "Edit-SafeguardSshKeyCheckSchedule updates schedule" {
            $updated = Edit-SafeguardSshKeyCheckSchedule -Insecure `
                $Context.SuiteData["CheckId"] -Description "Updated check schedule"
            $updated.Description -eq "Updated check schedule"
        }

        # --- Edit-SafeguardSshKeyCheckSchedule via pipeline ---
        Test-SgPsAssert "Edit-SafeguardSshKeyCheckSchedule via pipeline" {
            $sched = Get-SafeguardSshKeyCheckSchedule -Insecure $Context.SuiteData["CheckId"]
            $sched.Description = "Pipeline check edit"
            $edited = $sched | Edit-SafeguardSshKeyCheckSchedule -Insecure
            $edited.Description -eq "Pipeline check edit"
        }
        Test-SgPsAssert "Edit-SafeguardSshKeyCheckSchedule pipeline edit persisted" {
            $readback = Get-SafeguardSshKeyCheckSchedule -Insecure $Context.SuiteData["CheckId"]
            $readback.Description -eq "Pipeline check edit"
        }

        # =========================================
        # SSH Key Change Schedules
        # =========================================

        # --- Get-SafeguardSshKeyChangeSchedule (list) ---
        Test-SgPsAssert "Get-SafeguardSshKeyChangeSchedule lists schedules" {
            $schedules = Get-SafeguardSshKeyChangeSchedule -Insecure
            $null -ne $schedules
        }

        # --- New-SafeguardSshKeyChangeSchedule ---
        Test-SgPsAssert "New-SafeguardSshKeyChangeSchedule creates a schedule" {
            $sched = New-SafeguardSshKeyChangeSchedule -Insecure $Context.SuiteData["ChangeName"]
            $Context.SuiteData["ChangeId"] = $sched.Id

            Register-SgPsTestCleanup -Description "Delete SSH key change schedule" -Action {
                param($Ctx)
                try { Remove-SafeguardSshKeyChangeSchedule -Insecure $Ctx.SuiteData['ChangeId'] } catch {}
            }
            $sched.Name -eq $Context.SuiteData["ChangeName"]
        }

        # --- Get-SafeguardSshKeyChangeSchedule by ID ---
        Test-SgPsAssert "Get-SafeguardSshKeyChangeSchedule by ID" {
            $sched = Get-SafeguardSshKeyChangeSchedule -Insecure $Context.SuiteData["ChangeId"]
            $sched.Name -eq $Context.SuiteData["ChangeName"]
        }

        # --- Edit-SafeguardSshKeyChangeSchedule ---
        Test-SgPsAssert "Edit-SafeguardSshKeyChangeSchedule updates schedule" {
            $updated = Edit-SafeguardSshKeyChangeSchedule -Insecure `
                $Context.SuiteData["ChangeId"] -Description "Updated change schedule"
            $updated.Description -eq "Updated change schedule"
        }

        # --- Edit-SafeguardSshKeyChangeSchedule via pipeline ---
        Test-SgPsAssert "Edit-SafeguardSshKeyChangeSchedule via pipeline" {
            $sched = Get-SafeguardSshKeyChangeSchedule -Insecure $Context.SuiteData["ChangeId"]
            $sched.Description = "Pipeline change edit"
            $edited = $sched | Edit-SafeguardSshKeyChangeSchedule -Insecure
            $edited.Description -eq "Pipeline change edit"
        }
        Test-SgPsAssert "Edit-SafeguardSshKeyChangeSchedule pipeline edit persisted" {
            $readback = Get-SafeguardSshKeyChangeSchedule -Insecure $Context.SuiteData["ChangeId"]
            $readback.Description -eq "Pipeline change edit"
        }

        # =========================================
        # SSH Key Discovery Schedules
        # =========================================

        # --- Get-SafeguardSshKeyDiscoverySchedule (list) ---
        Test-SgPsAssert "Get-SafeguardSshKeyDiscoverySchedule lists schedules" {
            $schedules = Get-SafeguardSshKeyDiscoverySchedule -Insecure
            $null -ne $schedules
        }

        # --- New-SafeguardSshKeyDiscoverySchedule ---
        Test-SgPsAssert "New-SafeguardSshKeyDiscoverySchedule creates a schedule" {
            $sched = New-SafeguardSshKeyDiscoverySchedule -Insecure $Context.SuiteData["DiscoveryName"]
            $Context.SuiteData["DiscoveryId"] = $sched.Id

            Register-SgPsTestCleanup -Description "Delete SSH key discovery schedule" -Action {
                param($Ctx)
                try { Remove-SafeguardSshKeyDiscoverySchedule -Insecure $Ctx.SuiteData['DiscoveryId'] } catch {}
            }
            $sched.Name -eq $Context.SuiteData["DiscoveryName"]
        }

        # --- Get-SafeguardSshKeyDiscoverySchedule by ID ---
        Test-SgPsAssert "Get-SafeguardSshKeyDiscoverySchedule by ID" {
            $sched = Get-SafeguardSshKeyDiscoverySchedule -Insecure $Context.SuiteData["DiscoveryId"]
            $sched.Name -eq $Context.SuiteData["DiscoveryName"]
        }

        # --- Edit-SafeguardSshKeyDiscoverySchedule ---
        Test-SgPsAssert "Edit-SafeguardSshKeyDiscoverySchedule updates schedule" {
            $updated = Edit-SafeguardSshKeyDiscoverySchedule -Insecure `
                $Context.SuiteData["DiscoveryId"] -Description "Updated discovery schedule"
            $updated.Description -eq "Updated discovery schedule"
        }

        # --- Edit-SafeguardSshKeyDiscoverySchedule via pipeline ---
        Test-SgPsAssert "Edit-SafeguardSshKeyDiscoverySchedule via pipeline" {
            $sched = Get-SafeguardSshKeyDiscoverySchedule -Insecure $Context.SuiteData["DiscoveryId"]
            $sched.Description = "Pipeline discovery edit"
            $edited = $sched | Edit-SafeguardSshKeyDiscoverySchedule -Insecure
            $edited.Description -eq "Pipeline discovery edit"
        }
        Test-SgPsAssert "Edit-SafeguardSshKeyDiscoverySchedule pipeline edit persisted" {
            $readback = Get-SafeguardSshKeyDiscoverySchedule -Insecure $Context.SuiteData["DiscoveryId"]
            $readback.Description -eq "Pipeline discovery edit"
        }

        # =========================================
        # SSH Key Profiles
        # =========================================

        # --- Get-SafeguardSshKeyProfile (list) ---
        Test-SgPsAssert "Get-SafeguardSshKeyProfile lists profiles" {
            $profiles = Get-SafeguardSshKeyProfile -Insecure
            $null -ne $profiles
        }

        # --- New-SafeguardSshKeyProfile ---
        Test-SgPsAssert "New-SafeguardSshKeyProfile creates a profile" {
            $sshProfile = New-SafeguardSshKeyProfile -Insecure `
                $Context.SuiteData["ProfileName"] `
                -CheckScheduleToSet $Context.SuiteData["CheckName"] `
                -ChangeScheduleToSet $Context.SuiteData["ChangeName"] `
                -DiscoveryScheduleToSet $Context.SuiteData["DiscoveryName"]
            $Context.SuiteData["ProfileId"] = $sshProfile.Id

            Register-SgPsTestCleanup -Description "Delete SSH key profile" -Action {
                param($Ctx)
                try { Remove-SafeguardSshKeyProfile -Insecure $Ctx.SuiteData['ProfileId'] } catch {}
            }
            $sshProfile.Name -eq $Context.SuiteData["ProfileName"]
        }

        # --- Get-SafeguardSshKeyProfile by ID ---
        Test-SgPsAssert "Get-SafeguardSshKeyProfile by ID" {
            $sshProfile = Get-SafeguardSshKeyProfile -Insecure $Context.SuiteData["ProfileId"]
            $sshProfile.Name -eq $Context.SuiteData["ProfileName"]
        }

        # --- Get-SafeguardSshKeyProfile by Name ---
        Test-SgPsAssert "Get-SafeguardSshKeyProfile by Name" {
            $sshProfile = Get-SafeguardSshKeyProfile -Insecure $Context.SuiteData["ProfileName"]
            $sshProfile.Id -eq $Context.SuiteData["ProfileId"]
        }

        # --- Edit-SafeguardSshKeyProfile ---
        Test-SgPsAssert "Edit-SafeguardSshKeyProfile updates description" {
            $updated = Edit-SafeguardSshKeyProfile -Insecure `
                $Context.SuiteData["ProfileId"] -Description "Updated profile desc"
            $updated.Description -eq "Updated profile desc"
        }

        # --- Edit-SafeguardSshKeyProfile via pipeline ---
        Test-SgPsAssert "Edit-SafeguardSshKeyProfile via pipeline" {
            $profObj = Get-SafeguardSshKeyProfile -Insecure $Context.SuiteData["ProfileId"]
            $profObj.Description = "Pipeline profile edit"
            $edited = $profObj | Edit-SafeguardSshKeyProfile -Insecure
            $edited.Description -eq "Pipeline profile edit"
        }
        Test-SgPsAssert "Edit-SafeguardSshKeyProfile pipeline edit persisted" {
            $readback = Get-SafeguardSshKeyProfile -Insecure $Context.SuiteData["ProfileId"]
            $readback.Description -eq "Pipeline profile edit"
        }

        # --- Copy-SafeguardSshKeyProfile ---
        Test-SgPsAssert "Copy-SafeguardSshKeyProfile creates a copy" {
            $copy = Copy-SafeguardSshKeyProfile -Insecure `
                $Context.SuiteData["ProfileId"] $Context.SuiteData["ProfileCopyName"]
            $Context.SuiteData["ProfileCopyId"] = $copy.Id

            Register-SgPsTestCleanup -Description "Delete copied SSH key profile" -Action {
                param($Ctx)
                try { Remove-SafeguardSshKeyProfile -Insecure $Ctx.SuiteData['ProfileCopyId'] } catch {}
            }
            $copy.Name -eq $Context.SuiteData["ProfileCopyName"]
        }

        # --- Rename-SafeguardSshKeyProfile ---
        Test-SgPsAssert "Rename-SafeguardSshKeyProfile renames the copy" {
            $renamed = Rename-SafeguardSshKeyProfile -Insecure `
                $Context.SuiteData["ProfileCopyId"] "$($Context.SuiteData['ProfileCopyName'])_Renamed"
            $readback = Get-SafeguardSshKeyProfile -Insecure $Context.SuiteData["ProfileCopyId"]
            $readback.Name -eq "$($Context.SuiteData['ProfileCopyName'])_Renamed"
        }

        # --- Remove-SafeguardSshKeyProfile (the copy) ---
        Test-SgPsAssert "Remove-SafeguardSshKeyProfile deletes the copy" {
            Remove-SafeguardSshKeyProfile -Insecure $Context.SuiteData["ProfileCopyId"]
            $remaining = Get-SafeguardSshKeyProfile -Insecure
            $list = @($remaining)
            -not ($list | Where-Object { $_.Id -eq $Context.SuiteData["ProfileCopyId"] })
        }

        # =========================================
        # Cleanup schedules
        # =========================================

        # --- Remove-SafeguardSshKeyDiscoverySchedule ---
        Test-SgPsAssert "Remove-SafeguardSshKeyDiscoverySchedule deletes a schedule" {
            # First need to remove the profile that references this schedule
            Remove-SafeguardSshKeyProfile -Insecure $Context.SuiteData["ProfileId"]
            Remove-SafeguardSshKeyDiscoverySchedule -Insecure $Context.SuiteData["DiscoveryId"]
            $remaining = Get-SafeguardSshKeyDiscoverySchedule -Insecure
            $list = @($remaining)
            -not ($list | Where-Object { $_.Id -eq $Context.SuiteData["DiscoveryId"] })
        }

        # --- Remove-SafeguardSshKeyChangeSchedule ---
        Test-SgPsAssert "Remove-SafeguardSshKeyChangeSchedule deletes a schedule" {
            Remove-SafeguardSshKeyChangeSchedule -Insecure $Context.SuiteData["ChangeId"]
            $remaining = Get-SafeguardSshKeyChangeSchedule -Insecure
            $list = @($remaining)
            -not ($list | Where-Object { $_.Id -eq $Context.SuiteData["ChangeId"] })
        }

        # --- Remove-SafeguardSshKeyCheckSchedule ---
        Test-SgPsAssert "Remove-SafeguardSshKeyCheckSchedule deletes a schedule" {
            Remove-SafeguardSshKeyCheckSchedule -Insecure $Context.SuiteData["CheckId"]
            $remaining = Get-SafeguardSshKeyCheckSchedule -Insecure
            $list = @($remaining)
            -not ($list | Where-Object { $_.Id -eq $Context.SuiteData["CheckId"] })
        }
    }

    Cleanup = {
        param($Context)
    }
}
