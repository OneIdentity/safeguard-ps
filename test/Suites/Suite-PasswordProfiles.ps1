@{
    Name        = "Password Profiles"
    Description = "Tests password profile, password rule, check schedule, and change schedule CRUD"
    Tags        = @("profiles", "passwords")

    Setup = {
        param($Context)

        $prefix = $Context.TestPrefix
        $profileName = "${prefix}_PwdProfile"
        $profileName2 = "${prefix}_PwdProfile2"
        $checkName = "${prefix}_ChkSched"
        $changeName = "${prefix}_ChgSched"
        $ruleName = "${prefix}_PwdRule"

        # Pre-cleanup
        try {
            $profiles = Get-SafeguardPasswordProfile -Insecure
            @($profiles) | Where-Object { $_.Name -match $prefix } | ForEach-Object {
                try { Remove-SafeguardPasswordProfile -Insecure $_.Id } catch {}
            }
        } catch {}
        try {
            $checks = Get-SafeguardPasswordCheckSchedule -Insecure
            @($checks) | Where-Object { $_.Name -match $prefix } | ForEach-Object {
                try { Remove-SafeguardPasswordCheckSchedule -Insecure $_.Id } catch {}
            }
        } catch {}
        try {
            $changes = Get-SafeguardPasswordChangeSchedule -Insecure
            @($changes) | Where-Object { $_.Name -match $prefix } | ForEach-Object {
                try { Remove-SafeguardPasswordChangeSchedule -Insecure $_.Id } catch {}
            }
        } catch {}
        try {
            $rules = Get-SafeguardAccountPasswordRule -Insecure
            @($rules) | Where-Object { $_.Name -match $prefix } | ForEach-Object {
                try { Remove-SafeguardAccountPasswordRule -Insecure $_.Id } catch {}
            }
        } catch {}

        $Context.SuiteData["ProfileName"] = $profileName
        $Context.SuiteData["ProfileName2"] = $profileName2
        $Context.SuiteData["CheckName"] = $checkName
        $Context.SuiteData["ChangeName"] = $changeName
        $Context.SuiteData["RuleName"] = $ruleName
    }

    Execute = {
        param($Context)

        # =========================================
        # Password Check Schedules
        # =========================================

        # --- Get-SafeguardPasswordCheckSchedule (list) ---
        Test-SgPsAssert "Get-SafeguardPasswordCheckSchedule lists schedules" {
            $schedules = Get-SafeguardPasswordCheckSchedule -Insecure
            $null -ne $schedules
        }

        # --- New-SafeguardPasswordCheckSchedule ---
        Test-SgPsAssert "New-SafeguardPasswordCheckSchedule creates a schedule" {
            $sched = New-SafeguardPasswordCheckSchedule -Insecure $Context.SuiteData["CheckName"]
            $Context.SuiteData["CheckId"] = $sched.Id

            Register-SgPsTestCleanup -Description "Delete check schedule" -Action {
                param($Ctx)
                try { Remove-SafeguardPasswordCheckSchedule -Insecure $Ctx.SuiteData['CheckId'] } catch {}
            }
            $sched.Name -eq $Context.SuiteData["CheckName"]
        }

        # --- Get-SafeguardPasswordCheckSchedule by ID ---
        Test-SgPsAssert "Get-SafeguardPasswordCheckSchedule by ID" {
            $sched = Get-SafeguardPasswordCheckSchedule -Insecure $Context.SuiteData["CheckId"]
            $sched.Name -eq $Context.SuiteData["CheckName"]
        }

        # --- Edit-SafeguardPasswordCheckSchedule ---
        Test-SgPsAssert "Edit-SafeguardPasswordCheckSchedule updates schedule" {
            $updated = Edit-SafeguardPasswordCheckSchedule -Insecure `
                $Context.SuiteData["CheckId"] -Description "Updated check schedule"
            $updated.Description -eq "Updated check schedule"
        }

        # =========================================
        # Password Change Schedules
        # =========================================

        # --- Get-SafeguardPasswordChangeSchedule (list) ---
        Test-SgPsAssert "Get-SafeguardPasswordChangeSchedule lists schedules" {
            $schedules = Get-SafeguardPasswordChangeSchedule -Insecure
            $null -ne $schedules
        }

        # --- New-SafeguardPasswordChangeSchedule ---
        Test-SgPsAssert "New-SafeguardPasswordChangeSchedule creates a schedule" {
            $sched = New-SafeguardPasswordChangeSchedule -Insecure $Context.SuiteData["ChangeName"]
            $Context.SuiteData["ChangeId"] = $sched.Id

            Register-SgPsTestCleanup -Description "Delete change schedule" -Action {
                param($Ctx)
                try { Remove-SafeguardPasswordChangeSchedule -Insecure $Ctx.SuiteData['ChangeId'] } catch {}
            }
            $sched.Name -eq $Context.SuiteData["ChangeName"]
        }

        # --- Get-SafeguardPasswordChangeSchedule by ID ---
        Test-SgPsAssert "Get-SafeguardPasswordChangeSchedule by ID" {
            $sched = Get-SafeguardPasswordChangeSchedule -Insecure $Context.SuiteData["ChangeId"]
            $sched.Name -eq $Context.SuiteData["ChangeName"]
        }

        # --- Edit-SafeguardPasswordChangeSchedule ---
        Test-SgPsAssert "Edit-SafeguardPasswordChangeSchedule updates schedule" {
            $updated = Edit-SafeguardPasswordChangeSchedule -Insecure `
                $Context.SuiteData["ChangeId"] -Description "Updated change schedule"
            $updated.Description -eq "Updated change schedule"
        }

        # =========================================
        # Account Password Rules
        # =========================================

        # --- Get-SafeguardAccountPasswordRule (list) ---
        Test-SgPsAssert "Get-SafeguardAccountPasswordRule lists rules" {
            $rules = Get-SafeguardAccountPasswordRule -Insecure
            $null -ne $rules
        }

        # --- New-SafeguardAccountPasswordRule ---
        Test-SgPsAssert "New-SafeguardAccountPasswordRule creates a rule" {
            $rule = New-SafeguardAccountPasswordRule -Insecure $Context.SuiteData["RuleName"]
            $Context.SuiteData["RuleId"] = $rule.Id

            Register-SgPsTestCleanup -Description "Delete password rule" -Action {
                param($Ctx)
                try { Remove-SafeguardAccountPasswordRule -Insecure $Ctx.SuiteData['RuleId'] } catch {}
            }
            $rule.Name -eq $Context.SuiteData["RuleName"]
        }

        # --- Get-SafeguardAccountPasswordRule by ID ---
        Test-SgPsAssert "Get-SafeguardAccountPasswordRule by ID" {
            $rule = Get-SafeguardAccountPasswordRule -Insecure $Context.SuiteData["RuleId"]
            $rule.Name -eq $Context.SuiteData["RuleName"]
        }

        # --- Edit-SafeguardAccountPasswordRule ---
        Test-SgPsAssert "Edit-SafeguardAccountPasswordRule updates rule" {
            $updated = Edit-SafeguardAccountPasswordRule -Insecure `
                $Context.SuiteData["RuleId"] -Description "Updated password rule"
            $updated.Description -eq "Updated password rule"
        }

        # =========================================
        # Password Profiles
        # =========================================

        # --- Get-SafeguardPasswordProfile (list) ---
        Test-SgPsAssert "Get-SafeguardPasswordProfile lists profiles" {
            $profiles = Get-SafeguardPasswordProfile -Insecure
            $null -ne $profiles
        }

        # --- New-SafeguardPasswordProfile ---
        Test-SgPsAssert "New-SafeguardPasswordProfile creates a profile" {
            $profile = New-SafeguardPasswordProfile -Insecure `
                $Context.SuiteData["ProfileName"] `
                -PasswordRuleToSet $Context.SuiteData["RuleName"] `
                -CheckScheduleToSet $Context.SuiteData["CheckName"] `
                -ChangeScheduleToSet $Context.SuiteData["ChangeName"]
            $Context.SuiteData["ProfileId"] = $profile.Id

            Register-SgPsTestCleanup -Description "Delete password profile" -Action {
                param($Ctx)
                try { Remove-SafeguardPasswordProfile -Insecure $Ctx.SuiteData['ProfileId'] } catch {}
            }
            $profile.Name -eq $Context.SuiteData["ProfileName"]
        }

        # --- Get-SafeguardPasswordProfile by ID ---
        Test-SgPsAssert "Get-SafeguardPasswordProfile by ID" {
            $profile = Get-SafeguardPasswordProfile -Insecure $Context.SuiteData["ProfileId"]
            $profile.Name -eq $Context.SuiteData["ProfileName"]
        }

        # --- Get-SafeguardPasswordProfile by Name ---
        Test-SgPsAssert "Get-SafeguardPasswordProfile by Name" {
            $profile = Get-SafeguardPasswordProfile -Insecure $Context.SuiteData["ProfileName"]
            $profile.Id -eq $Context.SuiteData["ProfileId"]
        }

        # --- Edit-SafeguardPasswordProfile ---
        Test-SgPsAssert "Edit-SafeguardPasswordProfile updates description" {
            $updated = Edit-SafeguardPasswordProfile -Insecure `
                $Context.SuiteData["ProfileId"] -Description "Updated profile desc"
            $updated.Description -eq "Updated profile desc"
        }

        # --- New-SafeguardPasswordProfile (second, for delete) ---
        Test-SgPsAssert "New-SafeguardPasswordProfile second profile" {
            $profile2 = New-SafeguardPasswordProfile -Insecure `
                $Context.SuiteData["ProfileName2"] `
                -PasswordRuleToSet $Context.SuiteData["RuleName"] `
                -CheckScheduleToSet $Context.SuiteData["CheckName"] `
                -ChangeScheduleToSet $Context.SuiteData["ChangeName"]
            $Context.SuiteData["Profile2Id"] = $profile2.Id

            Register-SgPsTestCleanup -Description "Delete second password profile" -Action {
                param($Ctx)
                try { Remove-SafeguardPasswordProfile -Insecure $Ctx.SuiteData['Profile2Id'] } catch {}
            }
            $profile2.Name -eq $Context.SuiteData["ProfileName2"]
        }

        # --- Remove-SafeguardPasswordProfile ---
        Test-SgPsAssert "Remove-SafeguardPasswordProfile deletes a profile" {
            Remove-SafeguardPasswordProfile -Insecure $Context.SuiteData["Profile2Id"]
            $remaining = Get-SafeguardPasswordProfile -Insecure
            $list = @($remaining)
            -not ($list | Where-Object { $_.Id -eq $Context.SuiteData["Profile2Id"] })
        }

        # =========================================
        # Cleanup schedules and rules
        # =========================================

        # --- Remove-SafeguardPasswordChangeSchedule ---
        Test-SgPsAssert "Remove-SafeguardPasswordChangeSchedule deletes a schedule" {
            # First need to remove the profile that references this schedule
            Remove-SafeguardPasswordProfile -Insecure $Context.SuiteData["ProfileId"]
            Remove-SafeguardPasswordChangeSchedule -Insecure $Context.SuiteData["ChangeId"]
            $remaining = Get-SafeguardPasswordChangeSchedule -Insecure
            $list = @($remaining)
            -not ($list | Where-Object { $_.Id -eq $Context.SuiteData["ChangeId"] })
        }

        # --- Remove-SafeguardPasswordCheckSchedule ---
        Test-SgPsAssert "Remove-SafeguardPasswordCheckSchedule deletes a schedule" {
            Remove-SafeguardPasswordCheckSchedule -Insecure $Context.SuiteData["CheckId"]
            $remaining = Get-SafeguardPasswordCheckSchedule -Insecure
            $list = @($remaining)
            -not ($list | Where-Object { $_.Id -eq $Context.SuiteData["CheckId"] })
        }

        # --- Remove-SafeguardAccountPasswordRule ---
        Test-SgPsAssert "Remove-SafeguardAccountPasswordRule deletes a rule" {
            Remove-SafeguardAccountPasswordRule -Insecure $Context.SuiteData["RuleId"]
            $remaining = Get-SafeguardAccountPasswordRule -Insecure
            $list = @($remaining)
            -not ($list | Where-Object { $_.Id -eq $Context.SuiteData["RuleId"] })
        }
    }

    Cleanup = {
        param($Context)
    }
}
