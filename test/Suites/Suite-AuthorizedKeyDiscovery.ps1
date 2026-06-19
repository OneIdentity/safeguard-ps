@{
    Name        = "Authorized Key Discovery"
    Description = "Tests Invoke-SafeguardAssetAccountAuthorizedKeyDiscovery, including the SSH key profile prerequisite chain and the live discovery result-retrieval path"
    Tags        = @("assetaccounts", "sshkeys")

    Setup = {
        param($Context)

        $prefix = $Context.TestPrefix
        $checkName = "${prefix}_KeyDiscChkSched"
        $changeName = "${prefix}_KeyDiscChgSched"
        $discoveryName = "${prefix}_KeyDiscDiscSched"
        $profileName = "${prefix}_KeyDiscProfile"

        # Pre-cleanup any leftovers from a previous run
        try {
            @(Get-SafeguardSshKeyProfile -Insecure) | Where-Object { $_.Name -match $prefix } | ForEach-Object {
                try { Remove-SafeguardSshKeyProfile -Insecure $_.Id } catch {}
            }
        } catch {}
        foreach ($getter in @("Get-SafeguardSshKeyCheckSchedule", "Get-SafeguardSshKeyChangeSchedule", "Get-SafeguardSshKeyDiscoverySchedule")) {
            $remover = $getter -replace "^Get-", "Remove-"
            try {
                @(& $getter -Insecure) | Where-Object { $_.Name -match $prefix } | ForEach-Object {
                    try { & $remover -Insecure $_.Id } catch {}
                }
            } catch {}
        }

        $Context.SuiteData["CheckName"] = $checkName
        $Context.SuiteData["ChangeName"] = $changeName
        $Context.SuiteData["DiscoveryName"] = $discoveryName
        $Context.SuiteData["ProfileName"] = $profileName

        # The live discovery test needs an account on a reachable, discovery-capable asset.
        # That cannot be provisioned generically, so resolve it from an environment variable
        # (SGPS_KEYDISCOVERY_ACCOUNT, an account Id or name) or auto-detect an account that
        # already has discovered SSH keys recorded. When neither is available, skip the live
        # portion rather than fail.
        $Context.SuiteData["TargetAccountId"] = $null
        $Context.SuiteData["TargetAccount"] = $null
        try {
            $target = $env:SGPS_KEYDISCOVERY_ACCOUNT
            $acct = $null
            if ($target) {
                if ($target -match '^\d+$') {
                    $acct = Invoke-SafeguardMethod -Insecure Core GET "AssetAccounts/$target"
                }
                else {
                    $acct = Get-SafeguardAssetAccount -Insecure -AccountToGet $target
                }
            }
            else {
                foreach ($candidate in @(Get-SafeguardAssetAccount -Insecure)) {
                    try {
                        $keys = Invoke-SafeguardMethod -Insecure Core GET "AssetAccounts/$($candidate.Id)/DiscoveredSshKeys"
                        if (@($keys).Count -gt 0) { $acct = $candidate; break }
                    } catch {}
                }
            }
            if ($acct) {
                $acct = @($acct)[0]
                $Context.SuiteData["TargetAccount"] = $acct
                $Context.SuiteData["TargetAccountId"] = $acct.Id
            }
        } catch {}
    }

    Execute = {
        param($Context)

        # =========================================
        # Cmdlet surface
        # =========================================

        Test-SgPsAssert "Invoke-SafeguardAssetAccountAuthorizedKeyDiscovery is available" {
            $null -ne (Get-Command Invoke-SafeguardAssetAccountAuthorizedKeyDiscovery -ErrorAction SilentlyContinue)
        }

        Test-SgPsAssert "Discovery cmdlet exposes an integer -Timeout parameter" {
            $cmd = Get-Command Invoke-SafeguardAssetAccountAuthorizedKeyDiscovery
            $cmd.Parameters.ContainsKey("Timeout") -and $cmd.Parameters["Timeout"].ParameterType -eq [int]
        }

        Test-SgPsAssert "Discovery cmdlet binds AccountToUse from the pipeline" {
            $cmd = Get-Command Invoke-SafeguardAssetAccountAuthorizedKeyDiscovery
            $attrs = $cmd.Parameters["AccountToUse"].Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] }
            ($attrs.ValueFromPipeline -contains $true) -or ($attrs.ValueFromPipelineByPropertyName -contains $true)
        }

        # =========================================
        # SSH key profile prerequisite chain
        # (an account must have a profile wired before discovery is accepted)
        # =========================================

        Test-SgPsAssert "Create SSH key check schedule" {
            $sched = New-SafeguardSshKeyCheckSchedule -Insecure $Context.SuiteData["CheckName"]
            $Context.SuiteData["CheckId"] = $sched.Id
            Register-SgPsTestCleanup -Description "Delete key-discovery check schedule" -Action {
                param($Ctx)
                try { Remove-SafeguardSshKeyCheckSchedule -Insecure $Ctx.SuiteData["CheckId"] } catch {}
            }
            $sched.Name -eq $Context.SuiteData["CheckName"]
        }

        Test-SgPsAssert "Create SSH key change schedule" {
            $sched = New-SafeguardSshKeyChangeSchedule -Insecure $Context.SuiteData["ChangeName"]
            $Context.SuiteData["ChangeId"] = $sched.Id
            Register-SgPsTestCleanup -Description "Delete key-discovery change schedule" -Action {
                param($Ctx)
                try { Remove-SafeguardSshKeyChangeSchedule -Insecure $Ctx.SuiteData["ChangeId"] } catch {}
            }
            $sched.Name -eq $Context.SuiteData["ChangeName"]
        }

        Test-SgPsAssert "Create SSH key discovery schedule" {
            $sched = New-SafeguardSshKeyDiscoverySchedule -Insecure $Context.SuiteData["DiscoveryName"]
            $Context.SuiteData["DiscoveryId"] = $sched.Id
            Register-SgPsTestCleanup -Description "Delete key-discovery discovery schedule" -Action {
                param($Ctx)
                try { Remove-SafeguardSshKeyDiscoverySchedule -Insecure $Ctx.SuiteData["DiscoveryId"] } catch {}
            }
            $sched.Name -eq $Context.SuiteData["DiscoveryName"]
        }

        Test-SgPsAssert "Create SSH key profile wired with check, change, and discovery schedules" {
            $sshProfile = New-SafeguardSshKeyProfile -Insecure `
                $Context.SuiteData["ProfileName"] `
                -CheckScheduleToSet $Context.SuiteData["CheckName"] `
                -ChangeScheduleToSet $Context.SuiteData["ChangeName"] `
                -DiscoveryScheduleToSet $Context.SuiteData["DiscoveryName"]
            $Context.SuiteData["ProfileId"] = $sshProfile.Id
            Register-SgPsTestCleanup -Description "Delete key-discovery SSH key profile" -Action {
                param($Ctx)
                try { Remove-SafeguardSshKeyProfile -Insecure $Ctx.SuiteData["ProfileId"] } catch {}
            }
            $sshProfile.Name -eq $Context.SuiteData["ProfileName"]
        }

        Test-SgPsAssert "Profile readback reports the wired discovery schedule" {
            $readback = Get-SafeguardSshKeyProfile -Insecure $Context.SuiteData["ProfileId"]
            $readback.DiscoveryScheduleId -eq $Context.SuiteData["DiscoveryId"]
        }

        # =========================================
        # Negative path -- does not require a reachable target
        # =========================================

        Test-SgPsAssertThrows "Discovery against a non-existent account fails" {
            Invoke-SafeguardAssetAccountAuthorizedKeyDiscovery -Insecure -AccountToUse 999999999
        }

        # =========================================
        # Live discovery result-retrieval path
        # (regression guard: results come from AssetAccounts/{id}/DiscoveredSshKeys,
        #  not the Passwords audit log that the long-running-task Location header points at)
        # =========================================

        $targetId = $Context.SuiteData["TargetAccountId"]
        if ($targetId) {
            Test-SgPsAssert "Discovery returns the keys recorded on the account" {
                $result = Invoke-SafeguardAssetAccountAuthorizedKeyDiscovery -Insecure -AccountToUse $targetId
                $direct = Invoke-SafeguardMethod -Insecure Core GET "AssetAccounts/$targetId/DiscoveredSshKeys"
                @($result).Count -eq @($direct).Count
            }

            Test-SgPsAssert "Discovery accepts the account from the pipeline" {
                $result = $Context.SuiteData["TargetAccount"] | Invoke-SafeguardAssetAccountAuthorizedKeyDiscovery -Insecure
                $direct = Invoke-SafeguardMethod -Insecure Core GET "AssetAccounts/$targetId/DiscoveredSshKeys"
                @($result).Count -eq @($direct).Count
            }
        }
        else {
            Test-SgPsSkip "Discovery returns the keys recorded on the account" "No reachable discovery target (set SGPS_KEYDISCOVERY_ACCOUNT)"
            Test-SgPsSkip "Discovery accepts the account from the pipeline" "No reachable discovery target (set SGPS_KEYDISCOVERY_ACCOUNT)"
        }
    }

    Cleanup = {
        param($Context)
    }
}
