@{
    Name        = "Account Discovery"
    Description = "Tests account discovery schedules, rules, asset assignment, and discovered accounts"
    Tags        = @("discovery", "assets")

    Setup = {
        param($Context)

        $prefix = $Context.TestPrefix
        $schedName = "${prefix}_DiscSched"
        $schedName2 = "${prefix}_DiscSched2"
        $schedNameCopy = "${prefix}_DiscSchedCopy"
        $schedNameRenamed = "${prefix}_DiscSchedRenamed"
        $assetName1 = "${prefix}_DiscAsset1"
        $assetName2 = "${prefix}_DiscAsset2"
        $assetName3 = "${prefix}_DiscAssetSched"

        # Pre-cleanup: discovery schedules
        try {
            $schedules = Get-SafeguardAccountDiscoverySchedule -Insecure
            @($schedules) | Where-Object { $_.Name -match $prefix } | ForEach-Object {
                try { Remove-SafeguardAccountDiscoverySchedule -Insecure $_.Id } catch {}
            }
        } catch {}

        # Pre-cleanup: assets
        Remove-SgPsStaleTestObject -Collection "Assets" -Name $assetName1
        Remove-SgPsStaleTestObject -Collection "Assets" -Name $assetName2
        Remove-SgPsStaleTestObject -Collection "Assets" -Name $assetName3
        Remove-SgPsStaleTestObject -Collection "Assets" -Name $schedNameRenamed

        $Context.SuiteData["SchedName"] = $schedName
        $Context.SuiteData["SchedName2"] = $schedName2
        $Context.SuiteData["SchedNameCopy"] = $schedNameCopy
        $Context.SuiteData["SchedNameRenamed"] = $schedNameRenamed
        $Context.SuiteData["AssetName1"] = $assetName1
        $Context.SuiteData["AssetName2"] = $assetName2
        $Context.SuiteData["AssetName3"] = $assetName3
    }

    Execute = {
        param($Context)

        $schedName = $Context.SuiteData["SchedName"]
        $schedName2 = $Context.SuiteData["SchedName2"]
        $schedNameCopy = $Context.SuiteData["SchedNameCopy"]
        $schedNameRenamed = $Context.SuiteData["SchedNameRenamed"]
        $assetName1 = $Context.SuiteData["AssetName1"]
        $assetName2 = $Context.SuiteData["AssetName2"]
        $assetName3 = $Context.SuiteData["AssetName3"]

        # =========================================
        # Discovery Schedule CRUD
        # =========================================

        # --- Get-SafeguardAccountDiscoverySchedule (list) ---
        Test-SgPsAssert "Get-SafeguardAccountDiscoverySchedule lists schedules" {
            $schedules = Get-SafeguardAccountDiscoverySchedule -Insecure
            $null -ne $schedules
        }

        # --- New-SafeguardAccountDiscoverySchedule ---
        Test-SgPsAssert "New-SafeguardAccountDiscoverySchedule creates a schedule" {
            $sched = New-SafeguardAccountDiscoverySchedule -Insecure $schedName -DiscoveryType Unix
            $Context.SuiteData["SchedId"] = $sched.Id

            Register-SgPsTestCleanup -Description "Delete discovery schedule $schedName" -Action {
                param($Ctx)
                try { Remove-SafeguardAccountDiscoverySchedule -Insecure $Ctx.SuiteData['SchedId'] } catch {}
            }

            $sched.Name -eq $schedName -and $null -ne $sched.Id
        }

        # --- New-SafeguardAccountDiscoverySchedule with description ---
        Test-SgPsAssert "New-SafeguardAccountDiscoverySchedule with description" {
            $sched2 = New-SafeguardAccountDiscoverySchedule -Insecure $schedName2 `
                -DiscoveryType Windows -Description "Test schedule for discovery"
            $Context.SuiteData["Sched2Id"] = $sched2.Id

            Register-SgPsTestCleanup -Description "Delete discovery schedule $schedName2" -Action {
                param($Ctx)
                try { Remove-SafeguardAccountDiscoverySchedule -Insecure $Ctx.SuiteData['Sched2Id'] } catch {}
            }

            $sched2.Name -eq $schedName2 -and
                $sched2.Description -eq "Test schedule for discovery"
        }

        # --- Get-SafeguardAccountDiscoverySchedule by ID ---
        Test-SgPsAssert "Get-SafeguardAccountDiscoverySchedule by ID" {
            $sched = Get-SafeguardAccountDiscoverySchedule -Insecure $Context.SuiteData["SchedId"]
            $sched.Name -eq $schedName -and $sched.Id -eq $Context.SuiteData["SchedId"]
        }

        # --- Get-SafeguardAccountDiscoverySchedule by Name ---
        Test-SgPsAssert "Get-SafeguardAccountDiscoverySchedule by Name" {
            $sched = Get-SafeguardAccountDiscoverySchedule -Insecure $schedName
            $sched.Id -eq $Context.SuiteData["SchedId"]
        }

        # --- Get-SafeguardAccountDiscoverySchedule with -Fields ---
        Test-SgPsAssert "Get-SafeguardAccountDiscoverySchedule with Fields" {
            $sched = Get-SafeguardAccountDiscoverySchedule -Insecure $Context.SuiteData["SchedId"] `
                -Fields "Id","Name"
            $sched.Id -eq $Context.SuiteData["SchedId"] -and
                $sched.Name -eq $schedName -and
                $null -eq $sched.Description
        }

        # --- Edit-SafeguardAccountDiscoverySchedule ---
        Test-SgPsAssert "Edit-SafeguardAccountDiscoverySchedule updates description" {
            $updated = Edit-SafeguardAccountDiscoverySchedule -Insecure `
                $Context.SuiteData["SchedId"] -Description "Edited description"
            $updated.Description -eq "Edited description"
        }
        Test-SgPsAssert "Edit-SafeguardAccountDiscoverySchedule persisted" {
            $readback = Get-SafeguardAccountDiscoverySchedule -Insecure $Context.SuiteData["SchedId"]
            $readback.Description -eq "Edited description" -and $readback.Name -eq $schedName
        }

        # --- Edit-SafeguardAccountDiscoverySchedule: ScheduleDiscoverServices ---
        Test-SgPsAssert "Edit-SafeguardAccountDiscoverySchedule sets ScheduleDiscoverServices" {
            $updated = Edit-SafeguardAccountDiscoverySchedule -Insecure `
                $Context.SuiteData["SchedId"] -ScheduleDiscoverServices
            $updated.ScheduleDiscoverServices -eq $true
        }
        Test-SgPsAssert "Edit-SafeguardAccountDiscoverySchedule ScheduleDiscoverServices persisted" {
            $readback = Get-SafeguardAccountDiscoverySchedule -Insecure $Context.SuiteData["SchedId"]
            $readback.ScheduleDiscoverServices -eq $true -and
                $readback.Description -eq "Edited description"
        }

        # --- Edit-SafeguardAccountDiscoverySchedule: AutoConfigureDependentSystems ---
        Test-SgPsAssert "Edit-SafeguardAccountDiscoverySchedule sets AutoConfigureDependentSystems" {
            $updated = Edit-SafeguardAccountDiscoverySchedule -Insecure `
                $Context.SuiteData["SchedId"] -AutoConfigureDependentSystems
            $updated.AutoConfigureDependentSystems -eq $true
        }
        Test-SgPsAssert "Edit-SafeguardAccountDiscoverySchedule AutoConfigureDependentSystems persisted" {
            $readback = Get-SafeguardAccountDiscoverySchedule -Insecure $Context.SuiteData["SchedId"]
            $readback.AutoConfigureDependentSystems -eq $true -and
                $readback.ScheduleDiscoverServices -eq $true
        }

        # --- Edit-SafeguardAccountDiscoverySchedule via pipeline ---
        Test-SgPsAssert "Edit-SafeguardAccountDiscoverySchedule via pipeline" {
            $sched = Get-SafeguardAccountDiscoverySchedule -Insecure $Context.SuiteData["SchedId"]
            $sched.Description = "Pipeline schedule edit"
            $edited = $sched | Edit-SafeguardAccountDiscoverySchedule -Insecure
            $edited.Description -eq "Pipeline schedule edit"
        }
        Test-SgPsAssert "Edit-SafeguardAccountDiscoverySchedule pipeline edit persisted" {
            $readback = Get-SafeguardAccountDiscoverySchedule -Insecure $Context.SuiteData["SchedId"]
            $readback.Description -eq "Pipeline schedule edit" -and
                $readback.AutoConfigureDependentSystems -eq $true
        }

        # --- Rename-SafeguardAccountDiscoverySchedule ---
        Test-SgPsAssert "Rename-SafeguardAccountDiscoverySchedule changes name" {
            $renamed = Rename-SafeguardAccountDiscoverySchedule -Insecure `
                $Context.SuiteData["SchedId"] -NewName $schedNameRenamed
            $renamed.Name -eq $schedNameRenamed
        }
        Test-SgPsAssert "Rename-SafeguardAccountDiscoverySchedule rename persisted" {
            $readback = Get-SafeguardAccountDiscoverySchedule -Insecure $Context.SuiteData["SchedId"]
            $readback.Name -eq $schedNameRenamed
        }
        # Rename back for later tests
        Test-SgPsAssert "Rename-SafeguardAccountDiscoverySchedule back to original" {
            $restored = Rename-SafeguardAccountDiscoverySchedule -Insecure `
                $Context.SuiteData["SchedId"] -NewName $schedName
            $restored.Name -eq $schedName
        }

        # --- Copy-SafeguardAccountDiscoverySchedule ---
        Test-SgPsAssert "Copy-SafeguardAccountDiscoverySchedule creates a copy" {
            $copy = Copy-SafeguardAccountDiscoverySchedule -Insecure `
                $Context.SuiteData["SchedId"] -CopyName $schedNameCopy
            $Context.SuiteData["SchedCopyId"] = $copy.Id

            Register-SgPsTestCleanup -Description "Delete copied schedule" -Action {
                param($Ctx)
                try { Remove-SafeguardAccountDiscoverySchedule -Insecure $Ctx.SuiteData['SchedCopyId'] } catch {}
            }

            $copy.Name -eq $schedNameCopy -and $copy.Id -ne $Context.SuiteData["SchedId"]
        }
        Test-SgPsAssert "Copy-SafeguardAccountDiscoverySchedule preserves description" {
            $copy = Get-SafeguardAccountDiscoverySchedule -Insecure $Context.SuiteData["SchedCopyId"]
            $copy.Description -eq "Pipeline schedule edit"
        }

        # --- Remove-SafeguardAccountDiscoverySchedule ---
        Test-SgPsAssert "Remove-SafeguardAccountDiscoverySchedule deletes second schedule" {
            Remove-SafeguardAccountDiscoverySchedule -Insecure $Context.SuiteData["Sched2Id"]
            $found = $false
            try {
                $null = Get-SafeguardAccountDiscoverySchedule -Insecure $Context.SuiteData["Sched2Id"]
                $found = $true
            } catch {}
            -not $found
        }

        # --- Error path: resolve invalid schedule name ---
        Test-SgPsAssert "Get-SafeguardAccountDiscoverySchedule throws for invalid name" {
            $threw = $false
            try {
                $null = Get-SafeguardAccountDiscoverySchedule -Insecure "NonExistent_Schedule_XYZ_999"
            } catch {
                $threw = $true
            }
            $threw
        }

        # =========================================
        # Discovery Schedule Asset Assignment
        # =========================================

        # Create test assets for assignment
        Test-SgPsAssert "Create test assets for schedule assignment" {
            $asset1 = New-SafeguardAsset -Insecure -DisplayName $assetName1 `
                -Platform 521 -NetworkAddress "10.99.0.1" `
                -ServiceAccountCredentialType "None" -NoSshHostKeyDiscovery
            $Context.SuiteData["Asset1Id"] = $asset1.Id

            Register-SgPsTestCleanup -Description "Delete asset $assetName1" -Action {
                param($Ctx)
                try { Remove-SafeguardAsset -Insecure $Ctx.SuiteData['Asset1Id'] } catch {}
            }

            $asset2 = New-SafeguardAsset -Insecure -DisplayName $assetName2 `
                -Platform 521 -NetworkAddress "10.99.0.2" `
                -ServiceAccountCredentialType "None" -NoSshHostKeyDiscovery
            $Context.SuiteData["Asset2Id"] = $asset2.Id

            Register-SgPsTestCleanup -Description "Delete asset $assetName2" -Action {
                param($Ctx)
                try { Remove-SafeguardAsset -Insecure $Ctx.SuiteData['Asset2Id'] } catch {}
            }

            $null -ne $asset1.Id -and $null -ne $asset2.Id
        }

        # --- Get-SafeguardAccountDiscoveryScheduleAsset (empty) ---
        Test-SgPsAssert "Get-SafeguardAccountDiscoveryScheduleAsset initially empty" {
            $assets = Get-SafeguardAccountDiscoveryScheduleAsset -Insecure `
                -Schedule $Context.SuiteData["SchedId"]
            @($assets).Count -eq 0
        }

        # --- Add-SafeguardAccountDiscoveryScheduleAsset (single) ---
        Test-SgPsAssert "Add-SafeguardAccountDiscoveryScheduleAsset adds one asset" {
            $result = Add-SafeguardAccountDiscoveryScheduleAsset -Insecure `
                -Schedule $Context.SuiteData["SchedId"] -AssetsToAdd $Context.SuiteData["Asset1Id"]
            $null -ne $result
        }
        Test-SgPsAssert "Add-SafeguardAccountDiscoveryScheduleAsset persisted (one asset)" {
            $assets = Get-SafeguardAccountDiscoveryScheduleAsset -Insecure `
                -Schedule $Context.SuiteData["SchedId"]
            $list = @($assets)
            $list.Count -eq 1 -and $list[0].Id -eq $Context.SuiteData["Asset1Id"]
        }

        # --- Add-SafeguardAccountDiscoveryScheduleAsset (another asset by name) ---
        Test-SgPsAssert "Add-SafeguardAccountDiscoveryScheduleAsset adds by name" {
            $result = Add-SafeguardAccountDiscoveryScheduleAsset -Insecure `
                -Schedule $schedName -AssetsToAdd $assetName2
            $null -ne $result
        }
        Test-SgPsAssert "Add-SafeguardAccountDiscoveryScheduleAsset now has two assets" {
            $assets = Get-SafeguardAccountDiscoveryScheduleAsset -Insecure `
                -Schedule $Context.SuiteData["SchedId"]
            @($assets).Count -eq 2
        }

        # --- Remove-SafeguardAccountDiscoveryScheduleAsset ---
        Test-SgPsAssert "Remove-SafeguardAccountDiscoveryScheduleAsset removes one asset" {
            $result = Remove-SafeguardAccountDiscoveryScheduleAsset -Insecure `
                -Schedule $Context.SuiteData["SchedId"] -AssetsToRemove $Context.SuiteData["Asset1Id"]
            $null -ne $result
        }
        Test-SgPsAssert "Remove-SafeguardAccountDiscoveryScheduleAsset only one remains" {
            $assets = Get-SafeguardAccountDiscoveryScheduleAsset -Insecure `
                -Schedule $Context.SuiteData["SchedId"]
            $list = @($assets)
            $list.Count -eq 1 -and $list[0].Id -eq $Context.SuiteData["Asset2Id"]
        }

        # --- Remove-SafeguardAccountDiscoveryScheduleAsset by name ---
        Test-SgPsAssert "Remove-SafeguardAccountDiscoveryScheduleAsset by name" {
            $result = Remove-SafeguardAccountDiscoveryScheduleAsset -Insecure `
                -Schedule $schedName -AssetsToRemove $assetName2
            $null -ne $result
        }
        Test-SgPsAssert "Remove-SafeguardAccountDiscoveryScheduleAsset schedule now empty" {
            $assets = Get-SafeguardAccountDiscoveryScheduleAsset -Insecure `
                -Schedule $Context.SuiteData["SchedId"]
            @($assets).Count -eq 0
        }

        # --- Multi-asset add in one call ---
        Test-SgPsAssert "Add-SafeguardAccountDiscoveryScheduleAsset adds multiple assets" {
            $result = Add-SafeguardAccountDiscoveryScheduleAsset -Insecure `
                -Schedule $Context.SuiteData["SchedId"] `
                -AssetsToAdd $Context.SuiteData["Asset1Id"],$Context.SuiteData["Asset2Id"]
            $null -ne $result
        }
        Test-SgPsAssert "Add-SafeguardAccountDiscoveryScheduleAsset multi-add persisted" {
            $assets = Get-SafeguardAccountDiscoveryScheduleAsset -Insecure `
                -Schedule $Context.SuiteData["SchedId"]
            @($assets).Count -eq 2
        }

        # --- Multi-asset remove ---
        Test-SgPsAssert "Remove-SafeguardAccountDiscoveryScheduleAsset removes multiple assets" {
            $result = Remove-SafeguardAccountDiscoveryScheduleAsset -Insecure `
                -Schedule $Context.SuiteData["SchedId"] `
                -AssetsToRemove $Context.SuiteData["Asset1Id"],$Context.SuiteData["Asset2Id"]
            $null -ne $result
        }
        Test-SgPsAssert "Remove-SafeguardAccountDiscoveryScheduleAsset multi-remove persisted" {
            $assets = Get-SafeguardAccountDiscoveryScheduleAsset -Insecure `
                -Schedule $Context.SuiteData["SchedId"]
            @($assets).Count -eq 0
        }

        # --- Get-SafeguardAccountDiscoveryScheduleAsset with -Fields ---
        Test-SgPsAssert "Get-SafeguardAccountDiscoveryScheduleAsset with Fields" {
            Add-SafeguardAccountDiscoveryScheduleAsset -Insecure `
                -Schedule $Context.SuiteData["SchedId"] -AssetsToAdd $Context.SuiteData["Asset1Id"] | Out-Null
            $assets = Get-SafeguardAccountDiscoveryScheduleAsset -Insecure `
                -Schedule $Context.SuiteData["SchedId"] -Fields "Id","Name"
            $list = @($assets)
            $list.Count -eq 1 -and $null -ne $list[0].Id -and $null -ne $list[0].Name
        }
        # Clean up for rule tests
        Remove-SafeguardAccountDiscoveryScheduleAsset -Insecure `
            -Schedule $Context.SuiteData["SchedId"] -AssetsToRemove $Context.SuiteData["Asset1Id"] | Out-Null

        # =========================================
        # Discovery Rules
        # =========================================

        # --- Get-SafeguardAccountDiscoveryRule (initially empty or defaults) ---
        Test-SgPsAssert "Get-SafeguardAccountDiscoveryRule returns rules list" {
            $rules = Get-SafeguardAccountDiscoveryRule -Insecure `
                -Schedule $Context.SuiteData["SchedId"]
            $null -ne $rules
        }

        # --- Rule Builder: Unix FindAll ---
        Test-SgPsAssert "New-SafeguardAccountDiscoveryRuleUnix creates FindAll rule" {
            $rule = New-SafeguardAccountDiscoveryRuleUnix -Name "UnixAll" -FindAll
            $rule -is [hashtable] -and
                $rule.Name -eq "UnixAll" -and
                $rule.UnixAccountDiscoveryProperties.RuleType -eq "FindAll"
        }

        # --- Rule Builder: Unix with filters ---
        Test-SgPsAssert "New-SafeguardAccountDiscoveryRuleUnix with filters" {
            $rule = New-SafeguardAccountDiscoveryRuleUnix -Name "UnixFiltered" `
                -NameFilter "svc_*" -GroupFilter "wheel" -UidFilter "1000-60000"
            $rule -is [hashtable] -and
                $rule.Name -eq "UnixFiltered" -and
                $rule.UnixAccountDiscoveryProperties.RuleType -eq "PropertyConstraint" -and
                $rule.UnixAccountDiscoveryProperties.PropertyConstraintProperties.NameFilter -eq "svc_*" -and
                $rule.UnixAccountDiscoveryProperties.PropertyConstraintProperties.GroupFilter -eq "wheel" -and
                $rule.UnixAccountDiscoveryProperties.PropertyConstraintProperties.UidFilter -contains "1000-60000"
        }

        # --- Rule Builder: Windows ---
        Test-SgPsAssert "New-SafeguardAccountDiscoveryRuleWindows creates rule" {
            $rule = New-SafeguardAccountDiscoveryRuleWindows -Name "WinAdmins" `
                -GroupFilter "Administrators"
            $rule -is [hashtable] -and
                $rule.Name -eq "WinAdmins" -and
                $rule.WindowsAccountDiscoveryProperties.RuleType -eq "PropertyConstraint" -and
                $rule.WindowsAccountDiscoveryProperties.PropertyConstraintProperties.GroupFilter -eq "Administrators"
        }

        # --- Rule Builder: Windows FindAll ---
        Test-SgPsAssert "New-SafeguardAccountDiscoveryRuleWindows FindAll" {
            $rule = New-SafeguardAccountDiscoveryRuleWindows -Name "WinAll" -FindAll
            $rule -is [hashtable] -and
                $rule.Name -eq "WinAll" -and
                $rule.WindowsAccountDiscoveryProperties.RuleType -eq "FindAll"
        }

        # --- Rule Builder: Directory (FindAll) ---
        Test-SgPsAssert "New-SafeguardAccountDiscoveryRuleDirectory FindAll" {
            $rule = New-SafeguardAccountDiscoveryRuleDirectory -Name "DirAll" -FindAll
            $rule -is [hashtable] -and
                $rule.Name -eq "DirAll" -and
                $rule.DirectoryAccountDiscoveryProperties.RuleType -eq "FindAll"
        }

        # --- Rule Builder: Directory (Name) ---
        Test-SgPsAssert "New-SafeguardAccountDiscoveryRuleDirectory with Name" {
            $rule = New-SafeguardAccountDiscoveryRuleDirectory -Name "DirName" `
                -SearchByName -SearchName "svc_" -SearchNameType "StartsWith" `
                -SearchBase "OU=ServiceAccounts,DC=corp,DC=local"
            $rule -is [hashtable] -and
                $rule.DirectoryAccountDiscoveryProperties.RuleType -eq "Name" -and
                $rule.DirectoryAccountDiscoveryProperties.SearchName -eq "svc_" -and
                $rule.DirectoryAccountDiscoveryProperties.SearchBase -eq "OU=ServiceAccounts,DC=corp,DC=local"
        }

        # --- Rule Builder: Directory (Group) ---
        Test-SgPsAssert "New-SafeguardAccountDiscoveryRuleDirectory with Group" {
            $rule = New-SafeguardAccountDiscoveryRuleDirectory -Name "DirGrp" `
                -SearchByGroup -Groups "CN=Domain Admins,CN=Users,DC=corp,DC=local"
            $rule -is [hashtable] -and
                $rule.DirectoryAccountDiscoveryProperties.RuleType -eq "Group" -and
                $rule.DirectoryAccountDiscoveryProperties.Groups -contains "CN=Domain Admins,CN=Users,DC=corp,DC=local"
        }

        # --- Rule Builder: Directory (LdapFilter) ---
        Test-SgPsAssert "New-SafeguardAccountDiscoveryRuleDirectory with LdapFilter" {
            $rule = New-SafeguardAccountDiscoveryRuleDirectory -Name "DirLdap" `
                -SearchByLdapFilter -LdapFilter "(servicePrincipalName=*)"
            $rule -is [hashtable] -and
                $rule.DirectoryAccountDiscoveryProperties.RuleType -eq "LdapFilter" -and
                $rule.DirectoryAccountDiscoveryProperties.LdapFilter -eq "(servicePrincipalName=*)"
        }

        # --- Rule Builder: SPS ---
        Test-SgPsAssert "New-SafeguardAccountDiscoveryRuleSps creates rule" {
            $rule = New-SafeguardAccountDiscoveryRuleSps -Name "SpsAll" -FindAll
            $rule -is [hashtable] -and
                $rule.Name -eq "SpsAll" -and
                $rule.SpsAccountDiscoveryProperties.RuleType -eq "FindAll"
        }

        # --- Rule Builder: SPS PropertyConstraint ---
        Test-SgPsAssert "New-SafeguardAccountDiscoveryRuleSps PropertyConstraint" {
            $rule = New-SafeguardAccountDiscoveryRuleSps -Name "SpsFiltered" `
                -NameFilter "admin" -GroupFilter "ops"
            $rule -is [hashtable] -and
                $rule.SpsAccountDiscoveryProperties.RuleType -eq "PropertyConstraint" -and
                $rule.SpsAccountDiscoveryProperties.PropertyConstraintProperties.NameFilter -eq "admin" -and
                $rule.SpsAccountDiscoveryProperties.PropertyConstraintProperties.GroupFilter -eq "ops"
        }

        # --- Rule Builder: StarlingConnect ---
        Test-SgPsAssert "New-SafeguardAccountDiscoveryRuleStarlingConnect creates rule" {
            $rule = New-SafeguardAccountDiscoveryRuleStarlingConnect -Name "ScRole" `
                -RoleFilter "admin"
            $rule -is [hashtable] -and
                $rule.Name -eq "ScRole" -and
                $rule.StarlingConnectAccountDiscoveryProperties.RuleType -eq "PropertyConstraint" -and
                $rule.StarlingConnectAccountDiscoveryProperties.PropertyConstraintProperties.RoleFilter -eq "admin"
        }

        # --- Rule Builder: StarlingConnect FindAll ---
        Test-SgPsAssert "New-SafeguardAccountDiscoveryRuleStarlingConnect FindAll" {
            $rule = New-SafeguardAccountDiscoveryRuleStarlingConnect -Name "ScAll" -FindAll
            $rule -is [hashtable] -and
                $rule.Name -eq "ScAll" -and
                $rule.StarlingConnectAccountDiscoveryProperties.RuleType -eq "FindAll"
        }

        # --- Rule Builder: RoleBased ---
        Test-SgPsAssert "New-SafeguardAccountDiscoveryRuleRoleBased creates rule" {
            $rule = New-SafeguardAccountDiscoveryRuleRoleBased -Name "RbRole" `
                -RoleFilter "DBA" -PermissionFilter "SELECT"
            $rule -is [hashtable] -and
                $rule.Name -eq "RbRole" -and
                $rule.RoleBasedAccountDiscoveryProperties.RuleType -eq "PropertyConstraint" -and
                $rule.RoleBasedAccountDiscoveryProperties.PropertyConstraintProperties.RoleFilter -eq "DBA" -and
                $rule.RoleBasedAccountDiscoveryProperties.PropertyConstraintProperties.PermissionFilter -eq "SELECT"
        }

        # --- Rule Builder: RoleBased FindAll ---
        Test-SgPsAssert "New-SafeguardAccountDiscoveryRuleRoleBased FindAll" {
            $rule = New-SafeguardAccountDiscoveryRuleRoleBased -Name "RbAll" -FindAll
            $rule -is [hashtable] -and
                $rule.Name -eq "RbAll" -and
                $rule.RoleBasedAccountDiscoveryProperties.RuleType -eq "FindAll"
        }

        # --- AutoManageDiscoveredAccounts on builder ---
        Test-SgPsAssert "Rule builder sets AutoManageDiscoveredAccounts" {
            $rule = New-SafeguardAccountDiscoveryRuleUnix -Name "AutoManaged" -FindAll `
                -AutoManageDiscoveredAccounts
            $rule.AutoManageDiscoveredAccounts -eq $true
        }
        Test-SgPsAssert "Rule builder defaults AutoManageDiscoveredAccounts to false" {
            $rule = New-SafeguardAccountDiscoveryRuleUnix -Name "NotAutoManaged" -FindAll
            $rule.AutoManageDiscoveredAccounts -eq $false
        }

        # --- Add-SafeguardAccountDiscoveryRule (simple with builder) ---
        Test-SgPsAssert "Add-SafeguardAccountDiscoveryRule adds a FindAll rule" {
            $rule = New-SafeguardAccountDiscoveryRuleUnix -Name "TestFindAll" -FindAll
            $result = Add-SafeguardAccountDiscoveryRule -Insecure `
                -Schedule $Context.SuiteData["SchedId"] -RuleObject $rule
            $null -ne $result
        }
        Test-SgPsAssert "Add-SafeguardAccountDiscoveryRule rule readback" {
            $rules = Get-SafeguardAccountDiscoveryRule -Insecure `
                -Schedule $Context.SuiteData["SchedId"]
            $list = @($rules)
            ($list | Where-Object { $_.Name -eq "TestFindAll" }) -ne $null
        }

        # --- Add-SafeguardAccountDiscoveryRule with builder object ---
        Test-SgPsAssert "Add-SafeguardAccountDiscoveryRule with RuleObject from builder" {
            $rule = New-SafeguardAccountDiscoveryRuleUnix -Name "UnixSvc" `
                -NameFilter "svc_*" -GroupFilter "wheel"
            $result = Add-SafeguardAccountDiscoveryRule -Insecure `
                -Schedule $Context.SuiteData["SchedId"] -RuleObject $rule
            $null -ne $result
        }
        Test-SgPsAssert "Add-SafeguardAccountDiscoveryRule both rules persisted" {
            $rules = Get-SafeguardAccountDiscoveryRule -Insecure `
                -Schedule $Context.SuiteData["SchedId"]
            $list = @($rules)
            $list.Count -ge 2 -and
                ($list | Where-Object { $_.Name -eq "UnixSvc" }) -ne $null
        }

        # --- Add-SafeguardAccountDiscoveryRule via pipeline ---
        Test-SgPsAssert "Add-SafeguardAccountDiscoveryRule via pipeline" {
            $rule = New-SafeguardAccountDiscoveryRuleUnix -Name "PipeRule" -FindAll
            $result = $rule | Add-SafeguardAccountDiscoveryRule -Insecure `
                -Schedule $Context.SuiteData["SchedId"]
            $null -ne $result
        }
        Test-SgPsAssert "Add-SafeguardAccountDiscoveryRule pipeline rule persisted" {
            $rules = Get-SafeguardAccountDiscoveryRule -Insecure `
                -Schedule $Context.SuiteData["SchedId"]
            $found = @($rules) | Where-Object { $_.Name -eq "PipeRule" }
            $null -ne $found
        }
        # Clean up pipeline rule
        try {
            Remove-SafeguardAccountDiscoveryRule -Insecure `
                -Schedule $Context.SuiteData["SchedId"] -RuleName "PipeRule"
        } catch {}

        # --- Remove-SafeguardAccountDiscoveryRule ---
        Test-SgPsAssert "Remove-SafeguardAccountDiscoveryRule removes a rule by name" {
            $result = Remove-SafeguardAccountDiscoveryRule -Insecure `
                -Schedule $Context.SuiteData["SchedId"] -RuleName "TestFindAll"
            $null -ne $result
        }
        Test-SgPsAssert "Remove-SafeguardAccountDiscoveryRule rule is gone" {
            $rules = Get-SafeguardAccountDiscoveryRule -Insecure `
                -Schedule $Context.SuiteData["SchedId"]
            $list = @($rules)
            -not ($list | Where-Object { $_.Name -eq "TestFindAll" })
        }

        # Remove the second rule -- verify it actually exists first
        Test-SgPsAssert "Remove-SafeguardAccountDiscoveryRule removes second rule" {
            $rules = Get-SafeguardAccountDiscoveryRule -Insecure `
                -Schedule $Context.SuiteData["SchedId"]
            $remaining = @($rules) | Where-Object { $_.Name -eq "UnixSvc" }
            if (-not $remaining) {
                # If not present, the Add/Remove API replaced rather than appended.
                # Document this by verifying schedule has zero rules now.
                @($rules).Count -eq 0
            } else {
                Remove-SafeguardAccountDiscoveryRule -Insecure `
                    -Schedule $Context.SuiteData["SchedId"] -RuleName "UnixSvc" | Out-Null
                $after = Get-SafeguardAccountDiscoveryRule -Insecure `
                    -Schedule $Context.SuiteData["SchedId"]
                -not (@($after) | Where-Object { $_.Name -eq "UnixSvc" })
            }
        }

        # --- Error path: remove non-existent rule ---
        Test-SgPsAssert "Remove-SafeguardAccountDiscoveryRule throws for missing rule" {
            $threw = $false
            try {
                Remove-SafeguardAccountDiscoveryRule -Insecure `
                    -Schedule $Context.SuiteData["SchedId"] -RuleName "NoSuchRule_XYZ"
            } catch {
                $threw = $_ -match "Unable to find"
            }
            $threw
        }

        # --- Add rule with AutoManageDiscoveredAccounts via API round-trip ---
        Test-SgPsAssert "Add-SafeguardAccountDiscoveryRule with AutoManage persists" {
            $rule = New-SafeguardAccountDiscoveryRuleUnix -Name "AutoManagedRule" -FindAll `
                -AutoManageDiscoveredAccounts
            Add-SafeguardAccountDiscoveryRule -Insecure `
                -Schedule $Context.SuiteData["SchedId"] -RuleObject $rule | Out-Null
            $rules = Get-SafeguardAccountDiscoveryRule -Insecure `
                -Schedule $Context.SuiteData["SchedId"]
            $found = @($rules) | Where-Object { $_.Name -eq "AutoManagedRule" }
            $result = $null -ne $found -and $found.AutoManageDiscoveredAccounts -eq $true
            # Clean up
            try {
                Remove-SafeguardAccountDiscoveryRule -Insecure `
                    -Schedule $Context.SuiteData["SchedId"] -RuleName "AutoManagedRule"
            } catch {}
            $result
        }

        # =========================================
        # New-SafeguardAsset with AccountDiscoverySchedule
        # =========================================

        Test-SgPsAssert "New-SafeguardAsset with AccountDiscoverySchedule by name" {
            $asset3 = New-SafeguardAsset -Insecure -DisplayName $assetName3 `
                -Platform 521 -NetworkAddress "10.99.0.3" `
                -ServiceAccountCredentialType "None" -NoSshHostKeyDiscovery `
                -AccountDiscoverySchedule $schedName
            $Context.SuiteData["Asset3Id"] = $asset3.Id

            Register-SgPsTestCleanup -Description "Delete asset $assetName3" -Action {
                param($Ctx)
                try { Remove-SafeguardAsset -Insecure $Ctx.SuiteData['Asset3Id'] } catch {}
            }

            $asset3.AccountDiscoveryScheduleId -eq $Context.SuiteData["SchedId"]
        }
        Test-SgPsAssert "New-SafeguardAsset AccountDiscoverySchedule persisted" {
            $readback = Get-SafeguardAsset -Insecure $Context.SuiteData["Asset3Id"]
            $readback.AccountDiscoveryScheduleId -eq $Context.SuiteData["SchedId"]
        }

        # =========================================
        # Edit-SafeguardAsset with AccountDiscoverySchedule
        # =========================================

        Test-SgPsAssert "Edit-SafeguardAsset with AccountDiscoverySchedule assigns schedule" {
            $updated = Edit-SafeguardAsset -Insecure $Context.SuiteData["Asset1Id"] `
                -AccountDiscoverySchedule $schedName
            $updated.AccountDiscoveryScheduleId -eq $Context.SuiteData["SchedId"]
        }
        Test-SgPsAssert "Edit-SafeguardAsset AccountDiscoverySchedule persisted" {
            $readback = Get-SafeguardAsset -Insecure $Context.SuiteData["Asset1Id"]
            $readback.AccountDiscoveryScheduleId -eq $Context.SuiteData["SchedId"]
        }

        # Assign via copy schedule to confirm by-ID also works
        Test-SgPsAssert "Edit-SafeguardAsset with AccountDiscoverySchedule by ID" {
            $updated = Edit-SafeguardAsset -Insecure $Context.SuiteData["Asset2Id"] `
                -AccountDiscoverySchedule $Context.SuiteData["SchedCopyId"]
            $updated.AccountDiscoveryScheduleId -eq $Context.SuiteData["SchedCopyId"]
        }

        # =========================================
        # Discovered Accounts
        # =========================================

        # These tests verify the cmdlets work correctly. Without real discovery
        # infrastructure the result sets may be empty, but we validate the
        # parameters, filtering logic, and error paths.

        Test-SgPsAssert "Get-SafeguardDiscoveredAccount returns array or empty" {
            $result = Get-SafeguardDiscoveredAccount -Insecure
            # Should return an array (possibly empty), not throw
            $result -is [array] -or $null -eq $result
        }

        Test-SgPsAssert "Get-SafeguardDiscoveredAccount with Asset filter returns array" {
            $result = Get-SafeguardDiscoveredAccount -Insecure `
                -Asset $Context.SuiteData["Asset1Id"]
            $result -is [array] -or $null -eq $result
        }

        Test-SgPsAssert "Get-SafeguardDiscoveredAccount default filter excludes Ignored" {
            # Call with -IncludeIgnored and without, verify the cmdlet itself doesn't throw
            # and that the non-ignored call works (the filter is Status ne 'Ignored')
            $withoutIgnored = Get-SafeguardDiscoveredAccount -Insecure `
                -Asset $Context.SuiteData["Asset1Id"]
            $withIgnored = Get-SafeguardDiscoveredAccount -Insecure `
                -Asset $Context.SuiteData["Asset1Id"] -IncludeIgnored
            # IncludeIgnored count should be >= non-ignored count
            @($withIgnored).Count -ge @($withoutIgnored).Count
        }

        Test-SgPsAssert "Get-SafeguardDiscoveredAccount with Filter and IncludeIgnored" {
            # Verify that -Filter and -IncludeIgnored can be combined without throwing
            $threw = $false
            try
            {
                $null = Get-SafeguardDiscoveredAccount -Insecure `
                    -Filter "Status eq 'None'" -IncludeIgnored
            }
            catch { $threw = $true }
            -not $threw
        }

        Test-SgPsAssert "Get-SafeguardDiscoveredAccount with Fields" {
            $result = Get-SafeguardDiscoveredAccount -Insecure `
                -Asset $Context.SuiteData["Asset1Id"] -Fields "Name","Status"
            # Should not throw; fields param should be passed through
            $result -is [array] -or $null -eq $result
        }

        # --- Import-SafeguardDiscoveredAccount: error path ---
        Test-SgPsAssert "Import-SafeguardDiscoveredAccount throws for non-existent account" {
            $threw = $false
            try {
                Import-SafeguardDiscoveredAccount -Insecure `
                    -Asset $Context.SuiteData["Asset1Id"] -AccountName "NoSuchAccount_XYZ_999"
            } catch {
                $threw = $true
            }
            $threw
        }

        # --- Set-SafeguardDiscoveredAccountStatus: error path ---
        Test-SgPsAssert "Set-SafeguardDiscoveredAccountStatus throws for non-existent account" {
            $threw = $false
            try {
                Set-SafeguardDiscoveredAccountStatus -Insecure `
                    -Asset $Context.SuiteData["Asset1Id"] -AccountName "NoSuchAccount_XYZ_999" `
                    -Action Ignore
            } catch {
                $threw = $true
            }
            $threw
        }

        # =========================================
        # Trigger cmdlets (verify they accept parameters, may fail on non-real asset)
        # =========================================

        Test-SgPsAssert "Invoke-SafeguardAssetAccountDiscovery invokes without hard failure" {
            # This will likely return an error about the asset not being properly
            # configured for discovery, but it should not throw a parse/parameter error
            $threw = $false
            try {
                $null = Invoke-SafeguardAssetAccountDiscovery -Insecure $Context.SuiteData["Asset1Id"]
            }
            catch {
                # Expected: asset is not configured for actual discovery
                # As long as it is an API error (not a cmdlet bug), this is fine
                if ($_ -match "parameter" -or $_ -match "not recognized") {
                    $threw = $true
                }
            }
            # Success = either it ran or got an expected API-level error
            -not $threw
        }

        Test-SgPsAssert "Invoke-SafeguardAssetServiceDiscovery invokes without hard failure" {
            $threw = $false
            try {
                $null = Invoke-SafeguardAssetServiceDiscovery -Insecure $Context.SuiteData["Asset1Id"]
            }
            catch {
                if ($_ -match "parameter" -or $_ -match "not recognized") {
                    $threw = $true
                }
            }
            -not $threw
        }

        # =========================================
        # Cleanup: Remove schedule with assigned assets (verify cascade)
        # =========================================

        Test-SgPsAssert "Remove-SafeguardAccountDiscoverySchedule with assigned assets" {
            # Must unassign asset from schedule before deleting the schedule
            $assetObj = Get-SafeguardAsset -Insecure $Context.SuiteData["Asset2Id"]
            $assetObj.AccountDiscoveryScheduleId = $null
            Edit-SafeguardAsset -Insecure -AssetObject $assetObj | Out-Null
            Remove-SafeguardAccountDiscoverySchedule -Insecure $Context.SuiteData["SchedCopyId"]
            $found = $false
            try {
                $null = Get-SafeguardAccountDiscoverySchedule -Insecure $Context.SuiteData["SchedCopyId"]
                $found = $true
            } catch {}
            -not $found
        }

        # Verify the asset no longer has a schedule
        Test-SgPsAssert "Asset schedule cleared after unassign and schedule deletion" {
            $readback = Get-SafeguardAsset -Insecure $Context.SuiteData["Asset2Id"]
            $null -eq $readback.AccountDiscoveryScheduleId -or $readback.AccountDiscoveryScheduleId -eq 0
        }
    }

    Cleanup = {
        param($Context)
        # Registered cleanups handle individual objects
    }
}
