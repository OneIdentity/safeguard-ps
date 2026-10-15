@{
    Name        = "Access Policies"
    Description = "Tests access policy CRUD, scope items, and properties"
    Tags        = @("policies", "access")

    Setup = {
        param($Context)

        $prefix = $Context.TestPrefix
        $testEntitlement = "${prefix}_PolEntl"
        $testPolicy = "${prefix}_Policy1"
        $testPolicy2 = "${prefix}_Policy2"
        $testAsset = "${prefix}_PolAsset"
        $testAccount = "${prefix}_PolAcct"
        $testUser = "${prefix}_PolUser"
        $testAccountGroup = "${prefix}_PolAcctGrp"

        # Pre-cleanup
        Remove-SgPsStaleTestObject -Collection "Roles" -Name $testEntitlement
        Remove-SgPsStaleTestObject -Collection "AccountGroups" -Name $testAccountGroup
        Remove-SgPsStaleTestObject -Collection "AssetAccounts" -Name $testAccount
        Remove-SgPsStaleTestObject -Collection "Assets" -Name $testAsset
        Remove-SgPsStaleTestObject -Collection "Users" -Name $testUser

        $Context.SuiteData["TestPolicy"] = $testPolicy
        $Context.SuiteData["TestPolicy2"] = $testPolicy2

        # Create prerequisite objects: user, asset, account, account group, entitlement
        $secPwd = ConvertTo-SecureString "Pol1234!xyzABC" -AsPlainText -Force
        $user = New-SafeguardUser -Insecure -Provider -1 -NewUserName $testUser -Password $secPwd
        $Context.SuiteData["UserId"] = $user.Id

        $asset = New-SafeguardAsset -Insecure -DisplayName $testAsset `
            -Platform 521 -NetworkAddress "10.0.5.100" `
            -ServiceAccountCredentialType "None" -NoSshHostKeyDiscovery
        $Context.SuiteData["AssetId"] = $asset.Id
        $Context.SuiteData["TestAsset"] = $testAsset

        $account = New-SafeguardAssetAccount -Insecure -ParentAsset $asset.Id -NewAccountName $testAccount
        $Context.SuiteData["AccountId"] = $account.Id
        $Context.SuiteData["TestAccount"] = $testAccount

        $acctGroup = New-SafeguardAccountGroup -Insecure $testAccountGroup
        $Context.SuiteData["AccountGroupId"] = $acctGroup.Id
        $acctRef = "${testAsset}\${testAccount}"
        Add-SafeguardAccountGroupMember -Insecure $testAccountGroup -AccountList $acctRef

        # Create entitlement with the user as a member
        $entl = New-SafeguardEntitlement -Insecure $testEntitlement -MemberUsers $testUser
        $Context.SuiteData["EntitlementId"] = $entl.Id
        $Context.SuiteData["TestEntitlement"] = $testEntitlement

        # Register cleanup in reverse dependency order
        Register-SgPsTestCleanup -Description "Delete policy entitlement" -Action {
            param($Ctx)
            try { Remove-SafeguardEntitlement -Insecure $Ctx.SuiteData['EntitlementId'] } catch {}
        }
        Register-SgPsTestCleanup -Description "Delete policy account group" -Action {
            param($Ctx)
            try { Remove-SafeguardAccountGroup -Insecure $Ctx.SuiteData['AccountGroupId'] } catch {}
        }
        Register-SgPsTestCleanup -Description "Delete policy account" -Action {
            param($Ctx)
            try { Remove-SafeguardAssetAccount -Insecure $Ctx.SuiteData['AssetId'] $Ctx.SuiteData['AccountId'] } catch {}
        }
        Register-SgPsTestCleanup -Description "Delete policy asset" -Action {
            param($Ctx)
            try { Remove-SafeguardAsset -Insecure $Ctx.SuiteData['AssetId'] } catch {}
        }
        Register-SgPsTestCleanup -Description "Delete policy user" -Action {
            param($Ctx)
            try { Remove-SafeguardUser -Insecure $Ctx.SuiteData['UserId'] } catch {}
        }

        # --- Fixtures for copying access policies ---
        $copySrcA = "${prefix}_CopySrcA"
        $copySrcB = "${prefix}_CopySrcB"
        $copyTarget = "${prefix}_CopyTarget"
        $copyNewEntl = "${prefix}_CopyNewEntl"
        $copyNewEntlBad = "${prefix}_CopyNewEntlBad"
        $copyNewEntlPartial = "${prefix}_CopyNewEntlPartial"
        $copyReason = "${prefix}_CopyReason"
        $copyApprovers = "${prefix}_CopyApprovers"
        $copyEmptied = "${prefix}_CopyEmptied"
        foreach ($name in @($copySrcA, $copySrcB, $copyTarget, $copyNewEntl, $copyNewEntlBad, $copyNewEntlPartial)) {
            Remove-SgPsStaleTestObject -Collection "AccessPolicies" -Name $name
            Remove-SgPsStaleTestObject -Collection "Roles" -Name $name
        }
        Remove-SgPsStaleTestObject -Collection "ReasonCodes" -Name $copyReason
        Remove-SgPsStaleTestObject -Collection "UserGroups" -Name $copyApprovers
        Remove-SgPsStaleTestObject -Collection "UserGroups" -Name $copyEmptied

        $Context.SuiteData["CopyRoleIds"] = [System.Collections.Generic.List[int]]::new()
        $Context.SuiteData["CopyNames"] = @{
            SrcA = $copySrcA; SrcB = $copySrcB; Target = $copyTarget
            NewEntl = $copyNewEntl; NewEntlBad = $copyNewEntlBad; NewEntlPartial = $copyNewEntlPartial
            Rich = "${prefix}_CopyRich"; Session = "${prefix}_CopySession"; Fails = "${prefix}_CopyFails"
        }

        # Deletes every policy in each entitlement created for copy tests, then the entitlements,
        # then the supporting reason code and groups.
        Register-SgPsTestCleanup -Description "Delete copy-test reason code and groups" -Action {
            param($Ctx)
            foreach ($key in @('CopyReasonId', 'CopyApproversId', 'CopyEmptiedId')) {
                if ($Ctx.SuiteData[$key]) {
                    $path = if ($key -eq 'CopyReasonId') { "ReasonCodes" } else { "UserGroups" }
                    try { Invoke-SafeguardMethod -Insecure Core DELETE "$path/$($Ctx.SuiteData[$key])" | Out-Null } catch {}
                }
            }
        }
        Register-SgPsTestCleanup -Description "Delete copy-test policies and entitlements" -Action {
            param($Ctx)
            foreach ($roleId in @($Ctx.SuiteData['CopyRoleIds'])) {
                try {
                    $policies = @(Invoke-SafeguardMethod -Insecure Core GET AccessPolicies -Parameters @{ filter = "RoleId eq $roleId"; fields = "Id" })
                    foreach ($p in $policies) { if ($p.Id) { try { Invoke-SafeguardMethod -Insecure Core DELETE "AccessPolicies/$($p.Id)" | Out-Null } catch {} } }
                } catch {}
                try { Invoke-SafeguardMethod -Insecure Core DELETE "Roles/$roleId" | Out-Null } catch {}
            }
        }

        foreach ($key in @('SrcA', 'SrcB', 'Target')) {
            $role = New-SafeguardEntitlement -Insecure $Context.SuiteData["CopyNames"][$key]
            $Context.SuiteData["CopyRoleIds"].Add([int]$role.Id)
            $Context.SuiteData["Copy${key}Id"] = $role.Id
        }

        $reason = Invoke-SafeguardMethod -Insecure Core POST ReasonCodes -Body @{ Name = $copyReason; Description = "Reason for copy tests" }
        $Context.SuiteData["CopyReasonId"] = $reason.Id
        $approvers = New-SafeguardUserGroup -Insecure $copyApprovers
        $Context.SuiteData["CopyApproversId"] = $approvers.Id
        $emptied = New-SafeguardUserGroup -Insecure $copyEmptied
        $Context.SuiteData["CopyEmptiedId"] = $emptied.Id
        Invoke-SafeguardMethod -Insecure Core POST "UserGroups/$($emptied.Id)/Members/Add" -JsonBody "[{`"Id`":$($user.Id)}]" | Out-Null

        # A policy that touches every writable area, including nested approver/reviewer/scope objects.
        $rich = @{
            Name = $Context.SuiteData["CopyNames"]["Rich"]; Description = "Rich policy for copy tests"; RoleId = $Context.SuiteData["CopySrcAId"]
            ExpirationDate = (Get-Date).ToUniversalTime().Date.AddDays(60).ToString("yyyy-MM-ddTHH:mm:ssZ")
            RequesterProperties = @{ DefaultReleaseDurationDays = 0; DefaultReleaseDurationHours = 3; DefaultReleaseDurationMinutes = 15
                                     MaximumReleaseDurationDays = 1; MaximumReleaseDurationHours = 2; MaximumReleaseDurationMinutes = 30
                                     AllowCustomDuration = $true; RequireReasonCode = $true; RequireReasonComment = $true; RequireServiceTicket = $false }
            ApproverProperties = @{ RequireApproval = $true; PendingApprovalEscalationEnabled = $true
                                    PendingApprovalDurationBeforeEscalationDays = 0; PendingApprovalDurationBeforeEscalationHours = 4; PendingApprovalDurationBeforeEscalationMinutes = 0 }
            ReviewerProperties = @{ RequiredReviewers = 1; RequireReviewerComment = $true; AllowSubsequentAccessRequestsWithoutReview = $false
                                    PendingReviewEscalationEnabled = $true; PendingReviewDurationBeforeEscalationDays = 1; PendingReviewDurationBeforeEscalationHours = 0; PendingReviewDurationBeforeEscalationMinutes = 0 }
            AccessRequestProperties = @{ AccessRequestType = "Password"; AllowSimultaneousAccess = $true; MaximumSimultaneousReleases = 3; ChangePasswordAfterCheckin = $false }
            EmergencyAccessProperties = @{ AllowEmergencyAccess = $true; IgnoreHourlyRestrictions = $true }
            HourlyRestrictionProperties = @{ EnableHourlyRestrictions = $true; MondayValidHours = @(8, 9, 10, 11); TuesdayValidHours = @(13, 14); WednesdayValidHours = @()
                                             ThursdayValidHours = @(); FridayValidHours = @(1); SaturdayValidHours = @(); SundayValidHours = @() }
            ApproverSets = @(@{ RequiredApprovers = 1; Approvers = @(@{ Id = $user.Id; PrincipalKind = "User" }, @{ Id = $approvers.Id; PrincipalKind = "Group" }) })
            Reviewers = @(@{ Id = $user.Id; PrincipalKind = "User" })
            NotificationContacts = @(@{ ContactType = "ApprovalEscalation"; ContactAddress = "copytest@example.com" })
            ReasonCodes = @(@{ Id = $reason.Id; Name = $reason.Name; Description = $reason.Description })
            ScopeItems = @(@{ Id = $account.Id; ScopeItemType = "Account" }, @{ Id = $acctGroup.Id; ScopeItemType = "AccountGroup" }, @{ Id = $asset.Id; ScopeItemType = "Asset" })
        }
        $Context.SuiteData["CopyRichId"] = (Invoke-SafeguardMethod -Insecure Core POST AccessPolicies -Body $rich).Id

        $session = @{
            Name = $Context.SuiteData["CopyNames"]["Session"]; RoleId = $Context.SuiteData["CopySrcAId"]
            AccessRequestProperties = @{ AccessRequestType = "Ssh"; SessionAccessAccountType = "UserSupplied" }
            SessionProperties = @{ RdpShowWallpaper = $false }
            ApproverProperties = @{ RequireApproval = $false }
            ScopeItems = @(@{ Id = $asset.Id; ScopeItemType = "Asset" })
        }
        $Context.SuiteData["CopySessionId"] = (Invoke-SafeguardMethod -Insecure Core POST AccessPolicies -Body $session).Id

        # Same name as the rich policy except for case, in a different entitlement. Names are
        # case-insensitive, so this makes the rich policy name ambiguous.
        $Context.SuiteData["CopyRichBId"] = (Invoke-SafeguardMethod -Insecure Core POST AccessPolicies -Body @{
            Name = $Context.SuiteData["CopyNames"]["Rich"].ToUpperInvariant(); RoleId = $Context.SuiteData["CopySrcBId"]
            AccessRequestProperties = @{ AccessRequestType = "Password" }; ApproverProperties = @{ RequireApproval = $false }
        }).Id

        # Valid when created, but its only reviewer group is emptied afterwards, so the appliance
        # rejects any copy of it. This drives the partial-failure tests.
        $Context.SuiteData["CopyFailsId"] = (Invoke-SafeguardMethod -Insecure Core POST AccessPolicies -Body @{
            Name = $Context.SuiteData["CopyNames"]["Fails"]; RoleId = $Context.SuiteData["CopySrcAId"]
            AccessRequestProperties = @{ AccessRequestType = "Password" }; ApproverProperties = @{ RequireApproval = $false }
            ReviewerProperties = @{ RequiredReviewers = 1 }; Reviewers = @(@{ Id = $emptied.Id; PrincipalKind = "Group" })
        }).Id
        Invoke-SafeguardMethod -Insecure Core POST "UserGroups/$($emptied.Id)/Members/Remove" -JsonBody "[{`"Id`":$($user.Id)}]" | Out-Null
    }

    Execute = {
        param($Context)

        $testPolicy = $Context.SuiteData["TestPolicy"]
        $testPolicy2 = $Context.SuiteData["TestPolicy2"]

        # --- Get-SafeguardAccessPolicy (list) ---
        Test-SgPsAssert "Get-SafeguardAccessPolicy lists policies" {
            $policies = Get-SafeguardAccessPolicy -Insecure
            $null -ne $policies
        }

        # --- Add-SafeguardAccessPolicy ---
        Test-SgPsAssert "Add-SafeguardAccessPolicy creates a policy" {
            $acctRef = "$($Context.SuiteData['TestAsset'])\$($Context.SuiteData['TestAccount'])"
            $policy = Add-SafeguardAccessPolicy -Insecure `
                -Entitlement $Context.SuiteData["TestEntitlement"] `
                -Name $testPolicy `
                -AccessRequestType "Password" `
                -ScopeAccounts $acctRef
            $Context.SuiteData["PolicyId"] = $policy.Id

            Register-SgPsTestCleanup -Description "Delete policy $testPolicy" -Action {
                param($Ctx)
                try { Remove-SafeguardAccessPolicy -Insecure $Ctx.SuiteData['PolicyId'] } catch {}
            }
            $policy.Name -eq $testPolicy
        }

        # --- Get-SafeguardAccessPolicy by ID ---
        Test-SgPsAssert "Get-SafeguardAccessPolicy by ID" {
            $policy = Get-SafeguardAccessPolicy -Insecure -PolicyToGet $Context.SuiteData["PolicyId"]
            $policy.Name -eq $testPolicy
        }

        # --- Get-SafeguardAccessPolicy by entitlement ---
        Test-SgPsAssert "Get-SafeguardAccessPolicy by entitlement" {
            $policies = Get-SafeguardAccessPolicy -Insecure -EntitlementToGet $Context.SuiteData["EntitlementId"]
            $list = @($policies)
            $list.Count -ge 1 -and ($list | Where-Object { $_.Id -eq $Context.SuiteData["PolicyId"] })
        }

        # --- Get-SafeguardAccessPolicy with Fields ---
        Test-SgPsAssert "Get-SafeguardAccessPolicy with Fields" {
            $policy = Get-SafeguardAccessPolicy -Insecure -PolicyToGet $Context.SuiteData["PolicyId"] -Fields "Id","Name","AccessRequestProperties"
            $null -ne $policy.Id -and $null -ne $policy.Name
        }

        # --- Edit-SafeguardAccessPolicy (description) ---
        Test-SgPsAssert "Edit-SafeguardAccessPolicy updates description" {
            $updated = Edit-SafeguardAccessPolicy -Insecure -PolicyToEdit $Context.SuiteData["PolicyId"] -Description "Updated policy"
            $updated.Description -eq "Updated policy"
        }

        # --- Edit-SafeguardAccessPolicy with NoApproval ---
        Test-SgPsAssert "Edit-SafeguardAccessPolicy sets NoApproval" {
            $updated = Edit-SafeguardAccessPolicy -Insecure -PolicyToEdit $Context.SuiteData["PolicyId"] -NoApproval
            $updated.ApproverProperties.RequireApproval -eq $false
        }

        # --- Edit-SafeguardAccessPolicy with object ---
        Test-SgPsAssert "Edit-SafeguardAccessPolicy with object" {
            $policy = Get-SafeguardAccessPolicy -Insecure -PolicyToGet $Context.SuiteData["PolicyId"]
            $policy | Add-Member -NotePropertyName Description -NotePropertyValue "Modified via object" -Force
            $updated = Edit-SafeguardAccessPolicy -Insecure -AccessPolicyObject $policy
            $updated.Description -eq "Modified via object"
        }
        Test-SgPsAssert "Edit-SafeguardAccessPolicy changes persisted" {
            $readback = Get-SafeguardAccessPolicy -Insecure -PolicyToGet $Context.SuiteData["PolicyId"]
            $readback.Description -eq "Modified via object" -and $readback.ApproverProperties.RequireApproval -eq $false
        }

        # --- Get-SafeguardAccessPolicyScopeItem ---
        Test-SgPsAssert "Get-SafeguardAccessPolicyScopeItem lists scope" {
            $items = Get-SafeguardAccessPolicyScopeItem -Insecure $Context.SuiteData["PolicyId"]
            $list = @($items)
            $list.Count -ge 1
        }

        # --- Get-SafeguardAccessPolicyAccessRequestProperty ---
        Test-SgPsAssert "Get-SafeguardAccessPolicyAccessRequestProperty returns properties" {
            $props = Get-SafeguardAccessPolicyAccessRequestProperty -Insecure $Context.SuiteData["PolicyId"]
            $null -ne $props
        }

        # --- Get-SafeguardPolicyAsset ---
        Test-SgPsAssert "Get-SafeguardPolicyAsset lists policy-accessible assets" {
            $assets = Get-SafeguardPolicyAsset -Insecure
            $null -ne $assets
        }

        # --- Get-SafeguardPolicyAccount ---
        Test-SgPsAssert "Get-SafeguardPolicyAccount lists policy-accessible accounts" {
            $accounts = Get-SafeguardPolicyAccount -Insecure
            $null -ne $accounts
        }

        # --- Add-SafeguardAccessPolicy (second, for remove test) ---
        Test-SgPsAssert "Add-SafeguardAccessPolicy second policy" {
            $policy2 = Add-SafeguardAccessPolicy -Insecure `
                -Entitlement $Context.SuiteData["TestEntitlement"] `
                -Name $testPolicy2 `
                -AccessRequestType "Password" `
                -ScopeAccountGroups $Context.SuiteData["AccountGroupId"]
            $Context.SuiteData["Policy2Id"] = $policy2.Id

            Register-SgPsTestCleanup -Description "Delete policy $testPolicy2" -Action {
                param($Ctx)
                try { Remove-SafeguardAccessPolicy -Insecure $Ctx.SuiteData['Policy2Id'] } catch {}
            }
            $policy2.Name -eq $testPolicy2
        }

        # --- Remove-SafeguardAccessPolicy ---
        Test-SgPsAssert "Remove-SafeguardAccessPolicy deletes a policy" {
            Remove-SafeguardAccessPolicy -Insecure $Context.SuiteData["Policy2Id"]
            $remaining = Get-SafeguardAccessPolicy -Insecure -EntitlementToGet $Context.SuiteData["EntitlementId"]
            $list = @($remaining)
            -not ($list | Where-Object { $_.Id -eq $Context.SuiteData["Policy2Id"] })
        }

        # ====================================================================
        # Copy-SafeguardAccessPolicy and New-SafeguardEntitlement -CopyAccessPolicy
        # ====================================================================
        $names = $Context.SuiteData["CopyNames"]
        $richId = $Context.SuiteData["CopyRichId"]
        $sessionId = $Context.SuiteData["CopySessionId"]
        $failsId = $Context.SuiteData["CopyFailsId"]
        $srcAId = $Context.SuiteData["CopySrcAId"]
        $targetId = $Context.SuiteData["CopyTargetId"]
        $subCollections = @("ApproverSets", "Reviewers", "NotificationContacts", "ReasonCodes", "ScopeItems")
        $notCompared = @("Id", "Name", "RoleId", "RoleName", "RolePriority", "Priority", "CreatedDate", "CreatedByUserId",
                         "CreatedByUserDisplayName", "IsExpired", "AccountCount", "AssetCount", "AccountGroupCount",
                         "AssetGroupCount", "InvalidConnectionPolicy")

        # Canonical JSON of a policy's configuration read independently from the appliance:
        # every non-computed property plus each sub-collection endpoint, sorted by property name.
        function Get-PolicyConfiguration([int]$PolicyId) {
            $policy = Invoke-SafeguardMethod -Insecure Core GET "AccessPolicies/$PolicyId"
            $canon = [ordered]@{}
            foreach ($prop in ($policy.PSObject.Properties.Name | Sort-Object)) {
                if ($prop -notin $notCompared) { $canon[$prop] = $policy.$prop }
            }
            foreach ($sub in $subCollections) {
                $canon["Sub_$sub"] = @(Invoke-SafeguardMethod -Insecure Core GET "AccessPolicies/$PolicyId/$sub" | Where-Object { $null -ne $_ -and "$_" -ne "" })
            }
            $canon | ConvertTo-Json -Depth 100 -Compress
        }
        function Get-PolicyIdentity([int]$PolicyId) {
            $p = Invoke-SafeguardMethod -Insecure Core GET "AccessPolicies/$PolicyId"
            "$($p.Id)|$($p.Name)|$($p.RoleId)|$($p.Priority)"
        }
        function Get-RolePolicies([int]$RoleId) {
            @(Invoke-SafeguardMethod -Insecure Core GET AccessPolicies -Parameters @{ filter = "RoleId eq $RoleId"; fields = "Id,Name,Priority"; orderby = "Priority" } |
                Where-Object { $null -ne $_ -and $_.Id })
        }

        $Context.SuiteData["RichBefore"] = Get-PolicyConfiguration $richId
        $Context.SuiteData["SessionBefore"] = Get-PolicyConfiguration $sessionId
        $Context.SuiteData["RichIdentityBefore"] = Get-PolicyIdentity $richId
        $Context.SuiteData["SessionIdentityBefore"] = Get-PolicyIdentity $sessionId

        Test-SgPsAssert "Get-SafeguardPolicyAccount resolves an asset-qualified account name" {
            $qualified = "$($Context.SuiteData['TestAsset'])\$($Context.SuiteData['TestAccount'])"
            $found = Get-SafeguardPolicyAccount -Insecure -AccountToGet $qualified.ToUpperInvariant()
            $found.Id -eq $Context.SuiteData["AccountId"] -and $found.Asset.Id -eq $Context.SuiteData["AssetId"]
        }
        Test-SgPsAssertThrows "Get-SafeguardPolicyAccount rejects malformed qualified names" {
            Get-SafeguardPolicyAccount -Insecure -AccountToGet "asset\account\extra"
        } -ExpectedMessage "expected format"

        Test-SgPsAssert "Copy fixture: rich policy has nested approver, reviewer, contact, reason, and scope settings" {
            $p = Invoke-SafeguardMethod -Insecure Core GET "AccessPolicies/$richId"
            @($p.ApproverSets).Count -eq 1 -and @($p.ApproverSets[0].Approvers).Count -eq 2 -and @($p.Reviewers).Count -eq 1 -and
                @($p.NotificationContacts).Count -eq 1 -and @($p.ReasonCodes).Count -eq 1 -and @($p.ScopeItems).Count -eq 3 -and
                $p.HourlyRestrictionProperties.EnableHourlyRestrictions -and $null -ne $p.ExpirationDate
        }

        Test-SgPsAssertThrows "Copy-SafeguardAccessPolicy rejects a name found in more than one entitlement" {
            Copy-SafeguardAccessPolicy -Insecure $names["Rich"] -TargetEntitlement $targetId
        } -ExpectedMessage "is ambiguous"
        Test-SgPsAssertThrows "Copy-SafeguardAccessPolicy rejects additional backslashes" {
            Copy-SafeguardAccessPolicy -Insecure "$($names['SrcA'])\$($names['Rich'])\extra" -TargetEntitlement $targetId
        } -ExpectedMessage "expected format"
        Test-SgPsAssertThrows "Copy-SafeguardAccessPolicy rejects an empty qualified-name part" {
            Copy-SafeguardAccessPolicy -Insecure "$($names['SrcA'])\" -TargetEntitlement $targetId
        } -ExpectedMessage "expected format"
        Test-SgPsAssert "Ambiguous name created nothing in the target" {
            (Get-RolePolicies $targetId).Count -eq 0
        }

        Test-SgPsAssertThrows "Copy-SafeguardAccessPolicy rejects a qualified name not in that entitlement" {
            Copy-SafeguardAccessPolicy -Insecure "$($names['SrcB'])\$($names['Session'])" -TargetEntitlement $targetId
        } -ExpectedMessage "in entitlement '$($names['SrcB'])'"

        Test-SgPsAssertThrows "Copy-SafeguardAccessPolicy rejects a qualified name with an unknown entitlement" {
            Copy-SafeguardAccessPolicy -Insecure "$($names['SrcA'])_DoesNotExist\$($names['Session'])" -TargetEntitlement $targetId
        } -ExpectedMessage "Unable to find entitlement named"

        Test-SgPsAssertThrows "Copy-SafeguardAccessPolicy rejects the same source specified twice" {
            Copy-SafeguardAccessPolicy -Insecure $richId, "$($names['SrcA'])\$($names['Rich'])" -TargetEntitlement $targetId
        } -ExpectedMessage "more than once"

        Test-SgPsAssertThrows "Copy-SafeguardAccessPolicy rejects an unknown policy name" {
            Copy-SafeguardAccessPolicy -Insecure "$($names['Rich'])_DoesNotExist" -TargetEntitlement $targetId
        } -ExpectedMessage "Unable to find access policy"

        # --- Single policy by entitlement\policy name ---
        Test-SgPsAssert "Copy-SafeguardAccessPolicy copies a single policy by entitlement\policy name" {
            $copies = @(Copy-SafeguardAccessPolicy -Insecure "$($names['SrcA'])\$($names['Rich'])" -TargetEntitlement $names["Target"])
            $Context.SuiteData["RichCopyId"] = $copies[0].Id
            $copies.Count -eq 1 -and $copies[0].Name -eq $names["Rich"] -and $copies[0].Id -ne $richId
        }
        Test-SgPsAssert "Copied policy is owned by the target entitlement" {
            (Invoke-SafeguardMethod -Insecure Core GET "AccessPolicies/$($Context.SuiteData['RichCopyId'])").RoleId -eq $targetId
        }
        Test-SgPsAssert "Copied policy configuration matches the source" {
            $copy = Get-PolicyConfiguration $Context.SuiteData["RichCopyId"]
            if ($copy -ne $Context.SuiteData["RichBefore"]) { throw "Source: $($Context.SuiteData['RichBefore'])`nCopy: $copy" }
            $true
        }
        Test-SgPsAssert "Source policy Id, owner, priority, and configuration are unchanged" {
            (Get-PolicyIdentity $richId) -eq $Context.SuiteData["RichIdentityBefore"] -and
                (Get-PolicyConfiguration $richId) -eq $Context.SuiteData["RichBefore"]
        }

        # --- Shallow-copy check: changing the copy must not change the source ---
        Test-SgPsAssert "Editing nested settings on the copy leaves the source unchanged" {
            $copyId = $Context.SuiteData["RichCopyId"]
            $copy = Invoke-SafeguardMethod -Insecure Core GET "AccessPolicies/$copyId"
            $copy.ApproverSets[0].Approvers = @($copy.ApproverSets[0].Approvers | Select-Object -First 1)
            $copy.HourlyRestrictionProperties.MondayValidHours = @(20)
            $copy.ScopeItems = @($copy.ScopeItems | Select-Object -First 1)
            Invoke-SafeguardMethod -Insecure Core PUT "AccessPolicies/$copyId" -Body $copy | Out-Null
            $edited = Invoke-SafeguardMethod -Insecure Core GET "AccessPolicies/$copyId"
            @($edited.ApproverSets[0].Approvers).Count -eq 1 -and
                (Get-PolicyConfiguration $richId) -eq $Context.SuiteData["RichBefore"]
        }

        # --- Duplicate-name prevalidation ---
        Test-SgPsAssertThrows "Copy-SafeguardAccessPolicy rejects a name already used in the target" {
            Copy-SafeguardAccessPolicy -Insecure $sessionId, $richId -TargetEntitlement $targetId
        } -ExpectedMessage "already has access policies with these names"
        Test-SgPsAssert "Duplicate-name failure created nothing (prevalidated)" {
            $list = Get-RolePolicies $targetId
            $list.Count -eq 1 -and $list[0].Id -eq $Context.SuiteData["RichCopyId"]
        }
        Test-SgPsAssertThrows "Copy-SafeguardAccessPolicy rejects a name differing only by case" {
            Copy-SafeguardAccessPolicy -Insecure $Context.SuiteData["CopyRichBId"] -TargetEntitlement $targetId
        } -ExpectedMessage "already has access policies with these names"

        # --- Multiple policies by Id and object, with prefix/suffix ---
        Test-SgPsAssert "Copy-SafeguardAccessPolicy copies multiple policies by Id and object in order" {
            $sessionObject = Get-SafeguardAccessPolicy -Insecure -PolicyToGet $sessionId
            $copies = @(Copy-SafeguardAccessPolicy -Insecure $richId, $sessionObject -TargetEntitlement $targetId -NamePrefix "Lab-" -NameSuffix "-2")
            $Context.SuiteData["MultiCopyIds"] = @($copies | ForEach-Object { $_.Id })
            $list = Get-RolePolicies $targetId
            $copies.Count -eq 2 -and $copies[0].Name -eq "Lab-$($names['Rich'])-2" -and $copies[1].Name -eq "Lab-$($names['Session'])-2" -and
                $list.Count -eq 3 -and $list[1].Id -eq $copies[0].Id -and $list[2].Id -eq $copies[1].Id
        }
        Test-SgPsAssert "Multiple copies match their sources" {
            (Get-PolicyConfiguration $Context.SuiteData["MultiCopyIds"][0]) -eq $Context.SuiteData["RichBefore"] -and
                (Get-PolicyConfiguration $Context.SuiteData["MultiCopyIds"][1]) -eq $Context.SuiteData["SessionBefore"]
        }
        Test-SgPsAssert "Session source policy is unchanged" {
            (Get-PolicyIdentity $sessionId) -eq $Context.SuiteData["SessionIdentityBefore"] -and
                (Get-PolicyConfiguration $sessionId) -eq $Context.SuiteData["SessionBefore"]
        }

        # --- Qualified names from different entitlements in one call ---
        Test-SgPsAssert "Copy-SafeguardAccessPolicy copies policies from different entitlements in one call" {
            $copies = @(Copy-SafeguardAccessPolicy -Insecure "$($names['SrcA'])\$($names['Session'])", "$($names['SrcB'])\$($names['Rich'])" `
                            -TargetEntitlement $targetId -NameSuffix "-Q")
            $copies.Count -eq 2 -and $copies[0].Name -eq "$($names['Session'])-Q" -and
                $copies[1].Name -eq "$($names['Rich'].ToUpperInvariant())-Q" -and
                (Get-PolicyConfiguration $copies[0].Id) -eq $Context.SuiteData["SessionBefore"] -and
                (Invoke-SafeguardMethod -Insecure Core GET "AccessPolicies/$($Context.SuiteData['CopyRichBId'])").RoleId -eq $Context.SuiteData["CopySrcBId"]
        }

        Test-SgPsAssertThrows "Copy-SafeguardAccessPolicy rejects two copies with the same final name" {
            Copy-SafeguardAccessPolicy -Insecure $richId, $Context.SuiteData["CopyRichBId"] -TargetEntitlement $targetId -NameSuffix "-3"
        } -ExpectedMessage "More than one copied access policy"

        # --- Partial failure: best effort, nothing rolled back ---
        Test-SgPsAssert "Copy-SafeguardAccessPolicy reports a partial failure without rolling back" {
            $before = (Get-RolePolicies $targetId).Count
            $caught = $null
            try { $null = Copy-SafeguardAccessPolicy -Insecure $sessionId, $failsId -TargetEntitlement $targetId -NameSuffix "-PF" }
            catch { $caught = $_ }
            if (-not $caught) { throw "Expected a partial-failure error" }
            $detail = $caught.TargetObject
            $after = Get-RolePolicies $targetId
            $kept = $after | Where-Object { $_.Name -eq "$($names['Session'])-PF" }
            $caught.FullyQualifiedErrorId -like "SafeguardAccessPolicyCopyIncomplete*" -and
                $caught.Exception.Message -like "*Copied 1 of 2*" -and
                $detail.EntitlementId -eq $targetId -and -not $detail.EntitlementCreated -and
                @($detail.Succeeded).Count -eq 1 -and $detail.Succeeded[0].SourceId -eq $sessionId -and $detail.Succeeded[0].NewId -eq $kept.Id -and
                @($detail.Failed).Count -eq 1 -and $detail.Failed[0].SourceId -eq $failsId -and $detail.Failed[0].Message -like "*50185*" -and
                $after.Count -eq ($before + 1)
        }
        Test-SgPsAssert "Partial failure left the failing source policy unchanged" {
            $p = Invoke-SafeguardMethod -Insecure Core GET "AccessPolicies/$failsId"
            $p.RoleId -eq $srcAId -and $p.Name -eq $names["Fails"]
        }

        # --- New-SafeguardEntitlement -CopyAccessPolicy ---
        Test-SgPsAssertThrows "New-SafeguardEntitlement copy options require CopyAccessPolicy" {
            New-SafeguardEntitlement -Insecure $names["NewEntlBad"] -CopyAccessPolicyNameSuffix "-x"
        } -ExpectedMessage "require CopyAccessPolicy"
        Test-SgPsAssertThrows "New-SafeguardEntitlement rejects an ambiguous policy before creating the entitlement" {
            New-SafeguardEntitlement -Insecure $names["NewEntlBad"] -CopyAccessPolicy $names["Rich"]
        } -ExpectedMessage "is ambiguous"
        Test-SgPsAssert "Rejected New-SafeguardEntitlement created no entitlement" {
            @(Invoke-SafeguardMethod -Insecure Core GET Roles -Parameters @{ filter = "Name eq '$($names['NewEntlBad'])'" } | Where-Object { $null -ne $_ -and $_.Id }).Count -eq 0
        }

        Test-SgPsAssert "New-SafeguardEntitlement -CopyAccessPolicy returns one entitlement with the copies" {
            $out = @(New-SafeguardEntitlement -Insecure $names["NewEntl"] -Description "Copied" `
                        -CopyAccessPolicy "$($names['SrcA'])\$($names['Rich'])", "$($names['SrcA'])\$($names['Session'])")
            if ($out.Count -ge 1 -and $out[0].Id) { $Context.SuiteData["CopyRoleIds"].Add([int]$out[0].Id) }
            $Context.SuiteData["NewEntlId"] = $out[0].Id
            $list = Get-RolePolicies $out[0].Id
            $out.Count -eq 1 -and $out[0].Name -eq $names["NewEntl"] -and $out[0].Description -eq "Copied" -and
                $list.Count -eq 2 -and $list[0].Name -eq $names["Rich"] -and $list[1].Name -eq $names["Session"]
        }
        Test-SgPsAssert "New-SafeguardEntitlement copies match their sources" {
            $list = Get-RolePolicies $Context.SuiteData["NewEntlId"]
            (Get-PolicyConfiguration $list[0].Id) -eq $Context.SuiteData["RichBefore"] -and
                (Get-PolicyConfiguration $list[1].Id) -eq $Context.SuiteData["SessionBefore"] -and
                (Get-PolicyIdentity $richId) -eq $Context.SuiteData["RichIdentityBefore"]
        }

        Test-SgPsAssert "New-SafeguardEntitlement keeps the entitlement and successful copies on partial failure" {
            $caught = $null
            try { $null = New-SafeguardEntitlement -Insecure $names["NewEntlPartial"] -CopyAccessPolicy $sessionId, $failsId }
            catch { $caught = $_ }
            $role = @(Invoke-SafeguardMethod -Insecure Core GET Roles -Parameters @{ filter = "Name eq '$($names['NewEntlPartial'])'" } | Where-Object { $null -ne $_ -and $_.Id })
            if ($role.Count -eq 1) { $Context.SuiteData["CopyRoleIds"].Add([int]$role[0].Id) }
            if (-not $caught) { throw "Expected a partial-failure error" }
            $detail = $caught.TargetObject
            $list = if ($role.Count -eq 1) { Get-RolePolicies $role[0].Id } else { @() }
            $caught.FullyQualifiedErrorId -like "SafeguardAccessPolicyCopyIncomplete*" -and
                $detail.EntitlementCreated -and $detail.EntitlementId -eq $role[0].Id -and
                @($detail.Succeeded).Count -eq 1 -and @($detail.Failed).Count -eq 1 -and
                $list.Count -eq 1 -and $list[0].Id -eq $detail.Succeeded[0].NewId
        }
    }

    Cleanup = {
        param($Context)
    }
}
