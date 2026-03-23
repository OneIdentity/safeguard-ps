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
    }

    Cleanup = {
        param($Context)
    }
}
