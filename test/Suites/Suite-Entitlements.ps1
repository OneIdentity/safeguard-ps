@{
    Name        = "Entitlements"
    Description = "Tests entitlement CRUD and member management"
    Tags        = @("entitlements", "access")

    Setup = {
        param($Context)

        $prefix = $Context.TestPrefix
        $testEntitlement = "${prefix}_Entl1"
        $testEntitlement2 = "${prefix}_Entl2"
        $testUser = "${prefix}_EntlUser"
        $testGroup = "${prefix}_EntlGrp"

        # Pre-cleanup
        Remove-SgPsStaleTestObject -Collection "Roles" -Name $testEntitlement
        Remove-SgPsStaleTestObject -Collection "Roles" -Name $testEntitlement2
        Remove-SgPsStaleTestObject -Collection "UserGroups" -Name $testGroup
        Remove-SgPsStaleTestObject -Collection "Users" -Name $testUser

        $Context.SuiteData["TestEntitlement"] = $testEntitlement
        $Context.SuiteData["TestEntitlement2"] = $testEntitlement2

        # Create a user and group for entitlement membership tests
        $secPwd = ConvertTo-SecureString "Entl1234!xyzABC" -AsPlainText -Force
        $user = New-SafeguardUser -Insecure -Provider -1 -NewUserName $testUser -Password $secPwd
        $Context.SuiteData["UserId"] = $user.Id
        $Context.SuiteData["TestUser"] = $testUser

        $group = New-SafeguardUserGroup -Insecure $testGroup
        $Context.SuiteData["GroupId"] = $group.Id
        $Context.SuiteData["TestGroup"] = $testGroup

        Register-SgPsTestCleanup -Description "Delete entitlement test group" -Action {
            param($Ctx)
            try { Remove-SafeguardUserGroup -Insecure $Ctx.SuiteData['GroupId'] } catch {}
        }
        Register-SgPsTestCleanup -Description "Delete entitlement test user" -Action {
            param($Ctx)
            try { Remove-SafeguardUser -Insecure $Ctx.SuiteData['UserId'] } catch {}
        }
    }

    Execute = {
        param($Context)

        $testEntitlement = $Context.SuiteData["TestEntitlement"]
        $testEntitlement2 = $Context.SuiteData["TestEntitlement2"]

        # --- Get-SafeguardEntitlement (list) ---
        Test-SgPsAssert "Get-SafeguardEntitlement lists entitlements" {
            $entitlements = Get-SafeguardEntitlement -Insecure
            $null -ne $entitlements
        }

        # --- New-SafeguardEntitlement ---
        Test-SgPsAssert "New-SafeguardEntitlement creates an entitlement" {
            $entl = New-SafeguardEntitlement -Insecure $testEntitlement -Description "Test entitlement"
            $Context.SuiteData["EntitlementId"] = $entl.Id

            Register-SgPsTestCleanup -Description "Delete entitlement $testEntitlement" -Action {
                param($Ctx)
                try { Remove-SafeguardEntitlement -Insecure $Ctx.SuiteData['EntitlementId'] } catch {}
            }
            $entl.Name -eq $testEntitlement
        }

        # --- Get-SafeguardEntitlement by ID ---
        Test-SgPsAssert "Get-SafeguardEntitlement by ID" {
            $entl = Get-SafeguardEntitlement -Insecure $Context.SuiteData["EntitlementId"]
            $entl.Name -eq $testEntitlement
        }

        # --- Get-SafeguardEntitlement by Name ---
        Test-SgPsAssert "Get-SafeguardEntitlement by Name" {
            $entl = Get-SafeguardEntitlement -Insecure $testEntitlement
            $entl.Id -eq $Context.SuiteData["EntitlementId"]
        }

        # --- Get-SafeguardEntitlement with Fields ---
        Test-SgPsAssert "Get-SafeguardEntitlement with Fields" {
            $entl = Get-SafeguardEntitlement -Insecure $Context.SuiteData["EntitlementId"] -Fields "Id","Name","Description"
            $null -ne $entl.Id -and $null -ne $entl.Name
        }

        # --- Edit-SafeguardEntitlement (attributes) ---
        Test-SgPsAssert "Edit-SafeguardEntitlement updates description" {
            $updated = Edit-SafeguardEntitlement -Insecure $Context.SuiteData["EntitlementId"] -Description "Updated description"
            $updated.Description -eq "Updated description"
        }

        # --- Edit-SafeguardEntitlement with object ---
        Test-SgPsAssert "Edit-SafeguardEntitlement with EntitlementObject" {
            $entl = Get-SafeguardEntitlement -Insecure $Context.SuiteData["EntitlementId"]
            $entl.Description = "Modified via object"
            $updated = Edit-SafeguardEntitlement -Insecure -EntitlementObject $entl
            $updated.Description -eq "Modified via object"
        }
        Test-SgPsAssert "Edit-SafeguardEntitlement changes persisted" {
            $readback = Get-SafeguardEntitlement -Insecure $Context.SuiteData["EntitlementId"]
            $readback.Description -eq "Modified via object"
        }

        # --- Add-SafeguardEntitlementMember (user) ---
        Test-SgPsAssert "Add-SafeguardEntitlementMember adds a user" {
            Add-SafeguardEntitlementMember -Insecure $Context.SuiteData["EntitlementId"] -Users $Context.SuiteData["TestUser"]
            $entl = Get-SafeguardEntitlement -Insecure $Context.SuiteData["EntitlementId"]
            $hasUser = @($entl.Members) | Where-Object { $_.Id -eq $Context.SuiteData["UserId"] }
            $null -ne $hasUser
        }

        # --- Add-SafeguardEntitlementMember (group) ---
        Test-SgPsAssert "Add-SafeguardEntitlementMember adds a group" {
            Add-SafeguardEntitlementMember -Insecure $Context.SuiteData["EntitlementId"] -Groups $Context.SuiteData["TestGroup"]
            $entl = Get-SafeguardEntitlement -Insecure $Context.SuiteData["EntitlementId"]
            $hasGroup = @($entl.Members) | Where-Object { $_.Id -eq $Context.SuiteData["GroupId"] }
            $null -ne $hasGroup
        }

        # --- Verify members via Get ---
        Test-SgPsAssert "Entitlement has user and group members" {
            $entl = Get-SafeguardEntitlement -Insecure $Context.SuiteData["EntitlementId"]
            $members = @($entl.Members)
            $hasUser = $members | Where-Object { $_.Id -eq $Context.SuiteData["UserId"] }
            $hasGroup = $members | Where-Object { $_.Id -eq $Context.SuiteData["GroupId"] }
            $null -ne $hasUser -and $null -ne $hasGroup
        }

        # --- Remove-SafeguardEntitlementMember (user) ---
        Test-SgPsAssert "Remove-SafeguardEntitlementMember removes a user" {
            Remove-SafeguardEntitlementMember -Insecure $Context.SuiteData["EntitlementId"] -Users $Context.SuiteData["TestUser"]
            $entl = Get-SafeguardEntitlement -Insecure $Context.SuiteData["EntitlementId"]
            $hasUser = @($entl.Members) | Where-Object { $_.Id -eq $Context.SuiteData["UserId"] }
            $null -eq $hasUser
        }

        # --- Remove-SafeguardEntitlementMember (group) ---
        Test-SgPsAssert "Remove-SafeguardEntitlementMember removes a group" {
            Remove-SafeguardEntitlementMember -Insecure $Context.SuiteData["EntitlementId"] -Groups $Context.SuiteData["TestGroup"]
            $entl = Get-SafeguardEntitlement -Insecure $Context.SuiteData["EntitlementId"]
            $hasGroup = @($entl.Members) | Where-Object { $_.Id -eq $Context.SuiteData["GroupId"] }
            $null -eq $hasGroup
        }

        # --- New-SafeguardEntitlement (second, for remove test) ---
        Test-SgPsAssert "New-SafeguardEntitlement second entitlement" {
            $entl2 = New-SafeguardEntitlement -Insecure $testEntitlement2
            $Context.SuiteData["Entitlement2Id"] = $entl2.Id

            Register-SgPsTestCleanup -Description "Delete entitlement $testEntitlement2" -Action {
                param($Ctx)
                try { Remove-SafeguardEntitlement -Insecure $Ctx.SuiteData['Entitlement2Id'] } catch {}
            }
            $entl2.Name -eq $testEntitlement2
        }

        # --- Remove-SafeguardEntitlement ---
        Test-SgPsAssert "Remove-SafeguardEntitlement deletes an entitlement" {
            Remove-SafeguardEntitlement -Insecure $Context.SuiteData["Entitlement2Id"]
            $remaining = Get-SafeguardEntitlement -Insecure
            $list = @($remaining)
            -not ($list | Where-Object { $_.Id -eq $Context.SuiteData["Entitlement2Id"] })
        }
    }

    Cleanup = {
        param($Context)
    }
}
