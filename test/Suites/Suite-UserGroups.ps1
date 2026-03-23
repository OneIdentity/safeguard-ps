@{
    Name        = "User Groups"
    Description = "Tests user group CRUD and member management"
    Tags        = @("groups", "users")

    Setup = {
        param($Context)

        $prefix = $Context.TestPrefix
        $testGroup = "${prefix}_UGroup1"
        $testGroup2 = "${prefix}_UGroup2"
        $testUser = "${prefix}_UGMember"

        # Pre-cleanup
        Remove-SgPsStaleTestObject -Collection "UserGroups" -Name $testGroup
        Remove-SgPsStaleTestObject -Collection "UserGroups" -Name $testGroup2
        Remove-SgPsStaleTestObject -Collection "Users" -Name $testUser

        $Context.SuiteData["TestGroup"] = $testGroup
        $Context.SuiteData["TestGroup2"] = $testGroup2
        $Context.SuiteData["TestUser"] = $testUser

        # Create a user to use as group member
        $secPwd = ConvertTo-SecureString "Mem1234!xyzABC" -AsPlainText -Force
        $user = New-SafeguardUser -Insecure -Provider -1 -NewUserName $testUser -Password $secPwd
        $Context.SuiteData["UserId"] = $user.Id

        Register-SgPsTestCleanup -Description "Delete member user" -Action {
            param($Ctx)
            try { Remove-SafeguardUser -Insecure $Ctx.SuiteData['UserId'] } catch {}
        }
    }

    Execute = {
        param($Context)

        $testGroup = $Context.SuiteData["TestGroup"]
        $testGroup2 = $Context.SuiteData["TestGroup2"]

        # --- Get-SafeguardUserGroup (list) ---
        Test-SgPsAssert "Get-SafeguardUserGroup lists groups" {
            $groups = Get-SafeguardUserGroup -Insecure
            $null -ne $groups
        }

        # --- New-SafeguardUserGroup ---
        Test-SgPsAssert "New-SafeguardUserGroup creates a group" {
            $group = New-SafeguardUserGroup -Insecure $testGroup -Description "Test user group"
            $Context.SuiteData["GroupId"] = $group.Id

            Register-SgPsTestCleanup -Description "Delete user group $testGroup" -Action {
                param($Ctx)
                try { Remove-SafeguardUserGroup -Insecure $Ctx.SuiteData['GroupId'] } catch {}
            }
            $group.Name -eq $testGroup
        }

        # --- Get-SafeguardUserGroup by ID ---
        Test-SgPsAssert "Get-SafeguardUserGroup by ID" {
            $group = Get-SafeguardUserGroup -Insecure $Context.SuiteData["GroupId"]
            $group.Name -eq $testGroup
        }

        # --- Get-SafeguardUserGroup by Name ---
        Test-SgPsAssert "Get-SafeguardUserGroup by Name" {
            $group = Get-SafeguardUserGroup -Insecure $testGroup
            $group.Id -eq $Context.SuiteData["GroupId"]
        }

        # --- Get-SafeguardUserGroup with Fields ---
        Test-SgPsAssert "Get-SafeguardUserGroup with Fields" {
            $group = Get-SafeguardUserGroup -Insecure $Context.SuiteData["GroupId"] -Fields "Id","Name","Description"
            $null -ne $group.Id -and $null -ne $group.Name
        }

        # --- Edit-SafeguardUserGroup (description) ---
        Test-SgPsAssert "Edit-SafeguardUserGroup updates description" {
            $updated = Edit-SafeguardUserGroup -Insecure $Context.SuiteData["GroupId"] -Description "Updated description"
            $updated.Description -eq "Updated description"
        }
        Test-SgPsAssert "Edit-SafeguardUserGroup changes persisted" {
            $readback = Get-SafeguardUserGroup -Insecure $Context.SuiteData["GroupId"]
            $readback.Description -eq "Updated description"
        }

        # --- Add-SafeguardUserGroupMember ---
        Test-SgPsAssert "Add-SafeguardUserGroupMember adds a member" {
            Add-SafeguardUserGroupMember -Insecure $testGroup -UserList $Context.SuiteData["TestUser"]
            $members = Get-SafeguardUserGroupMember -Insecure $testGroup
            $list = @($members)
            ($list | Where-Object { $_.Id -eq $Context.SuiteData["UserId"] }) -ne $null
        }

        # --- Get-SafeguardUserGroupMember ---
        Test-SgPsAssert "Get-SafeguardUserGroupMember lists members" {
            $members = Get-SafeguardUserGroupMember -Insecure $testGroup
            $list = @($members)
            $list.Count -ge 1 -and ($list | Where-Object { $_.Id -eq $Context.SuiteData["UserId"] })
        }

        # --- Remove-SafeguardUserGroupMember ---
        Test-SgPsAssert "Remove-SafeguardUserGroupMember removes a member" {
            Remove-SafeguardUserGroupMember -Insecure $testGroup -UserList $Context.SuiteData["TestUser"]
            $members = Get-SafeguardUserGroupMember -Insecure $testGroup
            $list = @($members)
            -not ($list | Where-Object { $_.Id -eq $Context.SuiteData["UserId"] })
        }

        # --- New-SafeguardUserGroup (second, for remove test) ---
        Test-SgPsAssert "New-SafeguardUserGroup second group" {
            $group2 = New-SafeguardUserGroup -Insecure $testGroup2
            $Context.SuiteData["Group2Id"] = $group2.Id

            Register-SgPsTestCleanup -Description "Delete user group $testGroup2" -Action {
                param($Ctx)
                try { Remove-SafeguardUserGroup -Insecure $Ctx.SuiteData['Group2Id'] } catch {}
            }
            $group2.Name -eq $testGroup2
        }

        # --- Remove-SafeguardUserGroup ---
        Test-SgPsAssert "Remove-SafeguardUserGroup deletes a group" {
            Remove-SafeguardUserGroup -Insecure $Context.SuiteData["Group2Id"]
            $remaining = Get-SafeguardUserGroup -Insecure
            $list = @($remaining)
            -not ($list | Where-Object { $_.Id -eq $Context.SuiteData["Group2Id"] })
        }
    }

    Cleanup = {
        param($Context)
    }
}
