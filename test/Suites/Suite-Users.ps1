@{
    Name        = "User Management"
    Description = "Tests user CRUD, password, enable/disable, and search operations"
    Tags        = @("users", "core")

    Setup = {
        param($Context)

        $prefix = $Context.TestPrefix
        $testUser = "${prefix}_User1"
        $testUser2 = "${prefix}_User2"
        $testPassword = "Test1234!abcXYZ"

        # Pre-cleanup: remove stale objects from previous failed runs
        Remove-SgPsStaleTestObject -Collection "Users" -Name $testUser
        Remove-SgPsStaleTestObject -Collection "Users" -Name $testUser2

        $Context.SuiteData["TestUser"] = $testUser
        $Context.SuiteData["TestUser2"] = $testUser2
        $Context.SuiteData["TestPassword"] = $testPassword
    }

    Execute = {
        param($Context)

        $testUser = $Context.SuiteData["TestUser"]
        $testUser2 = $Context.SuiteData["TestUser2"]
        $testPassword = $Context.SuiteData["TestPassword"]

        # --- Get-SafeguardUser (list all) ---
        Test-SgPsAssert "Get-SafeguardUser lists users" {
            $users = Get-SafeguardUser -Insecure
            @($users).Count -gt 0
        }

        # --- New-SafeguardUser ---
        Test-SgPsAssert "New-SafeguardUser creates a local user" {
            $secPwd = ConvertTo-SecureString $testPassword -AsPlainText -Force
            $user = New-SafeguardUser -Insecure -Provider -1 -NewUserName $testUser `
                -FirstName "Test" -LastName "User1" -Description "Integration test user" `
                -AdminRoles "Auditor" -Password $secPwd
            $Context.SuiteData["UserId"] = $user.Id

            Register-SgPsTestCleanup -Description "Delete test user $testUser" -Action {
                param($Ctx)
                try { Remove-SafeguardUser -Insecure $Ctx.SuiteData['UserId'] } catch {}
            }

            $null -ne $user.Id -and $user.Name -eq $testUser
        }

        # --- Get-SafeguardUser by ID ---
        Test-SgPsAssert "Get-SafeguardUser by ID" {
            $user = Get-SafeguardUser -Insecure $Context.SuiteData["UserId"]
            $user.Name -eq $testUser -and $user.FirstName -eq "Test"
        }

        # --- Get-SafeguardUser by Name ---
        Test-SgPsAssert "Get-SafeguardUser by Name" {
            $user = Get-SafeguardUser -Insecure $testUser
            $user.Name -eq $testUser
        }

        # --- Get-SafeguardUser with Fields filter ---
        Test-SgPsAssert "Get-SafeguardUser with Fields" {
            $user = Get-SafeguardUser -Insecure $Context.SuiteData["UserId"] -Fields "Id","Name","FirstName"
            $null -ne $user.Id -and $user.Name -eq $testUser
        }

        # --- Edit-SafeguardUser ---
        Test-SgPsAssert "Edit-SafeguardUser updates attributes" {
            $updated = Edit-SafeguardUser -Insecure $Context.SuiteData["UserId"] `
                -Description "Updated description" -LastName "Updated"
            $updated.Description -eq "Updated description" -and $updated.LastName -eq "Updated"
        }

        # --- Edit-SafeguardUser with object ---
        Test-SgPsAssert "Edit-SafeguardUser with UserObject" {
            $user = Get-SafeguardUser -Insecure $Context.SuiteData["UserId"]
            $user.FirstName = "Modified"
            $edited = Edit-SafeguardUser -Insecure -UserObject $user
            $edited.FirstName -eq "Modified"
        }

        # --- Find-SafeguardUser ---
        Test-SgPsAssert "Find-SafeguardUser by search string" {
            $results = Find-SafeguardUser -Insecure $testUser
            $found = @($results) | Where-Object { $_.Name -eq $testUser }
            $null -ne $found
        }

        # --- Find-SafeguardUser with QueryFilter ---
        Test-SgPsAssert "Find-SafeguardUser with QueryFilter" {
            $results = Find-SafeguardUser -Insecure -QueryFilter "Name eq '$testUser'"
            $found = @($results) | Where-Object { $_.Name -eq $testUser }
            $null -ne $found
        }

        # --- Set-SafeguardUserPassword ---
        Test-SgPsAssert "Set-SafeguardUserPassword changes password" {
            $newPassword = "NewPass5678!defGHI"
            $secPwd = ConvertTo-SecureString $newPassword -AsPlainText -Force
            Set-SafeguardUserPassword -Insecure $Context.SuiteData["UserId"] -Password $secPwd
            $Context.SuiteData["TestPassword"] = $newPassword
            # Verify by logging in as the test user
            $token = Connect-SgPsTestUser -Username $testUser -Password $newPassword
            Disconnect-Safeguard -Appliance $Context.Appliance -AccessToken $token -Insecure
            $null -ne $token
        }

        # --- Disable-SafeguardUser ---
        Test-SgPsAssert "Disable-SafeguardUser disables a user" {
            $result = Disable-SafeguardUser -Insecure $Context.SuiteData["UserId"]
            $result.Disabled -eq $true
        }

        # --- Enable-SafeguardUser ---
        Test-SgPsAssert "Enable-SafeguardUser re-enables a user" {
            $result = Enable-SafeguardUser -Insecure $Context.SuiteData["UserId"]
            $result.Disabled -eq $false
        }

        # --- New-SafeguardUser with -NoPassword ---
        Test-SgPsAssert "New-SafeguardUser with -NoPassword" {
            $user2 = New-SafeguardUser -Insecure -Provider -1 -NewUserName $testUser2 -NoPassword
            $Context.SuiteData["User2Id"] = $user2.Id

            Register-SgPsTestCleanup -Description "Delete test user $testUser2" -Action {
                param($Ctx)
                try { Remove-SafeguardUser -Insecure $Ctx.SuiteData['User2Id'] } catch {}
            }

            $null -ne $user2.Id -and $user2.Name -eq $testUser2
        }

        # --- Remove-SafeguardUser ---
        Test-SgPsAssert "Remove-SafeguardUser deletes a user" {
            Remove-SafeguardUser -Insecure $Context.SuiteData["User2Id"]
            # Verify the user is gone
            $found = $false
            try {
                $null = Get-SafeguardUser -Insecure $Context.SuiteData["User2Id"]
                $found = $true
            } catch {}
            -not $found
        }
    }

    Cleanup = {
        param($Context)
        # Registered cleanup handles remaining user deletion
    }
}
