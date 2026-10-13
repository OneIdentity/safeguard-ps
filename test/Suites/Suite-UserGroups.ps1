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

        # --- Edit-SafeguardUserGroup via pipeline ---
        Test-SgPsAssert "Edit-SafeguardUserGroup via pipeline" {
            $ug = Get-SafeguardUserGroup -Insecure $Context.SuiteData["GroupId"]
            $ug.Description = "Pipeline edit"
            $edited = $ug | Edit-SafeguardUserGroup -Insecure
            $edited.Description -eq "Pipeline edit"
        }
        Test-SgPsAssert "Edit-SafeguardUserGroup pipeline edit persisted" {
            $readback = Get-SafeguardUserGroup -Insecure $Context.SuiteData["GroupId"]
            $readback.Description -eq "Pipeline edit"
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

        # --- Directory sync options on local groups (always available) ---
        Test-SgPsAssertThrows "New-SafeguardUserGroup rejects LinkDirectoryAccounts without -Directory" {
            New-SafeguardUserGroup -Insecure "${testGroup}_NoDir" -LinkDirectoryAccounts $true
        }
        Test-SgPsAssertThrows "New-SafeguardUserGroup rejects PrimaryAuthenticationProvider without -Directory" {
            New-SafeguardUserGroup -Insecure "${testGroup}_NoDir" -Description "x" -PrimaryAuthenticationProvider -1
        }
        Test-SgPsAssert "No local group created by rejected sync-option calls" {
            -not @(Get-SafeguardUserGroup -Insecure | Where-Object { $_.Name -eq "${testGroup}_NoDir" })
        }
        Test-SgPsAssertThrows "Edit-SafeguardUserGroup rejects LinkDirectoryAccounts on a local group" {
            Edit-SafeguardUserGroup -Insecure $Context.SuiteData["GroupId"] -LinkDirectoryAccounts $true
        } -ExpectedMessage "only valid for directory user groups"
        Test-SgPsAssertThrows "Edit-SafeguardUserGroup rejects PrimaryAuthenticationProvider on a local group" {
            Edit-SafeguardUserGroup -Insecure $Context.SuiteData["GroupId"] -PrimaryAuthenticationProvider -1
        } -ExpectedMessage "only valid for directory user groups"
        Test-SgPsAssertThrows "Edit-SafeguardUserGroup rejects ResetPrimaryAuthenticationProvider on a local group" {
            Edit-SafeguardUserGroup -Insecure $Context.SuiteData["GroupId"] -ResetPrimaryAuthenticationProvider
        } -ExpectedMessage "only valid for directory user groups"
        Test-SgPsAssertThrows "Edit-SafeguardUserGroup rejects provider and reset together" {
            Edit-SafeguardUserGroup -Insecure $Context.SuiteData["GroupId"] -PrimaryAuthenticationProvider -1 -ResetPrimaryAuthenticationProvider
        } -ExpectedMessage "cannot be specified together"
        Test-SgPsAssert "Local group unchanged after rejected sync-option edits" {
            $readback = Get-SafeguardUserGroup -Insecure $Context.SuiteData["GroupId"]
            $readback.Description -eq "Pipeline edit" -and
                $readback.DirectoryGroupSyncProperties.LinkDirectoryAccounts -eq $false -and
                $null -eq $readback.DirectoryGroupSyncProperties.PrimaryAuthenticationProviderId
        }

        # --- Directory sync options on directory groups ---
        # Requires an existing directory identity provider and a directory group that is not yet a
        # Safeguard user group.  Choose a group whose members are not existing Safeguard users: the
        # test group is synchronized, and its synchronized users are removed during cleanup.
        $directoryNames = @(
            "Create directory group with LinkDirectoryAccounts",
            "Directory group without sync options uses appliance defaults",
            "Create directory group with PrimaryAuthenticationProvider",
            "Edit LinkDirectoryAccounts false to true preserves provider and AdminRoles",
            "Edit AdminRoles with sync options omitted preserves them",
            "Edit ResetPrimaryAuthenticationProvider with link omitted",
            "Edit PrimaryAuthenticationProvider by ID",
            "Edit LinkDirectoryAccounts true to false preserves provider and AdminRoles",
            "Edit PrimaryAuthenticationProvider by provider object",
            "Edit LinkDirectoryAccounts and PrimaryAuthenticationProvider",
            "Edit directory group via pipeline preserves sync options",
            "Invalid authentication provider is rejected",
            "Invalid authentication provider ID is rejected",
            "New-SafeguardUserGroup with invalid provider is rejected",
            "Rejected provider edits leave settings unchanged",
            "Existing directory users are unchanged"
        )
        $dirSetting = $env:SGPS_USERGROUP_DIRECTORY
        $dirGroupName = $env:SGPS_USERGROUP_DIRECTORYGROUP
        $dirDomain = $env:SGPS_USERGROUP_DOMAIN
        $directory = $null
        $skipReason = $null
        if (-not $dirSetting -or -not $dirGroupName) {
            $skipReason = "No test directory group (set SGPS_USERGROUP_DIRECTORY and SGPS_USERGROUP_DIRECTORYGROUP)"
        }
        else {
            try { $directory = Get-SafeguardDirectoryIdentityProvider -Insecure $dirSetting } catch { $directory = $null }
            if (-not $directory) {
                $skipReason = "Directory identity provider '$dirSetting' not found"
            }
            elseif (@(Get-SafeguardUserGroup -Insecure | Where-Object { $_.Name -eq $dirGroupName -and $_.DirectoryProperties.DirectoryId -eq $directory.Id })) {
                $skipReason = "Directory group '$dirGroupName' is already a Safeguard user group; refusing to modify it"
            }
        }

        if ($skipReason) {
            foreach ($n in $directoryNames) { Test-SgPsSkip $n $skipReason }
            return
        }

        $dirId = $directory.Id
        $newDirArgs = @{ Insecure = $true; Name = $dirGroupName; Directory = $dirId }
        if ($dirDomain) { $newDirArgs.DomainName = $dirDomain }

        # Snapshot existing directory users so cleanup only removes users synchronized by this test,
        # and so their authentication providers can be verified afterwards.
        $existingDirUsers = @(Get-SafeguardUser -Insecure -Fields Id,Name,DirectoryProperties,PrimaryAuthenticationProvider |
            Where-Object { $_.DirectoryProperties.DirectoryId -eq $dirId })
        $Context.SuiteData["DirId"] = $dirId
        $Context.SuiteData["ExistingDirUserIds"] = @($existingDirUsers | ForEach-Object { $_.Id })
        Register-SgPsTestCleanup -Description "Delete users synchronized from test directory group" -Action {
            param($Ctx)
            $users = @(Get-SafeguardUser -Insecure -Fields Id,DirectoryProperties |
                Where-Object { $_.DirectoryProperties.DirectoryId -eq $Ctx.SuiteData['DirId'] -and $Ctx.SuiteData['ExistingDirUserIds'] -notcontains $_.Id })
            foreach ($u in $users) { try { Remove-SafeguardUser -Insecure $u.Id } catch {} }
        }

        # An isolated External Federation provider is a valid alternate primary provider for directory groups.
        $fedName = "$($Context.TestPrefix)_UGFed"
        Remove-SgPsStaleTestObject -Collection "IdentityProviders" -Name $fedName
        $fedId = $null
        try {
            $rsa = [System.Security.Cryptography.RSA]::Create(2048)
            $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new("CN=$fedName", $rsa,
                [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
            $cert = $req.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddDays(30))
            $b64 = [Convert]::ToBase64String($cert.RawData)
            $metadata = "<?xml version=`"1.0`"?><md:EntityDescriptor xmlns:md=`"urn:oasis:names:tc:SAML:2.0:metadata`" entityID=`"https://sgpstest.invalid/idp`">" +
                "<md:IDPSSODescriptor protocolSupportEnumeration=`"urn:oasis:names:tc:SAML:2.0:protocol`"><md:KeyDescriptor use=`"signing`">" +
                "<ds:KeyInfo xmlns:ds=`"http://www.w3.org/2000/09/xmldsig#`"><ds:X509Data><ds:X509Certificate>$b64</ds:X509Certificate></ds:X509Data></ds:KeyInfo>" +
                "</md:KeyDescriptor><md:SingleSignOnService Binding=`"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect`" Location=`"https://sgpstest.invalid/sso`"/>" +
                "</md:IDPSSODescriptor></md:EntityDescriptor>"
            $fed = Invoke-SafeguardMethod -Insecure Core POST IdentityProviders -Body @{
                Name = $fedName; TypeReferenceName = "ExternalFederation"
                ExternalFederationProperties = @{ Realm = "sgpstest.invalid"; FederationMetadata = $metadata }
            }
            $fedId = $fed.Id
            $Context.SuiteData["FedId"] = $fedId
            Register-SgPsTestCleanup -Description "Delete test federation provider $fedName" -Action {
                param($Ctx)
                try { Invoke-SafeguardMethod -Insecure Core DELETE "IdentityProviders/$($Ctx.SuiteData['FedId'])" } catch {}
            }
        }
        catch {
            Write-Host "    Could not create test federation provider: $($_.Exception.Message)" -ForegroundColor DarkYellow
        }

        $getSync = { (Get-SafeguardUserGroup -Insecure $Context.SuiteData["DirGroupId"]).DirectoryGroupSyncProperties }
        $registerDirGroupCleanup = {
            Register-SgPsTestCleanup -Description "Delete directory user group $dirGroupName" -Action {
                param($Ctx)
                try { Remove-SafeguardUserGroup -Insecure $Ctx.SuiteData['DirGroupId'] } catch {}
            }
        }

        Test-SgPsAssert "Create directory group with LinkDirectoryAccounts" {
            $group = New-SafeguardUserGroup @newDirArgs -LinkDirectoryAccounts $true -AdminRoles Auditor
            $Context.SuiteData["DirGroupId"] = $group.Id
            & $registerDirGroupCleanup
            $sync = & $getSync
            $sync.LinkDirectoryAccounts -eq $true -and
                $sync.PrimaryAuthenticationProviderId -eq $dirId -and
                $sync.AdminRoles -contains "Auditor"
        }
        Test-SgPsAssert "Directory group without sync options uses appliance defaults" {
            Remove-SafeguardUserGroup -Insecure $Context.SuiteData["DirGroupId"]
            $group = New-SafeguardUserGroup @newDirArgs
            $Context.SuiteData["DirGroupId"] = $group.Id
            $sync = & $getSync
            $sync.LinkDirectoryAccounts -eq $false -and $sync.PrimaryAuthenticationProviderId -eq $dirId
        }

        if (-not $fedId) {
            $fedNames = $directoryNames[2..10]
            foreach ($n in $fedNames) { Test-SgPsSkip $n "Could not create a test External Federation provider" }
        }
        else {
            Test-SgPsAssert "Create directory group with PrimaryAuthenticationProvider" {
                Remove-SafeguardUserGroup -Insecure $Context.SuiteData["DirGroupId"]
                $group = New-SafeguardUserGroup @newDirArgs -PrimaryAuthenticationProvider $fedName -LinkDirectoryAccounts $false -AdminRoles Auditor
                $Context.SuiteData["DirGroupId"] = $group.Id
                $sync = & $getSync
                $sync.PrimaryAuthenticationProviderId -eq $fedId -and
                    $sync.LinkDirectoryAccounts -eq $false -and
                    $sync.AdminRoles -contains "Auditor"
            }

            Test-SgPsAssert "Edit LinkDirectoryAccounts false to true preserves provider and AdminRoles" {
                $null = Edit-SafeguardUserGroup -Insecure $Context.SuiteData["DirGroupId"] -LinkDirectoryAccounts $true
                $sync = & $getSync
                $sync.LinkDirectoryAccounts -eq $true -and $sync.PrimaryAuthenticationProviderId -eq $fedId -and $sync.AdminRoles -contains "Auditor"
            }
            Test-SgPsAssert "Edit AdminRoles with sync options omitted preserves them" {
                $null = Edit-SafeguardUserGroup -Insecure $Context.SuiteData["DirGroupId"] -AdminRoles Auditor,PolicyAdmin
                $sync = & $getSync
                $sync.LinkDirectoryAccounts -eq $true -and $sync.PrimaryAuthenticationProviderId -eq $fedId -and
                    $sync.AdminRoles -contains "PolicyAdmin" -and $sync.AdminRoles -contains "Auditor"
            }
            Test-SgPsAssert "Edit ResetPrimaryAuthenticationProvider with link omitted" {
                $null = Edit-SafeguardUserGroup -Insecure $Context.SuiteData["DirGroupId"] -ResetPrimaryAuthenticationProvider
                $sync = & $getSync
                $sync.PrimaryAuthenticationProviderId -eq $dirId -and $sync.LinkDirectoryAccounts -eq $true -and $sync.AdminRoles -contains "PolicyAdmin"
            }
            Test-SgPsAssert "Edit PrimaryAuthenticationProvider by ID" {
                $null = Edit-SafeguardUserGroup -Insecure $Context.SuiteData["DirGroupId"] -PrimaryAuthenticationProvider $fedId
                $sync = & $getSync
                $sync.PrimaryAuthenticationProviderId -eq $fedId -and $sync.LinkDirectoryAccounts -eq $true
            }
            Test-SgPsAssert "Edit LinkDirectoryAccounts true to false preserves provider and AdminRoles" {
                $null = Edit-SafeguardUserGroup -Insecure $Context.SuiteData["DirGroupId"] -LinkDirectoryAccounts $false
                $sync = & $getSync
                $sync.LinkDirectoryAccounts -eq $false -and $sync.PrimaryAuthenticationProviderId -eq $fedId -and $sync.AdminRoles -contains "PolicyAdmin"
            }
            Test-SgPsAssert "Edit PrimaryAuthenticationProvider by provider object" {
                $provider = Get-SafeguardAuthenticationProvider -Insecure $dirId
                $null = Edit-SafeguardUserGroup -Insecure $Context.SuiteData["DirGroupId"] -PrimaryAuthenticationProvider $provider
                $sync = & $getSync
                $sync.PrimaryAuthenticationProviderId -eq $dirId -and $sync.LinkDirectoryAccounts -eq $false
            }
            Test-SgPsAssert "Edit LinkDirectoryAccounts and PrimaryAuthenticationProvider" {
                $null = Edit-SafeguardUserGroup -Insecure $Context.SuiteData["DirGroupId"] -LinkDirectoryAccounts $true -PrimaryAuthenticationProvider $fedName
                $sync = & $getSync
                $sync.LinkDirectoryAccounts -eq $true -and $sync.PrimaryAuthenticationProviderId -eq $fedId -and $sync.AdminRoles -contains "PolicyAdmin"
            }
            Test-SgPsAssert "Edit directory group via pipeline preserves sync options" {
                $ug = Get-SafeguardUserGroup -Insecure $Context.SuiteData["DirGroupId"]
                $ug.DirectoryGroupSyncProperties.LinkDirectoryAccounts = $false
                $edited = $ug | Edit-SafeguardUserGroup -Insecure
                $sync = & $getSync
                $edited.DirectoryGroupSyncProperties.LinkDirectoryAccounts -eq $false -and
                    $sync.LinkDirectoryAccounts -eq $false -and $sync.PrimaryAuthenticationProviderId -eq $fedId -and $sync.AdminRoles -contains "PolicyAdmin"
            }
        }

        Test-SgPsAssertThrows "Invalid authentication provider is rejected" {
            Edit-SafeguardUserGroup -Insecure $Context.SuiteData["DirGroupId"] -PrimaryAuthenticationProvider "$($Context.TestPrefix)_NoSuchProvider"
        } -ExpectedMessage "Unable to find authentication provider"
        Test-SgPsAssertThrows "Invalid authentication provider ID is rejected" {
            Edit-SafeguardUserGroup -Insecure $Context.SuiteData["DirGroupId"] -PrimaryAuthenticationProvider 999999
        } -ExpectedMessage "Unable to find authentication provider"
        Test-SgPsAssertThrows "New-SafeguardUserGroup with invalid provider is rejected" {
            New-SafeguardUserGroup @newDirArgs -PrimaryAuthenticationProvider "$($Context.TestPrefix)_NoSuchProvider"
        } -ExpectedMessage "Unable to find authentication provider"
        Test-SgPsAssert "Rejected provider edits leave settings unchanged" {
            $sync = & $getSync
            $expected = if ($fedId) { $fedId } else { $dirId }
            $sync.PrimaryAuthenticationProviderId -eq $expected
        }

        Test-SgPsAssert "Existing directory users are unchanged" {
            $after = @(Get-SafeguardUser -Insecure -Fields Id,PrimaryAuthenticationProvider |
                Where-Object { $Context.SuiteData["ExistingDirUserIds"] -contains $_.Id })
            $changed = @($existingDirUsers | Where-Object {
                $before = $_
                $now = $after | Where-Object { $_.Id -eq $before.Id }
                -not $now -or $now.PrimaryAuthenticationProvider.Id -ne $before.PrimaryAuthenticationProvider.Id
            })
            $changed.Count -eq 0
        }
    }

    Cleanup = {
        param($Context)
    }
}
