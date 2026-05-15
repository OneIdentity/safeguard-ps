@{
    Name        = "Pipeline Input"
    Description = "Tests ValueFromPipeline support on Edit/Add cmdlets"
    Tags        = @("pipeline", "core")

    Setup = {
        param($Context)

        $prefix = $Context.TestPrefix
        $testAsset = "${prefix}_PipeAsset"
        $testUser = "${prefix}_PipeUser"
        $testUserGroup = "${prefix}_PipeUG"
        $testAssetGroup = "${prefix}_PipeAG"
        $testPassword = "Test1234!abcXYZ"

        # Pre-cleanup
        Remove-SgPsStaleTestObject -Collection "Users" -Name $testUser
        Remove-SgPsStaleTestObject -Collection "Assets" -Name $testAsset
        Remove-SgPsStaleTestObject -Collection "UserGroups" -Name $testUserGroup
        Remove-SgPsStaleTestObject -Collection "AssetGroups" -Name $testAssetGroup

        $Context.SuiteData["TestAsset"] = $testAsset
        $Context.SuiteData["TestUser"] = $testUser
        $Context.SuiteData["TestUserGroup"] = $testUserGroup
        $Context.SuiteData["TestAssetGroup"] = $testAssetGroup
        $Context.SuiteData["TestPassword"] = $testPassword

        # Create test user
        $secPwd = ConvertTo-SecureString $testPassword -AsPlainText -Force
        $user = New-SafeguardUser -Insecure -Provider -1 -NewUserName $testUser `
            -FirstName "Pipe" -LastName "User" -Description "Pipeline test user" -Password $secPwd
        $Context.SuiteData["UserId"] = $user.Id
        Register-SgPsTestCleanup -Description "Delete pipeline test user" -Action {
            param($Ctx)
            try { Remove-SafeguardUser -Insecure $Ctx.SuiteData['UserId'] } catch {}
        }

        # Create test asset
        $asset = New-SafeguardAsset -Insecure -DisplayName $testAsset `
            -Platform 521 -NetworkAddress "10.99.0.1" `
            -ServiceAccountCredentialType "None" -NoSshHostKeyDiscovery
        $Context.SuiteData["AssetId"] = $asset.Id
        Register-SgPsTestCleanup -Description "Delete pipeline test asset" -Action {
            param($Ctx)
            try { Remove-SafeguardAsset -Insecure $Ctx.SuiteData['AssetId'] } catch {}
        }

        # Create test user group
        $ug = New-SafeguardUserGroup -Insecure $testUserGroup -Description "Pipeline test UG"
        $Context.SuiteData["UserGroupId"] = $ug.Id
        Register-SgPsTestCleanup -Description "Delete pipeline test user group" -Action {
            param($Ctx)
            try { Remove-SafeguardUserGroup -Insecure $Ctx.SuiteData['UserGroupId'] } catch {}
        }

        # Create test asset group
        $ag = New-SafeguardAssetGroup -Insecure $testAssetGroup -Description "Pipeline test AG"
        $Context.SuiteData["AssetGroupId"] = $ag.Id
        Register-SgPsTestCleanup -Description "Delete pipeline test asset group" -Action {
            param($Ctx)
            try { Remove-SafeguardAssetGroup -Insecure $Ctx.SuiteData['AssetGroupId'] } catch {}
        }
    }

    Execute = {
        param($Context)

        # ===== Edit-SafeguardUser: pipeline =====
        Test-SgPsAssert "Edit-SafeguardUser accepts pipeline input" {
            $user = Get-SafeguardUser -Insecure $Context.SuiteData["UserId"]
            $user.Description = "Piped edit"
            $edited = $user | Edit-SafeguardUser -Insecure
            $edited.Description -eq "Piped edit"
        }
        Test-SgPsAssert "Edit-SafeguardUser pipeline edit persisted" {
            $readback = Get-SafeguardUser -Insecure $Context.SuiteData["UserId"]
            $readback.Description -eq "Piped edit"
        }

        # ===== Edit-SafeguardAsset: pipeline =====
        Test-SgPsAssert "Edit-SafeguardAsset accepts pipeline input" {
            $asset = Get-SafeguardAsset -Insecure $Context.SuiteData["AssetId"]
            $asset.Description = "Piped asset edit"
            $edited = $asset | Edit-SafeguardAsset -Insecure
            $edited.Description -eq "Piped asset edit"
        }
        Test-SgPsAssert "Edit-SafeguardAsset pipeline edit persisted" {
            $readback = Get-SafeguardAsset -Insecure $Context.SuiteData["AssetId"]
            $readback.Description -eq "Piped asset edit"
        }

        # ===== Edit-SafeguardAssetAccount: pipeline =====
        Test-SgPsAssert "Create account for pipeline test" {
            $acct = New-SafeguardAssetAccount -Insecure -ParentAsset $Context.SuiteData["AssetId"] `
                -NewAccountName "${prefix}_PipeAcct"
            $Context.SuiteData["AccountId"] = $acct.Id
            Register-SgPsTestCleanup -Description "Delete pipeline test account" -Action {
                param($Ctx)
                try { Remove-SafeguardAssetAccount -Insecure -AccountToDelete $Ctx.SuiteData['AccountId'] } catch {}
            }
            $null -ne $acct.Id
        }
        Test-SgPsAssert "Edit-SafeguardAssetAccount accepts pipeline input" {
            $acct = Get-SafeguardAssetAccount -Insecure -AccountToGet $Context.SuiteData["AccountId"]
            $acct.Description = "Piped account edit"
            $edited = $acct | Edit-SafeguardAssetAccount -Insecure
            $edited.Description -eq "Piped account edit"
        }
        Test-SgPsAssert "Edit-SafeguardAssetAccount pipeline edit persisted" {
            $readback = Get-SafeguardAssetAccount -Insecure -AccountToGet $Context.SuiteData["AccountId"]
            $readback.Description -eq "Piped account edit"
        }

        # ===== Edit-SafeguardUserGroup: pipeline =====
        Test-SgPsAssert "Edit-SafeguardUserGroup accepts pipeline input" {
            $ug = Get-SafeguardUserGroup -Insecure $Context.SuiteData["UserGroupId"]
            $ug.Description = "Piped UG edit"
            $edited = $ug | Edit-SafeguardUserGroup -Insecure
            $edited.Description -eq "Piped UG edit"
        }
        Test-SgPsAssert "Edit-SafeguardUserGroup pipeline edit persisted" {
            $readback = Get-SafeguardUserGroup -Insecure $Context.SuiteData["UserGroupId"]
            $readback.Description -eq "Piped UG edit"
        }

        # ===== Edit-SafeguardAssetGroup: pipeline =====
        Test-SgPsAssert "Edit-SafeguardAssetGroup accepts pipeline input" {
            $ag = Get-SafeguardAssetGroup -Insecure $Context.SuiteData["AssetGroupId"]
            $ag.Description = "Piped AG edit"
            $edited = $ag | Edit-SafeguardAssetGroup -Insecure
            $edited.Description -eq "Piped AG edit"
        }
        Test-SgPsAssert "Edit-SafeguardAssetGroup pipeline edit persisted" {
            $readback = Get-SafeguardAssetGroup -Insecure $Context.SuiteData["AssetGroupId"]
            $readback.Description -eq "Piped AG edit"
        }

        # ===== Edit-SafeguardCustomPlatform: pipeline =====
        Test-SgPsAssert "Create custom platform for pipeline test" {
            $plat = New-SafeguardCustomPlatform -Insecure "${prefix}PipePlat"
            $Context.SuiteData["PlatformId"] = $plat.Id
            Register-SgPsTestCleanup -Description "Delete pipeline test platform" -Action {
                param($Ctx)
                try { Remove-SafeguardCustomPlatform -Insecure $Ctx.SuiteData['PlatformId'] } catch {}
            }
            $null -ne $plat.Id
        }
        Test-SgPsAssert "Edit-SafeguardCustomPlatform accepts pipeline input" {
            $plat = Get-SafeguardCustomPlatform -Insecure $Context.SuiteData["PlatformId"]
            $plat.Description = "Piped platform edit"
            $edited = $plat | Edit-SafeguardCustomPlatform -Insecure
            $edited.Description -eq "Piped platform edit"
        }
        Test-SgPsAssert "Edit-SafeguardCustomPlatform pipeline edit persisted" {
            $readback = Get-SafeguardCustomPlatform -Insecure $Context.SuiteData["PlatformId"]
            $readback.Description -eq "Piped platform edit"
        }

        # ===== Edit-SafeguardSyslogServer: pipeline =====
        Test-SgPsAssert "Create syslog server for pipeline test" {
            $server = New-SafeguardSyslogServer -Insecure -NetworkAddress "10.99.99.1" -Name "${prefix}_PipeSyslog"
            $Context.SuiteData["SyslogId"] = $server.Id
            Register-SgPsTestCleanup -Description "Delete pipeline test syslog server" -Action {
                param($Ctx)
                try { Remove-SafeguardSyslogServer -Insecure $Ctx.SuiteData['SyslogId'] } catch {}
            }
            $null -ne $server.Id
        }
        Test-SgPsAssert "Edit-SafeguardSyslogServer accepts pipeline input" {
            $server = Get-SafeguardSyslogServer -Insecure $Context.SuiteData["SyslogId"]
            $server.Name = "${prefix}_PipeSyslogRenamed"
            $edited = $server | Edit-SafeguardSyslogServer -Insecure
            $edited.Name -eq "${prefix}_PipeSyslogRenamed"
        }
        Test-SgPsAssert "Edit-SafeguardSyslogServer pipeline edit persisted" {
            $readback = Get-SafeguardSyslogServer -Insecure $Context.SuiteData["SyslogId"]
            $readback.Name -eq "${prefix}_PipeSyslogRenamed"
        }

        # ===== Verify Attributes parameter set still works =====
        Test-SgPsAssert "Edit-SafeguardUser Attributes set still works" {
            $edited = Edit-SafeguardUser -Insecure $Context.SuiteData["UserId"] -Description "Attributes edit"
            $edited.Description -eq "Attributes edit"
        }
        Test-SgPsAssert "Edit-SafeguardAsset Attributes set still works" {
            $edited = Edit-SafeguardAsset -Insecure $Context.SuiteData["AssetId"] -Description "Attributes edit"
            $edited.Description -eq "Attributes edit"
        }

        # ===== Multi-object pipeline (batch piping) =====
        Test-SgPsAssert "Multiple objects can be piped to Edit-SafeguardAsset" {
            $asset = Get-SafeguardAsset -Insecure $Context.SuiteData["AssetId"]
            $asset.Description = "Batch pipe 1"
            # Single item array to test process{} block iteration
            $result = @($asset) | Edit-SafeguardAsset -Insecure
            @($result).Count -eq 1 -and $result.Description -eq "Batch pipe 1"
        }

        # ===== Edit-SafeguardReasonCode: pipeline (if reason codes exist) =====
        Test-SgPsAssert "Edit-SafeguardReasonCode accepts pipeline input" {
            $code = New-SafeguardReasonCode -Insecure -Name "${prefix}_PipeRC" -Description "Pipeline test reason code"
            $Context.SuiteData["ReasonCodeId"] = $code.Id
            Register-SgPsTestCleanup -Description "Delete pipeline test reason code" -Action {
                param($Ctx)
                try { Remove-SafeguardReasonCode -Insecure $Ctx.SuiteData['ReasonCodeId'] } catch {}
            }
            $code.Description = "Piped RC edit"
            $edited = $code | Edit-SafeguardReasonCode -Insecure
            $edited.Description -eq "Piped RC edit"
        }
    }

    Cleanup = {
        param($Context)
        # Registered cleanups run automatically
    }
}
