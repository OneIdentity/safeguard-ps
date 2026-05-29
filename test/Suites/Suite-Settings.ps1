@{
    Name        = "Settings"
    Description = "Tests appliance and core settings read/write operations"
    Tags        = @("settings", "configuration")

    Setup = {
        param($Context)
        $prefix = $Context.TestPrefix
        # Pre-cleanup stale syslog server from prior failed runs
        try {
            $stale = Get-SafeguardSyslogServer -Insecure | Where-Object { $_.Name -match $prefix }
            $stale | ForEach-Object { Remove-SafeguardSyslogServer -Insecure $_.Id }
        } catch {}
    }

    Execute = {
        param($Context)

        # --- Get-SafeguardApplianceSetting (list all) ---
        Test-SgPsAssert "Get-SafeguardApplianceSetting lists all settings" {
            $settings = Get-SafeguardApplianceSetting -Insecure
            $list = @($settings)
            $list.Count -ge 1
        }

        # --- Get-SafeguardApplianceSetting by name ---
        Test-SgPsAssert "Get-SafeguardApplianceSetting by name" {
            $settings = Get-SafeguardApplianceSetting -Insecure
            $list = @($settings)
            $first = $list[0]
            $Context.SuiteData["AppSettingName"] = $first.Name
            $Context.SuiteData["AppSettingOriginalValue"] = $first.Value
            $setting = Get-SafeguardApplianceSetting -Insecure $first.Name
            $setting.Name -eq $first.Name
        }

        # --- Set/Restore-SafeguardApplianceSetting roundtrip ---
        Test-SgPsAssert "Set-SafeguardApplianceSetting updates a setting" {
            $name = $Context.SuiteData["AppSettingName"]
            $origValue = $Context.SuiteData["AppSettingOriginalValue"]

            Register-SgPsTestCleanup -Description "Restore appliance setting $name" -Action {
                param($Ctx)
                try {
                    Set-SafeguardApplianceSetting -Insecure `
                        $Ctx.SuiteData['AppSettingName'] $Ctx.SuiteData['AppSettingOriginalValue']
                } catch {}
            }

            # Set same value (safe roundtrip -- avoids changing behavior)
            $result = Set-SafeguardApplianceSetting -Insecure $name $origValue
            $result.Name -eq $name
        }
        Test-SgPsAssert "Set-SafeguardApplianceSetting change persisted" {
            $readback = Get-SafeguardApplianceSetting -Insecure $Context.SuiteData["AppSettingName"]
            $readback.Name -eq $Context.SuiteData["AppSettingName"]
        }

        # --- Get-SafeguardCoreSetting (list all) ---
        Test-SgPsAssert "Get-SafeguardCoreSetting lists all settings" {
            $settings = Get-SafeguardCoreSetting -Insecure
            $list = @($settings)
            $list.Count -ge 1
        }

        # --- Get-SafeguardCoreSetting by name ---
        Test-SgPsAssert "Get-SafeguardCoreSetting by name" {
            $settings = Get-SafeguardCoreSetting -Insecure
            $list = @($settings)
            $first = $list[0]
            $Context.SuiteData["CoreSettingName"] = $first.Name
            $Context.SuiteData["CoreSettingOriginalValue"] = $first.Value
            $setting = Get-SafeguardCoreSetting -Insecure $first.Name
            $setting.Name -eq $first.Name
        }

        # --- Set/Restore-SafeguardCoreSetting roundtrip ---
        Test-SgPsAssert "Set-SafeguardCoreSetting updates a setting" {
            $name = $Context.SuiteData["CoreSettingName"]
            $origValue = $Context.SuiteData["CoreSettingOriginalValue"]

            Register-SgPsTestCleanup -Description "Restore core setting $name" -Action {
                param($Ctx)
                try {
                    Set-SafeguardCoreSetting -Insecure `
                        $Ctx.SuiteData['CoreSettingName'] $Ctx.SuiteData['CoreSettingOriginalValue']
                } catch {}
            }

            # Set same value (safe roundtrip)
            $result = Set-SafeguardCoreSetting -Insecure $name $origValue
            $result.Name -eq $name
        }
        Test-SgPsAssert "Set-SafeguardCoreSetting change persisted" {
            $readback = Get-SafeguardCoreSetting -Insecure $Context.SuiteData["CoreSettingName"]
            $readback.Name -eq $Context.SuiteData["CoreSettingName"]
        }

        # --- Get-SafeguardCoreSetting with Fields ---
        Test-SgPsAssert "Get-SafeguardCoreSetting with Fields" {
            $settings = Get-SafeguardCoreSetting -Insecure -Fields "Name","Value"
            $list = @($settings)
            $list.Count -ge 1 -and $null -ne $list[0].Name
        }

        # =========================================
        # Syslog Server pipeline tests
        # =========================================

        # --- New-SafeguardSyslogServer ---
        Test-SgPsAssert "New-SafeguardSyslogServer creates a server" {
            $prefix = $Context.TestPrefix
            $server = New-SafeguardSyslogServer -Insecure -NetworkAddress "10.99.99.1" `
                -Name "${prefix}_Syslog"
            $Context.SuiteData["SyslogId"] = $server.Id

            Register-SgPsTestCleanup -Description "Delete test syslog server" -Action {
                param($Ctx)
                try { Remove-SafeguardSyslogServer -Insecure $Ctx.SuiteData['SyslogId'] } catch {}
            }
            $server.Name -eq "${prefix}_Syslog"
        }

        # --- Edit-SafeguardSyslogServer via pipeline ---
        Test-SgPsAssert "Edit-SafeguardSyslogServer via pipeline" {
            $prefix = $Context.TestPrefix
            $server = Get-SafeguardSyslogServer -Insecure $Context.SuiteData["SyslogId"]
            $server.Name = "${prefix}_SyslogRenamed"
            $edited = $server | Edit-SafeguardSyslogServer -Insecure
            $edited.Name -eq "${prefix}_SyslogRenamed"
        }
        Test-SgPsAssert "Edit-SafeguardSyslogServer pipeline edit persisted" {
            $prefix = $Context.TestPrefix
            $readback = Get-SafeguardSyslogServer -Insecure $Context.SuiteData["SyslogId"]
            $readback.Name -eq "${prefix}_SyslogRenamed"
        }

        # =========================================
        # OAuth2 Grant Type tests
        # =========================================

        # Save original state for cleanup
        Test-SgPsAssert "Get-SafeguardOAuth2GrantType returns a list" {
            $grantTypes = Get-SafeguardOAuth2GrantType -Insecure
            $Context.SuiteData["OriginalGrantTypes"] = $grantTypes

            Register-SgPsTestCleanup -Description "Restore OAuth2 grant types" -Action {
                param($Ctx)
                try {
                    $original = $Ctx.SuiteData['OriginalGrantTypes']
                    # Disable all first
                    @("AuthorizationCode", "Implicit", "ResourceOwner", "DeviceCode") | ForEach-Object {
                        try { Disable-SafeguardOAuth2GrantType -Insecure $_ } catch {}
                    }
                    # Re-enable original set
                    if ($original -and $original.Count -gt 0) {
                        $original | ForEach-Object {
                            try { Enable-SafeguardOAuth2GrantType -Insecure $_ } catch {}
                        }
                    }
                } catch {}
            }

            $grantTypes -is [array]
        }

        # --- Enable-SafeguardOAuth2GrantType ---
        Test-SgPsAssert "Enable-SafeguardOAuth2GrantType enables a grant type" {
            $result = Enable-SafeguardOAuth2GrantType -Insecure "Implicit"
            $result -contains "Implicit"
        }

        Test-SgPsAssert "Enable-SafeguardOAuth2GrantType is idempotent" {
            $before = Get-SafeguardOAuth2GrantType -Insecure
            $result = Enable-SafeguardOAuth2GrantType -Insecure "Implicit"
            $result.Count -eq $before.Count
        }

        Test-SgPsAssert "Get-SafeguardOAuth2GrantType confirms enable" {
            $grantTypes = Get-SafeguardOAuth2GrantType -Insecure
            $grantTypes -contains "Implicit"
        }

        # --- Disable-SafeguardOAuth2GrantType ---
        Test-SgPsAssert "Disable-SafeguardOAuth2GrantType disables a grant type" {
            $result = Disable-SafeguardOAuth2GrantType -Insecure "Implicit"
            $result -notcontains "Implicit"
        }

        Test-SgPsAssert "Disable-SafeguardOAuth2GrantType is idempotent" {
            $before = Get-SafeguardOAuth2GrantType -Insecure
            $result = Disable-SafeguardOAuth2GrantType -Insecure "Implicit"
            $result.Count -eq $before.Count
        }

        Test-SgPsAssert "Get-SafeguardOAuth2GrantType confirms disable" {
            $grantTypes = Get-SafeguardOAuth2GrantType -Insecure
            $grantTypes -notcontains "Implicit"
        }

        # --- Enable multiple grant types ---
        Test-SgPsAssert "Enable-SafeguardOAuth2GrantType supports multiple types" {
            Enable-SafeguardOAuth2GrantType -Insecure "AuthorizationCode"
            $result = Enable-SafeguardOAuth2GrantType -Insecure "DeviceCode"
            ($result -contains "AuthorizationCode") -and ($result -contains "DeviceCode")
        }

        # --- Disable all ---
        Test-SgPsAssert "Disable-SafeguardOAuth2GrantType can clear all" {
            Disable-SafeguardOAuth2GrantType -Insecure "AuthorizationCode"
            Disable-SafeguardOAuth2GrantType -Insecure "DeviceCode"
            Disable-SafeguardOAuth2GrantType -Insecure "Implicit"
            $result = Disable-SafeguardOAuth2GrantType -Insecure "ResourceOwner"
            $result.Count -eq 0
        }
    }

    Cleanup = {
        param($Context)
    }
}
