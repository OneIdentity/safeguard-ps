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
    }

    Cleanup = {
        param($Context)
    }
}
