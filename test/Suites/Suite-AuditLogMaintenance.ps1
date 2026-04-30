@{
    Name        = "AuditLogMaintenance"
    Description = "Tests for audit log maintenance configuration, run-now, and signing certificate history cmdlets"
    Tags        = @("auditlog","maintenance","certificates")

    Setup = {
        param($Context)
        # Store original maintenance config for restoration
        $config = Get-SafeguardAuditLogMaintenanceConfig -Insecure
        $Context.SuiteData["OriginalConfig"] = $config
    }

    Execute = {
        param($Context)
        $originalConfig = $Context.SuiteData["OriginalConfig"]

        # --- Get-SafeguardAuditLogMaintenanceConfig tests ---
        Test-SgPsAssert "Get maintenance config returns object" {
            $config = Get-SafeguardAuditLogMaintenanceConfig -Insecure
            $null -ne $config
        }
        Test-SgPsAssert "Maintenance config has expected properties" {
            $config = Get-SafeguardAuditLogMaintenanceConfig -Insecure
            $null -ne $config.DayOfWeek -and
                $null -ne $config.StartHour -and
                $null -ne $config.DaysToRetainLogs -and
                $null -ne $config.NextScheduledMaintenance
        }
        Test-SgPsAssert "Maintenance config DaysToRetainLogs is positive integer" {
            $config = Get-SafeguardAuditLogMaintenanceConfig -Insecure
            $config.DaysToRetainLogs -gt 0
        }
        Test-SgPsAssert "Maintenance config has TimeZone info" {
            $config = Get-SafeguardAuditLogMaintenanceConfig -Insecure
            $null -ne $config.TimeZoneId -and $null -ne $config.TimeZoneDisplayName
        }
        Test-SgPsAssert "Maintenance config has scheduling timestamps" {
            $config = Get-SafeguardAuditLogMaintenanceConfig -Insecure
            $null -ne $config.NextScheduledMaintenance -and
                $null -ne $config.LastScheduledMaintenance
        }

        # --- Set-SafeguardAuditLogMaintenanceConfig tests ---
        Test-SgPsAssert "Set maintenance config changes StartHour" {
            $config = Get-SafeguardAuditLogMaintenanceConfig -Insecure
            $newHour = if ($config.StartHour -eq 5) { 6 } else { 5 }
            $config.StartHour = $newHour
            $updated = Set-SafeguardAuditLogMaintenanceConfig -Insecure $config
            $updated.StartHour -eq $newHour
        }
        Test-SgPsAssert "Set maintenance config change persisted" {
            $readback = Get-SafeguardAuditLogMaintenanceConfig -Insecure
            $readback.StartHour -eq 5 -or $readback.StartHour -eq 6
        }
        Test-SgPsAssert "Set maintenance config changes DayOfWeek" {
            $config = Get-SafeguardAuditLogMaintenanceConfig -Insecure
            $newDay = if ($config.DayOfWeek -eq "Sunday") { "Monday" } else { "Sunday" }
            $config.DayOfWeek = $newDay
            $updated = Set-SafeguardAuditLogMaintenanceConfig -Insecure $config
            $updated.DayOfWeek -eq $newDay
        }
        Test-SgPsAssert "Set maintenance config DayOfWeek persisted" {
            $readback = Get-SafeguardAuditLogMaintenanceConfig -Insecure
            $readback.DayOfWeek -eq "Sunday" -or $readback.DayOfWeek -eq "Monday"
        }
        Test-SgPsAssert "Set maintenance config restore original values" {
            $restored = Set-SafeguardAuditLogMaintenanceConfig -Insecure $originalConfig
            $restored.StartHour -eq $originalConfig.StartHour -and
                $restored.DayOfWeek -eq $originalConfig.DayOfWeek
        }
        Test-SgPsAssert "Restored config readback matches original" {
            $readback = Get-SafeguardAuditLogMaintenanceConfig -Insecure
            $readback.StartHour -eq $originalConfig.StartHour -and
                $readback.DayOfWeek -eq $originalConfig.DayOfWeek -and
                $readback.DaysToRetainLogs -eq $originalConfig.DaysToRetainLogs
        }

        # --- Invoke-SafeguardAuditLogMaintenance tests ---
        Test-SgPsAssert "Invoke maintenance does not throw unexpected error" {
            $threw = $false
            try { Invoke-SafeguardAuditLogMaintenance -Insecure }
            catch {
                # 60818 means a maintenance operation is already in progress -- acceptable
                if ($_ -match "60818") { $threw = $false }
                else { $threw = $true }
            }
            -not $threw
        }
        Test-SgPsAssert "Invoke maintenance returns empty or already-in-progress" {
            $success = $false
            try {
                $result = Invoke-SafeguardAuditLogMaintenance -Insecure
                $success = ($null -eq $result -or $result -eq "")
            }
            catch {
                # Already in progress is acceptable
                $success = ($_ -match "60818")
            }
            $success
        }

        # --- Get-SafeguardAuditLogSigningCertificateHistory tests ---
        Test-SgPsAssert "Get signing certificate history returns array" {
            $history = Get-SafeguardAuditLogSigningCertificateHistory -Insecure
            $history -is [Array] -or $null -ne $history
        }
        Test-SgPsAssert "Signing certificate history has at least one entry" {
            $history = Get-SafeguardAuditLogSigningCertificateHistory -Insecure
            if ($history -is [Array]) { $history.Count -ge 1 }
            else { $null -ne $history }
        }
        Test-SgPsAssert "Signing certificate entry has Subject" {
            $history = Get-SafeguardAuditLogSigningCertificateHistory -Insecure
            $entry = if ($history -is [Array]) { $history[0] } else { $history }
            $null -ne $entry.Subject -and $entry.Subject.Length -gt 0
        }
        Test-SgPsAssert "Signing certificate entry has Thumbprint" {
            $history = Get-SafeguardAuditLogSigningCertificateHistory -Insecure
            $entry = if ($history -is [Array]) { $history[0] } else { $history }
            $null -ne $entry.Thumbprint -and $entry.Thumbprint.Length -gt 0
        }
        Test-SgPsAssert "Signing certificate entry has InstalledDate" {
            $history = Get-SafeguardAuditLogSigningCertificateHistory -Insecure
            $entry = if ($history -is [Array]) { $history[0] } else { $history }
            $null -ne $entry.InstalledDate
        }
        Test-SgPsAssert "Signing certificate entry has CertificateType AuditLogSigning" {
            $history = Get-SafeguardAuditLogSigningCertificateHistory -Insecure
            $entry = if ($history -is [Array]) { $history[0] } else { $history }
            $entry.CertificateType -eq "AuditLogSigning"
        }
        Test-SgPsAssert "Signing certificate entry has NotBefore and NotAfter" {
            $history = Get-SafeguardAuditLogSigningCertificateHistory -Insecure
            $entry = if ($history -is [Array]) { $history[0] } else { $history }
            $null -ne $entry.NotBefore -and $null -ne $entry.NotAfter
        }
    }

    Cleanup = {
        param($Context)
        # Restore original maintenance config in case tests left it modified
        $originalConfig = $Context.SuiteData["OriginalConfig"]
        if ($originalConfig)
        {
            try { Set-SafeguardAuditLogMaintenanceConfig -Insecure $originalConfig | Out-Null }
            catch {}
        }
    }
}
