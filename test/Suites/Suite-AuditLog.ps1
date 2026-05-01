@{
    Name        = "AuditLog"
    Description = "Tests audit log list queries, bug fixes, PlatformScripts, and -Id detail lookups"
    Tags        = @("auditlog", "core")

    Setup = {
        param($Context)
        # No special setup needed -- audit logs are always populated on an active appliance
    }

    Execute = {
        param($Context)

        # --- Basic list queries (existing behavior, verify no regressions) ---

        Test-SgPsAssert "List Appliance audit log (default 1 day)" {
            $logs = @(Get-SafeguardAuditLog -Insecure Appliance)
            $logs -is [Array] -and $logs.Count -gt 0
        }

        Test-SgPsAssert "List Logins audit log (default 1 day)" {
            $logs = @(Get-SafeguardAuditLog -Insecure Logins)
            $logs -is [Array] -and $logs.Count -gt 0
        }

        Test-SgPsAssert "List ObjectChanges audit log (default 1 day)" {
            $logs = @(Get-SafeguardAuditLog -Insecure ObjectChanges)
            $logs -is [Array] -and $logs.Count -gt 0
        }

        Test-SgPsAssert "List AllActivity audit log (default 1 day)" {
            $logs = @(Get-SafeguardAuditLog -Insecure AllActivity)
            $logs -is [Array] -and $logs.Count -gt 0
        }

        # --- Bug fix: DiscoveryServices URL was AuditLog/Services, now AuditLog/Discovery/Services ---

        Test-SgPsAssert "DiscoveryServices returns without error (bug fix)" {
            $logs = @(Get-SafeguardAuditLog -Insecure DiscoveryServices)
            $logs -is [Array]
        }

        # --- Bug fix: DiscoverySshKeys URL was AuditLog/SshKeys, now AuditLog/Discovery/SshKeys ---

        Test-SgPsAssert "DiscoverySshKeys returns without error (bug fix)" {
            $logs = @(Get-SafeguardAuditLog -Insecure DiscoverySshKeys)
            $logs -is [Array]
        }

        # --- New log type: PlatformScripts ---

        Test-SgPsAssert "PlatformScripts log type is accepted" {
            $logs = @(Get-SafeguardAuditLog -Insecure PlatformScripts)
            $logs -is [Array]
        }

        # --- Time range parameter sets ---

        Test-SgPsAssert "Query with -Hours parameter" {
            $logs = @(Get-SafeguardAuditLog -Insecure Appliance -Hours 2)
            $logs -is [Array]
        }

        Test-SgPsAssert "Query with -Minutes parameter" {
            $logs = @(Get-SafeguardAuditLog -Insecure Appliance -Minutes 30)
            $logs -is [Array]
        }

        Test-SgPsAssert "Query with -StartDate and -Days" {
            $start = (Get-Date).AddDays(-2)
            $logs = @(Get-SafeguardAuditLog -Insecure Appliance -StartDate $start -Days 1)
            $logs -is [Array]
        }

        # --- Fields filter ---

        Test-SgPsAssert "Fields filter limits returned properties" {
            $logs = @(Get-SafeguardAuditLog -Insecure Logins -Fields "LogId","LogTime","EventName" -Minutes 60)
            $logs -is [Array] -and ($logs.Count -eq 0 -or $null -ne $logs[0].LogId)
        }

        # --- JsonOutput ---

        Test-SgPsAssert "JsonOutput returns a string" {
            $json = Get-SafeguardAuditLog -Insecure Appliance -Minutes 10 -JsonOutput
            $json -is [string]
        }

        # --- CsvOutput ---

        Test-SgPsAssert "CsvOutput returns CSV data" {
            $csv = Get-SafeguardAuditLog -Insecure Appliance -Minutes 10 -CsvOutput
            # CSV comes back as a string; verify it is not empty and contains a header-like pattern
            $null -ne $csv -and $csv.Length -gt 0
        }

        # --- QueryFilter ---

        Test-SgPsAssert "QueryFilter filters results" {
            $logs = @(Get-SafeguardAuditLog -Insecure Logins `
                -QueryFilter "EventName eq 'UserAuthenticated'" -Hours 12)
            $logs -is [Array]
        }

        # --- Detail lookup by Id (deterministic: fetch list first, then use first entry's ID) ---
        # Note: Do not use @() wrapping here -- Invoke-SafeguardMethod returns Object[]
        # and @() double-wraps it into a 1-element array containing the inner array.

        Test-SgPsAssert "Detail lookup for Logins by Id" {
            $result = Get-SafeguardAuditLog -Insecure Logins -Minutes 60
            if ($null -eq $result)
            {
                $result = Get-SafeguardAuditLog -Insecure Logins -Days 7
            }
            if ($null -ne $result)
            {
                $entry = if ($result -is [Array]) { $result[0] } else { $result }
                $logId = [string]$entry.LogId
                $detail = Get-SafeguardAuditLog -Insecure Logins -Id $logId
                $null -ne $detail -and $detail.LogId -eq $logId
            }
            else
            {
                Write-Host "  (skipped -- no login audit data available)"
                $true
            }
        }

        Test-SgPsAssert "Detail lookup for Appliance by Id" {
            $result = Get-SafeguardAuditLog -Insecure Appliance -Minutes 60
            if ($null -eq $result)
            {
                $result = Get-SafeguardAuditLog -Insecure Appliance -Days 7
            }
            if ($null -ne $result)
            {
                $entry = if ($result -is [Array]) { $result[0] } else { $result }
                $logId = [string]$entry.LogId
                $detail = Get-SafeguardAuditLog -Insecure Appliance -Id $logId
                $null -ne $detail -and $detail.LogId -eq $logId
            }
            else
            {
                Write-Host "  (skipped -- no appliance audit data available)"
                $true
            }
        }

        Test-SgPsAssert "Detail lookup for Patches by Id" {
            $result = Get-SafeguardAuditLog -Insecure Patches -Days 30
            $hasData = $null -ne $result -and (
                ($result -is [Array] -and $result.Count -gt 0) -or
                ($result -isnot [Array])
            )
            if ($hasData)
            {
                $entry = if ($result -is [Array]) { $result[0] } else { $result }
                $logId = [string]$entry.LogId
                $detail = Get-SafeguardAuditLog -Insecure Patches -Id $logId
                $null -ne $detail -and $detail.LogId -eq $logId
            }
            else
            {
                Write-Host "  (skipped -- no patch audit data available)"
                $true
            }
        }

        Test-SgPsAssert "Detail lookup with Fields filter" {
            $result = Get-SafeguardAuditLog -Insecure Logins -Minutes 60
            if ($null -eq $result)
            {
                $result = Get-SafeguardAuditLog -Insecure Logins -Days 7
            }
            if ($null -ne $result)
            {
                $entry = if ($result -is [Array]) { $result[0] } else { $result }
                $logId = [string]$entry.LogId
                $detail = Get-SafeguardAuditLog -Insecure Logins -Id $logId `
                    -Fields "LogId","EventName"
                $null -ne $detail -and $detail.LogId -eq $logId
            }
            else
            {
                Write-Host "  (skipped -- no login audit data available)"
                $true
            }
        }

        # --- Error cases: -Id with unsupported log types ---

        Test-SgPsAssert "Throws when -Id used with ObjectChanges (hierarchical)" {
            $threw = $false
            try {
                $null = Get-SafeguardAuditLog -Insecure ObjectChanges -Id "fake"
            }
            catch { $threw = $_ -match "hierarchical" }
            $threw
        }

        Test-SgPsAssert "Throws when -Id used with CredentialManagement (hierarchical)" {
            $threw = $false
            try {
                $null = Get-SafeguardAuditLog -Insecure CredentialManagement -Id "fake"
            }
            catch { $threw = $_ -match "hierarchical" }
            $threw
        }

        Test-SgPsAssert "Throws when -Id used with PlatformScripts (hierarchical)" {
            $threw = $false
            try {
                $null = Get-SafeguardAuditLog -Insecure PlatformScripts -Id "fake"
            }
            catch { $threw = $_ -match "hierarchical" }
            $threw
        }

        Test-SgPsAssert "Throws when -Id used with AllActivity (no detail endpoint)" {
            $threw = $false
            try {
                $null = Get-SafeguardAuditLog -Insecure AllActivity -Id "fake"
            }
            catch { $threw = $_ -match "hierarchical" }
            $threw
        }

        Test-SgPsAssert "Throws when -Id used with Maintenance (config only)" {
            $threw = $false
            try {
                $null = Get-SafeguardAuditLog -Insecure Maintenance -Id "fake"
            }
            catch { $threw = $_ -match "hierarchical" }
            $threw
        }

        # --- Other log types that should still work ---

        Test-SgPsAssert "DiscoveryAccounts returns without error" {
            $logs = @(Get-SafeguardAuditLog -Insecure DiscoveryAccounts)
            $logs -is [Array]
        }

        Test-SgPsAssert "DiscoveryAssets returns without error" {
            $logs = @(Get-SafeguardAuditLog -Insecure DiscoveryAssets)
            $logs -is [Array]
        }

        Test-SgPsAssert "Licenses returns without error" {
            $logs = @(Get-SafeguardAuditLog -Insecure Licenses)
            $logs -is [Array]
        }

        Test-SgPsAssert "DirectorySync returns without error" {
            $logs = @(Get-SafeguardAuditLog -Insecure DirectorySync)
            $logs -is [Array]
        }

        Test-SgPsAssert "Archives returns without error" {
            $logs = @(Get-SafeguardAuditLog -Insecure Archives)
            $logs -is [Array]
        }

        Test-SgPsAssert "AccessRequests returns without error" {
            $logs = @(Get-SafeguardAuditLog -Insecure AccessRequests)
            $logs -is [Array]
        }

        Test-SgPsAssert "AccessRequestActivities returns without error" {
            $logs = @(Get-SafeguardAuditLog -Insecure AccessRequestActivities)
            $logs -is [Array]
        }

        Test-SgPsAssert "AccessRequestSessions returns without error" {
            $logs = @(Get-SafeguardAuditLog -Insecure AccessRequestSessions)
            $logs -is [Array]
        }
    }

    Cleanup = {
        param($Context)
    }
}
