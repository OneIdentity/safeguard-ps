@{
    Name        = "AuditLogAccessRequests"
    Description = "Tests access request activity and session audit log drill-down cmdlets"
    Tags        = @("auditlog", "accessrequests")

    Setup = {
        param($Context)
        # No special setup needed -- audit logs are read-only
        # Capture whether access request data exists for conditional drill-down tests
        $activities = Get-SafeguardAuditLogAccessRequestActivity -Insecure `
            -StartDate (Get-Date).AddDays(-90)
        if ($null -ne $activities -and $activities -is [Array] -and $activities.Count -gt 0)
        {
            $Context.SuiteData["HasActivityData"] = $true
            $Context.SuiteData["FirstActivity"] = $activities[0]
        }
        elseif ($null -ne $activities -and $activities -isnot [Array])
        {
            $Context.SuiteData["HasActivityData"] = $true
            $Context.SuiteData["FirstActivity"] = $activities
        }
        else
        {
            $Context.SuiteData["HasActivityData"] = $false
        }

        $sessions = Get-SafeguardAuditLogAccessRequestSession -Insecure `
            -StartDate (Get-Date).AddDays(-90)
        if ($null -ne $sessions -and $sessions -is [Array] -and $sessions.Count -gt 0)
        {
            $Context.SuiteData["HasSessionData"] = $true
            $Context.SuiteData["FirstSession"] = $sessions[0]
        }
        elseif ($null -ne $sessions -and $sessions -isnot [Array])
        {
            $Context.SuiteData["HasSessionData"] = $true
            $Context.SuiteData["FirstSession"] = $sessions
        }
        else
        {
            $Context.SuiteData["HasSessionData"] = $false
        }
    }

    Execute = {
        param($Context)

        # =======================================================
        # Get-SafeguardAuditLogAccessRequestActivity -- List mode
        # =======================================================

        Test-SgPsAssert "Activity list returns array (default)" {
            $result = Get-SafeguardAuditLogAccessRequestActivity -Insecure
            # Empty array or populated array are both valid
            $null -eq $result -or $result -is [Array] -or $result -is [PSCustomObject]
        }

        Test-SgPsAssert "Activity list with StartDate" {
            $result = Get-SafeguardAuditLogAccessRequestActivity -Insecure `
                -StartDate (Get-Date).AddDays(-7)
            $null -eq $result -or $result -is [Array] -or $result -is [PSCustomObject]
        }

        Test-SgPsAssert "Activity list with StartDate and EndDate" {
            $start = (Get-Date).AddDays(-7)
            $end = (Get-Date).AddDays(-1)
            $result = Get-SafeguardAuditLogAccessRequestActivity -Insecure `
                -StartDate $start -EndDate $end
            $null -eq $result -or $result -is [Array] -or $result -is [PSCustomObject]
        }

        Test-SgPsAssert "Activity list with QueryFilter" {
            $result = Get-SafeguardAuditLogAccessRequestActivity -Insecure `
                -QueryFilter "EventName eq 'AccessRequestCreated'"
            $null -eq $result -or $result -is [Array] -or $result -is [PSCustomObject]
        }

        Test-SgPsAssert "Activity list with Fields" {
            $result = Get-SafeguardAuditLogAccessRequestActivity -Insecure `
                -Fields "Id","LogTime","EventName"
            $null -eq $result -or $result -is [Array] -or $result -is [PSCustomObject]
        }

        Test-SgPsAssert "Activity list with JsonOutput" {
            $json = Get-SafeguardAuditLogAccessRequestActivity -Insecure -JsonOutput
            $null -eq $json -or $json -is [string]
        }

        # --- Activity drill-down (conditional on data availability) ---

        Test-SgPsAssert "Activity drill-down by RequestId" {
            if (-not $Context.SuiteData["HasActivityData"])
            {
                Write-Host "  (skipped -- no access request activity data)"
                return $true
            }
            $entry = $Context.SuiteData["FirstActivity"]
            $requestId = [string]$entry.RequestId
            $result = Get-SafeguardAuditLogAccessRequestActivity -Insecure `
                -RequestId $requestId
            $null -ne $result
        }

        Test-SgPsAssert "Activity detail by RequestId and LogId" {
            if (-not $Context.SuiteData["HasActivityData"])
            {
                Write-Host "  (skipped -- no access request activity data)"
                return $true
            }
            $entry = $Context.SuiteData["FirstActivity"]
            $requestId = [string]$entry.RequestId
            # The API may use Id or LogId as the detail key
            $logId = if ($null -ne $entry.Id) { [string]$entry.Id } else { [string]$entry.LogId }
            if ([string]::IsNullOrEmpty($logId))
            {
                Write-Host "  (skipped -- no usable Id or LogId on entry)"
                return $true
            }
            $detail = Get-SafeguardAuditLogAccessRequestActivity -Insecure `
                -RequestId $requestId -LogId $logId
            $null -ne $detail
        }

        # --- Activity error cases ---

        Test-SgPsAssert "Activity throws when UserId used with RequestId" {
            $threw = $false
            try {
                $null = Get-SafeguardAuditLogAccessRequestActivity -Insecure `
                    -RequestId "fake" -UserId 1
            }
            catch { $threw = $_ -match "only supported on the top-level" }
            $threw
        }

        Test-SgPsAssert "Activity throws when AssetId used with RequestId" {
            $threw = $false
            try {
                $null = Get-SafeguardAuditLogAccessRequestActivity -Insecure `
                    -RequestId "fake" -AssetId 1
            }
            catch { $threw = $_ -match "only supported on the top-level" }
            $threw
        }

        Test-SgPsAssert "Activity throws when AccountId used with RequestId" {
            $threw = $false
            try {
                $null = Get-SafeguardAuditLogAccessRequestActivity -Insecure `
                    -RequestId "fake" -AccountId 1
            }
            catch { $threw = $_ -match "only supported on the top-level" }
            $threw
        }

        Test-SgPsAssert "Activity rejects UserId of 0" {
            $threw = $false
            try {
                $null = Get-SafeguardAuditLogAccessRequestActivity -Insecure -UserId 0
            }
            catch { $threw = $true }
            $threw
        }

        # =======================================================
        # Get-SafeguardAuditLogAccessRequestSession -- List mode
        # =======================================================

        Test-SgPsAssert "Session list returns array (default)" {
            $result = Get-SafeguardAuditLogAccessRequestSession -Insecure
            $null -eq $result -or $result -is [Array] -or $result -is [PSCustomObject]
        }

        Test-SgPsAssert "Session list with StartDate" {
            $result = Get-SafeguardAuditLogAccessRequestSession -Insecure `
                -StartDate (Get-Date).AddDays(-7)
            $null -eq $result -or $result -is [Array] -or $result -is [PSCustomObject]
        }

        Test-SgPsAssert "Session list with Fields" {
            $result = Get-SafeguardAuditLogAccessRequestSession -Insecure `
                -Fields "Id","LogTime","EventName"
            $null -eq $result -or $result -is [Array] -or $result -is [PSCustomObject]
        }

        Test-SgPsAssert "Session list with JsonOutput" {
            $json = Get-SafeguardAuditLogAccessRequestSession -Insecure -JsonOutput
            $null -eq $json -or $json -is [string]
        }

        # --- Session drill-down (conditional on data availability) ---

        Test-SgPsAssert "Session drill-down by RequestId" {
            if (-not $Context.SuiteData["HasSessionData"])
            {
                Write-Host "  (skipped -- no access request session data)"
                return $true
            }
            $entry = $Context.SuiteData["FirstSession"]
            $requestId = [string]$entry.RequestId
            $result = Get-SafeguardAuditLogAccessRequestSession -Insecure `
                -RequestId $requestId
            $null -ne $result
        }

        Test-SgPsAssert "Session drill-down by RequestId and SessionId" {
            if (-not $Context.SuiteData["HasSessionData"])
            {
                Write-Host "  (skipped -- no access request session data)"
                return $true
            }
            $entry = $Context.SuiteData["FirstSession"]
            $requestId = [string]$entry.RequestId
            $sessionId = [int]$entry.SessionId
            if ($sessionId -gt 0)
            {
                $result = Get-SafeguardAuditLogAccessRequestSession -Insecure `
                    -RequestId $requestId -SessionId $sessionId
                $null -ne $result
            }
            else
            {
                Write-Host "  (skipped -- SessionId not available in data)"
                $true
            }
        }

        # --- Session error cases ---

        Test-SgPsAssert "Session throws when SessionId used without RequestId" {
            $threw = $false
            try {
                $null = Get-SafeguardAuditLogAccessRequestSession -Insecure -SessionId 1
            }
            catch { $threw = $_ -match "requires -RequestId" }
            $threw
        }

        Test-SgPsAssert "Session throws when UserId used with RequestId" {
            $threw = $false
            try {
                $null = Get-SafeguardAuditLogAccessRequestSession -Insecure `
                    -RequestId "fake" -UserId 1
            }
            catch { $threw = $_ -match "only supported on the top-level" }
            $threw
        }

        Test-SgPsAssert "Session rejects SessionId of 0" {
            $threw = $false
            try {
                $null = Get-SafeguardAuditLogAccessRequestSession -Insecure `
                    -RequestId "fake" -SessionId 0
            }
            catch { $threw = $true }
            $threw
        }

        Test-SgPsAssert "Session rejects negative SessionId" {
            $threw = $false
            try {
                $null = Get-SafeguardAuditLogAccessRequestSession -Insecure `
                    -RequestId "fake" -SessionId -1
            }
            catch { $threw = $true }
            $threw
        }
    }

    Cleanup = {
        param($Context)
    }
}
