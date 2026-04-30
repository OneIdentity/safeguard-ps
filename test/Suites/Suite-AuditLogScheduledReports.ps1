@{
    Name        = "AuditLogScheduledReports"
    Description = "Tests for scheduled audit log report CRUD and execution cmdlets"
    Tags        = @("auditlog","scheduledreports")

    Setup = {
        param($Context)
        $prefix = $Context.TestPrefix
        $reportName = "${prefix}SchedReport"
        $Context.SuiteData["ReportName"] = $reportName

        # Pre-cleanup: remove any stale test reports
        $existing = Get-SafeguardScheduledAuditLogReport -Insecure
        foreach ($r in $existing)
        {
            if ($r.Name -like "${prefix}*")
            {
                try { Remove-SafeguardScheduledAuditLogReport -Insecure -ReportId $r.Id } catch {}
            }
        }
    }

    Execute = {
        param($Context)
        $reportName = $Context.SuiteData["ReportName"]

        # --- New-SafeguardScheduledAuditLogReport tests ---
        Test-SgPsAssert "Create report with name only" {
            $report = New-SafeguardScheduledAuditLogReport -Insecure -Name "${reportName}Basic"
            $Context.SuiteData["BasicId"] = $report.Id
            $report.Name -eq "${reportName}Basic" -and $null -ne $report.Id
        }
        Test-SgPsAssert "Create report with all attributes" {
            $report = New-SafeguardScheduledAuditLogReport -Insecure -Name "${reportName}Full" `
                -Description "Full test report" -CategoryOption Login -SerializationFormat Csv
            $Context.SuiteData["FullId"] = $report.Id
            $report.Name -eq "${reportName}Full" -and
                $report.Description -eq "Full test report" -and
                $report.CategoryOption -eq "Login" -and
                $report.SerializationFormat -eq "Csv"
        }
        Test-SgPsAssert "Create report with Body parameter" {
            $report = New-SafeguardScheduledAuditLogReport -Insecure -Body @{
                Name = "${reportName}Body"
                CategoryOption = "Password"
                SerializationFormat = "Json"
            }
            $Context.SuiteData["BodyId"] = $report.Id
            $report.Name -eq "${reportName}Body" -and
                $report.CategoryOption -eq "Password"
        }
        Test-SgPsAssert "Created report persisted with correct values" {
            $readback = Get-SafeguardScheduledAuditLogReport -Insecure -ReportId $Context.SuiteData["FullId"]
            $readback.Name -eq "${reportName}Full" -and
                $readback.Description -eq "Full test report" -and
                $readback.CategoryOption -eq "Login" -and
                $readback.SerializationFormat -eq "Csv"
        }

        # --- Get-SafeguardScheduledAuditLogReport tests ---
        Test-SgPsAssert "Get all reports returns array" {
            $all = Get-SafeguardScheduledAuditLogReport -Insecure
            $all -is [Array] -and $all.Count -ge 3
        }
        Test-SgPsAssert "Get report by ID returns correct report" {
            $report = Get-SafeguardScheduledAuditLogReport -Insecure -ReportId $Context.SuiteData["BasicId"]
            $report.Id -eq $Context.SuiteData["BasicId"] -and
                $report.Name -eq "${reportName}Basic"
        }
        Test-SgPsAssert "Get report has scheduling properties" {
            $report = Get-SafeguardScheduledAuditLogReport -Insecure -ReportId $Context.SuiteData["FullId"]
            $null -ne $report.ScheduleType -and $null -ne $report.CreatedDate
        }

        # --- Edit-SafeguardScheduledAuditLogReport tests ---
        Test-SgPsAssert "Edit report changes description" {
            $report = Get-SafeguardScheduledAuditLogReport -Insecure -ReportId $Context.SuiteData["BasicId"]
            $report.Description = "Edited description"
            $edited = Edit-SafeguardScheduledAuditLogReport -Insecure -ReportId $report.Id -ReportObject $report
            $edited.Description -eq "Edited description"
        }
        Test-SgPsAssert "Edit report description persisted" {
            $readback = Get-SafeguardScheduledAuditLogReport -Insecure -ReportId $Context.SuiteData["BasicId"]
            $readback.Description -eq "Edited description"
        }
        Test-SgPsAssert "Edit report changes category" {
            $report = Get-SafeguardScheduledAuditLogReport -Insecure -ReportId $Context.SuiteData["BasicId"]
            $report.CategoryOption = "ObjectChange"
            $edited = Edit-SafeguardScheduledAuditLogReport -Insecure -ReportId $report.Id -ReportObject $report
            $edited.CategoryOption -eq "ObjectChange"
        }
        Test-SgPsAssert "Edit report via pipeline" {
            $report = Get-SafeguardScheduledAuditLogReport -Insecure -ReportId $Context.SuiteData["BasicId"]
            $report.SerializationFormat = "Csv"
            $edited = $report | Edit-SafeguardScheduledAuditLogReport -Insecure
            $edited.SerializationFormat -eq "Csv"
        }
        Test-SgPsAssert "Edit report pipeline change persisted" {
            $readback = Get-SafeguardScheduledAuditLogReport -Insecure -ReportId $Context.SuiteData["BasicId"]
            $readback.SerializationFormat -eq "Csv" -and
                $readback.CategoryOption -eq "ObjectChange"
        }

        # --- Invoke-SafeguardScheduledAuditLogReport tests ---
        Test-SgPsAssert "Execute report does not throw" {
            $threw = $false
            try { $null = Invoke-SafeguardScheduledAuditLogReport -Insecure -ReportId $Context.SuiteData["FullId"] }
            catch { $threw = $true }
            -not $threw
        }
        Test-SgPsAssert "Execute report returns array" {
            $results = Invoke-SafeguardScheduledAuditLogReport -Insecure -ReportId $Context.SuiteData["FullId"]
            $results -is [Array]
        }

        # --- Remove-SafeguardScheduledAuditLogReport tests ---
        Test-SgPsAssert "Remove report does not throw" {
            $threw = $false
            try { Remove-SafeguardScheduledAuditLogReport -Insecure -ReportId $Context.SuiteData["BodyId"] }
            catch { $threw = $true }
            -not $threw
        }
        Test-SgPsAssert "Remove report confirmed via get" {
            $threw = $false
            try { $null = Get-SafeguardScheduledAuditLogReport -Insecure -ReportId $Context.SuiteData["BodyId"] }
            catch { $threw = $true }
            $threw
        }
        Test-SgPsAssert "Remove second report" {
            $threw = $false
            try { Remove-SafeguardScheduledAuditLogReport -Insecure -ReportId $Context.SuiteData["BasicId"] }
            catch { $threw = $true }
            -not $threw
        }
        Test-SgPsAssert "Remove last report" {
            $threw = $false
            try { Remove-SafeguardScheduledAuditLogReport -Insecure -ReportId $Context.SuiteData["FullId"] }
            catch { $threw = $true }
            -not $threw
        }
        Test-SgPsAssert "All test reports cleaned up" {
            $remaining = Get-SafeguardScheduledAuditLogReport -Insecure
            $testReports = $remaining | Where-Object { $_.Name -like "${reportName}*" }
            $null -eq $testReports -or $testReports.Count -eq 0
        }
    }

    Cleanup = {
        param($Context)
        # Remove any lingering test reports
        $existing = Get-SafeguardScheduledAuditLogReport -Insecure
        foreach ($r in $existing)
        {
            if ($r.Name -like "$($Context.TestPrefix)*")
            {
                try { Remove-SafeguardScheduledAuditLogReport -Insecure -ReportId $r.Id } catch {}
            }
        }
    }
}
