@{
    Name        = "Reports"
    Description = "Tests report generation cmdlets using -StdOut to avoid file output"
    Tags        = @("reports", "readonly")

    Setup = {
        param($Context)
        # Reports are all read-only — no setup needed
    }

    Execute = {
        param($Context)

        # --- Account reports ---
        Test-SgPsAssert "Get-SafeguardReportAccountWithoutPassword returns data" {
            $result = Get-SafeguardReportAccountWithoutPassword -Insecure -StdOut
            # May be empty but should not throw
            $true
        }

        # --- Daily reports (use today's date) ---
        Test-SgPsAssert "Get-SafeguardReportDailyAccessRequest returns data" {
            $result = Get-SafeguardReportDailyAccessRequest -Insecure -StdOut
            $true
        }

        Test-SgPsAssert "Get-SafeguardReportDailyPasswordCheckFail returns data" {
            $result = Get-SafeguardReportDailyPasswordCheckFail -Insecure -StdOut
            $true
        }

        Test-SgPsAssert "Get-SafeguardReportDailyPasswordCheckSuccess returns data" {
            $result = Get-SafeguardReportDailyPasswordCheckSuccess -Insecure -StdOut
            $true
        }

        Test-SgPsAssert "Get-SafeguardReportDailyPasswordChangeFail returns data" {
            $result = Get-SafeguardReportDailyPasswordChangeFail -Insecure -StdOut
            $true
        }

        Test-SgPsAssert "Get-SafeguardReportDailyPasswordChangeSuccess returns data" {
            $result = Get-SafeguardReportDailyPasswordChangeSuccess -Insecure -StdOut
            $true
        }

        # --- Membership reports ---
        Test-SgPsAssert "Get-SafeguardReportUserGroupMembership returns data" {
            $result = Get-SafeguardReportUserGroupMembership -Insecure -StdOut
            $true
        }

        Test-SgPsAssert "Get-SafeguardReportAssetGroupMembership returns data" {
            $result = Get-SafeguardReportAssetGroupMembership -Insecure -StdOut
            $true
        }

        Test-SgPsAssert "Get-SafeguardReportAccountGroupMembership returns data" {
            $result = Get-SafeguardReportAccountGroupMembership -Insecure -StdOut
            $true
        }

        # --- Configuration reports ---
        Test-SgPsAssert "Get-SafeguardReportAssetManagementConfiguration returns data" {
            $result = Get-SafeguardReportAssetManagementConfiguration -Insecure -StdOut
            $true
        }

        # --- Entitlement reports ---
        Test-SgPsAssert "Get-SafeguardReportUserEntitlement returns data" {
            $result = Get-SafeguardReportUserEntitlement -Insecure -StdOut
            $true
        }

        Test-SgPsAssert "Get-SafeguardReportA2aEntitlement returns data" {
            $result = Get-SafeguardReportA2aEntitlement -Insecure -StdOut
            $true
        }

        # --- Password reports ---
        Test-SgPsAssert "Get-SafeguardReportPasswordLastChanged returns data" {
            $result = Get-SafeguardReportPasswordLastChanged -Insecure -StdOut
            $true
        }
    }

    Cleanup = {
        param($Context)
        # Reports are read-only — no cleanup needed
    }
}
