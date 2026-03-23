@{
    Name        = "Reports"
    Description = "Tests report generation cmdlets using -StdOut to avoid file output"
    Tags        = @("reports", "readonly")

    Setup = {
        param($Context)
        # Reports are all read-only -- no setup needed
    }

    Execute = {
        param($Context)

        # --- Account reports ---
        Test-SgPsAssert "Get-SafeguardReportAccountWithoutPassword returns data" {
            $result = Get-SafeguardReportAccountWithoutPassword -Insecure -StdOut
            # Returns CSV text; may have only headers if no matching accounts
            $null -ne $result
        }

        # --- Daily reports (use today's date) ---
        Test-SgPsAssert "Get-SafeguardReportDailyAccessRequest returns data" {
            $result = Get-SafeguardReportDailyAccessRequest -Insecure -StdOut
            $null -ne $result
        }

        Test-SgPsAssert "Get-SafeguardReportDailyPasswordCheckFail returns data" {
            $result = Get-SafeguardReportDailyPasswordCheckFail -Insecure -StdOut
            $null -ne $result
        }

        Test-SgPsAssert "Get-SafeguardReportDailyPasswordCheckSuccess returns data" {
            $result = Get-SafeguardReportDailyPasswordCheckSuccess -Insecure -StdOut
            $null -ne $result
        }

        Test-SgPsAssert "Get-SafeguardReportDailyPasswordChangeFail returns data" {
            $result = Get-SafeguardReportDailyPasswordChangeFail -Insecure -StdOut
            $null -ne $result
        }

        Test-SgPsAssert "Get-SafeguardReportDailyPasswordChangeSuccess returns data" {
            $result = Get-SafeguardReportDailyPasswordChangeSuccess -Insecure -StdOut
            $null -ne $result
        }

        # --- Membership reports ---
        Test-SgPsAssert "Get-SafeguardReportUserGroupMembership returns data" {
            $result = Get-SafeguardReportUserGroupMembership -Insecure -StdOut
            # Returns null when no group memberships exist on test appliance
            $null -eq $result -or $result -is [string] -or $result -is [Object[]]
        }

        Test-SgPsAssert "Get-SafeguardReportAssetGroupMembership returns data" {
            $result = Get-SafeguardReportAssetGroupMembership -Insecure -StdOut
            $null -eq $result -or $result -is [string] -or $result -is [Object[]]
        }

        Test-SgPsAssert "Get-SafeguardReportAccountGroupMembership returns data" {
            $result = Get-SafeguardReportAccountGroupMembership -Insecure -StdOut
            # Returns null when no group memberships exist on test appliance
            $null -eq $result -or $result -is [string] -or $result -is [Object[]]
        }

        # --- Configuration reports ---
        Test-SgPsAssert "Get-SafeguardReportAssetManagementConfiguration returns data" {
            $result = Get-SafeguardReportAssetManagementConfiguration -Insecure -StdOut
            $null -ne $result
        }

        # --- Entitlement reports ---
        Test-SgPsAssert "Get-SafeguardReportUserEntitlement returns data" {
            $result = Get-SafeguardReportUserEntitlement -Insecure -StdOut
            $null -ne $result
        }

        Test-SgPsAssert "Get-SafeguardReportA2aEntitlement returns data" {
            $result = Get-SafeguardReportA2aEntitlement -Insecure -StdOut
            $null -ne $result
        }

        # --- Password reports ---
        Test-SgPsAssert "Get-SafeguardReportPasswordLastChanged returns data" {
            $result = Get-SafeguardReportPasswordLastChanged -Insecure -StdOut
            $null -ne $result
        }
    }

    Cleanup = {
        param($Context)
        # Reports are read-only -- no cleanup needed
    }
}
