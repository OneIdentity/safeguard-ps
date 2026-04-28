@{
    Name        = "UserPasswordRule"
    Description = "Tests for user password rule management cmdlets"
    Tags        = @("userpasswordrule", "settings")

    Setup = {
        param($Context)
        $prefix = $Context.TestPrefix

        # Save original rule so we can restore it in cleanup
        $originalRule = Get-SafeguardUserPasswordRule -Insecure
        $Context.SuiteData["OriginalRule"] = $originalRule

        Register-SgPsTestCleanup -Description "Restore original user password rule" -Action {
            param($Ctx)
            try { Set-SafeguardUserPasswordRule -Insecure -RuleObject $Ctx.SuiteData["OriginalRule"] } catch {}
        }
    }

    Execute = {
        param($Context)
        $original = $Context.SuiteData["OriginalRule"]

        # -- GET --

        Test-SgPsAssert "Get user password rule returns object with Name" {
            $rule = Get-SafeguardUserPasswordRule -Insecure
            $null -ne $rule -and $null -ne $rule.Name -and $rule.Name.Length -gt 0
        }

        Test-SgPsAssert "Get user password rule has expected properties" {
            $rule = Get-SafeguardUserPasswordRule -Insecure
            $null -ne $rule.MinCharacters -and
                $null -ne $rule.MaxCharacters -and
                $null -ne $rule.AllowUppercaseCharacters -and
                $null -ne $rule.AllowLowercaseCharacters -and
                $null -ne $rule.AllowNumericCharacters -and
                $null -ne $rule.AllowNonAlphaNumericCharacters
        }

        # -- SET via Attributes --

        $newMin = if ($original.MinCharacters -eq 14) { 15 } else { 14 }
        Test-SgPsAssert "Set user password rule MinCharacters via attribute" {
            $result = Set-SafeguardUserPasswordRule -Insecure -MinCharacters $newMin
            $result.MinCharacters -eq $newMin
        }

        Test-SgPsAssert "Set MinCharacters persisted via readback" {
            $readback = Get-SafeguardUserPasswordRule -Insecure
            $readback.MinCharacters -eq $newMin
        }

        $newMax = if ($original.MaxCharacters -eq 100) { 80 } else { 100 }
        Test-SgPsAssert "Set user password rule MaxCharacters via attribute" {
            $result = Set-SafeguardUserPasswordRule -Insecure -MaxCharacters $newMax
            $result.MaxCharacters -eq $newMax
        }

        Test-SgPsAssert "Set MaxCharacters persisted via readback" {
            $readback = Get-SafeguardUserPasswordRule -Insecure
            $readback.MaxCharacters -eq $newMax
        }

        # -- SET via Object --

        Test-SgPsAssert "Set user password rule via RuleObject" {
            $ruleObj = Get-SafeguardUserPasswordRule -Insecure
            $ruleObj.Description = "SgPsTest modified rule"
            $result = Set-SafeguardUserPasswordRule -Insecure -RuleObject $ruleObj
            $result.Description -eq "SgPsTest modified rule"
        }

        Test-SgPsAssert "Set via RuleObject persisted via readback" {
            $readback = Get-SafeguardUserPasswordRule -Insecure
            $readback.Description -eq "SgPsTest modified rule"
        }

        # -- SET does not clobber unrelated properties --

        Test-SgPsAssert "Set attribute does not clobber other properties" {
            $before = Get-SafeguardUserPasswordRule -Insecure
            $beforeName = $before.Name
            $null = Set-SafeguardUserPasswordRule -Insecure -Description "Another change"
            $after = Get-SafeguardUserPasswordRule -Insecure
            $after.Name -eq $beforeName
        }

        # -- Restore before generate/validate tests --
        Set-SafeguardUserPasswordRule -Insecure -RuleObject $original | Out-Null

        # -- GENERATE PASSWORD --

        Test-SgPsAssert "New-SafeguardUserPassword returns a non-empty string" {
            $password = New-SafeguardUserPassword -Insecure
            $null -ne $password -and $password.Length -gt 0
        }

        Test-SgPsAssert "Generated password meets rule length constraints" {
            $rule = Get-SafeguardUserPasswordRule -Insecure
            $password = New-SafeguardUserPassword -Insecure
            $password.Length -ge $rule.MinCharacters -and $password.Length -le $rule.MaxCharacters
        }

        Test-SgPsAssert "New-SafeguardUserPassword with custom RuleObject" {
            $customRule = Get-SafeguardUserPasswordRule -Insecure
            $customRule.MinCharacters = 20
            $customRule.MaxCharacters = 25
            $password = New-SafeguardUserPassword -Insecure -RuleObject $customRule
            $password.Length -ge 20 -and $password.Length -le 25
        }

        # -- VALIDATE PASSWORD --

        Test-SgPsAssert "Test-SafeguardUserPassword returns true for generated password" {
            $password = New-SafeguardUserPassword -Insecure
            $secPassword = ConvertTo-SecureString $password -AsPlainText -Force
            $result = Test-SafeguardUserPassword -Insecure -Password $secPassword
            $result -eq $true
        }

        Test-SgPsAssert "Test-SafeguardUserPassword returns false for too-short password" {
            $secPassword = ConvertTo-SecureString "a" -AsPlainText -Force
            $result = Test-SafeguardUserPassword -Insecure -Password $secPassword
            $result -eq $false
        }

        # -- Restore original rule --

        Test-SgPsAssert "Restore original rule succeeds" {
            $result = Set-SafeguardUserPasswordRule -Insecure -RuleObject $original
            $result.MinCharacters -eq $original.MinCharacters -and
                $result.MaxCharacters -eq $original.MaxCharacters
        }

        Test-SgPsAssert "Restore original rule verified via readback" {
            $readback = Get-SafeguardUserPasswordRule -Insecure
            $readback.MinCharacters -eq $original.MinCharacters -and
                $readback.MaxCharacters -eq $original.MaxCharacters -and
                $readback.Name -eq $original.Name
        }
    }

    Cleanup = {
        param($Context)
        # Registered cleanup restores original rule automatically
    }
}
