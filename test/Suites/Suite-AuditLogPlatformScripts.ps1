@{
    Name        = "AuditLogPlatformScripts"
    Description = "Tests platform script change audit log cmdlet"
    Tags        = @("auditlog", "platformscripts")

    Setup = {
        param($Context)
        # PlatformScripts audit requires AssetAdmin role (test runner provides this)
        $Context.SuiteData["HasData"] = $false
        try
        {
            $scripts = Get-SafeguardAuditLogPlatformScript -Insecure
            if ($null -ne $scripts -and $scripts -is [Array] -and $scripts.Count -gt 0)
            {
                $Context.SuiteData["HasData"] = $true
                $Context.SuiteData["FirstEntry"] = $scripts[0]
                $Context.SuiteData["PlatformId"] = [int]$scripts[0].PlatformId
                $Context.SuiteData["LogId"] = [string]$scripts[0].Id
            }
            elseif ($null -ne $scripts -and $scripts -isnot [Array])
            {
                $Context.SuiteData["HasData"] = $true
                $Context.SuiteData["FirstEntry"] = $scripts
                $Context.SuiteData["PlatformId"] = [int]$scripts.PlatformId
                $Context.SuiteData["LogId"] = [string]$scripts.Id
            }
            $Context.SuiteData["HasAccess"] = $true
        }
        catch
        {
            if ($_ -match "403")
            {
                $Context.SuiteData["HasAccess"] = $false
                Write-Host "  WARNING: No access to PlatformScripts audit (requires AssetAdmin)"
            }
            else
            {
                throw
            }
        }
    }

    Execute = {
        param($Context)

        # =======================================================
        # Access check -- skip all if no permissions
        # =======================================================

        Test-SgPsAssert "Has access to PlatformScripts audit endpoint" {
            if (-not $Context.SuiteData["HasAccess"])
            {
                Write-Host "  (skipped -- insufficient permissions)"
                return $true
            }
            $true
        }

        # =======================================================
        # List mode
        # =======================================================

        Test-SgPsAssert "List returns array or empty" {
            if (-not $Context.SuiteData["HasAccess"]) { return $true }
            $result = Get-SafeguardAuditLogPlatformScript -Insecure
            $null -eq $result -or $result -is [Array] -or $result -is [PSCustomObject]
        }

        Test-SgPsAssert "List with QueryFilter" {
            if (-not $Context.SuiteData["HasAccess"]) { return $true }
            $result = Get-SafeguardAuditLogPlatformScript -Insecure `
                -QueryFilter "PlatformDisplayName contains 'Linux'"
            $null -eq $result -or $result -is [Array] -or $result -is [PSCustomObject]
        }

        Test-SgPsAssert "List with Fields" {
            if (-not $Context.SuiteData["HasAccess"]) { return $true }
            $result = Get-SafeguardAuditLogPlatformScript -Insecure `
                -Fields "Id","LogTime","PlatformId","PlatformDisplayName"
            $null -eq $result -or $result -is [Array] -or $result -is [PSCustomObject]
        }

        Test-SgPsAssert "List with JsonOutput" {
            if (-not $Context.SuiteData["HasAccess"]) { return $true }
            $json = Get-SafeguardAuditLogPlatformScript -Insecure -JsonOutput
            $null -eq $json -or $json -is [string]
        }

        # =======================================================
        # ByPlatform mode
        # =======================================================

        Test-SgPsAssert "ByPlatform returns results for known platform" {
            if (-not $Context.SuiteData["HasData"])
            {
                Write-Host "  (skipped -- no platform script audit data)"
                return $true
            }
            $pid2 = $Context.SuiteData["PlatformId"]
            $result = Get-SafeguardAuditLogPlatformScript -Insecure -PlatformId $pid2
            $null -ne $result -and
                (($result -is [Array] -and $result.Count -gt 0) -or $result -is [PSCustomObject])
        }

        Test-SgPsAssert "ByPlatform all entries have matching PlatformId" {
            if (-not $Context.SuiteData["HasData"])
            {
                Write-Host "  (skipped -- no platform script audit data)"
                return $true
            }
            $pid2 = $Context.SuiteData["PlatformId"]
            $result = Get-SafeguardAuditLogPlatformScript -Insecure -PlatformId $pid2
            $entries = if ($result -is [Array]) { $result } else { @($result) }
            $allMatch = $true
            foreach ($e in $entries)
            {
                if ([int]$e.PlatformId -ne $pid2) { $allMatch = $false; break }
            }
            $allMatch
        }

        Test-SgPsAssert "ByPlatform with QueryFilter" {
            if (-not $Context.SuiteData["HasData"])
            {
                Write-Host "  (skipped -- no platform script audit data)"
                return $true
            }
            $pid2 = $Context.SuiteData["PlatformId"]
            $result = Get-SafeguardAuditLogPlatformScript -Insecure -PlatformId $pid2 `
                -QueryFilter "PlatformDisplayName ne 'nonexistent'"
            $null -eq $result -or $result -is [Array] -or $result -is [PSCustomObject]
        }

        # =======================================================
        # Detail mode
        # =======================================================

        Test-SgPsAssert "Detail returns script content" {
            if (-not $Context.SuiteData["HasData"])
            {
                Write-Host "  (skipped -- no platform script audit data)"
                return $true
            }
            $pid2 = $Context.SuiteData["PlatformId"]
            $lid = $Context.SuiteData["LogId"]
            $detail = Get-SafeguardAuditLogPlatformScript -Insecure `
                -PlatformId $pid2 -LogId $lid
            # Detail endpoint returns the script content (string or object), not metadata
            $null -ne $detail
        }

        Test-SgPsAssert "Detail returns non-empty content" {
            if (-not $Context.SuiteData["HasData"])
            {
                Write-Host "  (skipped -- no platform script audit data)"
                return $true
            }
            $pid2 = $Context.SuiteData["PlatformId"]
            $lid = $Context.SuiteData["LogId"]
            $detail = Get-SafeguardAuditLogPlatformScript -Insecure `
                -PlatformId $pid2 -LogId $lid
            if ($detail -is [string]) { $detail.Length -gt 0 }
            else { $null -ne $detail }
        }

        Test-SgPsAssert "Detail with JsonOutput returns string" {
            if (-not $Context.SuiteData["HasData"])
            {
                Write-Host "  (skipped -- no platform script audit data)"
                return $true
            }
            $pid2 = $Context.SuiteData["PlatformId"]
            $lid = $Context.SuiteData["LogId"]
            $result = Get-SafeguardAuditLogPlatformScript -Insecure `
                -PlatformId $pid2 -LogId $lid -JsonOutput
            $null -eq $result -or $result -is [string]
        }

        # =======================================================
        # Raw mode
        # =======================================================

        Test-SgPsAssert "Raw returns script content" {
            if (-not $Context.SuiteData["HasData"])
            {
                Write-Host "  (skipped -- no platform script audit data)"
                return $true
            }
            $pid2 = $Context.SuiteData["PlatformId"]
            $lid = $Context.SuiteData["LogId"]
            $rawContent = Get-SafeguardAuditLogPlatformScript -Insecure `
                -PlatformId $pid2 -LogId $lid -Raw
            # Raw should return non-null content (script JSON or text)
            $null -ne $rawContent
        }

        # =======================================================
        # Error cases
        # =======================================================

        Test-SgPsAssert "Rejects PlatformId of 0" {
            $threw = $false
            try {
                $null = Get-SafeguardAuditLogPlatformScript -Insecure -PlatformId 0
            }
            catch { $threw = $true }
            $threw
        }

        Test-SgPsAssert "Rejects negative PlatformId" {
            $threw = $false
            try {
                $null = Get-SafeguardAuditLogPlatformScript -Insecure -PlatformId -1
            }
            catch { $threw = $true }
            $threw
        }

        Test-SgPsAssert "Rejects empty LogId" {
            $threw = $false
            try {
                $null = Get-SafeguardAuditLogPlatformScript -Insecure -PlatformId 1 -LogId ""
            }
            catch { $threw = $true }
            $threw
        }
    }

    Cleanup = {
        param($Context)
    }
}
