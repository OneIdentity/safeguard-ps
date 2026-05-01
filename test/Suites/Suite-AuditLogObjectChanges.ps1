@{
    Name        = "AuditLogObjectChanges"
    Description = "Tests object change and discovery drill-down audit log cmdlets"
    Tags        = @("auditlog", "objectchanges", "discovery")

    Setup = {
        param($Context)
        # ObjectChanges has abundant data; capture first entry for drill-down tests
        $changes = Get-SafeguardAuditLogObjectChange -Insecure User `
            -StartDate (Get-Date).AddDays(-30)
        if ($changes -is [Array] -and $changes.Count -gt 0)
        {
            $Context.SuiteData["HasObjectChangeData"] = $true
            $Context.SuiteData["FirstChange"] = $changes[0]
            # Find a distinct ObjectId with changes
            $Context.SuiteData["TestObjectType"] = "User"
            $Context.SuiteData["TestObjectId"] = [string]$changes[0].ObjectId
            $Context.SuiteData["TestLogId"] = [string]$changes[0].Id
        }
        else
        {
            $Context.SuiteData["HasObjectChangeData"] = $false
        }

        # Check if discovery data exists (requires AssetAdmin role from test runner)
        $Context.SuiteData["HasDiscoveryData"] = $false
        try
        {
            $discAccounts = Invoke-SafeguardMethod -Insecure Core GET "AuditLog/Discovery/Accounts" `
                -Parameters @{ startDate = (Get-Date).AddDays(-90).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }
            if ($discAccounts -is [Array] -and $discAccounts.Count -gt 0)
            {
                $Context.SuiteData["HasDiscoveryData"] = $true
                $Context.SuiteData["DiscoveryLogId"] = [string]$discAccounts[0].Id
                $Context.SuiteData["DiscoveryType"] = "Accounts"
            }
        }
        catch
        {
            # 403 or other error -- discovery data not accessible
        }
    }

    Execute = {
        param($Context)

        # =======================================================
        # Get-SafeguardAuditLogObjectChange -- ByType
        # =======================================================

        Test-SgPsAssert "ObjectChange ByType returns results for User" {
            $result = Get-SafeguardAuditLogObjectChange -Insecure User `
                -StartDate (Get-Date).AddDays(-30)
            $result -is [Array] -and $result.Count -gt 0
        }

        Test-SgPsAssert "ObjectChange ByType with StartDate and EndDate" {
            $start = (Get-Date).AddDays(-7)
            $end = (Get-Date)
            $result = Get-SafeguardAuditLogObjectChange -Insecure User `
                -StartDate $start -EndDate $end
            $null -eq $result -or $result -is [Array] -or $result -is [PSCustomObject]
        }

        Test-SgPsAssert "ObjectChange ByType with QueryFilter" {
            $result = Get-SafeguardAuditLogObjectChange -Insecure User `
                -StartDate (Get-Date).AddDays(-30) `
                -QueryFilter "EventName eq 'UserCreated'"
            $null -eq $result -or $result -is [Array] -or $result -is [PSCustomObject]
        }

        Test-SgPsAssert "ObjectChange ByType with Fields" {
            $result = Get-SafeguardAuditLogObjectChange -Insecure User `
                -StartDate (Get-Date).AddDays(-30) `
                -Fields "Id","LogTime","EventName","ObjectName"
            $null -eq $result -or $result -is [Array] -or $result -is [PSCustomObject]
        }

        Test-SgPsAssert "ObjectChange ByType with JsonOutput" {
            $json = Get-SafeguardAuditLogObjectChange -Insecure User `
                -StartDate (Get-Date).AddDays(-1) -JsonOutput
            $null -eq $json -or $json -is [string]
        }

        Test-SgPsAssert "ObjectChange accepts various object types" {
            # Test with a type that may or may not have data
            $result = Get-SafeguardAuditLogObjectChange -Insecure IdentityProvider `
                -StartDate (Get-Date).AddDays(-30)
            $null -eq $result -or $result -is [Array] -or $result -is [PSCustomObject]
        }

        # =======================================================
        # Get-SafeguardAuditLogObjectChange -- ByObject
        # =======================================================

        Test-SgPsAssert "ObjectChange ByObject returns changes for a specific object" {
            if (-not $Context.SuiteData["HasObjectChangeData"])
            {
                Write-Host "  (skipped -- no object change data)"
                return $true
            }
            $objType = $Context.SuiteData["TestObjectType"]
            $objId = $Context.SuiteData["TestObjectId"]
            $result = Get-SafeguardAuditLogObjectChange -Insecure $objType `
                -ObjectId $objId -StartDate (Get-Date).AddDays(-30)
            $result -is [Array] -and $result.Count -gt 0
        }

        Test-SgPsAssert "ObjectChange ByObject all entries have matching ObjectId" {
            if (-not $Context.SuiteData["HasObjectChangeData"])
            {
                Write-Host "  (skipped -- no object change data)"
                return $true
            }
            $objType = $Context.SuiteData["TestObjectType"]
            $objId = $Context.SuiteData["TestObjectId"]
            $result = Get-SafeguardAuditLogObjectChange -Insecure $objType `
                -ObjectId $objId -StartDate (Get-Date).AddDays(-30)
            $allMatch = $true
            foreach ($entry in $result)
            {
                if ([string]$entry.ObjectId -ne $objId)
                {
                    $allMatch = $false
                    break
                }
            }
            $allMatch
        }

        # =======================================================
        # Get-SafeguardAuditLogObjectChange -- Detail
        # =======================================================

        Test-SgPsAssert "ObjectChange Detail returns a single entry" {
            if (-not $Context.SuiteData["HasObjectChangeData"])
            {
                Write-Host "  (skipped -- no object change data)"
                return $true
            }
            $objType = $Context.SuiteData["TestObjectType"]
            $objId = $Context.SuiteData["TestObjectId"]
            $logId = $Context.SuiteData["TestLogId"]
            $detail = Get-SafeguardAuditLogObjectChange -Insecure $objType `
                -ObjectId $objId -LogId $logId
            $null -ne $detail -and $detail.Id -eq $logId
        }

        Test-SgPsAssert "ObjectChange Detail has expected properties" {
            if (-not $Context.SuiteData["HasObjectChangeData"])
            {
                Write-Host "  (skipped -- no object change data)"
                return $true
            }
            $objType = $Context.SuiteData["TestObjectType"]
            $objId = $Context.SuiteData["TestObjectId"]
            $logId = $Context.SuiteData["TestLogId"]
            $detail = Get-SafeguardAuditLogObjectChange -Insecure $objType `
                -ObjectId $objId -LogId $logId
            $null -ne $detail.EventName -and
                $null -ne $detail.LogTime -and
                [string]$detail.ObjectId -eq $objId
        }

        Test-SgPsAssert "ObjectChange Detail with Fields limits output" {
            if (-not $Context.SuiteData["HasObjectChangeData"])
            {
                Write-Host "  (skipped -- no object change data)"
                return $true
            }
            $objType = $Context.SuiteData["TestObjectType"]
            $objId = $Context.SuiteData["TestObjectId"]
            $logId = $Context.SuiteData["TestLogId"]
            $detail = Get-SafeguardAuditLogObjectChange -Insecure $objType `
                -ObjectId $objId -LogId $logId -Fields "Id","EventName"
            $null -ne $detail -and $null -ne $detail.Id
        }

        # =======================================================
        # Error cases
        # =======================================================

        Test-SgPsAssert "ObjectChange rejects StartDate later than EndDate" {
            $threw = $false
            try {
                $null = Get-SafeguardAuditLogObjectChange -Insecure User `
                    -StartDate (Get-Date) -EndDate (Get-Date).AddDays(-7)
            }
            catch { $threw = $_ -match "StartDate must not be later" }
            $threw
        }

        Test-SgPsAssert "ObjectChange rejects empty ObjectType" {
            $threw = $false
            try {
                $null = Get-SafeguardAuditLogObjectChange -Insecure ""
            }
            catch { $threw = $true }
            $threw
        }

        Test-SgPsAssert "ObjectChange handles nonexistent ObjectType gracefully" {
            # API should return empty or 400 for nonsense types
            $threw = $false
            try {
                $result = Get-SafeguardAuditLogObjectChange -Insecure "FakeTypeXyz123" `
                    -StartDate (Get-Date).AddDays(-1)
                # If no error, result should be empty
                $null -eq $result -or ($result -is [Array] -and $result.Count -eq 0)
            }
            catch {
                # API rejected the type -- also acceptable
                $threw = $true
            }
            $threw -or ($null -eq $result -or ($result -is [Array] -and $result.Count -eq 0))
        }

        # =======================================================
        # Get-SafeguardAuditLogDiscoveredItem
        # =======================================================

        Test-SgPsAssert "DiscoveredItem with valid DiscoveryType and LogId" {
            if (-not $Context.SuiteData["HasDiscoveryData"])
            {
                Write-Host "  (skipped -- no discovery data or insufficient permissions)"
                return $true
            }
            $discType = $Context.SuiteData["DiscoveryType"]
            $discId = $Context.SuiteData["DiscoveryLogId"]
            $result = Get-SafeguardAuditLogDiscoveredItem -Insecure $discType `
                -DiscoveryLogId $discId
            $null -eq $result -or $result -is [Array] -or $result -is [PSCustomObject]
        }

        Test-SgPsAssert "DiscoveredItem rejects invalid DiscoveryType" {
            $threw = $false
            try {
                $null = Get-SafeguardAuditLogDiscoveredItem -Insecure "SshKeys" `
                    -DiscoveryLogId "fake"
            }
            catch { $threw = $true }
            $threw
        }

        Test-SgPsAssert "DiscoveredItem rejects empty DiscoveryLogId" {
            $threw = $false
            try {
                $null = Get-SafeguardAuditLogDiscoveredItem -Insecure Accounts `
                    -DiscoveryLogId ""
            }
            catch { $threw = $true }
            $threw
        }

        Test-SgPsAssert "DiscoveredItem handles nonexistent LogId" {
            # API should return 404 or empty for a fake ID
            $threw = $false
            try {
                $result = Get-SafeguardAuditLogDiscoveredItem -Insecure Accounts `
                    -DiscoveryLogId "00000000-0000-0000-0000-000000000000"
                $null -eq $result -or ($result -is [Array] -and $result.Count -eq 0)
            }
            catch {
                $threw = $true
            }
            $threw -or ($null -eq $result -or ($result -is [Array] -and $result.Count -eq 0))
        }
    }

    Cleanup = {
        param($Context)
    }
}
