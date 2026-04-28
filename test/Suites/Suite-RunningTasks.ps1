@{
    Name        = "RunningTasks"
    Description = "Tests running task list and monitoring operations"
    Tags        = @("runningtasks", "core")

    Setup = {
        param($Context)

        $prefix = $Context.TestPrefix
        $testAsset = "${prefix}_TaskAsset"

        # Pre-cleanup
        Remove-SgPsStaleTestObject -Collection "Assets" -Name $testAsset

        # Create a test asset to trigger a TestConnection task
        $asset = New-SafeguardAsset -Insecure -DisplayName $testAsset `
            -Platform 521 -NetworkAddress "10.0.99.99" `
            -ServiceAccountCredentialType "None" -NoSshHostKeyDiscovery
        $Context.SuiteData["AssetId"] = $asset.Id

        Register-SgPsTestCleanup -Description "Delete running task test asset" -Action {
            param($Ctx)
            try { Remove-SafeguardAsset -Insecure $Ctx.SuiteData['AssetId'] } catch {}
        }
    }

    Execute = {
        param($Context)

        # --- Get-SafeguardRunningTask (list all) ---
        Test-SgPsAssert "Get-SafeguardRunningTask lists tasks" {
            $list = @(Get-SafeguardRunningTask -Insecure)
            $list -is [Array]
        }

        # --- Get-SafeguardRunningTask with IncludeSubmitted ---
        Test-SgPsAssert "Get-SafeguardRunningTask with IncludeSubmitted" {
            $list = @(Get-SafeguardRunningTask -Insecure -IncludeSubmitted)
            $list -is [Array]
        }

        # --- Get-SafeguardRunningTask by TaskName ---
        Test-SgPsAssert "Get-SafeguardRunningTask by TaskName" {
            $list = @(Get-SafeguardRunningTask -Insecure -TaskName TestConnection)
            $list -is [Array]
        }

        # --- Trigger a TestConnection to exercise task visibility ---
        Test-SgPsAssert "Trigger TestConnection and see running task" {
            $assetId = $Context.SuiteData["AssetId"]
            # Fire and forget -- TestConnection against unreachable IP will queue/run briefly
            try { Test-SafeguardAsset -Insecure $assetId } catch {}
            # Check that we can query tasks without error
            $list = @(Get-SafeguardRunningTask -Insecure -TaskName TestConnection -IncludeSubmitted)
            $list -is [Array]
        }

        # --- Get-SafeguardRunningTask with Fields ---
        Test-SgPsAssert "Get-SafeguardRunningTask with Fields filter" {
            $list = @(Get-SafeguardRunningTask -Insecure -Fields "TaskId","Name" -IncludeSubmitted)
            # Whether empty or populated, the call should succeed and return an array
            $list -is [Array]
        }

        # --- Validate TaskName parameter rejects invalid values ---
        Test-SgPsAssert "Get-SafeguardRunningTask rejects invalid TaskName" {
            $threw = $false
            try {
                $null = Get-SafeguardRunningTask -Insecure -TaskName "NotAValidTask"
            }
            catch { $threw = $true }
            $threw
        }

        # --- Stop-SafeguardRunningTask rejects invalid TaskName ---
        Test-SgPsAssert "Stop-SafeguardRunningTask rejects invalid TaskName" {
            $threw = $false
            try {
                $null = Stop-SafeguardRunningTask -Insecure -TaskName "NotAValidTask" -TaskId "fake"
            }
            catch { $threw = $true }
            $threw
        }

        # --- TaskId requires TaskName ---
        Test-SgPsAssert "Get-SafeguardRunningTask throws when TaskId without TaskName" {
            $threw = $false
            try {
                $null = Get-SafeguardRunningTask -Insecure -TaskId "fake-id"
            }
            catch { $threw = $true }
            $threw
        }
    }

    Cleanup = {
        param($Context)
    }
}
