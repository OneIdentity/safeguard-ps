@{
    Name        = "Event Listener"
    Description = "Tests Wait-SafeguardEvent SignalR SSE real-time event listening"
    Tags        = @("events", "signalr", "listener")

    Setup = {
        param($Context)

        $prefix = $Context.TestPrefix

        # Pre-cleanup: stale test objects from prior failed runs
        Remove-SgPsStaleTestObject -Collection "Assets" -Name "${prefix}_EvtLstn1"
        Remove-SgPsStaleTestObject -Collection "Assets" -Name "${prefix}_EvtLstn2"
        Remove-SgPsStaleTestObject -Collection "Assets" -Name "${prefix}_EvtLstn3"

        # Store values needed by background jobs (cannot access $SafeguardSession from job)
        $Context.SuiteData["ManifestPath"] = Join-Path $Context.ModuleRoot "safeguard-ps.psd1"
        $Context.SuiteData["Appliance"] = $Context.Appliance
        $Context.SuiteData["AccessToken"] = $SafeguardSession["AccessToken"]

        # Temp file paths for handler tests
        $tempDir = [System.IO.Path]::GetTempPath()
        $Context.SuiteData["OutputFile"] = Join-Path $tempDir "${prefix}_evtlstn_output.txt"
        $Context.SuiteData["HandlerScriptPath"] = Join-Path $tempDir "${prefix}_evtlstn_handler.ps1"

        # Clean up leftover temp files
        foreach ($f in @($Context.SuiteData["OutputFile"], $Context.SuiteData["HandlerScriptPath"])) {
            if (Test-Path $f) { Remove-Item $f -Force }
        }
    }

    Execute = {
        param($Context)

        $prefix = $Context.TestPrefix
        $manifestPath = $Context.SuiteData["ManifestPath"]
        $appliance = $Context.SuiteData["Appliance"]
        $token = $Context.SuiteData["AccessToken"]

        # ----------------------------------------------------------------
        # Helper: poll a job's verbose stream for a pattern
        # ----------------------------------------------------------------
        $waitForVerbose = {
            param([System.Management.Automation.Job]$Job, [string]$Pattern, [int]$TimeoutSeconds = 30)
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            while ($sw.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
                if ($Job.State -eq 'Failed' -or $Job.State -eq 'Completed') {
                    $jobErr = Receive-Job $Job -ErrorAction SilentlyContinue 2>&1
                    throw "Listener job ended unexpectedly ($($Job.State)): $jobErr"
                }
                if ($Job.ChildJobs.Count -gt 0) {
                    foreach ($msg in $Job.ChildJobs[0].Verbose) {
                        if ($msg.Message -match $Pattern) {
                            return $true
                        }
                    }
                }
                Start-Sleep -Milliseconds 500
            }
            return $false
        }

        # ----------------------------------------------------------------
        # Helper: poll Receive-Job output for a matching event
        # ----------------------------------------------------------------
        $waitForEvent = {
            param(
                [System.Management.Automation.Job]$Job,
                [string]$EventName,
                [string]$BodyPattern,
                [int]$TimeoutSeconds = 15
            )
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            while ($sw.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
                $output = @(Receive-Job $Job -Keep -ErrorAction SilentlyContinue)
                foreach ($evt in $output) {
                    if ($evt -is [PSCustomObject] -and $evt.EventName -eq $EventName) {
                        if (-not $BodyPattern) { return $true }
                        $bodyJson = $evt.EventBody | ConvertTo-Json -Compress -Depth 10
                        if ($bodyJson -match $BodyPattern) { return $true }
                    }
                }
                Start-Sleep -Milliseconds 500
            }
            return $false
        }

        # ================================================================
        # Test 1: Pipeline mode captures correlated events
        # ================================================================
        Test-SgPsAssert "Wait-SafeguardEvent captures events in pipeline mode" {
            $assetName = "${prefix}_EvtLstn1"
            $job = $null
            try {
                $job = Start-Job -ScriptBlock {
                    Import-Module $using:manifestPath -Force
                    $VerbosePreference = 'Continue'
                    Wait-SafeguardEvent -Appliance $using:appliance -AccessToken $using:token -Insecure
                }

                # Wait for SSE handshake to complete
                $ready = & $waitForVerbose $job 'SignalR handshake complete' 45
                if (-not $ready) { throw "Listener did not connect within 30 seconds" }

                # Trigger an event
                $asset = New-SafeguardAsset -Insecure -DisplayName $assetName `
                    -Platform 521 -NetworkAddress "10.99.0.1" `
                    -ServiceAccountCredentialType "None" -NoSshHostKeyDiscovery
                $Context.SuiteData["Asset1Id"] = $asset.Id
                Register-SgPsTestCleanup -Description "Delete $assetName" -Action {
                    param($Ctx)
                    try { Remove-SafeguardAsset -Insecure $Ctx.SuiteData['Asset1Id'] } catch {}
                }

                # Poll for the correlated event
                $found = & $waitForEvent $job 'AssetCreated' $assetName 15
                $found
            }
            finally {
                if ($job) {
                    Stop-Job $job -ErrorAction SilentlyContinue
                    Remove-Job $job -Force -ErrorAction SilentlyContinue
                }
            }
        }

        # ================================================================
        # Test 2: Event filter limits delivered events
        # ================================================================
        Test-SgPsAssert "Wait-SafeguardEvent -Event filter works" {
            $assetName = "${prefix}_EvtLstn2"
            $job = $null
            try {
                # Listen ONLY for AssetCreated events
                $job = Start-Job -ScriptBlock {
                    Import-Module $using:manifestPath -Force
                    $VerbosePreference = 'Continue'
                    Wait-SafeguardEvent -Appliance $using:appliance -AccessToken $using:token -Insecure `
                        -Event @("AssetCreated")
                }

                $ready = & $waitForVerbose $job 'SignalR handshake complete' 45
                if (-not $ready) { throw "Listener did not connect within 30 seconds" }

                # Trigger AssetCreated (should pass filter)
                $asset = New-SafeguardAsset -Insecure -DisplayName $assetName `
                    -Platform 521 -NetworkAddress "10.99.0.2" `
                    -ServiceAccountCredentialType "None" -NoSshHostKeyDiscovery
                $Context.SuiteData["Asset2Id"] = $asset.Id
                Register-SgPsTestCleanup -Description "Delete $assetName" -Action {
                    param($Ctx)
                    try { Remove-SafeguardAsset -Insecure $Ctx.SuiteData['Asset2Id'] } catch {}
                }

                # Poll for our AssetCreated event
                $found = & $waitForEvent $job 'AssetCreated' $assetName 15
                if (-not $found) { throw "Filtered AssetCreated event not received" }

                # Collect all events and verify ONLY AssetCreated events present
                $allOutput = @(Receive-Job $job -Keep -ErrorAction SilentlyContinue)
                $events = @($allOutput | Where-Object {
                    $_ -is [PSCustomObject] -and $null -ne $_.EventName
                })
                $nonAssetCreated = @($events | Where-Object { $_.EventName -ne 'AssetCreated' })
                $nonAssetCreated.Count -eq 0
            }
            finally {
                if ($job) {
                    Stop-Job $job -ErrorAction SilentlyContinue
                    Remove-Job $job -Force -ErrorAction SilentlyContinue
                }
            }
        }

        # ================================================================
        # Test 3: HandlerScript receives events
        # ================================================================
        Test-SgPsAssert "Wait-SafeguardEvent -HandlerScript receives events" {
            $assetName = "${prefix}_EvtLstn3"
            $outputFile = $Context.SuiteData["OutputFile"]
            $handlerPath = $Context.SuiteData["HandlerScriptPath"]
            $job = $null
            try {
                # Clean output file
                if (Test-Path $outputFile) { Remove-Item $outputFile -Force }

                # Create handler script that appends events to temp file
                @"
param(`$EventName, `$EventBody)
`$line = "`$EventName|`$(`$EventBody | ConvertTo-Json -Compress -Depth 10)"
`$line | Add-Content -Path "$outputFile" -Encoding UTF8
"@ | Set-Content -Path $handlerPath -Encoding UTF8

                $job = Start-Job -ScriptBlock {
                    Import-Module $using:manifestPath -Force
                    $VerbosePreference = 'Continue'
                    Wait-SafeguardEvent -Appliance $using:appliance -AccessToken $using:token -Insecure `
                        -HandlerScript $using:handlerPath
                }

                $ready = & $waitForVerbose $job 'SignalR handshake complete' 45
                if (-not $ready) { throw "Listener did not connect within 30 seconds" }

                # Trigger event
                $asset = New-SafeguardAsset -Insecure -DisplayName $assetName `
                    -Platform 521 -NetworkAddress "10.99.0.3" `
                    -ServiceAccountCredentialType "None" -NoSshHostKeyDiscovery
                $Context.SuiteData["Asset3Id"] = $asset.Id
                Register-SgPsTestCleanup -Description "Delete $assetName" -Action {
                    param($Ctx)
                    try { Remove-SafeguardAsset -Insecure $Ctx.SuiteData['Asset3Id'] } catch {}
                }

                # Poll output file for our event
                $found = $false
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                while ($sw.Elapsed.TotalSeconds -lt 15) {
                    if (Test-Path $outputFile) {
                        $content = Get-Content $outputFile -Raw -ErrorAction SilentlyContinue
                        if ($content -match $assetName) {
                            $found = $true
                            break
                        }
                    }
                    Start-Sleep -Milliseconds 500
                }
                $found
            }
            finally {
                if ($job) {
                    Stop-Job $job -ErrorAction SilentlyContinue
                    Remove-Job $job -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }

    Cleanup = {
        param($Context)

        # Remove temp files
        foreach ($key in @("OutputFile", "HandlerScriptPath")) {
            $path = $Context.SuiteData[$key]
            if ($path -and (Test-Path $path)) {
                try { Remove-Item $path -Force } catch {}
            }
        }
    }
}
