@{
    Name        = "A2A Event Listener"
    Description = "Tests Wait-SafeguardA2aEvent, Invoke-SafeguardA2aPasswordHandler, and Invoke-SafeguardA2aSshKeyHandler"
    Tags        = @("a2a", "signalr", "listener", "certificate")

    Setup = {
        param($Context)

        $prefix = $Context.TestPrefix
        $certUser = "${prefix}_A2aEvtCertUser"
        $testAsset = "${prefix}_A2aEvtAsset"
        $testAccount = "${prefix}_A2aEvtAcct"
        $testA2a = "${prefix}_A2aEvtReg"
        $initialPassword = "A2aEvtInitPwd_3xRz!"

        # Locate test certificate files
        $certDir = Join-Path $Context.TestRoot "TestData\CERTS"
        if (-not (Test-Path $certDir)) {
            throw "Test certificate directory not found: $certDir"
        }
        $Context.SuiteData["UserPfx"] = Join-Path $certDir "UserCert.pfx"
        $Context.SuiteData["RootCaPem"] = Join-Path $certDir "RootCA.pem"
        $Context.SuiteData["IntCaPem"] = Join-Path $certDir "IntermediateCA.pem"
        $Context.SuiteData["PfxPasswordPlain"] = "a"

        # Compute thumbprints for cleanup
        $rootCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            $Context.SuiteData["RootCaPem"])
        $Context.SuiteData["RootThumbprint"] = $rootCert.Thumbprint

        $intCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            $Context.SuiteData["IntCaPem"])
        $Context.SuiteData["IntThumbprint"] = $intCert.Thumbprint

        $userCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            $Context.SuiteData["UserPfx"],
            $Context.SuiteData["PfxPasswordPlain"])
        $Context.SuiteData["UserThumbprint"] = $userCert.Thumbprint

        # Pre-cleanup: remove stale objects (reverse dependency order)
        Remove-SgPsStaleTestObject -Collection "A2ARegistrations" -Name $testA2a
        Remove-SgPsStaleTestObject -Collection "AssetAccounts" -Name $testAccount
        Remove-SgPsStaleTestObject -Collection "Assets" -Name $testAsset
        Remove-SgPsStaleTestObject -Collection "Users" -Name $certUser
        try { Uninstall-SafeguardTrustedCertificate -Insecure $Context.SuiteData["IntThumbprint"] } catch {}
        try { Uninstall-SafeguardTrustedCertificate -Insecure $Context.SuiteData["RootThumbprint"] } catch {}

        # 1. Install trusted cert chain
        $null = Install-SafeguardTrustedCertificate -Insecure $Context.SuiteData["RootCaPem"]
        Register-SgPsTestCleanup -Description "Uninstall RootCA" -Action {
            param($Ctx)
            try { Uninstall-SafeguardTrustedCertificate -Insecure $Ctx.SuiteData['RootThumbprint'] } catch {}
        }

        $null = Install-SafeguardTrustedCertificate -Insecure $Context.SuiteData["IntCaPem"]
        Register-SgPsTestCleanup -Description "Uninstall IntermediateCA" -Action {
            param($Ctx)
            try { Uninstall-SafeguardTrustedCertificate -Insecure $Ctx.SuiteData['IntThumbprint'] } catch {}
        }

        # 2. Create certificate user
        $cUser = Invoke-SafeguardMethod -Insecure Core POST "Users" -Body @{
            PrimaryAuthenticationProvider = @{
                Id = -2
                Identity = $Context.SuiteData["UserThumbprint"]
            }
            Name = $certUser
        }
        $Context.SuiteData["CertUserId"] = $cUser.Id
        Register-SgPsTestCleanup -Description "Delete certificate user" -Action {
            param($Ctx)
            try { Remove-SafeguardUser -Insecure $Ctx.SuiteData['CertUserId'] } catch {}
        }

        # 3. Create asset and account
        $asset = New-SafeguardAsset -Insecure -DisplayName $testAsset `
            -Platform 521 -NetworkAddress "10.0.9.100" `
            -ServiceAccountCredentialType "None" -NoSshHostKeyDiscovery
        $Context.SuiteData["AssetId"] = $asset.Id
        $Context.SuiteData["TestAsset"] = $testAsset
        Register-SgPsTestCleanup -Description "Delete A2A event asset" -Action {
            param($Ctx)
            try { Remove-SafeguardAsset -Insecure $Ctx.SuiteData['AssetId'] } catch {}
        }

        $account = New-SafeguardAssetAccount -Insecure -ParentAsset $asset.Id -NewAccountName $testAccount
        $Context.SuiteData["AccountId"] = $account.Id
        $Context.SuiteData["TestAccount"] = $testAccount
        Register-SgPsTestCleanup -Description "Delete A2A event account" -Action {
            param($Ctx)
            try { Remove-SafeguardAssetAccount -Insecure $Ctx.SuiteData['AssetId'] $Ctx.SuiteData['AccountId'] } catch {}
        }

        # Set initial password
        Set-SafeguardAssetAccountPassword -Insecure $testAsset $testAccount `
            -NewPassword (ConvertTo-SecureString $initialPassword -AsPlainText -Force)
        $Context.SuiteData["InitialPassword"] = $initialPassword

        # Generate two RSA private keys for SSH key handler test
        $rsa1 = [System.Security.Cryptography.RSA]::Create(2048)
        $Context.SuiteData["SshKey1"] = $rsa1.ExportRSAPrivateKeyPem()
        $rsa1.Dispose()
        $rsa2 = [System.Security.Cryptography.RSA]::Create(2048)
        $Context.SuiteData["SshKey2"] = $rsa2.ExportRSAPrivateKeyPem()
        $rsa2.Dispose()

        # Set initial SSH key on the account
        Invoke-SafeguardMethod -Insecure Core PUT "AssetAccounts/$($account.Id)/SshKey" `
            -Parameters @{ keyFormat = "OpenSsh" } `
            -Body @{ Passphrase = ""; PrivateKey = $Context.SuiteData["SshKey1"] }

        # 4. Create A2A registration with credential retrieval
        $a2aReg = Invoke-SafeguardMethod -Insecure Core POST "A2ARegistrations" -Body @{
            AppName = $testA2a
            CertificateUserId = $cUser.Id
            Description = "A2A event listener test"
            VisibleToCertificateUsers = $true
            BidirectionalEnabled = $true
        }
        $Context.SuiteData["A2aId"] = $a2aReg.Id
        Register-SgPsTestCleanup -Description "Delete A2A registration" -Action {
            param($Ctx)
            try { Remove-SafeguardA2a -Insecure $Ctx.SuiteData['A2aId'] } catch {}
        }

        # 5. Add credential retrieval for the account
        Add-SafeguardA2aCredentialRetrieval -Insecure $Context.SuiteData["A2aId"] `
            -Asset $testAsset -Account $testAccount

        # 6. Get the API key
        $apiKey = Get-SafeguardA2aCredentialRetrievalApiKey -Insecure $Context.SuiteData["A2aId"] `
            -Asset $testAsset -Account $testAccount
        $Context.SuiteData["ApiKey"] = $apiKey

        # 7. Enable A2A service
        try {
            Invoke-SafeguardMethod -Insecure Appliance POST "A2AService/Enable"
        } catch {
            # May already be enabled
        }

        # Store values for background jobs
        $Context.SuiteData["ManifestPath"] = Join-Path $Context.ModuleRoot "safeguard-ps.psd1"
        $Context.SuiteData["Appliance"] = $Context.Appliance

        # Temp file paths
        $tempDir = [System.IO.Path]::GetTempPath()
        $Context.SuiteData["OutputFile"] = Join-Path $tempDir "${prefix}_a2aevt_output.txt"
        $Context.SuiteData["SshKeyOutputFile"] = Join-Path $tempDir "${prefix}_a2aevt_sshkey_output.txt"

        # Clean leftover temp files
        if (Test-Path $Context.SuiteData["OutputFile"]) {
            Remove-Item $Context.SuiteData["OutputFile"] -Force
        }
        if (Test-Path $Context.SuiteData["SshKeyOutputFile"]) {
            Remove-Item $Context.SuiteData["SshKeyOutputFile"] -Force
        }
    }

    Execute = {
        param($Context)

        $manifestPath = $Context.SuiteData["ManifestPath"]
        $appliance = $Context.SuiteData["Appliance"]
        $pfxPath = $Context.SuiteData["UserPfx"]
        $pfxPasswordPlain = $Context.SuiteData["PfxPasswordPlain"]
        $apiKey = $Context.SuiteData["ApiKey"]
        $testAsset = $Context.SuiteData["TestAsset"]
        $testAccount = $Context.SuiteData["TestAccount"]
        $accountId = $Context.SuiteData["AccountId"]

        # ----------------------------------------------------------------
        # Helper: poll a job's verbose stream for a pattern
        # ----------------------------------------------------------------
        $waitForVerbose = {
            param([System.Management.Automation.Job]$Job, [string]$Pattern, [int]$TimeoutSeconds = 45)
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

        # ================================================================
        # Test 1: Wait-SafeguardA2aEvent captures events in pipeline mode
        # ================================================================
        Test-SgPsAssert "Wait-SafeguardA2aEvent captures password change event" {
            $job = $null
            try {
                $job = Start-Job -ScriptBlock {
                    Import-Module $using:manifestPath -Force
                    $VerbosePreference = 'Continue'
                    $secPwd = ConvertTo-SecureString $using:pfxPasswordPlain -AsPlainText -Force
                    Wait-SafeguardA2aEvent -Appliance $using:appliance -Insecure `
                        -CertificateFile $using:pfxPath -Password $secPwd `
                        -ApiKey $using:apiKey
                }

                $ready = & $waitForVerbose $job 'SignalR handshake complete' 45
                if (-not $ready) { throw "A2A listener did not connect within 45 seconds" }

                # Trigger password change from main process
                $newPwd = "A2aEvtChanged1_8kWp!"
                Set-SafeguardAssetAccountPassword -Insecure $testAsset $testAccount `
                    -NewPassword (ConvertTo-SecureString $newPwd -AsPlainText -Force)

                # Poll for the correlated event
                $found = $false
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                while ($sw.Elapsed.TotalSeconds -lt 20) {
                    $output = @(Receive-Job $job -Keep -ErrorAction SilentlyContinue)
                    foreach ($evt in $output) {
                        if ($evt -is [PSCustomObject] -and
                            $evt.EventName -eq "AssetAccountPasswordUpdated" -and
                            ($evt.EventBody | ConvertTo-Json -Compress -Depth 10) -match [regex]::Escape("$accountId"))
                        {
                            $found = $true
                            break
                        }
                    }
                    if ($found) { break }
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

        # ================================================================
        # Test 2: Invoke-SafeguardA2aPasswordHandler delivers passwords
        # ================================================================
        Test-SgPsAssert "Invoke-SafeguardA2aPasswordHandler delivers initial and changed password" {
            $outputFile = $Context.SuiteData["OutputFile"]
            $job = $null
            try {
                # Clean output file
                if (Test-Path $outputFile) { Remove-Item $outputFile -Force }

                $job = Start-Job -ScriptBlock {
                    Import-Module $using:manifestPath -Force
                    $VerbosePreference = 'Continue'
                    $secPwd = ConvertTo-SecureString $using:pfxPasswordPlain -AsPlainText -Force
                    $outPath = $using:outputFile
                    $handler = {
                        param($EventName, $Password)
                        "$EventName=$Password" | Add-Content -Path $outPath -Encoding UTF8
                    }.GetNewClosure()
                    Invoke-SafeguardA2aPasswordHandler -Appliance $using:appliance -Insecure `
                        -CertificateFile $using:pfxPath -Password $secPwd `
                        -ApiKey $using:apiKey -Handler $handler
                }

                $ready = & $waitForVerbose $job 'SignalR handshake complete' 45
                if (-not $ready) { throw "Password handler did not connect within 45 seconds" }

                # Verify initial password was delivered
                $initialFound = $false
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                while ($sw.Elapsed.TotalSeconds -lt 10) {
                    if (Test-Path $outputFile) {
                        $content = Get-Content $outputFile -Raw -ErrorAction SilentlyContinue
                        if ($content -match "InitialPassword=") {
                            $initialFound = $true
                            break
                        }
                    }
                    Start-Sleep -Milliseconds 500
                }
                if (-not $initialFound) { throw "Initial password not delivered to handler" }

                # Trigger password change
                $newPwd = "A2aEvtChanged2_5mNq!"
                Set-SafeguardAssetAccountPassword -Insecure $testAsset $testAccount `
                    -NewPassword (ConvertTo-SecureString $newPwd -AsPlainText -Force)

                # Poll for the changed password
                $changeFound = $false
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                while ($sw.Elapsed.TotalSeconds -lt 20) {
                    if (Test-Path $outputFile) {
                        $content = Get-Content $outputFile -Raw -ErrorAction SilentlyContinue
                        if ($content -match "AssetAccountPasswordUpdated=$newPwd") {
                            $changeFound = $true
                            break
                        }
                    }
                    Start-Sleep -Milliseconds 500
                }
                $changeFound
            }
            finally {
                if ($job) {
                    Stop-Job $job -ErrorAction SilentlyContinue
                    Remove-Job $job -Force -ErrorAction SilentlyContinue
                }
            }
        }

        # ================================================================
        # Test 3: Invoke-SafeguardA2aSshKeyHandler delivers SSH keys
        # ================================================================
        Test-SgPsAssert "Invoke-SafeguardA2aSshKeyHandler delivers initial and changed SSH key" {
            $sshKeyOutputFile = $Context.SuiteData["SshKeyOutputFile"]
            $sshKey2 = $Context.SuiteData["SshKey2"]
            $job = $null
            try {
                # Clean output file
                if (Test-Path $sshKeyOutputFile) { Remove-Item $sshKeyOutputFile -Force }

                $job = Start-Job -ScriptBlock {
                    Import-Module $using:manifestPath -Force
                    $VerbosePreference = 'Continue'
                    $secPwd = ConvertTo-SecureString $using:pfxPasswordPlain -AsPlainText -Force
                    $outPath = $using:sshKeyOutputFile
                    $handler = {
                        param($EventName, $PrivateKey)
                        $marker = "NOKEY"
                        if ($PrivateKey -and $PrivateKey.Length -gt 100) {
                            $marker = "HASKEY"
                        }
                        "$EventName=$marker" | Add-Content -Path $outPath -Encoding UTF8
                    }.GetNewClosure()
                    Invoke-SafeguardA2aSshKeyHandler -Appliance $using:appliance -Insecure `
                        -CertificateFile $using:pfxPath -Password $secPwd `
                        -ApiKey $using:apiKey -Handler $handler
                }

                $ready = & $waitForVerbose $job 'SignalR handshake complete' 45
                if (-not $ready) { throw "SSH key handler did not connect within 45 seconds" }

                # Verify initial SSH key was delivered
                $initialFound = $false
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                while ($sw.Elapsed.TotalSeconds -lt 10) {
                    if (Test-Path $sshKeyOutputFile) {
                        $content = Get-Content $sshKeyOutputFile -Raw -ErrorAction SilentlyContinue
                        if ($content -match "InitialSshKey=HASKEY") {
                            $initialFound = $true
                            break
                        }
                    }
                    Start-Sleep -Milliseconds 500
                }
                if (-not $initialFound) { throw "Initial SSH key not delivered to handler" }

                # Trigger SSH key change by setting a different key
                Invoke-SafeguardMethod -Insecure Core PUT "AssetAccounts/$accountId/SshKey" `
                    -Parameters @{ keyFormat = "OpenSsh" } `
                    -Body @{ Passphrase = ""; PrivateKey = $sshKey2 }

                # Poll for the changed SSH key delivery
                $changeFound = $false
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                while ($sw.Elapsed.TotalSeconds -lt 20) {
                    if (Test-Path $sshKeyOutputFile) {
                        $content = Get-Content $sshKeyOutputFile -Raw -ErrorAction SilentlyContinue
                        if ($content -match "AssetAccountSshKeyUpdated=HASKEY") {
                            $changeFound = $true
                            break
                        }
                    }
                    Start-Sleep -Milliseconds 500
                }
                $changeFound
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
        $path = $Context.SuiteData["OutputFile"]
        if ($path -and (Test-Path $path)) {
            try { Remove-Item $path -Force } catch {}
        }
        $sshPath = $Context.SuiteData["SshKeyOutputFile"]
        if ($sshPath -and (Test-Path $sshPath)) {
            try { Remove-Item $sshPath -Force } catch {}
        }
    }
}
