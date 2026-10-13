#Requires -Version 7.0
@{
    Name        = "SSL Certificate Assignments"
    Description = "Opt-in HTTPS certificate rotation and verified rollback on the connected lab appliance only"
    Tags        = @("certificates", "optional", "disruptive")

    Setup       = {
        param($Context)
        $ErrorActionPreference = "Stop"
        try {
            $id = (Invoke-SafeguardMethod -Insecure -Anonymous Notification GET Status).ApplianceId
            if (-not $id) { throw "Cannot identify the connected appliance" }
            $original = Get-SafeguardSslCertificateForAppliance -Insecure -ApplianceId $id
            if (-not $original.Thumbprint) { throw "Cannot record the original HTTPS certificate" }
            $originalAssignments = @(Invoke-SafeguardMethod -Insecure Core GET "SslCertificates/$($original.Thumbprint)/Appliances" | ForEach-Object { $_ })
            if ($id -notin $originalAssignments.Id) { throw "Original certificate assignment cannot be verified" }
            $Context.SuiteData["ApplianceId"] = $id
            $Context.SuiteData["OriginalThumbprint"] = $original.Thumbprint
            $Context.SuiteData["OriginalAssignmentIds"] = @($originalAssignments.Id)
            $Context.SuiteData["OriginalTrustedThumbprints"] = @(Get-SafeguardTrustedCertificate -Insecure |
                    ForEach-Object { $_.Thumbprint } | Sort-Object)

            Write-Host "Target: $($Context.Appliance), appliance ID: $id"
            Write-Host "Rollback: reassign preserved certificate $($original.Thumbprint) to $id, verify original assignment IDs and active certificate, then delete only the generated test certificate."
            Write-Host "Only this node will be changed. HTTPS trust/connectivity may change; retain console access for recovery."
            if ((Read-Host "Type ROTATE $id to approve HTTPS rotation and rollback") -cne "ROTATE $id") {
                throw "HTTPS certificate rotation was not approved"
            }
            Write-Host "A temporary trusted certificate will be added and may replicate within the cluster."
            if ((Read-Host "Type TRUST $id to approve temporary trust and its removal") -cne "TRUST $id") {
                throw "Temporary certificate trust was not approved"
            }

            # Register rollback before uploading or changing any certificate assignment.
            Register-SgPsTestCleanup -Description "Restore HTTPS certificate and verify test certificate removal" -Action {
                param($Ctx)
                $ErrorActionPreference = "Stop"
                try {
                    $data = $Ctx.SuiteData
                    if ($data["RotationStarted"]) {
                        Set-SafeguardSslCertificateForAppliance -Insecure -Thumbprint $data["OriginalThumbprint"] `
                            -ApplianceId $data["ApplianceId"] | Out-Null
                    }
                    $active = Get-SafeguardSslCertificateForAppliance -Insecure -ApplianceId $data["ApplianceId"]
                    $restored = @(Invoke-SafeguardMethod -Insecure Core GET "SslCertificates/$($data['OriginalThumbprint'])/Appliances" | ForEach-Object { $_ })
                    $restorationVerified = $active.Thumbprint -eq $data["OriginalThumbprint"] -and
                    (@($restored.Id | Sort-Object) -join ",") -eq (@($data["OriginalAssignmentIds"] | Sort-Object) -join ",")
                    Test-SgPsAssert "Original HTTPS certificate and assignments restored" { $restorationVerified }
                    if (-not $restorationVerified) { throw "Rollback verification failed; test certificate retained for recovery" }
                    $status = Invoke-SafeguardMethod -Insecure -Anonymous Notification GET Status
                    $reachable = $status.ApplianceId -eq $data["ApplianceId"]
                    Test-SgPsAssert "Restored appliance remains reachable over HTTPS" { $reachable }
                    if (-not $reachable) { throw "HTTPS reachability verification failed; test certificate retained for recovery" }
                    if ($data["TestThumbprint"]) {
                        $assigned = @(Invoke-SafeguardMethod -Insecure Core GET "SslCertificates/$($data['TestThumbprint'])/Appliances" | ForEach-Object { $_ })
                        if ($assigned.Count -ne 0) { throw "Test certificate still assigned; refusing deletion" }
                        Uninstall-SafeguardSslCertificate -Insecure -Thumbprint $data["TestThumbprint"] | Out-Null
                        $remaining = @(Get-SafeguardSslCertificate -Insecure)
                        Test-SgPsAssert "Generated SSL certificate removed" { $data["TestThumbprint"] -notin $remaining.Thumbprint }
                        if ($data["TestThumbprint"] -in $remaining.Thumbprint) { throw "Test SSL certificate removal failed" }
                    }
                    if ($data["AddedTrustedThumbprint"]) {
                        Uninstall-SafeguardTrustedCertificate -Insecure -Thumbprint $data["AddedTrustedThumbprint"] | Out-Null
                    }
                    $trusted = @(Get-SafeguardTrustedCertificate -Insecure | ForEach-Object { $_.Thumbprint } | Sort-Object)
                    $trustRestored = ($trusted -join ",") -eq ($data["OriginalTrustedThumbprints"] -join ",")
                    Test-SgPsAssert "Trusted certificate list restored to baseline" { $trustRestored }
                    if (-not $trustRestored) { throw "Trusted certificate baseline restoration failed" }
                }
                catch {
                    $cleanupFailure = $_
                    Test-SgPsAssert "SSL assignment cleanup completes" { throw $cleanupFailure }
                    throw
                }
            }

            $rsa = [System.Security.Cryptography.RSA]::Create(2048)
            $certificate = $null
            $pfxPath = $null
            try {
                $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                    "CN=$($Context.TestPrefix) SSL assignment",
                    $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
                $eku = [System.Security.Cryptography.OidCollection]::new()
                $null = $eku.Add([System.Security.Cryptography.Oid]::new("1.3.6.1.5.5.7.3.1"))
                $request.CertificateExtensions.Add(
                    [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($eku, $false))
                $san = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
                $address = $null
                if ([System.Net.IPAddress]::TryParse($Context.Appliance, [ref]$address)) { $san.AddIpAddress($address) }
                else { $san.AddDnsName($Context.Appliance) }
                $request.CertificateExtensions.Add($san.Build())
                $certificate = $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5), [DateTimeOffset]::UtcNow.AddDays(1))
                if ($certificate.Thumbprint -in $Context.SuiteData["OriginalTrustedThumbprints"]) {
                    throw "Generated certificate unexpectedly exists in the trusted baseline"
                }
                Invoke-SafeguardMethod -Insecure Core POST TrustedCertificates -Verbose:$false -Body @{
                    Base64CertificateData = [Convert]::ToBase64String(
                        $certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
                } | Out-Null
                $Context.SuiteData["AddedTrustedThumbprint"] = $certificate.Thumbprint
                $trusted = @(Get-SafeguardTrustedCertificate -Insecure)
                if ($certificate.Thumbprint -notin $trusted.Thumbprint) { throw "Temporary certificate trust did not persist" }
                # Install requires a file; encrypt the temporary PFX and remove it immediately after upload.
                $pfxPassword = [Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
                $securePassword = ConvertTo-SecureString $pfxPassword -AsPlainText -Force
                $pfxPath = Join-Path ([System.IO.Path]::GetTempPath()) "$([guid]::NewGuid()).pfx"
                [System.IO.File]::WriteAllBytes($pfxPath,
                    $certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $pfxPassword))
                Install-SafeguardSslCertificate -Insecure -CertificateFile $pfxPath -Password $securePassword -Verbose:$false | Out-Null
                $Context.SuiteData["TestThumbprint"] = $certificate.Thumbprint
            }
            finally {
                if ($pfxPath -and (Test-Path $pfxPath)) { Remove-Item -LiteralPath $pfxPath -Force }
                if ($securePassword) { $securePassword.Dispose() }
                $pfxPassword = $null
                if ($certificate) { $certificate.Dispose() }
                $rsa.Dispose()
            }
            $assignments = @(Invoke-SafeguardMethod -Insecure Core GET "SslCertificates/$($Context.SuiteData['TestThumbprint'])/Appliances" | ForEach-Object { $_ })
            if ($assignments.Count -ne 0) { throw "New test certificate unexpectedly assigned" }
        }
        catch {
            # Rollback assertions must not hide setup failures in the suite report.
            $setupFailure = $_
            Test-SgPsAssert "SSL assignment setup completes" { throw $setupFailure }
            throw
        }
    }

    Execute     = {
        param($Context)
        $ErrorActionPreference = "Stop"
        $data = $Context.SuiteData
        $thumbprint = $data["TestThumbprint"]
        $id = $data["ApplianceId"]

        Test-SgPsAssert "Generated SSL certificate initially has zero assignments" {
            @(Invoke-SafeguardMethod -Insecure Core GET "SslCertificates/$thumbprint/Appliances" | ForEach-Object { $_ }).Count -eq 0
        }
        $data["RotationStarted"] = $true
        Test-SgPsAssert "Install then Set with explicit Thumbprint and ApplianceId persists from zero assignments" {
            Set-SafeguardSslCertificateForAppliance -Insecure -Thumbprint $thumbprint -ApplianceId $id | Out-Null
            $assigned = @(Invoke-SafeguardMethod -Insecure Core GET "SslCertificates/$thumbprint/Appliances" | ForEach-Object { $_ })
            $active = Get-SafeguardSslCertificateForAppliance -Insecure -ApplianceId $id
            $assigned.Count -eq 1 -and $assigned[0].Id -eq $id -and $active.Thumbprint -eq $thumbprint
        }
        Test-SgPsAssert "Repeated singleton assignment using default appliance resolution has no duplicate" {
            Set-SafeguardSslCertificateForAppliance -Insecure -Thumbprint $thumbprint | Out-Null
            $assigned = @(Invoke-SafeguardMethod -Insecure Core GET "SslCertificates/$thumbprint/Appliances" | ForEach-Object { $_ })
            $assigned.Count -eq 1 -and $assigned[0].Id -eq $id
        }
        Test-SgPsAssert "Default appliance clear persists an empty assignment list" {
            Clear-SafeguardSslCertificateForAppliance -Insecure -Thumbprint $thumbprint | Out-Null
            @(Invoke-SafeguardMethod -Insecure Core GET "SslCertificates/$thumbprint/Appliances" | ForEach-Object { $_ }).Count -eq 0
        }
        Test-SgPsAssert "Default appliance assignment persists after clear" {
            Set-SafeguardSslCertificateForAppliance -Insecure -Thumbprint $thumbprint | Out-Null
            $assigned = @(Invoke-SafeguardMethod -Insecure Core GET "SslCertificates/$thumbprint/Appliances" | ForEach-Object { $_ })
            $assigned.Count -eq 1 -and $assigned[0].Id -eq $id
        }
        Test-SgPsAssert "Explicit appliance clear persists an empty assignment list" {
            Clear-SafeguardSslCertificateForAppliance -Insecure -Thumbprint $thumbprint -ApplianceId $id | Out-Null
            @(Invoke-SafeguardMethod -Insecure Core GET "SslCertificates/$thumbprint/Appliances" | ForEach-Object { $_ }).Count -eq 0
        }
        Test-SgPsSkip "Live multi-appliance preservation and clear-to-singleton" `
            "Only the connected node is authorized; use local shape checks for synthetic multi-appliance coverage."
    }

    Cleanup     = { param($Context) }
}
