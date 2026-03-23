@{
    Name        = "Certificates"
    Description = "Tests trusted certificate, SSL certificate, and CSR operations"
    Tags        = @("certificates", "security")

    Setup = {
        param($Context)

        # Locate test certificate files (TestData/CERTS relative to test root)
        $certDir = Join-Path $Context.TestRoot "TestData\CERTS"
        if (-not (Test-Path $certDir)) {
            throw "Test certificate directory not found: $certDir"
        }
        $Context.SuiteData["CertDir"] = $certDir
        $Context.SuiteData["RootCaPem"] = Join-Path $certDir "RootCA.pem"
        $Context.SuiteData["IntermediateCaPem"] = Join-Path $certDir "IntermediateCA.pem"
        $Context.SuiteData["UserCertPem"] = Join-Path $certDir "UserCert.pem"

        # Pre-cleanup: remove any stale test-installed trusted certs
        # Read the RootCA thumbprint so we can check for stale installs
        $rootCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            $Context.SuiteData["RootCaPem"])
        $Context.SuiteData["RootCaThumbprint"] = $rootCert.Thumbprint

        $intCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            $Context.SuiteData["IntermediateCaPem"])
        $Context.SuiteData["IntCaThumbprint"] = $intCert.Thumbprint

        # Try to remove any previously-installed test certs
        try { Uninstall-SafeguardTrustedCertificate -Insecure $Context.SuiteData["RootCaThumbprint"] } catch {}
        try { Uninstall-SafeguardTrustedCertificate -Insecure $Context.SuiteData["IntCaThumbprint"] } catch {}

        # Pre-cleanup: remove stale CSRs from previous runs
        try {
            $csrs = Get-SafeguardCertificateSigningRequest -Insecure
            @($csrs) | Where-Object { $_.Subject -match "SgPsTest" } | ForEach-Object {
                try { Remove-SafeguardCertificateSigningRequest -Insecure $_.Thumbprint } catch {}
            }
        } catch {}
    }

    Execute = {
        param($Context)

        # --- Get-SafeguardTrustedCertificate (list) ---
        Test-SgPsAssert "Get-SafeguardTrustedCertificate lists certificates" {
            $certs = Get-SafeguardTrustedCertificate -Insecure
            $null -ne $certs
        }

        # --- Install-SafeguardTrustedCertificate (RootCA) ---
        Test-SgPsAssert "Install-SafeguardTrustedCertificate installs RootCA" {
            $result = Install-SafeguardTrustedCertificate -Insecure $Context.SuiteData["RootCaPem"]
            Register-SgPsTestCleanup -Description "Uninstall RootCA trusted cert" -Action {
                param($Ctx)
                try { Uninstall-SafeguardTrustedCertificate -Insecure $Ctx.SuiteData['RootCaThumbprint'] } catch {}
            }
            $null -ne $result -and $result.Subject -match "RootCA"
        }

        # --- Get-SafeguardTrustedCertificate by Thumbprint ---
        Test-SgPsAssert "Get-SafeguardTrustedCertificate by Thumbprint" {
            $cert = Get-SafeguardTrustedCertificate -Insecure $Context.SuiteData["RootCaThumbprint"]
            $cert.Thumbprint -eq $Context.SuiteData["RootCaThumbprint"]
        }

        # --- Install-SafeguardTrustedCertificate (IntermediateCA) ---
        Test-SgPsAssert "Install-SafeguardTrustedCertificate installs IntermediateCA" {
            $result = Install-SafeguardTrustedCertificate -Insecure $Context.SuiteData["IntermediateCaPem"]
            Register-SgPsTestCleanup -Description "Uninstall IntermediateCA trusted cert" -Action {
                param($Ctx)
                try { Uninstall-SafeguardTrustedCertificate -Insecure $Ctx.SuiteData['IntCaThumbprint'] } catch {}
            }
            $null -ne $result -and $result.Subject -match "IntermediateCA"
        }
        Test-SgPsAssert "Install-SafeguardTrustedCertificate IntermediateCA persisted" {
            $cert = Get-SafeguardTrustedCertificate -Insecure $Context.SuiteData["IntCaThumbprint"]
            $cert.Thumbprint -eq $Context.SuiteData["IntCaThumbprint"] -and $cert.Subject -match "IntermediateCA"
        }

        # --- Get-SafeguardTrustedCertificate with Fields ---
        Test-SgPsAssert "Get-SafeguardTrustedCertificate with Fields filter" {
            $cert = Get-SafeguardTrustedCertificate -Insecure $Context.SuiteData["RootCaThumbprint"] `
                -Fields "Thumbprint","Subject","IssuedBy"
            $null -ne $cert.Thumbprint -and $null -ne $cert.Subject
        }

        # --- Uninstall-SafeguardTrustedCertificate ---
        Test-SgPsAssert "Uninstall-SafeguardTrustedCertificate removes IntermediateCA" {
            Uninstall-SafeguardTrustedCertificate -Insecure $Context.SuiteData["IntCaThumbprint"]
            $remaining = Get-SafeguardTrustedCertificate -Insecure
            $list = @($remaining)
            -not ($list | Where-Object { $_.Thumbprint -eq $Context.SuiteData["IntCaThumbprint"] })
        }

        # --- Get-SafeguardSslCertificate (list) ---
        Test-SgPsAssert "Get-SafeguardSslCertificate lists SSL certificates" {
            $certs = Get-SafeguardSslCertificate -Insecure
            $null -ne $certs
        }

        # --- Get-SafeguardSslCertificate with Fields ---
        Test-SgPsAssert "Get-SafeguardSslCertificate with Fields" {
            $certs = Get-SafeguardSslCertificate -Insecure -Fields "Thumbprint","Subject","IssuedBy"
            $list = @($certs)
            $list.Count -ge 1 -and $null -ne $list[0].Thumbprint
        }

        # --- Get-SafeguardSslCertificateForAppliance ---
        Test-SgPsAssert "Get-SafeguardSslCertificateForAppliance returns current cert" {
            $cert = Get-SafeguardSslCertificateForAppliance -Insecure
            $null -ne $cert -and $null -ne $cert.Thumbprint
        }

        # --- Get-SafeguardCertificateSigningRequest (list) ---
        Test-SgPsAssert "Get-SafeguardCertificateSigningRequest lists CSRs" {
            $csrs = Get-SafeguardCertificateSigningRequest -Insecure
            $null -ne $csrs
        }

        # --- New-SafeguardCertificateSigningRequest ---
        Test-SgPsAssert "New-SafeguardCertificateSigningRequest creates a CSR" {
            $outFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "SgPsTest_csr.pem")
            $csr = New-SafeguardCertificateSigningRequest -Insecure `
                -CertificateType "Ssl" `
                -Subject "CN=SgPsTest CSR" `
                -OutFile $outFile
            $Context.SuiteData["CsrThumbprint"] = $csr.Thumbprint
            $Context.SuiteData["CsrOutFile"] = $outFile

            Register-SgPsTestCleanup -Description "Remove test CSR" -Action {
                param($Ctx)
                try { Remove-SafeguardCertificateSigningRequest -Insecure $Ctx.SuiteData['CsrThumbprint'] } catch {}
                $f = $Ctx.SuiteData['CsrOutFile']
                if ($f -and (Test-Path $f)) { Remove-Item $f -Force }
            }
            $null -ne $csr.Thumbprint -and (Test-Path $outFile)
        }

        # --- Get-SafeguardCertificateSigningRequest by Thumbprint ---
        Test-SgPsAssert "Get-SafeguardCertificateSigningRequest by Thumbprint" {
            $csr = Get-SafeguardCertificateSigningRequest -Insecure $Context.SuiteData["CsrThumbprint"]
            $csr.Subject -match "SgPsTest"
        }

        # --- Remove-SafeguardCertificateSigningRequest ---
        Test-SgPsAssert "Remove-SafeguardCertificateSigningRequest deletes a CSR" {
            Remove-SafeguardCertificateSigningRequest -Insecure $Context.SuiteData["CsrThumbprint"]
            $csrs = Get-SafeguardCertificateSigningRequest -Insecure
            $list = @($csrs)
            -not ($list | Where-Object { $_.Thumbprint -eq $Context.SuiteData["CsrThumbprint"] })
        }

        # --- Get-SafeguardAuditLogSigningCertificate ---
        Test-SgPsAssert "Get-SafeguardAuditLogSigningCertificate returns result" {
            $certs = Get-SafeguardAuditLogSigningCertificate -Insecure
            $null -ne $certs
        }
    }

    Cleanup = {
        param($Context)
    }
}
