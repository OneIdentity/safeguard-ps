@{
    Name        = "Diagnostics"
    Description = "Tests network diagnostic cmdlets (ping, nslookup, traceroute, netstat, arp)"
    Tags        = @("diagnostics", "network")

    Setup = {
        param($Context)
    }

    Execute = {
        param($Context)

        # --- Invoke-SafeguardPing to public DNS ---
        Test-SgPsAssert "Invoke-SafeguardPing pings 8.8.8.8" {
            $result = Invoke-SafeguardPing -Insecure "8.8.8.8" -Count 2
            $null -ne $result
        }

        # --- Invoke-SafeguardPing with size and nofrag ---
        Test-SgPsAssert "Invoke-SafeguardPing with size parameter" {
            $result = Invoke-SafeguardPing -Insecure "8.8.8.8" -Count 1 -Size 64
            $null -ne $result
        }

        # --- Invoke-SafeguardNsLookup ---
        Test-SgPsAssert "Invoke-SafeguardNsLookup resolves google.com" {
            $result = Invoke-SafeguardNsLookup -Insecure "google.com"
            $null -ne $result
        }

        # --- Invoke-SafeguardNsLookup with RecordType ---
        Test-SgPsAssert "Invoke-SafeguardNsLookup with A record type" {
            $result = Invoke-SafeguardNsLookup -Insecure "google.com" -RecordType "A"
            $null -ne $result
        }

        # --- Invoke-SafeguardTraceroute ---
        Test-SgPsAssert "Invoke-SafeguardTraceroute traces to 8.8.8.8" {
            $result = Invoke-SafeguardTraceroute -Insecure "8.8.8.8" -MaxHops 5
            $null -ne $result
        }

        # --- Invoke-SafeguardNetstat ---
        Test-SgPsAssert "Invoke-SafeguardNetstat returns connections" {
            $result = Invoke-SafeguardNetstat -Insecure
            $null -ne $result
        }

        # --- Invoke-SafeguardArp ---
        Test-SgPsAssert "Invoke-SafeguardArp returns ARP table" {
            $result = Invoke-SafeguardArp -Insecure
            $null -ne $result
        }

        # --- Invoke-SafeguardShowRoutes ---
        Test-SgPsAssert "Invoke-SafeguardShowRoutes returns routing table" {
            $result = Invoke-SafeguardShowRoutes -Insecure
            $null -ne $result
        }

        # --- Invoke-SafeguardTelnet ---
        Test-SgPsAssert "Invoke-SafeguardTelnet tests port connectivity" {
            $result = Invoke-SafeguardTelnet -Insecure "8.8.8.8" 53
            $null -ne $result
        }

        # --- Get-SafeguardDiagnosticPackageStatus ---
        Test-SgPsAssert "Get-SafeguardDiagnosticPackageStatus returns status" {
            $status = Get-SafeguardDiagnosticPackageStatus -Insecure
            # May return null when no diagnostic package exists -- that's valid
            $null -eq $status -or $null -ne $status.PackageState
        }
    }

    Cleanup = {
        param($Context)
    }
}
