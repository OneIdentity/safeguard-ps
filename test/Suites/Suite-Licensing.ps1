@{
    Name        = "Licensing"
    Description = "Tests read-only license listing (no install/uninstall on live appliance)"
    Tags        = @("licensing", "readonly")

    Setup = {
        param($Context)
        # Read-only suite -- no setup needed
    }

    Execute = {
        param($Context)

        Test-SgPsAssert "Get-SafeguardLicense returns license list" {
            $licenses = Get-SafeguardLicense -Insecure
            $null -ne $licenses
        }

        Test-SgPsAssert "License has expected properties" {
            $licenses = @(Get-SafeguardLicense -Insecure)
            if ($licenses.Count -gt 0) {
                $null -ne $licenses[0].Key
            } else {
                # No licenses installed -- still valid
                $true
            }
        }

        Test-SgPsAssert "Get-SafeguardLicense by key returns specific license" {
            $licenses = @(Get-SafeguardLicense -Insecure)
            if ($licenses.Count -gt 0) {
                $specific = Get-SafeguardLicense -Insecure $licenses[0].Key
                $null -ne $specific
            } else {
                $true
            }
        }
    }

    Cleanup = {
        param($Context)
        # Read-only suite -- no cleanup needed
    }
}
