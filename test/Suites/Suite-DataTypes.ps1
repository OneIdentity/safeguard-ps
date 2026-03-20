@{
    Name        = "Data Types"
    Description = "Tests read-only platform, timezone, transfer protocol, and identity provider type lookups"
    Tags        = @("datatypes", "readonly")

    Setup = {
        param($Context)
        # No setup needed -- all read-only operations
    }

    Execute = {
        param($Context)

        # --- Get-SafeguardPlatform (list all) ---
        Test-SgPsAssert "Get-SafeguardPlatform lists platforms" {
            $platforms = Get-SafeguardPlatform -Insecure
            @($platforms).Count -gt 0
        }

        # --- Get-SafeguardPlatform by ID ---
        Test-SgPsAssert "Get-SafeguardPlatform by ID" {
            $platforms = Get-SafeguardPlatform -Insecure
            $first = @($platforms)[0]
            $platform = Get-SafeguardPlatform -Insecure $first.Id
            $platform.Id -eq $first.Id
        }

        # --- Find-SafeguardPlatform ---
        Test-SgPsAssert "Find-SafeguardPlatform by search string" {
            $results = Find-SafeguardPlatform -Insecure "Windows"
            @($results).Count -gt 0
        }

        # --- Get-SafeguardTimeZone (list all) ---
        Test-SgPsAssert "Get-SafeguardTimeZone lists timezones" {
            $timezones = Get-SafeguardTimeZone -Insecure
            @($timezones).Count -gt 0
        }

        # --- Get-SafeguardTimeZone by ID ---
        Test-SgPsAssert "Get-SafeguardTimeZone by ID" {
            $tz = Get-SafeguardTimeZone -Insecure "UTC"
            $null -ne $tz
        }

        # --- Get-SafeguardTransferProtocol (list all) ---
        Test-SgPsAssert "Get-SafeguardTransferProtocol lists protocols" {
            $protocols = Get-SafeguardTransferProtocol -Insecure
            @($protocols).Count -gt 0
        }

        # --- Get-SafeguardIdentityProviderType (list all) ---
        Test-SgPsAssert "Get-SafeguardIdentityProviderType lists provider types" {
            $types = Get-SafeguardIdentityProviderType -Insecure
            @($types).Count -gt 0
        }

        # --- Get-SafeguardIdentityProviderType by ID ---
        Test-SgPsAssert "Get-SafeguardIdentityProviderType for Local provider" {
            $types = Get-SafeguardIdentityProviderType -Insecure
            $localType = @($types) | Where-Object { $_.Name -eq "Local" -or $_.Id -eq -1 }
            $null -ne $localType
        }
    }

    Cleanup = {
        param($Context)
        # Nothing to clean up -- all read-only
    }
}
