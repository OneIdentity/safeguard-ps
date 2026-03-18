@{
    Name        = "Appliance Status"
    Description = "Tests read-only appliance status, version, health, time, name, and state"
    Tags        = @("appliance", "readonly")

    Setup = {
        param($Context)
    }

    Execute = {
        param($Context)

        # --- Get-SafeguardStatus ---
        Test-SgPsAssert "Get-SafeguardStatus returns appliance status" {
            $status = Get-SafeguardStatus -Appliance $Context.Appliance -Insecure
            $null -ne $status
        }

        # --- Get-SafeguardVersion ---
        Test-SgPsAssert "Get-SafeguardVersion returns version info" {
            $version = Get-SafeguardVersion -Appliance $Context.Appliance -Insecure
            $null -ne $version -and $null -ne $version.Build
        }

        # --- Test-SafeguardVersion ---
        Test-SgPsAssert "Test-SafeguardVersion validates appliance version" {
            $result = Test-SafeguardVersion -Appliance $Context.Appliance -Insecure "2.0"
            $result -eq $true
        }

        # --- Get-SafeguardApplianceName ---
        Test-SgPsAssert "Get-SafeguardApplianceName returns name" {
            $name = Get-SafeguardApplianceName -Insecure
            $null -ne $name -and $name.Length -gt 0
        }

        # --- Get-SafeguardTime ---
        Test-SgPsAssert "Get-SafeguardTime returns current time" {
            $time = Get-SafeguardTime -Appliance $Context.Appliance -Insecure
            $null -ne $time
        }

        # --- Get-SafeguardHealth ---
        Test-SgPsAssert "Get-SafeguardHealth returns health status" {
            $health = Get-SafeguardHealth -Insecure
            $null -ne $health
        }

        # --- Get-SafeguardHealth with ForceUpdate ---
        Test-SgPsAssert "Get-SafeguardHealth with ForceUpdate" {
            $health = Get-SafeguardHealth -Insecure -ForceUpdate
            $null -ne $health
        }

        # --- Get-SafeguardApplianceState ---
        Test-SgPsAssert "Get-SafeguardApplianceState returns state" {
            $state = Get-SafeguardApplianceState -Insecure
            $null -ne $state
        }

        # --- Get-SafeguardApplianceUptime ---
        Test-SgPsAssert "Get-SafeguardApplianceUptime returns uptime" {
            $uptime = Get-SafeguardApplianceUptime -Insecure
            $null -ne $uptime
        }

        # --- Get-SafeguardApplianceAvailability ---
        Test-SgPsAssert "Get-SafeguardApplianceAvailability returns availability" {
            $avail = Get-SafeguardApplianceAvailability -Appliance $Context.Appliance -Insecure
            $null -ne $avail
        }

        # --- Get-SafeguardApplianceVerification ---
        Test-SgPsAssert "Get-SafeguardApplianceVerification returns result" {
            $verify = Get-SafeguardApplianceVerification -Insecure
            $null -ne $verify
        }

        # --- Get-SafeguardTls12OnlyStatus ---
        Test-SgPsAssert "Get-SafeguardTls12OnlyStatus returns TLS status" {
            $tls = Get-SafeguardTls12OnlyStatus -Insecure
            $null -ne $tls
        }

        # --- Get-SafeguardApplianceDnsSuffix ---
        Test-SgPsAssert "Get-SafeguardApplianceDnsSuffix returns DNS suffix" {
            $suffix = Get-SafeguardApplianceDnsSuffix -Insecure
            # May be null/empty but should not throw
            $true
        }
    }

    Cleanup = {
        param($Context)
    }
}
