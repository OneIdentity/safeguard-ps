@{
    Name        = "Networking"
    Description = "Tests read-only network interface and DNS suffix queries (no modifications to live appliance)"
    Tags        = @("networking", "readonly")

    Setup = {
        param($Context)
        # Read-only suite -- no setup needed
    }

    Execute = {
        param($Context)

        # --- Get all network interfaces ---
        Test-SgPsAssert "Get-SafeguardNetworkInterface returns all interfaces" {
            $interfaces = Get-SafeguardNetworkInterface -Insecure
            $null -ne $interfaces -and @($interfaces).Count -gt 0
        }

        # --- Get specific interfaces ---
        Test-SgPsAssert "Get-SafeguardNetworkInterface X0 returns interface" {
            $iface = Get-SafeguardNetworkInterface -Insecure "X0"
            $null -ne $iface
        }

        Test-SgPsAssert "Get-SafeguardNetworkInterface Mgmt returns interface" {
            $iface = Get-SafeguardNetworkInterface -Insecure "Mgmt"
            $null -ne $iface
        }

        Test-SgPsAssert "Network interface has expected properties" {
            $iface = Get-SafeguardNetworkInterface -Insecure "X0"
            $null -ne $iface.Name -and $null -ne $iface.Ipv4Address
        }

        # --- DNS suffix ---
        Test-SgPsAssert "Get-SafeguardDnsSuffix returns DNS suffix config" {
            $config = Get-SafeguardDnsSuffix -Insecure
            # Returns a DNS suffix configuration object
            $null -ne $config
        }
    }

    Cleanup = {
        param($Context)
        # Read-only suite -- no cleanup needed
    }
}
