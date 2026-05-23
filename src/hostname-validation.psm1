<# Copyright (c) 2026 One Identity LLC. All rights reserved. #>
# Hostname / appliance-address validation helpers.
# Nothing is exported from here for consumers of the module manifest;
# functions are visible to the other nested modules at module load.
#
# Security history (2026-05-22, S5 fix FP-safeguard-ps-003 / W7):
#   Connect-Safeguard and other appliance entry points used to accept any
#   string as the -Appliance value, allowing SSRF attacks aimed at IPv4/IPv6
#   loopback, link-local addresses, and the cloud metadata endpoint
#   (169.254.169.254). These targets are now rejected by default. A switch
#   parameter -AllowLocalhost is provided for legitimate dev/loopback use
#   (it does NOT relax the link-local or metadata-IP rejection).
#
# Scope (intentional non-goals):
#   * We do NOT resolve hostnames here. DNS rebind protection is assumed to
#     live in network-layer controls; client-side resolve-then-check has its
#     own TOCTOU risks and would slow every Connect-Safeguard call.
#   * RFC1918 addresses pass through -- corporate internal appliances are
#     a primary deployment shape for Safeguard.

function Assert-SafeguardApplianceAddress
{
    [CmdletBinding()]
    [OutputType([string])]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [AllowEmptyString()]
        [string]$Address,
        [Parameter(Mandatory=$false)]
        [switch]$AllowLocalhost
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }

    if ([string]::IsNullOrWhiteSpace($Address))
    {
        throw "Appliance address is empty."
    }

    $local:Trimmed = $Address.Trim()

    # Reject anything that looks like a URL -- the parameter expects a host.
    if ($local:Trimmed -match '^[A-Za-z][A-Za-z0-9+.-]*://')
    {
        throw "Appliance address '$local:Trimmed' must not include a URL scheme (e.g. 'https://'). Provide just the hostname or IP."
    }

    # Strip an optional :port suffix for validation (we still return the original input on success).
    $local:HostOnly = $local:Trimmed
    # IPv6 bracketed form: [fe80::1]:8443
    if ($local:HostOnly -match '^\[(?<h>[^\]]+)\](:\d+)?$')
    {
        $local:HostOnly = $Matches['h']
    }
    elseif ($local:HostOnly -match '^(?<h>[^:]+):\d+$')
    {
        # IPv4 or hostname with :port -- but only if exactly one colon (IPv6 has multiple).
        $local:HostOnly = $Matches['h']
    }

    # Hostname-level loopback shortcut
    if ($local:HostOnly -ieq 'localhost' -or $local:HostOnly -ieq 'localhost.localdomain' -or $local:HostOnly -ieq 'ip6-localhost')
    {
        if (-not $AllowLocalhost)
        {
            throw "Appliance address '$local:HostOnly' resolves to loopback. Refusing to connect (SSRF guard). Use -AllowLocalhost to override for development."
        }
        return $local:Trimmed
    }

    # Try to parse as IP. If it parses, run the IP classification gates.
    $local:Ip = $null
    if ([System.Net.IPAddress]::TryParse($local:HostOnly, [ref]$local:Ip))
    {
        $local:Bytes = $local:Ip.GetAddressBytes()

        if ($local:Ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork)
        {
            # 0.0.0.0/8 -- unspecified / "this network"
            if ($local:Bytes[0] -eq 0)
            {
                throw "Appliance address '$local:HostOnly' is in the unspecified range 0.0.0.0/8. Refusing to connect."
            }
            # 169.254.169.254 -- cloud instance metadata endpoint (AWS / Azure / GCP).
            # Check this BEFORE the broader 169.254.0.0/16 link-local gate so the
            # error message is specific.
            if ($local:Bytes[0] -eq 169 -and $local:Bytes[1] -eq 254 -and $local:Bytes[2] -eq 169 -and $local:Bytes[3] -eq 254)
            {
                throw "Appliance address '$local:HostOnly' is the cloud instance metadata endpoint. Refusing to connect (SSRF guard)."
            }
            # 169.254.0.0/16 -- link-local (RFC 3927).
            if ($local:Bytes[0] -eq 169 -and $local:Bytes[1] -eq 254)
            {
                throw "Appliance address '$local:HostOnly' is in the IPv4 link-local range 169.254.0.0/16. Refusing to connect (SSRF guard)."
            }
            # 127.0.0.0/8 -- loopback (RFC 1122).
            if ($local:Bytes[0] -eq 127)
            {
                if (-not $AllowLocalhost)
                {
                    throw "Appliance address '$local:HostOnly' is in the IPv4 loopback range 127.0.0.0/8. Refusing to connect (SSRF guard). Use -AllowLocalhost to override for development."
                }
            }
        }
        elseif ($local:Ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6)
        {
            if ([System.Net.IPAddress]::IsLoopback($local:Ip))
            {
                if (-not $AllowLocalhost)
                {
                    throw "Appliance address '$local:HostOnly' is the IPv6 loopback (::1). Refusing to connect (SSRF guard). Use -AllowLocalhost to override for development."
                }
            }
            # fe80::/10 -- IPv6 link-local. First 10 bits == 1111111010.
            elseif ($local:Bytes[0] -eq 0xFE -and (($local:Bytes[1] -band 0xC0) -eq 0x80))
            {
                throw "Appliance address '$local:HostOnly' is in the IPv6 link-local range fe80::/10. Refusing to connect (SSRF guard)."
            }
            # :: -- unspecified
            elseif (($local:Bytes | ForEach-Object { $_ } | Measure-Object -Sum).Sum -eq 0)
            {
                throw "Appliance address '$local:HostOnly' is the unspecified IPv6 address (::). Refusing to connect."
            }
        }
    }
    # If it didn't parse as an IP, it's a hostname; we trust DNS-layer controls.

    return $local:Trimmed
}
