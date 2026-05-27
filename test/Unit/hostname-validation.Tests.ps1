# Copyright (c) 2026 One Identity LLC. All rights reserved.
#
# Pester unit tests for hostname-validation.psm1 (FP-safeguard-ps-003 / W7 SSRF).
# Run with: Invoke-Pester -Path test/Unit/hostname-validation.Tests.ps1

BeforeAll {
    $script:RepoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
    $script:RepoRoot = Split-Path -Parent $script:RepoRoot
    $script:Module = Join-Path $script:RepoRoot 'src/hostname-validation.psm1'

    Get-Module hostname-validation | Remove-Module -Force -ErrorAction SilentlyContinue
    Import-Module $script:Module -Force
}

AfterAll {
    Get-Module hostname-validation | Remove-Module -Force -ErrorAction SilentlyContinue
}

Describe 'FP-safeguard-ps-003 -- Assert-SafeguardApplianceAddress' {

    Context 'Accepts legitimate addresses' {
        It 'Returns the input unchanged for an FQDN' {
            Assert-SafeguardApplianceAddress -Address 'appliance.example.com' | Should -Be 'appliance.example.com'
        }
        It 'Accepts a public IPv4' {
            Assert-SafeguardApplianceAddress -Address '203.0.113.7' | Should -Be '203.0.113.7'
        }
        It 'Accepts RFC1918 10/8' {
            Assert-SafeguardApplianceAddress -Address '10.5.32.54' | Should -Be '10.5.32.54'
        }
        It 'Accepts RFC1918 172.16/12' {
            Assert-SafeguardApplianceAddress -Address '172.20.0.10' | Should -Be '172.20.0.10'
        }
        It 'Accepts RFC1918 192.168/16' {
            Assert-SafeguardApplianceAddress -Address '192.168.117.15' | Should -Be '192.168.117.15'
        }
        It 'Accepts an IPv4 with port via host:port spelling (host stripped for validation)' {
            Assert-SafeguardApplianceAddress -Address '10.5.32.54:8443' | Should -Be '10.5.32.54:8443'
        }
    }

    Context 'Rejects dangerous SSRF targets' {
        It 'Throws on IPv4 loopback 127.0.0.1' {
            { Assert-SafeguardApplianceAddress -Address '127.0.0.1' } | Should -Throw -ExpectedMessage '*loopback*'
        }
        It 'Throws on IPv4 loopback elsewhere in 127/8' {
            { Assert-SafeguardApplianceAddress -Address '127.10.20.30' } | Should -Throw -ExpectedMessage '*loopback*'
        }
        It 'Throws on IPv6 loopback ::1' {
            { Assert-SafeguardApplianceAddress -Address '::1' } | Should -Throw -ExpectedMessage '*loopback*'
        }
        It 'Throws on cloud metadata IP 169.254.169.254' {
            { Assert-SafeguardApplianceAddress -Address '169.254.169.254' } | Should -Throw -ExpectedMessage '*metadata*'
        }
        It 'Throws on IPv4 link-local 169.254.x.x' {
            { Assert-SafeguardApplianceAddress -Address '169.254.10.20' } | Should -Throw -ExpectedMessage '*link-local*'
        }
        It 'Throws on IPv6 link-local fe80::' {
            { Assert-SafeguardApplianceAddress -Address 'fe80::1' } | Should -Throw -ExpectedMessage '*link-local*'
        }
        It 'Throws on IPv4 unspecified 0.0.0.0' {
            { Assert-SafeguardApplianceAddress -Address '0.0.0.0' } | Should -Throw -ExpectedMessage '*unspecified*'
        }
        It 'Throws on localhost hostname' {
            { Assert-SafeguardApplianceAddress -Address 'localhost' } | Should -Throw -ExpectedMessage '*loopback*'
        }
    }

    Context 'AllowLocalhost switch' {
        It 'Accepts 127.0.0.1 when -AllowLocalhost is set' {
            Assert-SafeguardApplianceAddress -Address '127.0.0.1' -AllowLocalhost | Should -Be '127.0.0.1'
        }
        It 'Accepts ::1 when -AllowLocalhost is set' {
            Assert-SafeguardApplianceAddress -Address '::1' -AllowLocalhost | Should -Be '::1'
        }
        It 'Accepts localhost when -AllowLocalhost is set' {
            Assert-SafeguardApplianceAddress -Address 'localhost' -AllowLocalhost | Should -Be 'localhost'
        }
        It 'STILL throws on metadata IP even with -AllowLocalhost' {
            { Assert-SafeguardApplianceAddress -Address '169.254.169.254' -AllowLocalhost } | Should -Throw -ExpectedMessage '*metadata*'
        }
        It 'STILL throws on link-local even with -AllowLocalhost' {
            { Assert-SafeguardApplianceAddress -Address 'fe80::1' -AllowLocalhost } | Should -Throw -ExpectedMessage '*link-local*'
        }
    }

    Context 'Input hygiene' {
        It 'Throws on empty input' {
            { Assert-SafeguardApplianceAddress -Address '' } | Should -Throw
        }
        It 'Throws on a URL (the parameter expects a host, not a URL)' {
            { Assert-SafeguardApplianceAddress -Address 'https://10.5.32.54/api' } | Should -Throw -ExpectedMessage '*scheme*'
        }
        It 'Trims whitespace' {
            Assert-SafeguardApplianceAddress -Address '   10.5.32.54   ' | Should -Be '10.5.32.54'
        }
    }
}
