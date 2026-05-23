# Copyright (c) 2026 One Identity LLC. All rights reserved.
#
# Pester integration test for Connect-Safeguard SSRF guard (FP-safeguard-ps-003).
# Verifies that the SSRF guard fires *before* any network call.

BeforeAll {
    $script:RepoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
    $script:RepoRoot = Split-Path -Parent $script:RepoRoot
    $script:Manifest = Join-Path $script:RepoRoot 'src/safeguard-ps.psd1'

    Get-Module safeguard-ps | Remove-Module -Force -ErrorAction SilentlyContinue
    Import-Module $script:Manifest -Force
}

AfterAll {
    Get-Module safeguard-ps | Remove-Module -Force -ErrorAction SilentlyContinue
}

Describe 'FP-safeguard-ps-003 -- Connect-Safeguard SSRF guard' {
    It 'Rejects -Appliance 127.0.0.1 before any network call' {
        { Connect-Safeguard -Appliance '127.0.0.1' -NoSessionVariable -ErrorAction Stop } |
            Should -Throw -ExpectedMessage '*loopback*'
    }
    It 'Rejects -Appliance 169.254.169.254 (cloud metadata) before any network call' {
        { Connect-Safeguard -Appliance '169.254.169.254' -NoSessionVariable -ErrorAction Stop } |
            Should -Throw -ExpectedMessage '*metadata*'
    }
    It 'Rejects -Appliance fe80::1 (link-local) before any network call' {
        { Connect-Safeguard -Appliance 'fe80::1' -NoSessionVariable -ErrorAction Stop } |
            Should -Throw -ExpectedMessage '*link-local*'
    }
    It 'Passes hostname validation with -AllowLocalhost (network attempt happens after; we only assert it is NOT the SSRF guard that throws)' {
        try {
            Connect-Safeguard -Appliance '127.0.0.1' -AllowLocalhost -NoSessionVariable -ErrorAction Stop
            # If no throw, that's also fine (extremely unlikely in CI).
            $true | Should -Be $true
        }
        catch {
            $_.Exception.Message | Should -Not -Match 'SSRF guard'
            $_.Exception.Message | Should -Not -Match 'Refusing to connect'
        }
    }
}
