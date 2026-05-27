# Copyright (c) 2026 One Identity LLC. All rights reserved.
#
# Pester unit tests for sslhandling.psm1.
# Run with: Invoke-Pester -Path test/Unit/ssl-handling.Tests.ps1

BeforeAll {
    $script:RepoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
    $script:RepoRoot = Split-Path -Parent $script:RepoRoot
    $script:SslModulePath = Join-Path $script:RepoRoot 'src/sslhandling.psm1'

    # Snapshot global state so each test can assert no leakage.
    $script:OriginalGlobalDefaults = @{}
    if ($global:PSDefaultParameterValues) {
        foreach ($k in $global:PSDefaultParameterValues.Keys) {
            $script:OriginalGlobalDefaults[$k] = $global:PSDefaultParameterValues[$k]
        }
    }

    Get-Module sslhandling | Remove-Module -Force -ErrorAction SilentlyContinue
    Import-Module $script:SslModulePath -Force
}

AfterAll {
    Get-Module sslhandling | Remove-Module -Force -ErrorAction SilentlyContinue
}

Describe 'FP-safeguard-ps-001 -- Global PSDefaultParameterValues mutation removed' {

    BeforeEach {
        # Reset global to original snapshot before each test
        $keysToRemove = @()
        foreach ($k in $global:PSDefaultParameterValues.Keys) {
            if (-not $script:OriginalGlobalDefaults.ContainsKey($k)) {
                $keysToRemove += $k
            }
        }
        foreach ($k in $keysToRemove) { $global:PSDefaultParameterValues.Remove($k) | Out-Null }
    }

    It 'Disable-SslVerification does NOT add SkipCertificateCheck to $global:PSDefaultParameterValues' {
        $before = $global:PSDefaultParameterValues.Contains('Invoke-RestMethod:SkipCertificateCheck')
        Disable-SslVerification
        $after = $global:PSDefaultParameterValues.Contains('Invoke-RestMethod:SkipCertificateCheck')
        $before | Should -Be $false
        $after  | Should -Be $false
    }

    It 'Disable-SslVerification does NOT add Invoke-WebRequest:SkipCertificateCheck to global defaults' {
        Disable-SslVerification
        $global:PSDefaultParameterValues.Contains('Invoke-WebRequest:SkipCertificateCheck') | Should -Be $false
    }

    It 'Enable-SslVerification leaves global defaults unchanged (does not remove keys it never added)' {
        # Pre-seed an unrelated key the user might have set themselves
        $global:PSDefaultParameterValues['Get-ChildItem:Force'] = $true
        Disable-SslVerification
        Enable-SslVerification
        $global:PSDefaultParameterValues.Contains('Get-ChildItem:Force') | Should -Be $true
        $global:PSDefaultParameterValues['Get-ChildItem:Force']           | Should -Be $true
        $global:PSDefaultParameterValues.Remove('Get-ChildItem:Force') | Out-Null
    }

    It 'Get-SafeguardSslPreferences returns SkipCertificateCheck splat when SSL verification disabled (PS6+ only)' {
        Disable-SslVerification
        $prefs = Get-SafeguardSslPreferences
        if ($PSVersionTable.PSEdition -eq 'Core' -and $PSVersionTable.PSVersion.Major -ge 6) {
            $prefs                                                  | Should -BeOfType 'System.Collections.IDictionary'
            $prefs.ContainsKey('Invoke-RestMethod:SkipCertificateCheck') | Should -Be $true
            $prefs['Invoke-RestMethod:SkipCertificateCheck']            | Should -Be $true
            $prefs.ContainsKey('Invoke-WebRequest:SkipCertificateCheck') | Should -Be $true
        }
        else {
            # On Windows PowerShell 5.1 the callback handles TLS skip; helper returns empty.
            $prefs.Count | Should -Be 0
        }
    }

    It 'Get-SafeguardSslPreferences returns empty hashtable when verification is enabled' {
        Enable-SslVerification
        $prefs = Get-SafeguardSslPreferences
        $prefs       | Should -BeOfType 'System.Collections.IDictionary'
        $prefs.Count | Should -Be 0
    }

    It 'Toggle cycle: Disable then Enable produces empty helper output' {
        Disable-SslVerification
        Enable-SslVerification
        (Get-SafeguardSslPreferences).Count | Should -Be 0
    }

    It 'Bug witness: non-Safeguard Invoke-RestMethod is NOT silently affected after Disable-SslVerification' {
        # Before the fix, $global:PSDefaultParameterValues['Invoke-RestMethod:SkipCertificateCheck']
        # would have been set, silently affecting unrelated cmdlets in the caller's session.
        Disable-SslVerification
        $global:PSDefaultParameterValues['Invoke-RestMethod:SkipCertificateCheck'] | Should -BeNullOrEmpty
        $global:PSDefaultParameterValues['Invoke-WebRequest:SkipCertificateCheck'] | Should -BeNullOrEmpty
    }
}

Describe 'FP-safeguard-ps-002 -- TLS 1.0/1.1 hardening in Edit-SslVersionSupport' {

    BeforeEach {
        $script:OriginalProtocol = [System.Net.ServicePointManager]::SecurityProtocol
    }

    AfterEach {
        [System.Net.ServicePointManager]::SecurityProtocol = $script:OriginalProtocol
    }

    It 'Strips Tls10 from SecurityProtocol when present' {
        [System.Net.ServicePointManager]::SecurityProtocol = `
            [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls
        Edit-SslVersionSupport
        $hasTls10 = [bool]([System.Net.ServicePointManager]::SecurityProtocol -band [System.Net.SecurityProtocolType]::Tls)
        $hasTls10 | Should -Be $false
    }

    It 'Strips Tls11 from SecurityProtocol when present' {
        [System.Net.ServicePointManager]::SecurityProtocol = `
            [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls11
        Edit-SslVersionSupport
        $hasTls11 = [bool]([System.Net.ServicePointManager]::SecurityProtocol -band [System.Net.SecurityProtocolType]::Tls11)
        $hasTls11 | Should -Be $false
    }

    It 'Strips Ssl3 from SecurityProtocol when present' {
        # Some modern .NET runtimes reject -Ssl3 with NotSupportedException; skip when unsupported.
        try {
            [System.Net.ServicePointManager]::SecurityProtocol = `
                [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Ssl3
        } catch {
            Set-ItResult -Skipped -Because 'Runtime refuses to honour Ssl3; nothing for Edit-SslVersionSupport to strip.'
            return
        }
        Edit-SslVersionSupport
        $hasSsl3 = [bool]([System.Net.ServicePointManager]::SecurityProtocol -band [System.Net.SecurityProtocolType]::Ssl3)
        $hasSsl3 | Should -Be $false
    }

    It 'Adds Tls12 if not already present' {
        [System.Net.ServicePointManager]::SecurityProtocol = `
            [System.Net.SecurityProtocolType]::SystemDefault
        Edit-SslVersionSupport
        $hasTls12 = [bool]([System.Net.ServicePointManager]::SecurityProtocol -band [System.Net.SecurityProtocolType]::Tls12)
        $hasTls12 | Should -Be $true
    }

    It 'Adds Tls13 when the runtime supports it' {
        $tls13 = [System.Net.SecurityProtocolType].GetEnumNames() -contains 'Tls13'
        if ($tls13) {
            [System.Net.ServicePointManager]::SecurityProtocol = `
                [System.Net.SecurityProtocolType]::SystemDefault
            Edit-SslVersionSupport
            $tls13Value = [System.Net.SecurityProtocolType]::Tls13
            $hasTls13 = [bool]([System.Net.ServicePointManager]::SecurityProtocol -band $tls13Value)
            $hasTls13 | Should -Be $true
        }
        else {
            Set-ItResult -Skipped -Because 'Runtime does not expose SecurityProtocolType::Tls13'
        }
    }
}
