#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

BeforeAll {
    $src = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'src'
    Import-Module (Join-Path $src 'safeguard-ps.psd1') -Force
    foreach ($module in 'sg-utilities', 'users', 'policies', 'groups') {
        Import-Module (Join-Path $src "$module.psm1")
    }
}

Describe 'Shared qualified-name parsing' {
    It 'Allows a plain name without trimming it' {
        $parts = Split-SafeguardQualifiedName ' a ' -Format 'parent\child'
        $parts.Parent | Should -BeNullOrEmpty
        $parts.Name | Should -BeExactly ' a '
    }

    It 'Splits a qualified name into its parent and child' {
        $parts = Split-SafeguardQualifiedName 'parent\child' -Format 'parent\child'
        $parts.Parent | Should -BeExactly 'parent'
        $parts.Name | Should -BeExactly 'child'
    }

    It 'Rejects malformed input <Value>' -ForEach @(
        @{ Value = 'a\b\c' }, @{ Value = '\b' }, @{ Value = 'a\' },
        @{ Value = ' \b' }, @{ Value = 'a\ ' }, @{ Value = ' ' }
    ) {
        { Split-SafeguardQualifiedName $Value -Format 'parent\child' } | Should -Throw
    }

    It 'Can require a qualified name' {
        { Split-SafeguardQualifiedName 'plain' -Format 'asset\account' -RequireQualified } |
            Should -Throw '*expected format*'
    }

    It 'Escapes filter metacharacters without changing the name' {
        ConvertTo-SafeguardFilterStringLiteral "O'Brien\*" | Should -BeExactly "O\'Brien\\\*"
    }
}

Describe 'Exact user lookup' {
    BeforeEach {
        Mock Invoke-SafeguardMethod { @() } -ModuleName users
    }

    It 'Prefers login names without querying display names' {
        Mock Invoke-SafeguardMethod {
            [pscustomobject]@{ Id = 101; Name = 'jdoe'; DisplayName = 'John Doe' }
        } -ModuleName users -ParameterFilter { $Parameters.filter -eq "Name ieq 'jdoe'" }
        Resolve-SafeguardUserId 'jdoe' | Should -Be 101
        Should -Invoke Invoke-SafeguardMethod -ModuleName users -Times 0 -Exactly -ParameterFilter {
            $Parameters.filter -like 'DisplayName*'
        }
    }

    It 'Resolves a display name only when no login name matches' {
        Mock Invoke-SafeguardMethod {
            [pscustomobject]@{ Id = 101; Name = 'jdoe'; DisplayName = 'John Doe' }
        } -ModuleName users -ParameterFilter { $Parameters.filter -eq "DisplayName ieq 'John Doe'" }
        (Resolve-SafeguardUserObject 'John Doe').Id | Should -Be 101
    }

    It 'Rejects ambiguous <Field> matches' -ForEach @(@{ Field = 'Name' }, @{ Field = 'DisplayName' }) {
        Mock Invoke-SafeguardMethod {
            if ($Parameters.filter -eq "$Field ieq 'duplicate'") {
                [pscustomobject]@{ Id = 101; Name = 'duplicate'; DisplayName = 'duplicate' }
                [pscustomobject]@{ Id = 102; Name = 'duplicate'; DisplayName = 'duplicate' }
            }
        } -ModuleName users
        { Resolve-SafeguardUserId 'duplicate' } | Should -Throw '*Found 2 users*'
    }

    It 'Keeps the provider constraint and rejects a wrong-provider response' {
        Mock Invoke-SafeguardMethod {
            [pscustomobject]@{ Id = 101; Name = 'jdoe'; DisplayName = 'John Doe'; IdentityProvider = @{ Name = 'Other' } }
        } -ModuleName users
        { Resolve-SafeguardUserId 'Local\jdoe' } | Should -Throw '*Unable to find user*'
        Should -Invoke Invoke-SafeguardMethod -ModuleName users -Times 2 -Exactly -ParameterFilter {
            $Parameters.filter -like "IdentityProvider.Name ieq 'Local' and *"
        }
    }

    It 'Rejects malformed names before any request' {
        { Resolve-SafeguardUserId 'Local\a\b' } | Should -Throw '*expected format*'
        Should -Invoke Invoke-SafeguardMethod -ModuleName users -Times 0 -Exactly
    }

    It 'Propagates API failures without broad search fallback' {
        Mock Invoke-SafeguardMethod { throw 'Forbidden' } -ModuleName users
        { Resolve-SafeguardUserId 'Local\jdoe' } | Should -Throw '*Forbidden*'
        Should -Invoke Invoke-SafeguardMethod -ModuleName users -Times 1 -Exactly
    }

    It 'Escapes provider and user names' {
        Mock Invoke-SafeguardMethod {
            [pscustomobject]@{ Id = 101; Name = "O'Brien*"; IdentityProvider = @{ Name = "P'rovider" } }
        } -ModuleName users -ParameterFilter {
            $Parameters.filter -eq "IdentityProvider.Name ieq 'P\'rovider' and Name ieq 'O\'Brien\*'"
        }
        Resolve-SafeguardUserId "P'rovider\O'Brien*" | Should -Be 101
    }
}

Describe 'Qualified policy and account lookups' {
    BeforeEach {
        Mock Invoke-SafeguardMethod { @() } -ModuleName policies
    }

    It 'Rejects a policy response from the wrong entitlement' {
        Mock Resolve-SafeguardExactEntitlementId { 7 } -ModuleName policies
        Mock Invoke-SafeguardMethod {
            [pscustomobject]@{ Id = 101; Name = 'policy'; RoleId = 8 }
        } -ModuleName policies
        { Resolve-SafeguardAccessPolicyCopySourceId 'role\policy' } | Should -Throw '*Unable to find access policy*'
    }

    It 'Resolves a qualified account case-insensitively and within its asset' {
        Mock Resolve-SafeguardPolicyAssetId { 7 } -ModuleName policies
        Mock Invoke-SafeguardMethod {
            [pscustomobject]@{ Id = 101; Name = 'ROOT'; Asset = @{ Id = 7 } }
        } -ModuleName policies -ParameterFilter { $Parameters.filter -eq "Asset.Id eq 7 and Name ieq 'root'" }
        Resolve-SafeguardPolicyAccountId 'server\root' | Should -Be 101
    }

    It 'Rejects an account response from the wrong asset' {
        Mock Resolve-SafeguardPolicyAssetId { 7 } -ModuleName policies
        Mock Invoke-SafeguardMethod {
            [pscustomobject]@{ Id = 101; Name = 'root'; Asset = @{ Id = 8 } }
        } -ModuleName policies
        { Resolve-SafeguardPolicyAccountId 'server\root' } | Should -Throw '*Unable to find policy account*'
    }

    It 'Rejects malformed input to <Resolver> before any request' -ForEach @(
        @{ Resolver = 'Resolve-SafeguardPolicyAccountId' },
        @{ Resolver = 'Resolve-SafeguardAccessPolicyCopySourceId' }
    ) {
        { & $Resolver 'a\b\c' } | Should -Throw '*expected format*'
        Should -Invoke Invoke-SafeguardMethod -ModuleName policies -Times 0 -Exactly
    }

    It 'Propagates account API failures without broad search fallback' {
        Mock Resolve-SafeguardPolicyAssetId { 7 } -ModuleName policies
        Mock Invoke-SafeguardMethod { throw 'Forbidden' } -ModuleName policies
        { Resolve-SafeguardPolicyAccountId 'server\root' } | Should -Throw '*Forbidden*'
        Should -Invoke Invoke-SafeguardMethod -ModuleName policies -Times 1 -Exactly
    }
}

Describe 'Account-group qualified-name validation' {
    It 'Rejects malformed names before resolving accounts' {
        Mock Get-SafeguardAssetAccount { throw 'Unexpected lookup' } -ModuleName groups
        { Edit-SafeguardAccountGroup -GroupToEdit 7 -Operation Add -AccountList 'server\root\extra' } |
            Should -Throw '*expected format*'
        Should -Invoke Get-SafeguardAssetAccount -ModuleName groups -Times 0 -Exactly
    }
}
