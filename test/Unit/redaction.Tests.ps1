#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

# Pester 5 tests for the D-013 redaction allowlist.
# Doctrine: exact, case-insensitive, top-level key match against a FIXED
# allowlist; string-valued leaves only; NO recursion; NO substring matching;
# NO regex. Anything not in the allowlist must pass through UNCHANGED.

BeforeAll {
    $script:ModulePath = Join-Path $PSScriptRoot '..\..\src\redaction.psm1'
    Import-Module $script:ModulePath -Force
}

AfterAll {
    Remove-Module redaction -ErrorAction SilentlyContinue
}

Describe 'Redact-SdkPlumbing - positive (allowlisted keys are redacted)' {

    It 'redacts a top-level Authorization Bearer token to "Bearer [REDACTED]"' {
        $h = @{ Authorization = 'Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig' }
        $r = Redact-SdkPlumbing -InputObject $h
        $r.Authorization | Should -Be 'Bearer [REDACTED]'
    }

    It 'redacts a top-level Authorization Basic credential to "Basic [REDACTED]"' {
        $h = @{ Authorization = 'Basic dXNlcjpwYXNz' }
        $r = Redact-SdkPlumbing -InputObject $h
        $r.Authorization | Should -Be 'Basic [REDACTED]'
    }

    It 'redacts a top-level Authorization with unknown scheme to "[REDACTED]"' {
        $h = @{ Authorization = 'SomethingElse abcdef' }
        $r = Redact-SdkPlumbing -InputObject $h
        $r.Authorization | Should -Be '[REDACTED]'
    }

    It 'is case-insensitive on the key name (authorization)' {
        $h = @{ authorization = 'Bearer secret' }
        $r = Redact-SdkPlumbing -InputObject $h
        $r.authorization | Should -Be 'Bearer [REDACTED]'
    }

    It 'redacts top-level Cookie' {
        $h = @{ Cookie = 'session=abc; csrf=def' }
        $r = Redact-SdkPlumbing -InputObject $h
        $r.Cookie | Should -Be '[REDACTED]'
    }

    It 'redacts top-level Set-Cookie' {
        $h = @{ 'Set-Cookie' = 'session=abc; HttpOnly' }
        $r = Redact-SdkPlumbing -InputObject $h
        $r.'Set-Cookie' | Should -Be '[REDACTED]'
    }

    It 'redacts top-level access_token' {
        $h = @{ access_token = 'eyJhbGciOi...' }
        $r = Redact-SdkPlumbing -InputObject $h
        $r.access_token | Should -Be '[REDACTED]'
    }

    It 'redacts top-level refresh_token' {
        $h = @{ refresh_token = 'rt_secret_value' }
        $r = Redact-SdkPlumbing -InputObject $h
        $r.refresh_token | Should -Be '[REDACTED]'
    }

    It 'redacts top-level id_token' {
        $h = @{ id_token = 'id_token_jwt' }
        $r = Redact-SdkPlumbing -InputObject $h
        $r.id_token | Should -Be '[REDACTED]'
    }

    It 'redacts top-level UserToken' {
        $h = @{ UserToken = 'ut_secret' }
        $r = Redact-SdkPlumbing -InputObject $h
        $r.UserToken | Should -Be '[REDACTED]'
    }

    It 'redacts multiple allowlisted keys in the same object' {
        $h = @{ Authorization = 'Bearer x'; access_token = 'y'; Cookie = 'z' }
        $r = Redact-SdkPlumbing -InputObject $h
        $r.Authorization | Should -Be 'Bearer [REDACTED]'
        $r.access_token  | Should -Be '[REDACTED]'
        $r.Cookie        | Should -Be '[REDACTED]'
    }
}

Describe 'Redact-SdkPlumbing - D-013 tripwires (MUST PASS THROUGH UNCHANGED)' {

    # These keys CONTAIN substrings of allowlisted keys but are NOT secrets;
    # any substring/regex-based redactor would incorrectly mangle them and
    # break Safeguard API payloads. They MUST be returned byte-for-byte.

    It 'PasswordRulesPolicyId is not redacted' {
        $h = @{ PasswordRulesPolicyId = 42 }
        $r = Redact-SdkPlumbing -InputObject $h
        $r.PasswordRulesPolicyId | Should -Be 42
    }

    It 'ApiKeyName is not redacted' {
        $h = @{ ApiKeyName = 'my-key' }
        $r = Redact-SdkPlumbing -InputObject $h
        $r.ApiKeyName | Should -Be 'my-key'
    }

    It 'RequirePasswordChange is not redacted' {
        $h = @{ RequirePasswordChange = $true }
        $r = Redact-SdkPlumbing -InputObject $h
        $r.RequirePasswordChange | Should -BeTrue
    }

    It 'PasswordHistoryDepth is not redacted' {
        $h = @{ PasswordHistoryDepth = 10 }
        $r = Redact-SdkPlumbing -InputObject $h
        $r.PasswordHistoryDepth | Should -Be 10
    }

    It 'NewPasswordValidUntil is not redacted' {
        $h = @{ NewPasswordValidUntil = '2030-01-01T00:00:00Z' }
        $r = Redact-SdkPlumbing -InputObject $h
        $r.NewPasswordValidUntil | Should -Be '2030-01-01T00:00:00Z'
    }

    It 'AccountPasswordRule is not redacted' {
        $h = @{ AccountPasswordRule = 'Strong' }
        $r = Redact-SdkPlumbing -InputObject $h
        $r.AccountPasswordRule | Should -Be 'Strong'
    }

    It 'Password (bare key) is not redacted' {
        # The allowlist does NOT include bare 'Password' -- only authentication
        # plumbing headers/tokens. Account password payload fields are NOT
        # treated as plumbing by this helper.
        $h = @{ Password = 'p@ss' }
        $r = Redact-SdkPlumbing -InputObject $h
        $r.Password | Should -Be 'p@ss'
    }

    It 'PrivateKey is not redacted' {
        $h = @{ PrivateKey = '-----BEGIN KEY-----' }
        $r = Redact-SdkPlumbing -InputObject $h
        $r.PrivateKey | Should -Be '-----BEGIN KEY-----'
    }

    It 'ApiKey (bare key) is not redacted' {
        $h = @{ ApiKey = 'ak_value' }
        $r = Redact-SdkPlumbing -InputObject $h
        $r.ApiKey | Should -Be 'ak_value'
    }
}

Describe 'Redact-SdkPlumbing - shape and edge cases' {

    It 'returns $null unchanged for $null input' {
        Redact-SdkPlumbing -InputObject $null | Should -BeNullOrEmpty
    }

    It 'returns a non-hashtable input unchanged' {
        $s = 'a plain string'
        Redact-SdkPlumbing -InputObject $s | Should -Be 'a plain string'
    }

    It 'does NOT redact non-string Authorization value (string-leaves-only rule)' {
        $h = @{ Authorization = 42 }
        $r = Redact-SdkPlumbing -InputObject $h
        $r.Authorization | Should -Be 42
    }

    It 'does NOT recurse into nested hashtables' {
        # Allowlisted key buried inside a nested object MUST be left alone --
        # recursion is forbidden by D-013.
        $h = @{ outer = @{ Authorization = 'Bearer secret' } }
        $r = Redact-SdkPlumbing -InputObject $h
        $r.outer.Authorization | Should -Be 'Bearer secret'
    }

    It 'preserves non-allowlisted top-level keys' {
        $h = @{ Authorization = 'Bearer t'; Accept = 'application/json'; UserAgent = 'sg-ps' }
        $r = Redact-SdkPlumbing -InputObject $h
        $r.Accept    | Should -Be 'application/json'
        $r.UserAgent | Should -Be 'sg-ps'
    }

    It 'does not mutate the input object' {
        $h = @{ Authorization = 'Bearer original' }
        $null = Redact-SdkPlumbing -InputObject $h
        $h.Authorization | Should -Be 'Bearer original'
    }

    It 'accepts a PSCustomObject and returns a hashtable with redaction applied' {
        $o = [PSCustomObject]@{ Authorization = 'Bearer x'; PasswordRulesPolicyId = 5 }
        $r = Redact-SdkPlumbing -InputObject $o
        $r.Authorization          | Should -Be 'Bearer [REDACTED]'
        $r.PasswordRulesPolicyId  | Should -Be 5
    }
}

Describe 'Redact-AuthHeaderValue - direct unit tests' {

    It 'redacts Bearer scheme' {
        Redact-AuthHeaderValue -Value 'Bearer abc.def.ghi' | Should -Be 'Bearer [REDACTED]'
    }

    It 'redacts Basic scheme' {
        Redact-AuthHeaderValue -Value 'Basic dXNlcjpwYXNz' | Should -Be 'Basic [REDACTED]'
    }

    It 'redacts unknown scheme to plain [REDACTED]' {
        Redact-AuthHeaderValue -Value 'Custom token123' | Should -Be '[REDACTED]'
    }

    It 'is case-insensitive on the scheme' {
        Redact-AuthHeaderValue -Value 'bearer abc' | Should -Be 'Bearer [REDACTED]'
        Redact-AuthHeaderValue -Value 'BASIC xyz'  | Should -Be 'Basic [REDACTED]'
    }

    It 'returns "[REDACTED]" for empty / whitespace input' {
        Redact-AuthHeaderValue -Value '' | Should -Be '[REDACTED]'
    }
}
