#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

# Integration tests confirming that the D-013 redaction helper is actually
# wired into the SDK-internal call sites that emit auth plumbing on the
# Verbose stream. These tests do NOT require an appliance: they exercise
# verbose-emit paths by parsing the .psm1 source and verifying the call
# pattern, and they exercise Hide-SdkPlumbing end-to-end with a captured
# Verbose stream.

BeforeAll {
    $script:SrcRoot = Join-Path $PSScriptRoot '..\..\src'
    Import-Module (Join-Path $script:SrcRoot 'redaction.psm1') -Force
}

AfterAll {
    Remove-Module redaction -ErrorAction SilentlyContinue
}

Describe 'D-013 wire-up: call sites use Hide-SdkPlumbing for Headers verbose emit' {

    It 'safeguard-ps.psm1 wraps Headers verbose emit with Hide-SdkPlumbing' {
        $file = Join-Path $script:SrcRoot 'safeguard-ps.psm1'
        $text = Get-Content -Raw -Path $file
        # The raw-headers dump must not be reintroduced.
        $text | Should -Not -Match 'Write-Verbose\s+"Headers=\$\(ConvertTo-Json\s+-InputObject\s+\$local:Headers\)"'
        # The redacted form must be present.
        $text | Should -Match 'Hide-SdkPlumbing\s+\$local:Headers'
    }

    It 'sessionapi.psm1 wraps Headers verbose emit with Hide-SdkPlumbing' {
        $file = Join-Path $script:SrcRoot 'sessionapi.psm1'
        $text = Get-Content -Raw -Path $file
        $text | Should -Not -Match 'Write-Verbose\s+"Headers=\$\(ConvertTo-Json\s+-InputObject\s+\$local:Headers\)"'
        $text | Should -Match 'Hide-SdkPlumbing\s+\$local:Headers'
    }

    It 'a2acallers.psm1 wraps Headers verbose emit with Hide-SdkPlumbing' {
        $file = Join-Path $script:SrcRoot 'a2acallers.psm1'
        $text = Get-Content -Raw -Path $file
        $text | Should -Match 'Hide-SdkPlumbing\s+\$local:Headers'
    }

    It 'clustering.psm1 no longer interpolates raw $AccessToken into Write-Verbose' {
        $file = Join-Path $script:SrcRoot 'clustering.psm1'
        $text = Get-Content -Raw -Path $file
        $text | Should -Not -Match "Write-Verbose\s+`"[^`"]*'\`$AccessToken'"
    }
}

Describe 'D-013 end-to-end: capturing Verbose stream proves no token leak' {

    It 'a known bearer token does not appear in the Verbose output of Hide-SdkPlumbing' {
        $secret = 'sg-token-DO-NOT-LEAK-eyJabc.def.ghi-9999'
        $headers = @{
            Authorization = "Bearer $secret"
            Accept        = 'application/json'
        }
        $vOut = & {
            $VerbosePreference = 'Continue'
            Write-Verbose "Headers=$(ConvertTo-Json -InputObject (Hide-SdkPlumbing $headers))"
        } 4>&1 | Out-String

        $vOut | Should -Not -Match ([regex]::Escape($secret))
        $vOut | Should -Match 'Bearer \[REDACTED\]'
    }

    It 'a known access_token value does not appear in the Verbose output' {
        $secret = 'at-DO-NOT-LEAK-12345xyz'
        $tokenResponse = @{
            access_token  = $secret
            token_type    = 'Bearer'
            expires_in    = 3600
        }
        $vOut = & {
            $VerbosePreference = 'Continue'
            Write-Verbose "TokenResp=$(ConvertTo-Json -InputObject (Hide-SdkPlumbing $tokenResponse))"
        } 4>&1 | Out-String

        $vOut | Should -Not -Match ([regex]::Escape($secret))
        $vOut | Should -Match '\[REDACTED\]'
        $vOut | Should -Match 'Bearer'             # token_type passthrough
        $vOut | Should -Match '3600'               # expires_in passthrough
    }
}
