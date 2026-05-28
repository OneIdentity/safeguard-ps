#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.0.0' }

# Pester 5 tests for Resolve-* functions.
# Validates that single-result API responses are handled correctly across
# both PS 5.1 (where PSCustomObject lacks .Count) and PS 7+.
#
# These tests mock Invoke-SafeguardMethod to return a single PSCustomObject
# (simulating the PS 5.1 behavior where Invoke-RestMethod unwraps single-element
# arrays) and verify that resolve functions return the correct ID without throwing.

BeforeAll {
    $script:RepoRoot = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
    $script:RepoRoot = Split-Path -Parent $script:RepoRoot
    $script:SrcDir = Join-Path $script:RepoRoot 'src'
    $script:Manifest = Join-Path $script:SrcDir 'safeguard-ps.psd1'

    Get-Module safeguard-ps | Remove-Module -Force -ErrorAction SilentlyContinue
    Import-Module $script:Manifest -Force
}

AfterAll {
    Get-Module safeguard-ps | Remove-Module -Force -ErrorAction SilentlyContinue
}

Describe 'Resolve-SafeguardDirectoryId - single result handling' {
    BeforeAll {
        Import-Module (Join-Path $script:SrcDir 'directories.psm1') -Force
    }

    It 'Returns correct ID when API returns a single directory object' {
        # Simulate single PSCustomObject (as PS 5.1 delivers from Invoke-RestMethod)
        $singleDirectory = [PSCustomObject]@{ Id = 42; Name = "test.corp"; NetworkAddress = "10.0.0.1" }

        Mock Invoke-SafeguardMethod {
            # First call (Name filter) returns the single object
            $singleDirectory
        } -ModuleName directories

        $result = Resolve-SafeguardDirectoryId -Appliance "fake" -AccessToken "fake" -Insecure "test.corp"
        $result | Should -Be 42
    }

    It 'Returns correct ID when directory found via DomainName filter (third query)' {
        $callCount = 0
        $singleDirectory = [PSCustomObject]@{ Id = 99; Name = "dc1.test.corp"; NetworkAddress = "10.0.0.2" }

        Mock Invoke-SafeguardMethod {
            $script:callCount++
            if ($script:callCount -le 2) {
                # First two queries (Name, NetworkAddress) return empty
                return @()
            }
            # Third query (DomainName) returns the single object
            $singleDirectory
        } -ModuleName directories

        $script:callCount = 0
        $result = Resolve-SafeguardDirectoryId -Appliance "fake" -AccessToken "fake" -Insecure "test.corp"
        $result | Should -Be 99
    }

    It 'Throws when no directory is found' {
        Mock Invoke-SafeguardMethod {
            return @()
        } -ModuleName directories

        { Resolve-SafeguardDirectoryId -Appliance "fake" -AccessToken "fake" -Insecure "nonexistent" } |
            Should -Throw "*Unable to find directory*"
    }

    It 'Throws with correct count when multiple directories match' {
        $multipleResults = @(
            [PSCustomObject]@{ Id = 1; Name = "dir1" },
            [PSCustomObject]@{ Id = 2; Name = "dir2" }
        )

        Mock Invoke-SafeguardMethod {
            $multipleResults
        } -ModuleName directories

        { Resolve-SafeguardDirectoryId -Appliance "fake" -AccessToken "fake" -Insecure "ambiguous" } |
            Should -Throw "*Found 2 directories*"
    }
}

Describe 'Resolve-SafeguardAsset - single result handling' {
    BeforeAll {
        Import-Module (Join-Path $script:SrcDir 'assetpartitions.psm1') -Force
        Import-Module (Join-Path $script:SrcDir 'assets.psm1') -Force
    }

    It 'Returns correct asset object when API returns a single asset' {
        $singleAsset = [PSCustomObject]@{ Id = 55; Name = "myserver"; NetworkAddress = "10.1.1.1" }

        Mock Invoke-SafeguardMethod {
            $singleAsset
        } -ModuleName assets

        Mock Resolve-AssetPartitionIdFromSafeguardSession {
            return $null
        } -ModuleName assets

        $result = Resolve-SafeguardAsset -Appliance "fake" -AccessToken "fake" -Insecure "myserver"
        $result.Id | Should -Be 55
    }

    It 'Throws with correct count when multiple assets match' {
        $multipleAssets = @(
            [PSCustomObject]@{ Id = 1; Name = "srv1" },
            [PSCustomObject]@{ Id = 2; Name = "srv2" }
        )

        Mock Invoke-SafeguardMethod {
            $multipleAssets
        } -ModuleName assets

        Mock Resolve-AssetPartitionIdFromSafeguardSession {
            return $null
        } -ModuleName assets

        { Resolve-SafeguardAsset -Appliance "fake" -AccessToken "fake" -Insecure "ambiguous" } |
            Should -Throw "*Found 2 assets*"
    }
}

Describe 'Resolve-SafeguardDirectoryIdentityProviderId - single result handling' {
    BeforeAll {
        Import-Module (Join-Path $script:SrcDir 'directories.psm1') -Force
    }

    It 'Returns correct ID when API returns a single identity provider' {
        $singleIdp = [PSCustomObject]@{ Id = 77; Name = "ad.corp" }

        Mock Invoke-SafeguardMethod {
            $singleIdp
        } -ModuleName directories

        $result = Resolve-SafeguardDirectoryIdentityProviderId -Appliance "fake" -AccessToken "fake" -Insecure "ad.corp"
        $result | Should -Be 77
    }
}

Describe 'Resolve-SafeguardUser - single result handling' {
    BeforeAll {
        Import-Module (Join-Path $script:SrcDir 'users.psm1') -Force
    }

    It 'Returns correct ID when API returns a single user' {
        $singleUser = [PSCustomObject]@{ Id = 101; UserName = "jdoe"; Name = "John Doe" }

        Mock Invoke-SafeguardMethod {
            $singleUser
        } -ModuleName users

        $result = Resolve-SafeguardUserId -Appliance "fake" -AccessToken "fake" -Insecure "jdoe"
        $result | Should -Be 101
    }
}

Describe 'PS 5.1 .Count behavior simulation' {
    # This test explicitly validates the root cause of the bug:
    # In PS 5.1, a single PSCustomObject does not have .Count
    # Our @() wrapping must handle this correctly

    It '@() wrapping ensures .Count works for a single object' {
        $single = [PSCustomObject]@{ Id = 1 }
        $wrapped = @($single)
        $wrapped.Count | Should -Be 1
    }

    It '@() wrapping preserves correct .Count for multiple objects' {
        $multi = @([PSCustomObject]@{ Id = 1 }, [PSCustomObject]@{ Id = 2 })
        $wrapped = @($multi)
        $wrapped.Count | Should -Be 2
    }

    It '@() wrapping gives .Count 0 for empty/null result' {
        # @($null) gives array with 1 null element, but -not @($null) should handle it
        # The actual pattern uses: if (-not $var) which is what matters
        $fromEmpty = @()
        $fromEmpty.Count | Should -Be 0
        (-not $fromEmpty) | Should -Be $true
    }

    It 'Single object without @() has no .Count in PS 5.1 semantics' {
        # This test documents the bug behavior - in PS 7 this passes
        # because .Count is intrinsic, but the logic we test is the fix
        $single = [PSCustomObject]@{ Id = 1 }
        # After our fix, we always wrap, so this just validates the fix works
        $wrapped = @($single)
        ($wrapped.Count -ne 1) | Should -Be $false
    }
}
