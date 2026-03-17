@{
    Name        = "Framework Smoke Test"
    Description = "Verifies the test framework itself works end-to-end"
    Tags        = @("framework", "smoke")

    Setup = {
        param($Context)
        # Verify we have a valid connection
        $Context.SuiteData["SetupRan"] = $true
    }

    Execute = {
        param($Context)

        Test-SgPsAssert "Framework setup ran" {
            $Context.SuiteData["SetupRan"] -eq $true
        }

        Test-SgPsAssert "safeguard-ps module is loaded" {
            $mod = Get-Module safeguard-ps
            $null -ne $mod
        }

        Test-SgPsAssert "Can call Get-SafeguardStatus" {
            $status = Get-SafeguardStatus -Appliance $Context.Appliance -Insecure
            $null -ne $status
        }

        Test-SgPsAssert "Can call Get-SafeguardLoggedInUser" {
            $me = Get-SafeguardLoggedInUser -Insecure
            $null -ne $me -and $null -ne $me.Id
        }
    }

    Cleanup = {
        param($Context)
        # Nothing to clean up
    }
}
