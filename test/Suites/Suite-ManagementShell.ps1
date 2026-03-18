@{
    Name        = "Management Shell"
    Description = "Tests Get-SafeguardCommand and Get-SafeguardBanner"
    Tags        = @("management", "readonly")

    Setup = {
        param($Context)
        # No setup needed
    }

    Execute = {
        param($Context)

        # --- Get-SafeguardCommand (no filter) ---
        Test-SgPsAssert "Get-SafeguardCommand lists all cmdlets" {
            $commands = Get-SafeguardCommand
            @($commands).Count -gt 50
        }

        # --- Get-SafeguardCommand with single filter ---
        Test-SgPsAssert "Get-SafeguardCommand with single criteria" {
            $commands = Get-SafeguardCommand "Asset"
            $all = @($commands)
            $all.Count -gt 0 -and ($all | ForEach-Object { $_ -match "Asset" }) -notcontains $false
        }

        # --- Get-SafeguardCommand with multiple criteria ---
        Test-SgPsAssert "Get-SafeguardCommand with multiple criteria" {
            $commands = Get-SafeguardCommand "Get" "User"
            $all = @($commands)
            $all.Count -gt 0 -and ($all | ForEach-Object { $_ -match "Get" -and $_ -match "User" }) -notcontains $false
        }

        # --- Get-SafeguardBanner ---
        Test-SgPsAssert "Get-SafeguardBanner returns output" {
            # Get-SafeguardBanner clears screen and writes to host, so just verify it doesn't throw
            $null = Get-SafeguardBanner
            $true
        }
    }

    Cleanup = {
        param($Context)
        # Nothing to clean up
    }
}
