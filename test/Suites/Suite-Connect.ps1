@{
    Name        = "Connect & Core"
    Description = "Tests Connect-Safeguard, Disconnect-Safeguard, Invoke-SafeguardMethod, token status, and logged-in user"
    Tags        = @("core", "auth")

    Setup = {
        param($Context)
        # Nothing to set up — we already have a session from the runner
    }

    Execute = {
        param($Context)

        # --- Connect-Safeguard with -NoSessionVariable (returns access token) ---
        Test-SgPsAssert "Connect-Safeguard -NoSessionVariable returns access token" {
            $secPwd = ConvertTo-SecureString $Context.AdminPassword -AsPlainText -Force
            $token = Connect-Safeguard -Appliance $Context.Appliance -IdentityProvider "Local" `
                -Username $Context.AdminUserName -Password $secPwd -Insecure -NoSessionVariable
            $Context.SuiteData["ExplicitToken"] = $token
            $null -ne $token -and $token.Length -gt 0
        }

        # --- Disconnect explicit token ---
        Test-SgPsAssert "Disconnect-Safeguard with explicit token" {
            Disconnect-Safeguard -Appliance $Context.Appliance `
                -AccessToken $Context.SuiteData["ExplicitToken"] -Insecure
            $true
        }

        # --- Connect-Safeguard sets $SafeguardSession ---
        Test-SgPsAssert "Connect-Safeguard sets SafeguardSession global" {
            # Reconnect using session variable (runner already connected, but let's verify behavior)
            $secPwd = ConvertTo-SecureString $Context.AdminPassword -AsPlainText -Force
            Connect-Safeguard -Appliance $Context.Appliance -IdentityProvider "Local" `
                -Username $Context.AdminUserName -Password $secPwd -Insecure
            $null -ne $SafeguardSession -and $SafeguardSession.Appliance -eq $Context.Appliance
        }

        # --- Get-SafeguardAccessTokenStatus (session-based, no -Insecure) ---
        Test-SgPsAssert "Get-SafeguardAccessTokenStatus returns valid timespan" {
            $remaining = Get-SafeguardAccessTokenStatus -Raw
            $remaining -is [TimeSpan] -and $remaining.TotalMinutes -gt 0
        }

        # --- Get-SafeguardAccessTokenStatus with explicit token ---
        Test-SgPsAssert "Get-SafeguardAccessTokenStatus with explicit token" {
            $secPwd = ConvertTo-SecureString $Context.AdminPassword -AsPlainText -Force
            $token = Connect-Safeguard -Appliance $Context.Appliance -IdentityProvider "Local" `
                -Username $Context.AdminUserName -Password $secPwd -Insecure -NoSessionVariable
            $remaining = Get-SafeguardAccessTokenStatus -Appliance $Context.Appliance `
                -AccessToken $token -Insecure -Raw
            Disconnect-Safeguard -Appliance $Context.Appliance -AccessToken $token -Insecure
            $remaining -is [TimeSpan] -and $remaining.TotalMinutes -gt 0
        }

        # --- Get-SafeguardLoggedInUser ---
        Test-SgPsAssert "Get-SafeguardLoggedInUser returns current user" {
            $me = Get-SafeguardLoggedInUser -Insecure
            $null -ne $me -and $null -ne $me.Id -and $null -ne $me.Name
        }

        Test-SgPsAssert "Get-SafeguardLoggedInUser with Fields parameter" {
            $me = Get-SafeguardLoggedInUser -Insecure -Fields "Id","Name","AdminRoles"
            $null -ne $me.Id -and $null -ne $me.Name -and $null -ne $me.AdminRoles
        }

        # --- Invoke-SafeguardMethod ---
        Test-SgPsAssert "Invoke-SafeguardMethod GET on Core service" {
            $result = Invoke-SafeguardMethod -Insecure -Service Core -Method Get -RelativeUrl "Me"
            $null -ne $result -and $null -ne $result.Id
        }

        Test-SgPsAssert "Invoke-SafeguardMethod GET on Appliance service" {
            $result = Invoke-SafeguardMethod -Insecure -Service Appliance -Method Get -RelativeUrl "ApplianceStatus"
            $null -ne $result
        }

        Test-SgPsAssert "Invoke-SafeguardMethod GET on Notification service" {
            $result = Invoke-SafeguardMethod -Insecure -Service Notification -Method Get -RelativeUrl "Status"
            $null -ne $result
        }

        Test-SgPsAssert "Invoke-SafeguardMethod with explicit token" {
            $secPwd = ConvertTo-SecureString $Context.AdminPassword -AsPlainText -Force
            $token = Connect-Safeguard -Appliance $Context.Appliance -IdentityProvider "Local" `
                -Username $Context.AdminUserName -Password $secPwd -Insecure -NoSessionVariable
            $result = Invoke-SafeguardMethod -Appliance $Context.Appliance `
                -AccessToken $token -Insecure -Service Core -Method Get -RelativeUrl "Me"
            Disconnect-Safeguard -Appliance $Context.Appliance -AccessToken $token -Insecure
            $null -ne $result -and $null -ne $result.Id
        }

        Test-SgPsAssert "Invoke-SafeguardMethod with Parameters" {
            $result = Invoke-SafeguardMethod -Insecure -Service Core -Method Get `
                -RelativeUrl "Users" -Parameters @{ fields = "Id,Name"; filter = "Name eq 'Admin'" }
            $null -ne $result
        }

        Test-SgPsAssert "Invoke-SafeguardMethod Anonymous GET on status" {
            $result = Invoke-SafeguardMethod -Appliance $Context.Appliance -Insecure `
                -Service Notification -Method Get -RelativeUrl "Status" -Anonymous
            $null -ne $result
        }

        # --- Update-SafeguardAccessToken ---
        Test-SgPsAssert "Update-SafeguardAccessToken refreshes the token" {
            $oldToken = $SafeguardSession.AccessToken
            $secPwd = ConvertTo-SecureString $Context.AdminPassword -AsPlainText -Force
            Update-SafeguardAccessToken -Password $secPwd
            $newToken = $SafeguardSession.AccessToken
            # New token should be valid (may or may not differ depending on timing)
            $null -ne $newToken -and $newToken.Length -gt 0
        }
    }

    Cleanup = {
        param($Context)
        # Ensure we're still connected for subsequent suites
        try {
            $null = Get-SafeguardLoggedInUser -Insecure -ErrorAction Stop
        }
        catch {
            # Reconnect if needed
            Connect-SgPsTestSession -Context $Context
        }
    }
}
