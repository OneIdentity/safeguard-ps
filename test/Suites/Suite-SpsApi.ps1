@{
    Name        = "SPS Integration"
    Description = "Tests Safeguard for Privileged Sessions API connectivity and operations"
    Tags        = @("sps")

    Setup = {
        param($Context)

        if (-not (Test-SgPsSpsConfigured)) {
            $Context.SuiteData["Skipped"] = $true
            return
        }

        # Connect to SPS
        $secPassword = ConvertTo-SecureString $Context.SpsPassword -AsPlainText -Force
        Connect-SafeguardSps $Context.SpsAppliance $Context.SpsUser -Password $secPassword -Insecure
    }

    Execute = {
        param($Context)

        if ($Context.SuiteData["Skipped"]) {
            Test-SgPsSkip "Connect-SafeguardSps connects to SPS" "SPS appliance not configured"
            Test-SgPsSkip "Get-SafeguardSpsVersion returns version" "SPS appliance not configured"
            Test-SgPsSkip "Get-SafeguardSpsInfo returns info" "SPS appliance not configured"
            Test-SgPsSkip "Invoke-SafeguardSpsMethod GET firmware slots" "SPS appliance not configured"
            Test-SgPsSkip "Get-SafeguardSpsFirmwareSlot returns slots" "SPS appliance not configured"
            Test-SgPsSkip "Invoke-SafeguardSpsMethod GET configuration endpoint" "SPS appliance not configured"
            Test-SgPsSkip "Get-SafeguardSpsLoginMethod lists methods" "SPS appliance not configured"
            Test-SgPsSkip "Disconnect-SafeguardSps disconnects" "SPS appliance not configured"
            return
        }

        # --- Connect-SafeguardSps ---
        Test-SgPsAssert "Connect-SafeguardSps connects to SPS" {
            # Already connected in Setup, verify session is usable
            $null -ne $SafeguardSpsSession
        }

        # --- Get-SafeguardSpsVersion ---
        Test-SgPsAssert "Get-SafeguardSpsVersion returns version" {
            $version = Get-SafeguardSpsVersion
            $null -ne $version
        }

        # --- Get-SafeguardSpsInfo ---
        Test-SgPsAssert "Get-SafeguardSpsInfo returns info" {
            $info = Get-SafeguardSpsInfo
            $null -ne $info
        }

        # --- Invoke-SafeguardSpsMethod GET firmware/slots ---
        Test-SgPsAssert "Invoke-SafeguardSpsMethod GET firmware slots" {
            $result = Invoke-SafeguardSpsMethod GET "firmware/slots"
            $null -ne $result
        }

        # --- Get-SafeguardSpsFirmwareSlot ---
        Test-SgPsAssert "Get-SafeguardSpsFirmwareSlot returns slots" {
            $slots = Get-SafeguardSpsFirmwareSlot
            $null -ne $slots
        }

        # --- Invoke-SafeguardSpsMethod GET configuration/management/email ---
        Test-SgPsAssert "Invoke-SafeguardSpsMethod GET configuration endpoint" {
            $result = Invoke-SafeguardSpsMethod GET "configuration/management/email"
            $null -ne $result
        }

        # --- Get-SafeguardSpsLoginMethod (pre-login discovery, needs explicit params) ---
        Test-SgPsAssert "Get-SafeguardSpsLoginMethod lists methods" {
            $methods = Get-SafeguardSpsLoginMethod $Context.SpsAppliance -Insecure
            $null -ne $methods
        }

        # --- Disconnect-SafeguardSps ---
        Test-SgPsAssert "Disconnect-SafeguardSps disconnects" {
            Disconnect-SafeguardSps
            $true
        }
    }

    Cleanup = {
        param($Context)

        if (-not $Context.SuiteData["Skipped"]) {
            try { Disconnect-SafeguardSps } catch {}
        }
    }
}
