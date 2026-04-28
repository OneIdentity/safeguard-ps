@{
    Name        = "Messages"
    Description = "Tests daily message and login message get/set operations"
    Tags        = @("messages", "settings")

    Setup = {
        param($Context)

        # Save original messages for restoration
        $dailyMsg = Get-SafeguardDailyMessage -Insecure
        $loginMsg = Get-SafeguardLoginMessage -Insecure
        $Context.SuiteData["OriginalDailyMessage"] = $dailyMsg
        $Context.SuiteData["OriginalLoginMessage"] = $loginMsg

        Register-SgPsTestCleanup -Description "Restore original daily message" -Action {
            param($Ctx)
            try {
                Set-SafeguardDailyMessage -Insecure -MessageObject $Ctx.SuiteData['OriginalDailyMessage']
            } catch {}
        }

        Register-SgPsTestCleanup -Description "Restore original login message" -Action {
            param($Ctx)
            try {
                Set-SafeguardLoginMessage -Insecure -MessageObject $Ctx.SuiteData['OriginalLoginMessage']
            } catch {}
        }
    }

    Execute = {
        param($Context)

        # ===================== DailyMessage =====================

        # --- Get-SafeguardDailyMessage ---
        Test-SgPsAssert "Get-SafeguardDailyMessage returns an object" {
            $msg = Get-SafeguardDailyMessage -Insecure
            # DailyMessage always has a Message property (possibly empty string)
            $null -ne $msg -and $msg.PSObject.Properties.Name -contains "Message"
        }

        # --- Set-SafeguardDailyMessage with attributes ---
        Test-SgPsAssert "Set-SafeguardDailyMessage sets message text" {
            $result = Set-SafeguardDailyMessage -Insecure -Message "SgPsTest daily message"
            $result.Message -eq "SgPsTest daily message"
        }

        Test-SgPsAssert "Set-SafeguardDailyMessage change persisted" {
            $readback = Get-SafeguardDailyMessage -Insecure
            $readback.Message -eq "SgPsTest daily message"
        }

        # --- Set-SafeguardDailyMessage with subject ---
        Test-SgPsAssert "Set-SafeguardDailyMessage sets subject" {
            $result = Set-SafeguardDailyMessage -Insecure -Message "Message with subject" -Subject "Test Subject"
            $result.Message -eq "Message with subject" -and $result.Subject -eq "Test Subject"
        }

        Test-SgPsAssert "Set-SafeguardDailyMessage subject persisted" {
            $readback = Get-SafeguardDailyMessage -Insecure
            $readback.Subject -eq "Test Subject"
        }

        # --- Set-SafeguardDailyMessage with object ---
        Test-SgPsAssert "Set-SafeguardDailyMessage with MessageObject" {
            $msg = Get-SafeguardDailyMessage -Insecure
            $msg.Message = "Object-based update"
            $msg.Subject = "Object Subject"
            $result = Set-SafeguardDailyMessage -Insecure -MessageObject $msg
            $result.Message -eq "Object-based update" -and $result.Subject -eq "Object Subject"
        }

        Test-SgPsAssert "Set-SafeguardDailyMessage object change persisted" {
            $readback = Get-SafeguardDailyMessage -Insecure
            $readback.Message -eq "Object-based update"
        }

        # --- Set-SafeguardDailyMessage second update ---
        Test-SgPsAssert "Set-SafeguardDailyMessage second update to prove edit" {
            $result = Set-SafeguardDailyMessage -Insecure -Message "Second update"
            $readback = Get-SafeguardDailyMessage -Insecure
            $result.Message -eq "Second update" -and $readback.Message -eq "Second update"
        }

        # --- Set-SafeguardDailyMessage UseRss/Address roundtrip ---
        Test-SgPsAssert "Set-SafeguardDailyMessage UseRss and Address" {
            $result = Set-SafeguardDailyMessage -Insecure -Message "RSS test" -UseRss $true -Address "https://rss.example.com/feed"
            $result.UseRss -eq $true -and $result.Address -eq "https://rss.example.com/feed"
        }

        Test-SgPsAssert "Set-SafeguardDailyMessage UseRss persisted" {
            $readback = Get-SafeguardDailyMessage -Insecure
            $readback.UseRss -eq $true -and $readback.Address -eq "https://rss.example.com/feed"
        }

        Test-SgPsAssert "Set-SafeguardDailyMessage disable UseRss" {
            $result = Set-SafeguardDailyMessage -Insecure -UseRss $false
            $readback = Get-SafeguardDailyMessage -Insecure
            $result.UseRss -eq $false -and $readback.UseRss -eq $false
        }

        # ===================== LoginMessage =====================

        # --- Get-SafeguardLoginMessage ---
        Test-SgPsAssert "Get-SafeguardLoginMessage returns an object" {
            $msg = Get-SafeguardLoginMessage -Insecure
            $null -ne $msg -and $msg.PSObject.Properties.Name -contains "Message"
        }

        # --- Set-SafeguardLoginMessage with string ---
        Test-SgPsAssert "Set-SafeguardLoginMessage sets message text" {
            $result = Set-SafeguardLoginMessage -Insecure -Message "SgPsTest login banner"
            $result.Message -eq "SgPsTest login banner"
        }

        Test-SgPsAssert "Set-SafeguardLoginMessage change persisted" {
            $readback = Get-SafeguardLoginMessage -Insecure
            $readback.Message -eq "SgPsTest login banner"
        }

        # --- Set-SafeguardLoginMessage with object ---
        Test-SgPsAssert "Set-SafeguardLoginMessage with MessageObject" {
            $msg = Get-SafeguardLoginMessage -Insecure
            $msg.Message = "Object login banner"
            $result = Set-SafeguardLoginMessage -Insecure -MessageObject $msg
            $result.Message -eq "Object login banner"
        }

        Test-SgPsAssert "Set-SafeguardLoginMessage object change persisted" {
            $readback = Get-SafeguardLoginMessage -Insecure
            $readback.Message -eq "Object login banner"
        }

        # --- Set-SafeguardLoginMessage second update ---
        Test-SgPsAssert "Set-SafeguardLoginMessage second update to prove edit" {
            $result = Set-SafeguardLoginMessage -Insecure -Message "Second login banner"
            $readback = Get-SafeguardLoginMessage -Insecure
            $result.Message -eq "Second login banner" -and $readback.Message -eq "Second login banner"
        }
    }

    Cleanup = {
        param($Context)
    }
}
