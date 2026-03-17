@{
    Name        = "Access Requests"
    Description = "Tests access request lifecycle: create, approve, checkout password, checkin, close"
    Tags        = @("requests", "access", "workflow")

    Setup = {
        param($Context)

        $prefix = $Context.TestPrefix
        $testEntitlement = "${prefix}_AREntl"
        $testPolicy = "${prefix}_ARPolicy"
        $testAsset = "${prefix}_ARAsset"
        $testAccount = "${prefix}_ARAcct"
        $testRequester = "${prefix}_ARRequester"
        $testApprover = "${prefix}_ARApprover"
        $testPassword = "ReqAcct1234!xyzABC"

        # Pre-cleanup: close any stale access requests before deleting objects
        try {
            $staleRequests = Find-SafeguardAccessRequest -Insecure $testAccount
            foreach ($req in @($staleRequests)) {
                if ($req.Id -and $req.State -notin @('Closed','Complete','Expired')) {
                    try { Close-SafeguardAccessRequest -Insecure $req.Id } catch {}
                }
            }
        } catch {}

        # Pre-cleanup: remove stale objects in dependency order
        Remove-SgPsStaleTestObject -Collection "Roles" -Name $testEntitlement
        Remove-SgPsStaleTestObject -Collection "AssetAccounts" -Name $testAccount
        Remove-SgPsStaleTestObject -Collection "Assets" -Name $testAsset
        Remove-SgPsStaleTestObject -Collection "Users" -Name $testRequester
        Remove-SgPsStaleTestObject -Collection "Users" -Name $testApprover

        $Context.SuiteData["TestPassword"] = $testPassword

        # Create requester user
        $secPwd = ConvertTo-SecureString $testPassword -AsPlainText -Force
        $requester = New-SafeguardUser -Insecure -Provider -1 -NewUserName $testRequester -Password $secPwd
        $Context.SuiteData["RequesterId"] = $requester.Id
        $Context.SuiteData["RequesterName"] = $testRequester
        $Context.SuiteData["RequesterPassword"] = $testPassword

        # Create approver user (same password for simplicity)
        $approver = New-SafeguardUser -Insecure -Provider -1 -NewUserName $testApprover `
            -AdminRoles @('PolicyAdmin') -Password $secPwd
        $Context.SuiteData["ApproverId"] = $approver.Id
        $Context.SuiteData["ApproverName"] = $testApprover
        $Context.SuiteData["ApproverPassword"] = $testPassword

        # Create asset and account
        $asset = New-SafeguardAsset -Insecure -DisplayName $testAsset `
            -Platform 521 -NetworkAddress "10.0.6.100" `
            -ServiceAccountCredentialType "None" -NoSshHostKeyDiscovery
        $Context.SuiteData["AssetId"] = $asset.Id
        $Context.SuiteData["TestAsset"] = $testAsset

        $account = New-SafeguardAssetAccount -Insecure -ParentAsset $asset.Id -NewAccountName $testAccount
        $Context.SuiteData["AccountId"] = $account.Id
        $Context.SuiteData["TestAccount"] = $testAccount

        # Set a password in the vault so checkout has something to return
        $secAcctPwd = ConvertTo-SecureString "VaultPwd5678!abc" -AsPlainText -Force
        Set-SafeguardAssetAccountPassword -Insecure $asset.Id $account.Id -NewPassword $secAcctPwd

        # Create entitlement with requester as member
        $entl = New-SafeguardEntitlement -Insecure $testEntitlement -MemberUsers $testRequester
        $Context.SuiteData["EntitlementId"] = $entl.Id

        # Create access policy with approver and scope to the account
        $policy = Add-SafeguardAccessPolicy -Insecure `
            -Entitlement $testEntitlement `
            -Name $testPolicy `
            -AccessRequestType "Password" `
            -ScopeAccounts $testAccount `
            -ApproverUsers $testApprover
        $Context.SuiteData["PolicyId"] = $policy.Id

        # Register cleanup in reverse dependency order
        Register-SgPsTestCleanup -Description "Delete AR entitlement" -Action {
            param($Ctx)
            try { Remove-SafeguardEntitlement -Insecure $Ctx.SuiteData['EntitlementId'] } catch {}
        }
        Register-SgPsTestCleanup -Description "Delete AR account" -Action {
            param($Ctx)
            try { Remove-SafeguardAssetAccount -Insecure $Ctx.SuiteData['AssetId'] $Ctx.SuiteData['AccountId'] } catch {}
        }
        Register-SgPsTestCleanup -Description "Delete AR asset" -Action {
            param($Ctx)
            try { Remove-SafeguardAsset -Insecure $Ctx.SuiteData['AssetId'] } catch {}
        }
        Register-SgPsTestCleanup -Description "Delete AR approver" -Action {
            param($Ctx)
            try { Remove-SafeguardUser -Insecure $Ctx.SuiteData['ApproverId'] } catch {}
        }
        Register-SgPsTestCleanup -Description "Delete AR requester" -Action {
            param($Ctx)
            try { Remove-SafeguardUser -Insecure $Ctx.SuiteData['RequesterId'] } catch {}
        }
    }

    Execute = {
        param($Context)

        # Helper to get token for a specific user
        function Get-UserToken {
            param([string]$UserName, [string]$Password)
            $secPwd = ConvertTo-SecureString $Password -AsPlainText -Force
            Connect-Safeguard -Appliance $Context.Appliance -IdentityProvider "Local" `
                -Username $UserName -Password $secPwd -Insecure -NoSessionVariable
        }

        # --- Get-SafeguardAccessRequest (list, empty initially) ---
        Test-SgPsAssert "Get-SafeguardAccessRequest lists requests" {
            $requests = Get-SafeguardAccessRequest -Insecure
            $null -ne $requests
        }

        # --- Get-SafeguardRequestableAccount (as requester) ---
        Test-SgPsAssert "Get-SafeguardRequestableAccount shows available accounts" {
            $token = Get-UserToken $Context.SuiteData["RequesterName"] $Context.SuiteData["RequesterPassword"]
            $accounts = Get-SafeguardRequestableAccount -Appliance $Context.Appliance `
                -AccessToken $token -Insecure
            Disconnect-Safeguard -Appliance $Context.Appliance -AccessToken $token -Insecure
            $list = @($accounts)
            $list.Count -ge 1
        }

        # --- New-SafeguardAccessRequest (as requester) ---
        Test-SgPsAssert "New-SafeguardAccessRequest creates a request" {
            $token = Get-UserToken $Context.SuiteData["RequesterName"] $Context.SuiteData["RequesterPassword"]
            $request = New-SafeguardAccessRequest -Appliance $Context.Appliance `
                -AccessToken $token -Insecure `
                -AssetToUse $Context.SuiteData["TestAsset"] `
                -AccountToUse $Context.SuiteData["TestAccount"] `
                -AccessRequestType "Password" -AllFields
            Disconnect-Safeguard -Appliance $Context.Appliance -AccessToken $token -Insecure
            $Context.SuiteData["RequestId"] = $request.Id
            $null -ne $request.Id -and $request.State -eq "PendingApproval"
        }

        # --- Get-SafeguardAccessRequest by ID ---
        Test-SgPsAssert "Get-SafeguardAccessRequest by ID" {
            $request = Get-SafeguardAccessRequest -Insecure $Context.SuiteData["RequestId"] -AllFields
            $request.Id -eq $Context.SuiteData["RequestId"]
        }

        # --- Get-SafeguardMyRequest (as requester) ---
        Test-SgPsAssert "Get-SafeguardMyRequest shows pending request" {
            $token = Get-UserToken $Context.SuiteData["RequesterName"] $Context.SuiteData["RequesterPassword"]
            $myRequests = Get-SafeguardMyRequest -Appliance $Context.Appliance `
                -AccessToken $token -Insecure
            Disconnect-Safeguard -Appliance $Context.Appliance -AccessToken $token -Insecure
            $list = @($myRequests)
            $list.Count -ge 1 -and ($list | Where-Object { $_.Id -eq $Context.SuiteData["RequestId"] })
        }

        # --- Get-SafeguardMyApproval (as approver) ---
        Test-SgPsAssert "Get-SafeguardMyApproval shows pending approval" {
            $token = Get-UserToken $Context.SuiteData["ApproverName"] $Context.SuiteData["ApproverPassword"]
            $approvals = Get-SafeguardMyApproval -Appliance $Context.Appliance `
                -AccessToken $token -Insecure
            Disconnect-Safeguard -Appliance $Context.Appliance -AccessToken $token -Insecure
            $list = @($approvals)
            $list.Count -ge 1
        }

        # --- Approve-SafeguardAccessRequest (as approver) ---
        Test-SgPsAssert "Approve-SafeguardAccessRequest approves request" {
            $token = Get-UserToken $Context.SuiteData["ApproverName"] $Context.SuiteData["ApproverPassword"]
            $result = Approve-SafeguardAccessRequest -Appliance $Context.Appliance `
                -AccessToken $token -Insecure `
                -RequestId $Context.SuiteData["RequestId"] -AllFields
            Disconnect-Safeguard -Appliance $Context.Appliance -AccessToken $token -Insecure
            $result.State -eq "Approved" -or $result.State -eq "RequestAvailable"
        }

        # --- Get-SafeguardAccessRequestPassword (checkout as requester) ---
        Test-SgPsAssert "Get-SafeguardAccessRequestPassword checks out password" {
            $token = Get-UserToken $Context.SuiteData["RequesterName"] $Context.SuiteData["RequesterPassword"]
            $password = Get-SafeguardAccessRequestPassword -Appliance $Context.Appliance `
                -AccessToken $token -Insecure `
                -RequestId $Context.SuiteData["RequestId"]
            Disconnect-Safeguard -Appliance $Context.Appliance -AccessToken $token -Insecure
            $null -ne $password -and $password.Length -gt 0
        }

        # --- Close-SafeguardAccessRequest (checkin as requester) ---
        Test-SgPsAssert "Close-SafeguardAccessRequest closes the request" {
            $token = Get-UserToken $Context.SuiteData["RequesterName"] $Context.SuiteData["RequesterPassword"]
            $result = Close-SafeguardAccessRequest -Appliance $Context.Appliance `
                -AccessToken $token -Insecure `
                -RequestId $Context.SuiteData["RequestId"] -AllFields
            Disconnect-Safeguard -Appliance $Context.Appliance -AccessToken $token -Insecure
            $result.State -eq "Closed" -or $result.State -eq "Complete"
        }

        # --- Find-SafeguardAccessRequest ---
        Test-SgPsAssert "Find-SafeguardAccessRequest searches requests" {
            $results = Find-SafeguardAccessRequest -Insecure $Context.SuiteData["TestAccount"]
            $list = @($results)
            $list.Count -ge 1
        }

        # --- Deny workflow: create request then deny it ---
        Test-SgPsAssert "Deny-SafeguardAccessRequest denies a request" {
            $token = Get-UserToken $Context.SuiteData["RequesterName"] $Context.SuiteData["RequesterPassword"]
            $request = New-SafeguardAccessRequest -Appliance $Context.Appliance `
                -AccessToken $token -Insecure `
                -AssetToUse $Context.SuiteData["TestAsset"] `
                -AccountToUse $Context.SuiteData["TestAccount"] `
                -AccessRequestType "Password" -AllFields
            Disconnect-Safeguard -Appliance $Context.Appliance -AccessToken $token -Insecure
            $Context.SuiteData["DenyRequestId"] = $request.Id

            $approverToken = Get-UserToken $Context.SuiteData["ApproverName"] $Context.SuiteData["ApproverPassword"]
            $result = Deny-SafeguardAccessRequest -Appliance $Context.Appliance `
                -AccessToken $approverToken -Insecure `
                -RequestId $request.Id -AllFields
            Disconnect-Safeguard -Appliance $Context.Appliance -AccessToken $approverToken -Insecure
            $result.State -eq "Denied" -or $result.State -eq "Closed"
        }
    }

    Cleanup = {
        param($Context)
    }
}
