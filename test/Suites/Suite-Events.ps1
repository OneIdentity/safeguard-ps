@{
    Name        = "Events"
    Description = "Tests event names, categories, and event subscription CRUD"
    Tags        = @("events", "configuration")

    Setup = {
        param($Context)

        $prefix = $Context.TestPrefix

        # Pre-cleanup: remove stale event subscriptions
        try {
            $subs = Get-SafeguardEventSubscription -Insecure
            $staleSubs = @($subs) | Where-Object { $_.Description -match $prefix }
            foreach ($sub in $staleSubs) {
                try { Remove-SafeguardEventSubscription -Insecure $sub.Id } catch {}
            }
        } catch {}
    }

    Execute = {
        param($Context)

        # --- Get-SafeguardEventName (list all) ---
        Test-SgPsAssert "Get-SafeguardEventName lists all event names" {
            $events = Get-SafeguardEventName -Insecure
            $list = @($events)
            $list.Count -ge 10
        }

        # --- Get-SafeguardEventName by TypeOfEvent ---
        Test-SgPsAssert "Get-SafeguardEventName filters by TypeOfEvent" {
            $events = Get-SafeguardEventName -Insecure -TypeofEvent "User"
            $list = @($events)
            $list.Count -ge 1
        }

        # --- Get-SafeguardEventCategory (list all) ---
        Test-SgPsAssert "Get-SafeguardEventCategory lists categories" {
            $cats = Get-SafeguardEventCategory -Insecure
            $list = @($cats)
            $list.Count -ge 1
        }

        # --- Get-SafeguardEventCategory by TypeOfEvent ---
        Test-SgPsAssert "Get-SafeguardEventCategory filters by type" {
            $cats = Get-SafeguardEventCategory -Insecure -TypeofEvent "Asset"
            $list = @($cats)
            $list.Count -ge 1
        }

        # --- Get-SafeguardEventProperty for a specific event ---
        Test-SgPsAssert "Get-SafeguardEventProperty returns properties for an event" {
            # Get-SafeguardEventName returns an array of strings
            $events = Get-SafeguardEventName -Insecure
            $eventName = @($events)[0]
            $props = Get-SafeguardEventProperty -Insecure $eventName
            $null -ne $props
        }

        # --- Get-SafeguardEventSubscription (list) ---
        Test-SgPsAssert "Get-SafeguardEventSubscription lists subscriptions" {
            $subs = Get-SafeguardEventSubscription -Insecure
            $null -ne $subs
        }

        # --- New-SafeguardEventSubscription ---
        Test-SgPsAssert "New-SafeguardEventSubscription creates a subscription" {
            $prefix = $Context.TestPrefix
            # Must provide SubscriptionEvent — use a known event name
            $sub = New-SafeguardEventSubscription -Insecure `
                -SubscriptionEvent "AssetCreated" `
                -Description "${prefix}_TestEventSub" `
                -IsSignalrEvent
            $Context.SuiteData["SubId"] = $sub.Id

            Register-SgPsTestCleanup -Description "Delete event subscription" -Action {
                param($Ctx)
                try { Remove-SafeguardEventSubscription -Insecure $Ctx.SuiteData['SubId'] } catch {}
            }
            $sub.Description -match $prefix
        }

        # --- Get-SafeguardEventSubscription by ID ---
        Test-SgPsAssert "Get-SafeguardEventSubscription by ID" {
            $sub = Get-SafeguardEventSubscription -Insecure $Context.SuiteData["SubId"]
            $sub.Id -eq $Context.SuiteData["SubId"]
        }

        # --- Edit-SafeguardEventSubscription ---
        Test-SgPsAssert "Edit-SafeguardEventSubscription updates subscription" {
            $prefix = $Context.TestPrefix
            $updated = Edit-SafeguardEventSubscription -Insecure `
                -SubscriptionId $Context.SuiteData["SubId"] `
                -Description "${prefix}_UpdatedEventSub"
            $updated.Description -match "Updated"
        }

        # --- Find-SafeguardEventSubscription ---
        Test-SgPsAssert "Find-SafeguardEventSubscription searches by text" {
            $prefix = $Context.TestPrefix
            $found = Find-SafeguardEventSubscription -Insecure -SearchString "${prefix}_Updated"
            $list = @($found)
            $list.Count -ge 1
        }

        # --- Remove-SafeguardEventSubscription ---
        Test-SgPsAssert "Remove-SafeguardEventSubscription deletes subscription" {
            Remove-SafeguardEventSubscription -Insecure $Context.SuiteData["SubId"]
            $subs = Get-SafeguardEventSubscription -Insecure
            $list = @($subs)
            -not ($list | Where-Object { $_.Id -eq $Context.SuiteData["SubId"] })
        }

        # --- Get-SafeguardEvent (list recent events) ---
        Test-SgPsAssert "Get-SafeguardEvent returns recent events" {
            $events = Get-SafeguardEvent -Insecure
            $null -ne $events
        }
    }

    Cleanup = {
        param($Context)
    }
}
