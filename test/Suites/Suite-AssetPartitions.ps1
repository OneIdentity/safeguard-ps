@{
    Name        = "Asset Partitions"
    Description = "Tests asset partition CRUD, enter/exit, and owner management"
    Tags        = @("partitions", "core")

    Setup = {
        param($Context)

        $prefix = $Context.TestPrefix
        $testPartition = "${prefix}_Partition1"
        $testPartition2 = "${prefix}_Partition2"
        $testOwnerUser = "${prefix}_PartOwner"

        # Pre-cleanup
        Remove-SgPsStaleTestObject -Collection "AssetPartitions" -Name $testPartition
        Remove-SgPsStaleTestObject -Collection "AssetPartitions" -Name $testPartition2
        Remove-SgPsStaleTestObject -Collection "Users" -Name $testOwnerUser

        # Create a user to serve as partition owner
        $secPwd = ConvertTo-SecureString "Owner1234!abcXYZ" -AsPlainText -Force
        $owner = New-SafeguardUser -Insecure -Provider -1 -NewUserName $testOwnerUser `
            -FirstName "Partition" -LastName "Owner" -Password $secPwd
        $Context.SuiteData["OwnerId"] = $owner.Id
        $Context.SuiteData["OwnerName"] = $testOwnerUser

        Register-SgPsTestCleanup -Description "Delete partition owner user" -Action {
            param($Ctx)
            try { Remove-SafeguardUser -Insecure $Ctx.SuiteData['OwnerId'] } catch {}
        }

        $Context.SuiteData["TestPartition"] = $testPartition
        $Context.SuiteData["TestPartition2"] = $testPartition2
    }

    Execute = {
        param($Context)

        $testPartition = $Context.SuiteData["TestPartition"]
        $testPartition2 = $Context.SuiteData["TestPartition2"]
        $ownerName = $Context.SuiteData["OwnerName"]

        # --- Get-SafeguardAssetPartition (list all) ---
        Test-SgPsAssert "Get-SafeguardAssetPartition lists partitions" {
            $partitions = Get-SafeguardAssetPartition -Insecure
            @($partitions).Count -gt 0
        }

        # --- New-SafeguardAssetPartition ---
        Test-SgPsAssert "New-SafeguardAssetPartition creates a partition" {
            $partition = New-SafeguardAssetPartition -Insecure -Name $testPartition `
                -Description "Integration test partition"
            $Context.SuiteData["PartitionId"] = $partition.Id

            Register-SgPsTestCleanup -Description "Delete test partition $testPartition" -Action {
                param($Ctx)
                try { Remove-SafeguardAssetPartition -Insecure $Ctx.SuiteData['PartitionId'] } catch {}
            }

            $null -ne $partition.Id -and $partition.Name -eq $testPartition
        }

        # --- Get-SafeguardAssetPartition by ID ---
        Test-SgPsAssert "Get-SafeguardAssetPartition by ID" {
            $partition = Get-SafeguardAssetPartition -Insecure $Context.SuiteData["PartitionId"]
            $partition.Name -eq $testPartition
        }

        # --- Get-SafeguardAssetPartition by Name ---
        Test-SgPsAssert "Get-SafeguardAssetPartition by Name" {
            $partition = Get-SafeguardAssetPartition -Insecure $testPartition
            $partition.Name -eq $testPartition
        }

        # --- Edit-SafeguardAssetPartition (attributes) ---
        Test-SgPsAssert "Edit-SafeguardAssetPartition updates attributes" {
            $updated = Edit-SafeguardAssetPartition -Insecure $Context.SuiteData["PartitionId"] `
                -Description "Updated description"
            $updated.Description -eq "Updated description"
        }

        # --- Edit-SafeguardAssetPartition (object) ---
        Test-SgPsAssert "Edit-SafeguardAssetPartition with object" {
            $partition = Get-SafeguardAssetPartition -Insecure $Context.SuiteData["PartitionId"]
            $partition.Description = "Modified via object"
            $edited = Edit-SafeguardAssetPartition -Insecure -AssetPartitionObject $partition
            $edited.Description -eq "Modified via object"
        }
        Test-SgPsAssert "Edit-SafeguardAssetPartition changes persisted" {
            $readback = Get-SafeguardAssetPartition -Insecure $Context.SuiteData["PartitionId"]
            $readback.Description -eq "Modified via object"
        }

        # --- Add-SafeguardAssetPartitionOwner ---
        Test-SgPsAssert "Add-SafeguardAssetPartitionOwner adds an owner" {
            Add-SafeguardAssetPartitionOwner -Insecure $Context.SuiteData["PartitionId"] `
                -UserList @($ownerName)
            $owners = Get-SafeguardAssetPartitionOwner -Insecure $Context.SuiteData["PartitionId"]
            $found = @($owners) | Where-Object { $_.Name -eq $ownerName }
            $null -ne $found
        }

        # --- Get-SafeguardAssetPartitionOwner ---
        Test-SgPsAssert "Get-SafeguardAssetPartitionOwner lists owners" {
            $owners = Get-SafeguardAssetPartitionOwner -Insecure $Context.SuiteData["PartitionId"]
            @($owners).Count -gt 0
        }

        # --- Remove-SafeguardAssetPartitionOwner ---
        Test-SgPsAssert "Remove-SafeguardAssetPartitionOwner removes an owner" {
            Remove-SafeguardAssetPartitionOwner -Insecure $Context.SuiteData["PartitionId"] `
                -UserList @($ownerName)
            $owners = Get-SafeguardAssetPartitionOwner -Insecure $Context.SuiteData["PartitionId"]
            $found = @($owners) | Where-Object { $_.Name -eq $ownerName }
            $null -eq $found
        }

        # --- Enter-SafeguardAssetPartition ---
        Test-SgPsAssert "Enter-SafeguardAssetPartition sets partition context" {
            Enter-SafeguardAssetPartition -Insecure $Context.SuiteData["PartitionId"]
            $current = Get-SafeguardCurrentAssetPartition -Insecure
            $null -ne $current -and $current.Id -eq $Context.SuiteData["PartitionId"]
        }

        # --- Exit-SafeguardAssetPartition ---
        Test-SgPsAssert "Exit-SafeguardAssetPartition clears partition context" {
            Exit-SafeguardAssetPartition -Insecure
            # Should no longer be in a partition -- CurrentAssetPartition should be null/empty
            $notInPartition = $false
            try {
                $current = Get-SafeguardCurrentAssetPartition -Insecure
                $notInPartition = ($null -eq $current)
            } catch {
                # Throws if not in a partition -- that's the expected behavior
                $notInPartition = $true
            }
            $notInPartition
        }

        # --- New-SafeguardAssetPartition (second, for remove test) ---
        Test-SgPsAssert "New-SafeguardAssetPartition second partition" {
            $partition2 = New-SafeguardAssetPartition -Insecure -Name $testPartition2
            $Context.SuiteData["Partition2Id"] = $partition2.Id

            Register-SgPsTestCleanup -Description "Delete test partition $testPartition2" -Action {
                param($Ctx)
                try { Remove-SafeguardAssetPartition -Insecure $Ctx.SuiteData['Partition2Id'] } catch {}
            }

            $null -ne $partition2.Id
        }

        # --- Remove-SafeguardAssetPartition ---
        Test-SgPsAssert "Remove-SafeguardAssetPartition deletes a partition" {
            Remove-SafeguardAssetPartition -Insecure $Context.SuiteData["Partition2Id"]
            $found = $false
            try {
                $null = Get-SafeguardAssetPartition -Insecure $Context.SuiteData["Partition2Id"]
                $found = $true
            } catch {}
            -not $found
        }
    }

    Cleanup = {
        param($Context)
        # Make sure we exit any partition context
        try { Exit-SafeguardAssetPartition } catch {}
        # Registered cleanups handle remaining deletion
    }
}
