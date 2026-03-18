@{
    Name        = "Backup and Restore"
    Description = "Tests backup CRUD and export/import lifecycle (puts appliance in maintenance mode)"
    Tags        = @("backup", "maintenance", "optional")

    Setup = {
        param($Context)

        # Pre-cleanup: remove any stale test backups
        try {
            $backups = Get-SafeguardBackup -Insecure
            @($backups) | Where-Object { $_.Description -match $Context.TestPrefix } | ForEach-Object {
                try { Remove-SafeguardBackup -Insecure $_.Id } catch {}
            }
        } catch {}
    }

    Execute = {
        param($Context)

        # --- Get-SafeguardBackup (list) ---
        Test-SgPsAssert "Get-SafeguardBackup lists backups" {
            $backups = Get-SafeguardBackup -Insecure
            $null -ne $backups
        }

        # --- New-SafeguardBackup ---
        Test-SgPsAssert "New-SafeguardBackup creates a backup" {
            $backup = New-SafeguardBackup -Insecure -Wait
            $Context.SuiteData["BackupId"] = $backup.Id

            Register-SgPsTestCleanup -Description "Delete test backup" -Action {
                param($Ctx)
                try { Remove-SafeguardBackup -Insecure $Ctx.SuiteData['BackupId'] } catch {}
            }
            $null -ne $backup.Id
        }

        # --- Get-SafeguardBackup by ID ---
        Test-SgPsAssert "Get-SafeguardBackup by ID" {
            $backup = Get-SafeguardBackup -Insecure $Context.SuiteData["BackupId"]
            $backup.Id -eq $Context.SuiteData["BackupId"]
        }

        # --- Export-SafeguardBackup ---
        Test-SgPsAssert "Export-SafeguardBackup exports to file" {
            $outFile = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "SgPsTest_backup.sgb")
            Export-SafeguardBackup -Insecure $Context.SuiteData["BackupId"] -OutFile $outFile
            $Context.SuiteData["BackupFile"] = $outFile

            Register-SgPsTestCleanup -Description "Delete exported backup file" -Action {
                param($Ctx)
                $f = $Ctx.SuiteData['BackupFile']
                if ($f -and (Test-Path $f)) { Remove-Item $f -Force }
            }
            Test-Path $outFile
        }

        # --- Remove-SafeguardBackup ---
        Test-SgPsAssert "Remove-SafeguardBackup deletes a backup" {
            Remove-SafeguardBackup -Insecure $Context.SuiteData["BackupId"]
            $remaining = Get-SafeguardBackup -Insecure
            $list = @($remaining)
            -not ($list | Where-Object { $_.Id -eq $Context.SuiteData["BackupId"] })
        }

        # --- Import-SafeguardBackup ---
        Test-SgPsAssert "Import-SafeguardBackup imports from file" {
            $importedBackup = Import-SafeguardBackup -Insecure $Context.SuiteData["BackupFile"]
            $Context.SuiteData["ImportedBackupId"] = $importedBackup.Id

            Register-SgPsTestCleanup -Description "Delete imported backup" -Action {
                param($Ctx)
                try { Remove-SafeguardBackup -Insecure $Ctx.SuiteData['ImportedBackupId'] } catch {}
            }
            $null -ne $importedBackup.Id
        }
    }

    Cleanup = {
        param($Context)
    }
}
