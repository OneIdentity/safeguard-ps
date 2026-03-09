# Copyright (c) 2026 One Identity LLC. All rights reserved.
#
# This script renames the default "Macrocosm" partition and its associated objects
# to more descriptive names, configures a stronger default password rule, and adds
# daily check and weekly change schedules. It is idempotent -- safe to run repeatedly.
#
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true,Position=0)]
    [string]$Appliance,
    [Parameter(Mandatory=$false)]
    [switch]$Insecure
)

if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }

if (-not (Get-Module safeguard-ps)) { Import-Module safeguard-ps }

# Browser-based login
Connect-Safeguard -Appliance $Appliance -Insecure:$Insecure -Gui
Write-Host -ForegroundColor Green "Connected to Safeguard -- $Appliance"

# --- Helper to find an item by old name or new name ---
function Find-OrVerify
{
    Param(
        [Parameter(Mandatory=$true)] [scriptblock]$GetBlock,
        [Parameter(Mandatory=$true)] [string]$OldName,
        [Parameter(Mandatory=$true)] [string]$NewName,
        [Parameter(Mandatory=$true)] [string]$ItemType
    )
    $local:Item = $null
    try { $local:Item = (& $GetBlock $OldName) } catch {}
    if ($local:Item)
    {
        Write-Host "Found $ItemType '$OldName' -- will rename to '$NewName'"
        return @{ Item = $local:Item; NeedsRename = $true }
    }
    try { $local:Item = (& $GetBlock $NewName) } catch {}
    if ($local:Item)
    {
        Write-Host "$ItemType '$NewName' already exists -- skipping rename"
        return @{ Item = $local:Item; NeedsRename = $false }
    }
    throw "Could not find $ItemType as '$OldName' or '$NewName'"
}

# ============================================================
# 1. Rename the default asset partition
# ============================================================
$local:PartitionResult = Find-OrVerify -GetBlock { param($n) Get-SafeguardAssetPartition $n } `
    -OldName "Macrocosm" -NewName "Default Partition" -ItemType "Asset Partition"
$local:PartitionId = $local:PartitionResult.Item.Id
if ($local:PartitionResult.NeedsRename)
{
    Edit-SafeguardAssetPartition $local:PartitionId -Name "Default Partition" | Out-Null
    Write-Host -ForegroundColor Cyan "  Renamed asset partition to 'Default Partition'"
}

# ============================================================
# 2. Rename the linked password profile
# ============================================================
$local:ProfileResult = Find-OrVerify `
    -GetBlock { param($n) Get-SafeguardPasswordProfile -AssetPartitionId $local:PartitionId $n } `
    -OldName "Macrocosm Profile" -NewName "Default Partition Profile" -ItemType "Password Profile"
if ($local:ProfileResult.NeedsRename)
{
    Rename-SafeguardPasswordProfile -AssetPartitionId $local:PartitionId $local:ProfileResult.Item.Id "Default Partition Profile" | Out-Null
    Write-Host -ForegroundColor Cyan "  Renamed password profile to 'Default Partition Profile'"
}

# ============================================================
# 3. Rename the check schedule
# ============================================================
$local:CheckResult = Find-OrVerify `
    -GetBlock { param($n) Get-SafeguardPasswordCheckSchedule -AssetPartitionId $local:PartitionId $n } `
    -OldName "Macrocosm Check Schedule" -NewName "Never Check Schedule" -ItemType "Check Schedule"
if ($local:CheckResult.NeedsRename)
{
    Rename-SafeguardPasswordCheckSchedule -AssetPartitionId $local:PartitionId $local:CheckResult.Item.Id "Never Check Schedule" | Out-Null
    Write-Host -ForegroundColor Cyan "  Renamed check schedule to 'Never Check Schedule'"
}

# ============================================================
# 4. Rename the change schedule
# ============================================================
$local:ChangeResult = Find-OrVerify `
    -GetBlock { param($n) Get-SafeguardPasswordChangeSchedule -AssetPartitionId $local:PartitionId $n } `
    -OldName "Macrocosm Change Schedule" -NewName "Never Change Schedule" -ItemType "Change Schedule"
if ($local:ChangeResult.NeedsRename)
{
    Rename-SafeguardPasswordChangeSchedule -AssetPartitionId $local:PartitionId $local:ChangeResult.Item.Id "Never Change Schedule" | Out-Null
    Write-Host -ForegroundColor Cyan "  Renamed change schedule to 'Never Change Schedule'"
}

# ============================================================
# 5. Rename the password rule
# ============================================================
$local:RuleResult = Find-OrVerify `
    -GetBlock { param($n) Get-SafeguardAccountPasswordRule -AssetPartitionId $local:PartitionId $n } `
    -OldName "Macrocosm Password Rule" -NewName "Default Basic Password Rule" -ItemType "Password Rule"
if ($local:RuleResult.NeedsRename)
{
    Rename-SafeguardAccountPasswordRule -AssetPartitionId $local:PartitionId $local:RuleResult.Item.Id "Default Basic Password Rule" | Out-Null
    Write-Host -ForegroundColor Cyan "  Renamed password rule to 'Default Basic Password Rule'"
}

# ============================================================
# 6. Configure the password rule: 10-16 chars, 1 letter,
#    1 number, 1 symbol from: !@#$%^&*-=+
# ============================================================
Write-Host "Updating password rule settings..."
Edit-SafeguardAccountPasswordRule -AssetPartitionId $local:PartitionId "Default Basic Password Rule" `
    -MinCharacters 10 `
    -MaxCharacters 16 `
    -AllowUppercase $true `
    -MinUppercase 0 `
    -AllowLowercase $true `
    -MinLowercase 1 `
    -AllowNumeric $true `
    -MinNumeric 1 `
    -AllowSymbols $true `
    -MinSymbols 1 `
    -AllowedSymbolChars '!@#$%^&*-=+' | Out-Null
Write-Host -ForegroundColor Cyan "  Password rule configured (10-16 chars, requires letter + number + symbol)"

# ============================================================
# 7. Add "Check Daily" schedule -- every day at 7:00 AM MT
# ============================================================
$local:DailyExists = $null
try { $local:DailyExists = (Get-SafeguardPasswordCheckSchedule -AssetPartitionId $local:PartitionId "Check Daily") } catch {}
if (-not $local:DailyExists)
{
    Write-Host "Creating 'Check Daily' check schedule..."
    $local:DailySchedule = (New-SafeguardScheduleDaily -StartHour 7 -StartMinute 0 -TimeZone "Mountain Standard Time")
    New-SafeguardPasswordCheckSchedule -AssetPartitionId $local:PartitionId "Check Daily" -Schedule $local:DailySchedule | Out-Null
    Write-Host -ForegroundColor Cyan "  Created 'Check Daily' -- runs every day at 7:00 AM Mountain Time"
}
else
{
    Write-Host "'Check Daily' check schedule already exists -- skipping"
}

# ============================================================
# 8. Add "Change Weekly" schedule -- Saturday at 2:00 AM MT
# ============================================================
$local:WeeklyExists = $null
try { $local:WeeklyExists = (Get-SafeguardPasswordChangeSchedule -AssetPartitionId $local:PartitionId "Change Weekly") } catch {}
if (-not $local:WeeklyExists)
{
    Write-Host "Creating 'Change Weekly' change schedule..."
    $local:WeeklySchedule = (New-SafeguardScheduleWeekly -RepeatDaysOfWeek "Saturday" -StartHour 2 -StartMinute 0 -TimeZone "Mountain Standard Time")
    New-SafeguardPasswordChangeSchedule -AssetPartitionId $local:PartitionId "Change Weekly" -Schedule $local:WeeklySchedule | Out-Null
    Write-Host -ForegroundColor Cyan "  Created 'Change Weekly' -- runs every Saturday at 2:00 AM Mountain Time"
}
else
{
    Write-Host "'Change Weekly' change schedule already exists -- skipping"
}

Write-Host ""
Write-Host -ForegroundColor Green "Safeguard default configuration complete!"
