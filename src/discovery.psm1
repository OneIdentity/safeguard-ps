<# Copyright (c) 2026 One Identity LLC. All rights reserved. #>
# Helpers
function Resolve-SafeguardAccountDiscoveryScheduleId
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [object]$AssetPartition = $null,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$Schedule
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($Schedule.Id -as [int])
    {
        $Schedule = $Schedule.Id
    }

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                             -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId)
    if ($AssetPartitionId)
    {
        $local:RelPath = "AssetPartitions/$AssetPartitionId/AccountDiscoverySchedules"
        $local:ErrMsgSuffix = " in asset partition (Id=$AssetPartitionId)"
    }
    else
    {
        $local:RelPath = "AssetPartitions/AccountDiscoverySchedules"
        $local:ErrMsgSuffix = ""
    }

    if (-not ($Schedule -as [int]))
    {
        try
        {
            $local:Schedules = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" `
                                    -Parameters @{ filter = "Name ieq '$Schedule'"; fields = "Id" })
        }
        catch
        {
            Write-Verbose $_
            Write-Verbose "Caught exception with ieq filter, trying with q parameter"
            $local:Schedules = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" `
                                    -Parameters @{ q = $Schedule; fields = "Id" })
        }
        if (-not $local:Schedules)
        {
            throw "Unable to find account discovery schedule matching '$Schedule'$($local:ErrMsgSuffix)"
        }
        if ($local:Schedules.Count -ne 1)
        {
            throw "Found $($local:Schedules.Count) account discovery schedules matching '$Schedule'$($local:ErrMsgSuffix)"
        }
        $local:Schedules[0].Id
    }
    else
    {
        if ($AssetPartitionId)
        {
            $local:Schedules = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" `
                                    -Parameters @{ filter = "Id eq $Schedule"; fields = "Id" })
            if (-not $local:Schedules)
            {
                throw "Unable to find account discovery schedule matching '$Schedule'$($local:ErrMsgSuffix)"
            }
        }
        $Schedule
    }
}

# Public cmdlets

<#
.SYNOPSIS
Get account discovery schedules from Safeguard via the Web API.

.DESCRIPTION
Get the account discovery schedules that have been configured in Safeguard.
Account discovery schedules control when Safeguard scans assets for new accounts.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to get account discovery schedules from.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to get account discovery schedules from.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ScheduleToGet
An integer containing the ID of the account discovery schedule to get or a string containing the name.

.PARAMETER Fields
An array of property names to return.

.EXAMPLE
Get-SafeguardAccountDiscoverySchedule -Insecure

.EXAMPLE
Get-SafeguardAccountDiscoverySchedule -Insecure "My Unix Schedule"

.EXAMPLE
Get-SafeguardAccountDiscoverySchedule -Insecure -AssetPartition "Unix Servers" -Fields "Id","Name"
#>
function Get-SafeguardAccountDiscoverySchedule
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$false,Position=0)]
        [object]$ScheduleToGet,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Parameters = $null
    if ($Fields)
    {
        $local:Parameters = @{ fields = ($Fields -join ",") }
    }

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                             -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId)

    if ($AssetPartitionId)
    {
        $local:RelPath = "AssetPartitions/$AssetPartitionId/AccountDiscoverySchedules"
    }
    else
    {
        $local:RelPath = "AssetPartitions/AccountDiscoverySchedules"
    }

    if ($ScheduleToGet)
    {
        $local:ScheduleId = (Resolve-SafeguardAccountDiscoveryScheduleId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                                 -AssetPartitionId $AssetPartitionId $ScheduleToGet)
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
            Core GET "$($local:RelPath)/$($local:ScheduleId)" -Parameters $local:Parameters
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
            Core GET "$($local:RelPath)" -Parameters $local:Parameters
    }
}

<#
.SYNOPSIS
Create a new account discovery schedule in Safeguard via the Web API.

.DESCRIPTION
Create a new account discovery schedule that controls when Safeguard scans assets
for new accounts. The schedule must be assigned to assets before discovery will run.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to create the account discovery schedule in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to create the account discovery schedule in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER Name
A string containing the name of the new account discovery schedule.

.PARAMETER Description
A string containing the description of the new account discovery schedule.

.PARAMETER DiscoveryType
The type of discovery to perform. Must be one of: Directory, Unix, Windows,
StarlingConnect, SPS, RoleBased.

.PARAMETER DirectoryId
An integer containing the directory ID when DiscoveryType is Directory.

.PARAMETER ScheduleDiscoverServices
Whether to also discover services during account discovery.

.PARAMETER AutoConfigureDependentSystems
Whether to automatically configure dependent systems discovered during discovery.

.PARAMETER Schedule
A Safeguard schedule object for when to run discovery, see New-SafeguardSchedule and associated cmdlets.

.EXAMPLE
New-SafeguardAccountDiscoverySchedule -Insecure -Name "Daily Unix Discovery" -DiscoveryType "Unix"

.EXAMPLE
New-SafeguardAccountDiscoverySchedule -Insecure -Name "Windows Nightly" -DiscoveryType "Windows" -Schedule (New-SafeguardScheduleDaily -StartTime "02:00")
#>
function New-SafeguardAccountDiscoverySchedule
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [string]$Description,
        [Parameter(Mandatory=$true)]
        [ValidateSet("Directory","Unix","Windows","StarlingConnect","SPS","RoleBased",IgnoreCase=$true)]
        [string]$DiscoveryType,
        [Parameter(Mandatory=$false)]
        [int]$DirectoryId,
        [Parameter(Mandatory=$false)]
        [switch]$ScheduleDiscoverServices,
        [Parameter(Mandatory=$false)]
        [switch]$AutoConfigureDependentSystems,
        [Parameter(Mandatory=$false)]
        [HashTable]$Schedule
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                            -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -UseDefault)

    $local:Body = @{
        "Name" = $Name;
        "DiscoveryType" = $DiscoveryType;
        "ScheduleDiscoverServices" = [bool]$ScheduleDiscoverServices;
        "AutoConfigureDependentSystems" = [bool]$AutoConfigureDependentSystems;
    }

    if ($PSBoundParameters.ContainsKey("Description")) { $local:Body.Description = $Description }
    if ($PSBoundParameters.ContainsKey("DirectoryId")) { $local:Body.DirectoryId = $DirectoryId }

    if ($Schedule)
    {
        Import-Module -Name "$PSScriptRoot\schedules.psm1" -Scope Local
        $local:Body = (Copy-ScheduleToDto -Schedule $Schedule -Dto $local:Body)
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
        POST "AssetPartitions/$AssetPartitionId/AccountDiscoverySchedules" -Body $local:Body
}

<#
.SYNOPSIS
Edit an existing account discovery schedule in Safeguard via the Web API.

.DESCRIPTION
Edit an existing account discovery schedule to change its description, service
discovery setting, dependent system configuration, or timing schedule.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
containing the account discovery schedule.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID containing the account discovery schedule.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ScheduleToEdit
An integer containing the ID of the account discovery schedule to edit or a string containing the name.

.PARAMETER Description
A string containing the new description for the account discovery schedule.

.PARAMETER ScheduleDiscoverServices
Whether to also discover services during account discovery.

.PARAMETER AutoConfigureDependentSystems
Whether to automatically configure dependent systems discovered during discovery.

.PARAMETER Schedule
A Safeguard schedule object for when to run discovery, see New-SafeguardSchedule and associated cmdlets.

.EXAMPLE
Edit-SafeguardAccountDiscoverySchedule -Insecure "My Schedule" -Description "Updated description"

.EXAMPLE
Edit-SafeguardAccountDiscoverySchedule -Insecure 3 -Schedule (New-SafeguardScheduleDaily -StartTime "03:00")
#>
function Edit-SafeguardAccountDiscoverySchedule
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$ScheduleToEdit,
        [Parameter(Mandatory=$false)]
        [string]$Description,
        [Parameter(Mandatory=$false)]
        [switch]$ScheduleDiscoverServices,
        [Parameter(Mandatory=$false)]
        [switch]$AutoConfigureDependentSystems,
        [Parameter(Mandatory=$false)]
        [HashTable]$Schedule
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:SchedObj = (Get-SafeguardAccountDiscoverySchedule -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                           -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId $ScheduleToEdit)

    if ($PSBoundParameters.ContainsKey("Description")) { $local:SchedObj.Description = $Description }
    if ($PSBoundParameters.ContainsKey("ScheduleDiscoverServices")) { $local:SchedObj.ScheduleDiscoverServices = [bool]$ScheduleDiscoverServices }
    if ($PSBoundParameters.ContainsKey("AutoConfigureDependentSystems")) { $local:SchedObj.AutoConfigureDependentSystems = [bool]$AutoConfigureDependentSystems }
    if ($PSBoundParameters.ContainsKey("Schedule"))
    {
        Import-Module -Name "$PSScriptRoot\schedules.psm1" -Scope Local
        $local:SchedObj = (Copy-ScheduleToDto -Schedule $Schedule -Dto $local:SchedObj)
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
        PUT "AssetPartitions/$($local:SchedObj.AssetPartitionId)/AccountDiscoverySchedules/$($local:SchedObj.Id)" -Body $local:SchedObj
}

<#
.SYNOPSIS
Delete an account discovery schedule from Safeguard via the Web API.

.DESCRIPTION
Delete an account discovery schedule. Assets that were assigned to this schedule
will no longer have automatic account discovery.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to delete the account discovery schedule from.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to delete the account discovery schedule from.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ScheduleToDelete
An integer containing the ID of the account discovery schedule to delete or a string containing the name.

.EXAMPLE
Remove-SafeguardAccountDiscoverySchedule -Insecure "Old Schedule"

.EXAMPLE
Remove-SafeguardAccountDiscoverySchedule -Insecure -AssetPartition "Unix Servers" 5
#>
function Remove-SafeguardAccountDiscoverySchedule
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$ScheduleToDelete
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                            -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -UseDefault)

    $local:ScheduleId = (Resolve-SafeguardAccountDiscoveryScheduleId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                             -AssetPartitionId $AssetPartitionId $ScheduleToDelete)

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
        DELETE "AssetPartitions/$AssetPartitionId/AccountDiscoverySchedules/$($local:ScheduleId)"
}

<#
.SYNOPSIS
Rename an account discovery schedule in Safeguard via the Web API.

.DESCRIPTION
Rename an account discovery schedule without changing any of its configuration.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
containing the account discovery schedule.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID containing the account discovery schedule.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ScheduleToRename
An integer containing the ID of the account discovery schedule to rename or a string containing the name.

.PARAMETER NewName
A string containing the new name for the account discovery schedule.

.EXAMPLE
Rename-SafeguardAccountDiscoverySchedule -Insecure "Old Name" -NewName "New Name"

.EXAMPLE
Rename-SafeguardAccountDiscoverySchedule -Insecure -AssetPartition "Unix Servers" 5 -NewName "Better Name"
#>
function Rename-SafeguardAccountDiscoverySchedule
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$ScheduleToRename,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$NewName
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:SchedObj = (Get-SafeguardAccountDiscoverySchedule -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                           -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId $ScheduleToRename)

    $local:SchedObj.Name = $NewName

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
        PUT "AssetPartitions/$($local:SchedObj.AssetPartitionId)/AccountDiscoverySchedules/$($local:SchedObj.Id)" -Body $local:SchedObj
}

<#
.SYNOPSIS
Copy an account discovery schedule in Safeguard via the Web API.

.DESCRIPTION
Create a copy of an existing account discovery schedule with a new name. The copy
will have all the same settings as the original but will not have any assets assigned.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
containing the account discovery schedule.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID containing the account discovery schedule.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ScheduleToCopy
An integer containing the ID of the account discovery schedule to copy or a string containing the name.

.PARAMETER CopyName
A string containing the name for the new copy of the account discovery schedule.

.EXAMPLE
Copy-SafeguardAccountDiscoverySchedule -Insecure "Existing Schedule" -CopyName "Copy of Schedule"

.EXAMPLE
Copy-SafeguardAccountDiscoverySchedule -Insecure 5 -CopyName "New Schedule from 5"
#>
function Copy-SafeguardAccountDiscoverySchedule
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$ScheduleToCopy,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$CopyName
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                            -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -UseDefault)

    $local:Item = (Get-SafeguardAccountDiscoverySchedule -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                       -AssetPartitionId $AssetPartitionId $ScheduleToCopy)

    $local:Item.Id = 0
    $local:Item.Name = $CopyName
    if ($local:Item.PSObject.Properties["AssetsCount"])
    {
        $local:Item.AssetsCount = 0
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
        POST "AssetPartitions/$AssetPartitionId/AccountDiscoverySchedules" -Body $local:Item
}

<#
.SYNOPSIS
Get assets assigned to an account discovery schedule in Safeguard via the Web API.

.DESCRIPTION
Get the list of assets that are assigned to a specific account discovery schedule.
These are the assets that will be scanned when the schedule runs.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
containing the account discovery schedule.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID containing the account discovery schedule.
(If specified, this will override the AssetPartition parameter)

.PARAMETER Schedule
An integer containing the ID of the account discovery schedule or a string containing the name.

.PARAMETER Fields
An array of property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardAccountDiscoveryScheduleAsset -Insecure "My Unix Schedule"

.EXAMPLE
Get-SafeguardAccountDiscoveryScheduleAsset -Insecure 3
#>
function Get-SafeguardAccountDiscoveryScheduleAsset
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$Schedule,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                             -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -UseDefault)

    $local:ScheduleId = (Resolve-SafeguardAccountDiscoveryScheduleId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                             -AssetPartitionId $AssetPartitionId $Schedule)

    $local:Parameters = $null
    if ($Fields)
    {
        $local:Parameters = @{ fields = ($Fields -join ",") }
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET `
        "AssetPartitions/$AssetPartitionId/AccountDiscoverySchedules/$($local:ScheduleId)/Assets" -Parameters $local:Parameters
}

<#
.SYNOPSIS
Add assets to an account discovery schedule in Safeguard via the Web API.

.DESCRIPTION
Add one or more assets to an account discovery schedule. The assets will be scanned
for new accounts when the schedule runs or when discovery is triggered manually.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
containing the account discovery schedule.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID containing the account discovery schedule.
(If specified, this will override the AssetPartition parameter)

.PARAMETER Schedule
An integer containing the ID of the account discovery schedule or a string containing the name.

.PARAMETER AssetsToAdd
A list of integers or strings containing the IDs or names of the assets to add to the schedule.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Add-SafeguardAccountDiscoveryScheduleAsset -Insecure -Schedule "My Schedule" -AssetsToAdd "linux-server1","linux-server2"

.EXAMPLE
Add-SafeguardAccountDiscoveryScheduleAsset -Insecure -Schedule 3 -AssetsToAdd 42,55
#>
function Add-SafeguardAccountDiscoveryScheduleAsset
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$Schedule,
        [Parameter(Mandatory=$true,Position=1)]
        [object[]]$AssetsToAdd
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                             -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -UseDefault)

    $local:ScheduleId = (Resolve-SafeguardAccountDiscoveryScheduleId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                             -AssetPartitionId $AssetPartitionId $Schedule)

    [object[]]$local:Assets = $null
    foreach ($local:Asset in $AssetsToAdd)
    {
        $local:ResolvedAsset = (Get-SafeguardAsset -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $local:Asset)
        $local:Assets += $($local:ResolvedAsset)
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST `
        "AssetPartitions/$AssetPartitionId/AccountDiscoverySchedules/$($local:ScheduleId)/Assets/Add" -Body $local:Assets
}

<#
.SYNOPSIS
Remove assets from an account discovery schedule in Safeguard via the Web API.

.DESCRIPTION
Remove one or more assets from an account discovery schedule. The assets will no
longer be scanned when the schedule runs.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
containing the account discovery schedule.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID containing the account discovery schedule.
(If specified, this will override the AssetPartition parameter)

.PARAMETER Schedule
An integer containing the ID of the account discovery schedule or a string containing the name.

.PARAMETER AssetsToRemove
A list of integers or strings containing the IDs or names of the assets to remove from the schedule.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardAccountDiscoveryScheduleAsset -Insecure -Schedule "My Schedule" -AssetsToRemove "linux-server1"

.EXAMPLE
Remove-SafeguardAccountDiscoveryScheduleAsset -Insecure -Schedule 3 -AssetsToRemove 42
#>
function Remove-SafeguardAccountDiscoveryScheduleAsset
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$Schedule,
        [Parameter(Mandatory=$true,Position=1)]
        [object[]]$AssetsToRemove
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                             -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -UseDefault)

    $local:ScheduleId = (Resolve-SafeguardAccountDiscoveryScheduleId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                             -AssetPartitionId $AssetPartitionId $Schedule)

    [object[]]$local:Assets = $null
    foreach ($local:Asset in $AssetsToRemove)
    {
        $local:ResolvedAsset = (Get-SafeguardAsset -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $local:Asset)
        $local:Assets += $($local:ResolvedAsset)
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST `
        "AssetPartitions/$AssetPartitionId/AccountDiscoverySchedules/$($local:ScheduleId)/Assets/Remove" -Body $local:Assets
}

<#
.SYNOPSIS
Get account discovery rules from an account discovery schedule in Safeguard via the Web API.

.DESCRIPTION
Get the list of account discovery rules configured on a specific account discovery
schedule. Rules control which accounts are discovered and whether they are
automatically brought under management.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
containing the account discovery schedule.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID containing the account discovery schedule.
(If specified, this will override the AssetPartition parameter)

.PARAMETER Schedule
An integer containing the ID of the account discovery schedule or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardAccountDiscoveryRule -Insecure -Schedule "My Unix Schedule"

.EXAMPLE
Get-SafeguardAccountDiscoveryRule -Insecure -Schedule 3
#>
function Get-SafeguardAccountDiscoveryRule
{
    [CmdletBinding()]
    [OutputType([object[]])]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$Schedule
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                             -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -UseDefault)

    $local:ScheduleId = (Resolve-SafeguardAccountDiscoveryScheduleId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                             -AssetPartitionId $AssetPartitionId $Schedule)

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET `
        "AssetPartitions/$AssetPartitionId/AccountDiscoverySchedules/$($local:ScheduleId)/Rules"
}

<#
.SYNOPSIS
Add an account discovery rule to an account discovery schedule in Safeguard via the Web API.

.DESCRIPTION
Add a new rule to an account discovery schedule. Rules define which accounts are
discovered and whether they should be automatically brought under management.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
containing the account discovery schedule.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID containing the account discovery schedule.
(If specified, this will override the AssetPartition parameter)

.PARAMETER Schedule
An integer containing the ID of the account discovery schedule or a string containing the name.

.PARAMETER RuleName
A string containing the name for the new discovery rule.

.PARAMETER AutoManageDiscoveredAccounts
Whether discovered accounts matching this rule should be automatically brought under management.

.PARAMETER RuleObject
A hashtable or PSObject containing the full rule definition including type-specific
properties (e.g., UnixAccountDiscoveryProperties, WindowsAccountDiscoveryProperties).
When specified, RuleName and AutoManageDiscoveredAccounts are ignored.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Add-SafeguardAccountDiscoveryRule -Insecure -Schedule "My Schedule" -RuleName "Discover All"

.EXAMPLE
Add-SafeguardAccountDiscoveryRule -Insecure -Schedule 3 -RuleName "Auto Manage" -AutoManageDiscoveredAccounts
#>
function Add-SafeguardAccountDiscoveryRule
{
    [CmdletBinding(DefaultParameterSetName="Attributes")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$Schedule,
        [Parameter(ParameterSetName="Attributes",Mandatory=$true)]
        [string]$RuleName,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [switch]$AutoManageDiscoveredAccounts,
        [Parameter(ParameterSetName="Object",Mandatory=$true)]
        [object]$RuleObject
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                             -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -UseDefault)

    $local:ScheduleId = (Resolve-SafeguardAccountDiscoveryScheduleId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                             -AssetPartitionId $AssetPartitionId $Schedule)

    if ($PSCmdlet.ParameterSetName -eq "Object")
    {
        $local:Body = @($RuleObject)
    }
    else
    {
        $local:Rule = @{
            "Name" = $RuleName;
            "AutoManageDiscoveredAccounts" = [bool]$AutoManageDiscoveredAccounts;
        }
        $local:Body = @($local:Rule)
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST `
        "AssetPartitions/$AssetPartitionId/AccountDiscoverySchedules/$($local:ScheduleId)/Rules/Add" -Body $local:Body
}

<#
.SYNOPSIS
Remove an account discovery rule from an account discovery schedule in Safeguard via the Web API.

.DESCRIPTION
Remove a rule from an account discovery schedule by name. The rule will no longer
apply to future discovery runs.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
containing the account discovery schedule.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID containing the account discovery schedule.
(If specified, this will override the AssetPartition parameter)

.PARAMETER Schedule
An integer containing the ID of the account discovery schedule or a string containing the name.

.PARAMETER RuleName
A string containing the name of the discovery rule to remove.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardAccountDiscoveryRule -Insecure -Schedule "My Schedule" -RuleName "Old Rule"

.EXAMPLE
Remove-SafeguardAccountDiscoveryRule -Insecure -Schedule 3 -RuleName "Deprecated Rule"
#>
function Remove-SafeguardAccountDiscoveryRule
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$Schedule,
        [Parameter(Mandatory=$true)]
        [string]$RuleName
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                             -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -UseDefault)

    $local:ScheduleId = (Resolve-SafeguardAccountDiscoveryScheduleId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                             -AssetPartitionId $AssetPartitionId $Schedule)

    $local:Rules = @(Get-SafeguardAccountDiscoveryRule -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                         -AssetPartitionId $AssetPartitionId -Schedule $Schedule)
    $local:RuleToRemove = ($local:Rules | Where-Object { $_.Name -ieq $RuleName })
    if (-not $local:RuleToRemove)
    {
        throw "Unable to find account discovery rule '$RuleName' on schedule (Id=$($local:ScheduleId))"
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST `
        "AssetPartitions/$AssetPartitionId/AccountDiscoverySchedules/$($local:ScheduleId)/Rules/Remove" -Body @($local:RuleToRemove)
}
