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

# Rule builder cmdlets

<#
.SYNOPSIS
Create a new Unix account discovery rule object for use with Add-SafeguardAccountDiscoveryRule.

.DESCRIPTION
Create a hashtable representing a Unix account discovery rule. Use -FindAll to discover
all accounts, or specify one or more filter parameters to use PropertyConstraint mode.
The resulting object can be passed to Add-SafeguardAccountDiscoveryRule -RuleObject.

.PARAMETER Name
A string containing the name for the discovery rule.

.PARAMETER FindAll
Discover all Unix accounts without filtering.

.PARAMETER AutoManageDiscoveredAccounts
Whether discovered accounts matching this rule should be automatically brought under management.

.PARAMETER NameFilter
A regular expression to filter account names.

.PARAMETER GroupFilter
A regular expression to filter account group names.

.PARAMETER UidFilter
An array of UID filters. Specify single IDs or ranges (e.g., "0", "500-1000").

.PARAMETER GidFilter
An array of GID filters. Specify single IDs or ranges (e.g., "0", "100-200").

.EXAMPLE
New-SafeguardAccountDiscoveryRuleUnix -Name "All Unix Accounts" -FindAll

.EXAMPLE
New-SafeguardAccountDiscoveryRuleUnix -Name "Root Only" -NameFilter "^root$" -AutoManageDiscoveredAccounts

.EXAMPLE
New-SafeguardAccountDiscoveryRuleUnix -Name "Service Accounts" -UidFilter "0","500-999"
#>
function New-SafeguardAccountDiscoveryRuleUnix
{
    [CmdletBinding(DefaultParameterSetName="PropertyConstraint")]
    [OutputType([hashtable])]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Name,
        [Parameter(ParameterSetName="FindAll",Mandatory=$true)]
        [switch]$FindAll,
        [Parameter(Mandatory=$false)]
        [switch]$AutoManageDiscoveredAccounts,
        [Parameter(ParameterSetName="PropertyConstraint",Mandatory=$false)]
        [string]$NameFilter,
        [Parameter(ParameterSetName="PropertyConstraint",Mandatory=$false)]
        [string]$GroupFilter,
        [Parameter(ParameterSetName="PropertyConstraint",Mandatory=$false)]
        [string[]]$UidFilter,
        [Parameter(ParameterSetName="PropertyConstraint",Mandatory=$false)]
        [string[]]$GidFilter
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Rule = @{
        "Name" = $Name;
        "AutoManageDiscoveredAccounts" = [bool]$AutoManageDiscoveredAccounts;
    }

    if ($FindAll)
    {
        $local:Rule.UnixAccountDiscoveryProperties = @{ "RuleType" = "FindAll" }
    }
    else
    {
        $local:Constraints = @{}
        if ($PSBoundParameters.ContainsKey("NameFilter")) { $local:Constraints.NameFilter = $NameFilter }
        if ($PSBoundParameters.ContainsKey("GroupFilter")) { $local:Constraints.GroupFilter = $GroupFilter }
        if ($PSBoundParameters.ContainsKey("UidFilter")) { $local:Constraints.UidFilter = $UidFilter }
        if ($PSBoundParameters.ContainsKey("GidFilter")) { $local:Constraints.GidFilter = $GidFilter }
        $local:Rule.UnixAccountDiscoveryProperties = @{
            "RuleType" = "PropertyConstraint";
            "PropertyConstraintProperties" = $local:Constraints;
        }
    }

    $local:Rule
}

<#
.SYNOPSIS
Create a new Windows account discovery rule object for use with Add-SafeguardAccountDiscoveryRule.

.DESCRIPTION
Create a hashtable representing a Windows account discovery rule. Use -FindAll to discover
all accounts, or specify one or more filter parameters to use PropertyConstraint mode.
The resulting object can be passed to Add-SafeguardAccountDiscoveryRule -RuleObject.

.PARAMETER Name
A string containing the name for the discovery rule.

.PARAMETER FindAll
Discover all Windows accounts without filtering.

.PARAMETER AutoManageDiscoveredAccounts
Whether discovered accounts matching this rule should be automatically brought under management.

.PARAMETER NameFilter
A regular expression to filter account names.

.PARAMETER GroupFilter
A regular expression to filter account group names.

.PARAMETER RidFilter
An array of Windows relative identifier filters. Specify single IDs or ranges (e.g., "500", "1000-1100").

.PARAMETER GidFilter
An array of GID filters. Specify single IDs or ranges (e.g., "0", "100-200").

.EXAMPLE
New-SafeguardAccountDiscoveryRuleWindows -Name "All Windows Accounts" -FindAll

.EXAMPLE
New-SafeguardAccountDiscoveryRuleWindows -Name "Admins Only" -GroupFilter "Administrators"

.EXAMPLE
New-SafeguardAccountDiscoveryRuleWindows -Name "Built-in Accounts" -RidFilter "500","501"
#>
function New-SafeguardAccountDiscoveryRuleWindows
{
    [CmdletBinding(DefaultParameterSetName="PropertyConstraint")]
    [OutputType([hashtable])]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Name,
        [Parameter(ParameterSetName="FindAll",Mandatory=$true)]
        [switch]$FindAll,
        [Parameter(Mandatory=$false)]
        [switch]$AutoManageDiscoveredAccounts,
        [Parameter(ParameterSetName="PropertyConstraint",Mandatory=$false)]
        [string]$NameFilter,
        [Parameter(ParameterSetName="PropertyConstraint",Mandatory=$false)]
        [string]$GroupFilter,
        [Parameter(ParameterSetName="PropertyConstraint",Mandatory=$false)]
        [string[]]$RidFilter,
        [Parameter(ParameterSetName="PropertyConstraint",Mandatory=$false)]
        [string[]]$GidFilter
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Rule = @{
        "Name" = $Name;
        "AutoManageDiscoveredAccounts" = [bool]$AutoManageDiscoveredAccounts;
    }

    if ($FindAll)
    {
        $local:Rule.WindowsAccountDiscoveryProperties = @{ "RuleType" = "FindAll" }
    }
    else
    {
        $local:Constraints = @{}
        if ($PSBoundParameters.ContainsKey("NameFilter")) { $local:Constraints.NameFilter = $NameFilter }
        if ($PSBoundParameters.ContainsKey("GroupFilter")) { $local:Constraints.GroupFilter = $GroupFilter }
        if ($PSBoundParameters.ContainsKey("RidFilter")) { $local:Constraints.RidFilter = $RidFilter }
        if ($PSBoundParameters.ContainsKey("GidFilter")) { $local:Constraints.GidFilter = $GidFilter }
        $local:Rule.WindowsAccountDiscoveryProperties = @{
            "RuleType" = "PropertyConstraint";
            "PropertyConstraintProperties" = $local:Constraints;
        }
    }

    $local:Rule
}

<#
.SYNOPSIS
Create a new Directory account discovery rule object for use with Add-SafeguardAccountDiscoveryRule.

.DESCRIPTION
Create a hashtable representing a Directory (Active Directory/LDAP) account discovery rule.
Directory rules support multiple rule types: FindAll, Name, Group, LdapFilter, and
PropertyConstraint. The resulting object can be passed to Add-SafeguardAccountDiscoveryRule -RuleObject.

.PARAMETER Name
A string containing the name for the discovery rule.

.PARAMETER FindAll
Discover all directory accounts without filtering.

.PARAMETER SearchByName
Use name-based search (ANR search for Active Directory).

.PARAMETER SearchByGroup
Use group membership search.

.PARAMETER SearchByLdapFilter
Use a custom LDAP filter for discovery.

.PARAMETER AutoManageDiscoveredAccounts
Whether discovered accounts matching this rule should be automatically brought under management.

.PARAMETER SearchBase
An LDAP distinguished name for the search base (e.g., "OU=Users,DC=corp,DC=local").

.PARAMETER SearchScope
How far to search: OneLevel or SubTree. (default: SubTree)

.PARAMETER SearchName
The name to search for when using -SearchByName rule type.

.PARAMETER SearchNameType
How to match the search name: StartsWith or Contains. (default: StartsWith)

.PARAMETER LdapFilter
A custom LDAP filter string when using -SearchByLdapFilter rule type.

.PARAMETER Groups
An array of group distinguished names when using -SearchByGroup rule type.

.PARAMETER NameFilter
A regular expression to filter account names (PropertyConstraint mode).

.PARAMETER GroupFilter
A regular expression to filter account group names (PropertyConstraint mode).

.PARAMETER UidFilter
An array of uidNumber filters (Active Directory only). Specify single IDs or ranges.

.PARAMETER RidFilter
An array of Windows relative identifier filters (Active Directory only). Specify single IDs or ranges.

.PARAMETER GidFilter
An array of gidNumber filters (Active Directory only). Specify single IDs or ranges.

.PARAMETER PrimaryGidFilter
An array of primaryGroupID filters (Active Directory only). Specify single IDs or ranges.

.EXAMPLE
New-SafeguardAccountDiscoveryRuleDirectory -Name "All Directory" -FindAll

.EXAMPLE
New-SafeguardAccountDiscoveryRuleDirectory -Name "Service Accounts" -SearchByName -SearchName "svc_" -SearchNameType StartsWith -SearchBase "OU=ServiceAccounts,DC=corp,DC=local"

.EXAMPLE
New-SafeguardAccountDiscoveryRuleDirectory -Name "Admin Group" -SearchByGroup -Groups "CN=Domain Admins,CN=Users,DC=corp,DC=local"

.EXAMPLE
New-SafeguardAccountDiscoveryRuleDirectory -Name "Custom LDAP" -SearchByLdapFilter -LdapFilter "(&(objectClass=user)(adminCount=1))"
#>
function New-SafeguardAccountDiscoveryRuleDirectory
{
    [CmdletBinding(DefaultParameterSetName="PropertyConstraint")]
    [OutputType([hashtable])]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Name,
        [Parameter(ParameterSetName="FindAll",Mandatory=$true)]
        [switch]$FindAll,
        [Parameter(ParameterSetName="Name",Mandatory=$true)]
        [switch]$SearchByName,
        [Parameter(ParameterSetName="Group",Mandatory=$true)]
        [switch]$SearchByGroup,
        [Parameter(ParameterSetName="LdapFilter",Mandatory=$true)]
        [switch]$SearchByLdapFilter,
        [Parameter(Mandatory=$false)]
        [switch]$AutoManageDiscoveredAccounts,
        [Parameter(ParameterSetName="FindAll",Mandatory=$false)]
        [Parameter(ParameterSetName="Name",Mandatory=$false)]
        [Parameter(ParameterSetName="Group",Mandatory=$false)]
        [Parameter(ParameterSetName="LdapFilter",Mandatory=$false)]
        [Parameter(ParameterSetName="PropertyConstraint",Mandatory=$false)]
        [string]$SearchBase,
        [Parameter(ParameterSetName="FindAll",Mandatory=$false)]
        [Parameter(ParameterSetName="Name",Mandatory=$false)]
        [Parameter(ParameterSetName="Group",Mandatory=$false)]
        [Parameter(ParameterSetName="LdapFilter",Mandatory=$false)]
        [Parameter(ParameterSetName="PropertyConstraint",Mandatory=$false)]
        [ValidateSet("OneLevel","SubTree",IgnoreCase=$true)]
        [string]$SearchScope,
        [Parameter(ParameterSetName="Name",Mandatory=$true)]
        [string]$SearchName,
        [Parameter(ParameterSetName="Name",Mandatory=$false)]
        [ValidateSet("StartsWith","Contains",IgnoreCase=$true)]
        [string]$SearchNameType = "StartsWith",
        [Parameter(ParameterSetName="LdapFilter",Mandatory=$true)]
        [string]$LdapFilter,
        [Parameter(ParameterSetName="Group",Mandatory=$true)]
        [string[]]$Groups,
        [Parameter(ParameterSetName="PropertyConstraint",Mandatory=$false)]
        [string]$NameFilter,
        [Parameter(ParameterSetName="PropertyConstraint",Mandatory=$false)]
        [string]$GroupFilter,
        [Parameter(ParameterSetName="PropertyConstraint",Mandatory=$false)]
        [string[]]$UidFilter,
        [Parameter(ParameterSetName="PropertyConstraint",Mandatory=$false)]
        [string[]]$RidFilter,
        [Parameter(ParameterSetName="PropertyConstraint",Mandatory=$false)]
        [string[]]$GidFilter,
        [Parameter(ParameterSetName="PropertyConstraint",Mandatory=$false)]
        [string[]]$PrimaryGidFilter
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Rule = @{
        "Name" = $Name;
        "AutoManageDiscoveredAccounts" = [bool]$AutoManageDiscoveredAccounts;
    }

    $local:Props = @{}

    switch ($PSCmdlet.ParameterSetName)
    {
        "FindAll" {
            $local:Props.RuleType = "FindAll"
        }
        "Name" {
            $local:Props.RuleType = "Name"
            $local:Props.SearchName = $SearchName
            $local:Props.SearchNameType = $SearchNameType
        }
        "Group" {
            $local:Props.RuleType = "Group"
            $local:Props.Groups = $Groups
        }
        "LdapFilter" {
            $local:Props.RuleType = "LdapFilter"
            $local:Props.LdapFilter = $LdapFilter
        }
        "PropertyConstraint" {
            $local:Props.RuleType = "PropertyConstraint"
            $local:Constraints = @{}
            if ($PSBoundParameters.ContainsKey("NameFilter")) { $local:Constraints.NameFilter = $NameFilter }
            if ($PSBoundParameters.ContainsKey("GroupFilter")) { $local:Constraints.GroupFilter = $GroupFilter }
            if ($PSBoundParameters.ContainsKey("UidFilter")) { $local:Constraints.UidFilter = $UidFilter }
            if ($PSBoundParameters.ContainsKey("RidFilter")) { $local:Constraints.RidFilter = $RidFilter }
            if ($PSBoundParameters.ContainsKey("GidFilter")) { $local:Constraints.GidFilter = $GidFilter }
            if ($PSBoundParameters.ContainsKey("PrimaryGidFilter")) { $local:Constraints.PrimaryGidFilter = $PrimaryGidFilter }
            $local:Props.PropertyConstraintProperties = $local:Constraints
        }
    }

    if ($PSBoundParameters.ContainsKey("SearchBase")) { $local:Props.SearchBase = $SearchBase }
    if ($PSBoundParameters.ContainsKey("SearchScope")) { $local:Props.SearchScope = $SearchScope }

    $local:Rule.DirectoryAccountDiscoveryProperties = $local:Props
    $local:Rule
}

<#
.SYNOPSIS
Create a new SPS account discovery rule object for use with Add-SafeguardAccountDiscoveryRule.

.DESCRIPTION
Create a hashtable representing an SPS (Safeguard for Privileged Sessions) account discovery
rule. Use -FindAll to discover all accounts, or specify filter parameters for PropertyConstraint
mode. The resulting object can be passed to Add-SafeguardAccountDiscoveryRule -RuleObject.

.PARAMETER Name
A string containing the name for the discovery rule.

.PARAMETER FindAll
Discover all SPS accounts without filtering.

.PARAMETER AutoManageDiscoveredAccounts
Whether discovered accounts matching this rule should be automatically brought under management.

.PARAMETER NameFilter
A regular expression to filter account names.

.PARAMETER GroupFilter
A regular expression to filter account group names.

.EXAMPLE
New-SafeguardAccountDiscoveryRuleSps -Name "All SPS Accounts" -FindAll

.EXAMPLE
New-SafeguardAccountDiscoveryRuleSps -Name "Admin Accounts" -NameFilter "^admin"
#>
function New-SafeguardAccountDiscoveryRuleSps
{
    [CmdletBinding(DefaultParameterSetName="PropertyConstraint")]
    [OutputType([hashtable])]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Name,
        [Parameter(ParameterSetName="FindAll",Mandatory=$true)]
        [switch]$FindAll,
        [Parameter(Mandatory=$false)]
        [switch]$AutoManageDiscoveredAccounts,
        [Parameter(ParameterSetName="PropertyConstraint",Mandatory=$false)]
        [string]$NameFilter,
        [Parameter(ParameterSetName="PropertyConstraint",Mandatory=$false)]
        [string]$GroupFilter
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Rule = @{
        "Name" = $Name;
        "AutoManageDiscoveredAccounts" = [bool]$AutoManageDiscoveredAccounts;
    }

    if ($FindAll)
    {
        $local:Rule.SpsAccountDiscoveryProperties = @{ "RuleType" = "FindAll" }
    }
    else
    {
        $local:Constraints = @{}
        if ($PSBoundParameters.ContainsKey("NameFilter")) { $local:Constraints.NameFilter = $NameFilter }
        if ($PSBoundParameters.ContainsKey("GroupFilter")) { $local:Constraints.GroupFilter = $GroupFilter }
        $local:Rule.SpsAccountDiscoveryProperties = @{
            "RuleType" = "PropertyConstraint";
            "PropertyConstraintProperties" = $local:Constraints;
        }
    }

    $local:Rule
}

<#
.SYNOPSIS
Create a new Starling Connect account discovery rule object for use with Add-SafeguardAccountDiscoveryRule.

.DESCRIPTION
Create a hashtable representing a Starling Connect account discovery rule. Use -FindAll to
discover all accounts, or specify filter parameters for PropertyConstraint mode.
The resulting object can be passed to Add-SafeguardAccountDiscoveryRule -RuleObject.

.PARAMETER Name
A string containing the name for the discovery rule.

.PARAMETER FindAll
Discover all Starling Connect accounts without filtering.

.PARAMETER AutoManageDiscoveredAccounts
Whether discovered accounts matching this rule should be automatically brought under management.

.PARAMETER NameFilter
A regular expression to filter account names.

.PARAMETER GroupFilter
A regular expression to filter account group names.

.PARAMETER RoleFilter
A regular expression to filter account roles.

.EXAMPLE
New-SafeguardAccountDiscoveryRuleStarlingConnect -Name "All Starling" -FindAll

.EXAMPLE
New-SafeguardAccountDiscoveryRuleStarlingConnect -Name "By Role" -RoleFilter "admin"
#>
function New-SafeguardAccountDiscoveryRuleStarlingConnect
{
    [CmdletBinding(DefaultParameterSetName="PropertyConstraint")]
    [OutputType([hashtable])]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Name,
        [Parameter(ParameterSetName="FindAll",Mandatory=$true)]
        [switch]$FindAll,
        [Parameter(Mandatory=$false)]
        [switch]$AutoManageDiscoveredAccounts,
        [Parameter(ParameterSetName="PropertyConstraint",Mandatory=$false)]
        [string]$NameFilter,
        [Parameter(ParameterSetName="PropertyConstraint",Mandatory=$false)]
        [string]$GroupFilter,
        [Parameter(ParameterSetName="PropertyConstraint",Mandatory=$false)]
        [string]$RoleFilter
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Rule = @{
        "Name" = $Name;
        "AutoManageDiscoveredAccounts" = [bool]$AutoManageDiscoveredAccounts;
    }

    if ($FindAll)
    {
        $local:Rule.StarlingConnectAccountDiscoveryProperties = @{ "RuleType" = "FindAll" }
    }
    else
    {
        $local:Constraints = @{}
        if ($PSBoundParameters.ContainsKey("NameFilter")) { $local:Constraints.NameFilter = $NameFilter }
        if ($PSBoundParameters.ContainsKey("GroupFilter")) { $local:Constraints.GroupFilter = $GroupFilter }
        if ($PSBoundParameters.ContainsKey("RoleFilter")) { $local:Constraints.RoleFilter = $RoleFilter }
        $local:Rule.StarlingConnectAccountDiscoveryProperties = @{
            "RuleType" = "PropertyConstraint";
            "PropertyConstraintProperties" = $local:Constraints;
        }
    }

    $local:Rule
}

<#
.SYNOPSIS
Create a new role-based account discovery rule object for use with Add-SafeguardAccountDiscoveryRule.

.DESCRIPTION
Create a hashtable representing a role-based account discovery rule. Use -FindAll to
discover all accounts, or specify filter parameters for PropertyConstraint mode.
The resulting object can be passed to Add-SafeguardAccountDiscoveryRule -RuleObject.

.PARAMETER Name
A string containing the name for the discovery rule.

.PARAMETER FindAll
Discover all role-based accounts without filtering.

.PARAMETER AutoManageDiscoveredAccounts
Whether discovered accounts matching this rule should be automatically brought under management.

.PARAMETER NameFilter
A regular expression to filter account names.

.PARAMETER RoleFilter
A regular expression to filter account roles.

.PARAMETER PermissionFilter
A regular expression to filter account permissions.

.EXAMPLE
New-SafeguardAccountDiscoveryRuleRoleBased -Name "All Role Based" -FindAll

.EXAMPLE
New-SafeguardAccountDiscoveryRuleRoleBased -Name "DBAs" -RoleFilter "db_owner"

.EXAMPLE
New-SafeguardAccountDiscoveryRuleRoleBased -Name "Write Access" -PermissionFilter "INSERT|UPDATE|DELETE"
#>
function New-SafeguardAccountDiscoveryRuleRoleBased
{
    [CmdletBinding(DefaultParameterSetName="PropertyConstraint")]
    [OutputType([hashtable])]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Name,
        [Parameter(ParameterSetName="FindAll",Mandatory=$true)]
        [switch]$FindAll,
        [Parameter(Mandatory=$false)]
        [switch]$AutoManageDiscoveredAccounts,
        [Parameter(ParameterSetName="PropertyConstraint",Mandatory=$false)]
        [string]$NameFilter,
        [Parameter(ParameterSetName="PropertyConstraint",Mandatory=$false)]
        [string]$RoleFilter,
        [Parameter(ParameterSetName="PropertyConstraint",Mandatory=$false)]
        [string]$PermissionFilter
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Rule = @{
        "Name" = $Name;
        "AutoManageDiscoveredAccounts" = [bool]$AutoManageDiscoveredAccounts;
    }

    if ($FindAll)
    {
        $local:Rule.RoleBasedAccountDiscoveryProperties = @{ "RuleType" = "FindAll" }
    }
    else
    {
        $local:Constraints = @{}
        if ($PSBoundParameters.ContainsKey("NameFilter")) { $local:Constraints.NameFilter = $NameFilter }
        if ($PSBoundParameters.ContainsKey("RoleFilter")) { $local:Constraints.RoleFilter = $RoleFilter }
        if ($PSBoundParameters.ContainsKey("PermissionFilter")) { $local:Constraints.PermissionFilter = $PermissionFilter }
        $local:Rule.RoleBasedAccountDiscoveryProperties = @{
            "RuleType" = "PropertyConstraint";
            "PropertyConstraintProperties" = $local:Constraints;
        }
    }

    $local:Rule
}
