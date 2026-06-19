<# Copyright (c) 2026 One Identity LLC. All rights reserved. #>
# Helpers
function Resolve-SafeguardSshKeyProfileItemId
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
        [Parameter(Mandatory=$true)]
        [ValidateSet("CheckSchedule", "ChangeSchedule", "DiscoverySchedule", "Profile", IgnoreCase=$true)]
        [string]$ItemType,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$Item
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    switch ($ItemType)
    {
        "checkschedule" { $local:ResourceName = "SshKeyCheckSchedules"; $local:ErrorResource = "SSH key check schedule"; break }
        "changeschedule" { $local:ResourceName = "SshKeyChangeSchedules"; $local:ErrorResource = "SSH key change schedule"; break }
        "discoveryschedule" { $local:ResourceName = "SshKeyDiscoverySchedules"; $local:ErrorResource = "SSH key discovery schedule"; break }
        "profile" { $local:ResourceName = "SshKeyProfiles"; $local:ErrorResource = "SSH key profile"; break }
    }

    if ($Item.Id -as [int])
    {
        $Item = $Item.Id
    }

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                             -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId)
    if ($AssetPartitionId)
    {
        $local:RelPath = "AssetPartitions/$AssetPartitionId/$($local:ResourceName)"
        $local:ErrMsgSuffix = " in asset partition (Id=$AssetPartitionId)"
    }
    else
    {
        $local:RelPath = "AssetPartitions/$($local:ResourceName)"
        $local:ErrMsgSuffix = ""
    }

    if (-not ($Item -as [int]))
    {
        try
        {
            $local:ItemList = @(Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" `
                                   -Parameters @{ filter = "Name ieq '$Item'"; fields = "Id" })
        }
        catch
        {
            Write-Verbose $_
            Write-Verbose "Caught exception with ieq filter, trying with q parameter"
            $local:ItemList = @(Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" `
                                   -Parameters @{ q = $Item; fields = "Id" })
        }
        if (-not $local:ItemList)
        {
            throw "Unable to find $($local:ErrorResource) matching '$Item'$($local:ErrMsgSuffix)"
        }
        if ($local:ItemList.Count -ne 1)
        {
            throw "Found $($local:ItemList.Count) $($local:ErrorResource)s matching '$Item'$($local:ErrMsgSuffix)"
        }
        $local:ItemList[0].Id
    }
    else
    {
        if ($AssetPartitionId)
        {
            # Make sure it actually exists
            $local:ItemList = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" `
                                   -Parameters @{ filter = "Id eq $Item and AssetPartitionId eq $AssetPartitionId"; fields = "Id" })
            if (-not $local:ItemList)
            {
                throw "Unable to find $($local:ErrorResource) matching '$Item'$($local:ErrMsgSuffix)"
            }
        }
        $Item
    }
}
function Resolve-SafeguardSshKeyCheckScheduleId
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
        [object]$SshKeyCheckSchedule
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Resolve-SafeguardSshKeyProfileItemId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
        -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -ItemType "CheckSchedule" -Item $SshKeyCheckSchedule
}
function Resolve-SafeguardSshKeyChangeScheduleId
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
        [object]$SshKeyChangeSchedule
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Resolve-SafeguardSshKeyProfileItemId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
        -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -ItemType "ChangeSchedule" -Item $SshKeyChangeSchedule
}
function Resolve-SafeguardSshKeyDiscoveryScheduleId
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
        [object]$SshKeyDiscoverySchedule
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Resolve-SafeguardSshKeyProfileItemId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
        -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -ItemType "DiscoverySchedule" -Item $SshKeyDiscoverySchedule
}
function Resolve-SafeguardSshKeyProfileId
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
        [object]$SshKeyProfile
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Resolve-SafeguardSshKeyProfileItemId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
        -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -ItemType "Profile" -Item $SshKeyProfile
}
function Get-SafeguardSshKeyProfileItem
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
        [Parameter(Mandatory=$true)]
        [ValidateSet("CheckSchedule", "ChangeSchedule", "DiscoverySchedule", "Profile", IgnoreCase=$true)]
        [string]$ItemType,
        [Parameter(Mandatory=$false,Position=0)]
        [object]$ItemToGet,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    switch ($ItemType)
    {
        "checkschedule" { $local:ResourceName = "SshKeyCheckSchedules"; break }
        "changeschedule" { $local:ResourceName = "SshKeyChangeSchedules"; break }
        "discoveryschedule" { $local:ResourceName = "SshKeyDiscoverySchedules"; break }
        "profile" { $local:ResourceName = "SshKeyProfiles"; break }
    }

    $local:Parameters = $null
    if ($Fields)
    {
        $local:Parameters = @{ fields = ($Fields -join ",")}
    }

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                            -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId)

    if ($AssetPartitionId)
    {
        $local:RelPath = "AssetPartitions/$AssetPartitionId/$($local:ResourceName)"
    }
    else
    {
        $local:RelPath = "AssetPartitions/$($local:ResourceName)"
    }

    if ($ItemToGet)
    {
        $local:ItemId = (Resolve-SafeguardSshKeyProfileItemId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                                -AssetPartitionId $AssetPartitionId -ItemType $ItemType $ItemToGet)
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
            Core GET "$($local:RelPath)/$($local:ItemId)" -Parameters $local:Parameters
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
            Core GET "$($local:RelPath)" -Parameters $local:Parameters
    }
}
function Remove-SafeguardSshKeyProfileItem
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
        [Parameter(Mandatory=$true)]
        [ValidateSet("CheckSchedule", "ChangeSchedule", "DiscoverySchedule", "Profile", IgnoreCase=$true)]
        [string]$ItemType,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$ItemToDelete
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    switch ($ItemType)
    {
        "checkschedule" { $local:ResourceName = "SshKeyCheckSchedules"; break }
        "changeschedule" { $local:ResourceName = "SshKeyChangeSchedules"; break }
        "discoveryschedule" { $local:ResourceName = "SshKeyDiscoverySchedules"; break }
        "profile" { $local:ResourceName = "SshKeyProfiles"; break }
    }

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                            -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -UseDefault)

    $local:RelPath = "AssetPartitions/$AssetPartitionId/$($local:ResourceName)"

    $local:ItemId = (Resolve-SafeguardSshKeyProfileItemId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                       -AssetPartitionId $AssetPartitionId -ItemType $ItemType -Item $ItemToDelete)

    Invoke-SafeguardMethod -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure Core DELETE "$($local:RelPath)/$($local:ItemId)"
}
function Rename-SafeguardSshKeyProfileItem
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
        [Parameter(Mandatory=$true)]
        [ValidateSet("CheckSchedule", "ChangeSchedule", "DiscoverySchedule", "Profile", IgnoreCase=$true)]
        [string]$ItemType,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$ItemToEdit,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$NewName
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    switch ($ItemType)
    {
        "checkschedule" { $local:ResourceName = "SshKeyCheckSchedules"; break }
        "changeschedule" { $local:ResourceName = "SshKeyChangeSchedules"; break }
        "discoveryschedule" { $local:ResourceName = "SshKeyDiscoverySchedules"; break }
        "profile" { $local:ResourceName = "SshKeyProfiles"; break }
    }

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                            -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -UseDefault)

    $local:RelPath = "AssetPartitions/$AssetPartitionId/$($local:ResourceName)"

    $local:Item = (Get-SafeguardSshKeyProfileItem -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                       -AssetPartitionId $AssetPartitionId -ItemType $ItemType -ItemToGet $ItemToEdit)

    $local:Item.Name = $NewName

    Invoke-SafeguardMethod -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure Core PUT "$($local:RelPath)/$($local:Item.Id)" -Body $local:Item
}
function Copy-SafeguardSshKeyProfileItem
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
        [Parameter(Mandatory=$true)]
        [ValidateSet("CheckSchedule", "ChangeSchedule", "DiscoverySchedule", "Profile", IgnoreCase=$true)]
        [string]$ItemType,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$ItemToCopy,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$CopyName
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    switch ($ItemType)
    {
        "checkschedule" { $local:ResourceName = "SshKeyCheckSchedules"; break }
        "changeschedule" { $local:ResourceName = "SshKeyChangeSchedules"; break }
        "discoveryschedule" { $local:ResourceName = "SshKeyDiscoverySchedules"; break }
        "profile" { $local:ResourceName = "SshKeyProfiles"; break }
    }

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                            -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -UseDefault)

    $local:RelPath = "AssetPartitions/$AssetPartitionId/$($local:ResourceName)"

    $local:Item = (Get-SafeguardSshKeyProfileItem -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                       -AssetPartitionId $AssetPartitionId -ItemType $ItemType -ItemToGet $ItemToCopy)

    $local:Item.Id = 0 # <== gets ignored for POST
    $local:Item.Name = $CopyName

    Invoke-SafeguardMethod -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure Core POST "$($local:RelPath)" -Body $local:Item
}


# SSH key check schedules

<#
.SYNOPSIS
Get SSH key check schedules in Safeguard via the Web API.

.DESCRIPTION
Get one or all SSH key check schedules that can be associated to an SSH key profile
which can be assigned to partitions, assets, and accounts.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to get SSH key check schedules from.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to get SSH key check schedules from.
(If specified, this will override the AssetPartition parameter)

.PARAMETER CheckScheduleToGet
An integer containing the ID of the SSH key check schedule to get or a string containing the name.

.PARAMETER Fields
An array of the SSH key check schedule property names to return.

.EXAMPLE
Get-SafeguardSshKeyCheckSchedule

.EXAMPLE
Get-SafeguardSshKeyCheckSchedule -AssetPartition "Unix Servers" "Daily Check"
#>
function Get-SafeguardSshKeyCheckSchedule
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
        [object]$CheckScheduleToGet,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Get-SafeguardSshKeyProfileItem -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
        -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -ItemType "CheckSchedule" -ItemToGet $CheckScheduleToGet -Fields $Fields
}

<#
.SYNOPSIS
Create a new SSH key check schedule in Safeguard via the Web API.

.DESCRIPTION
Create a new SSH key check schedule that can be associated to an SSH key profile
which can be assigned to partitions, assets, and accounts.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to create the SSH key check schedule in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to create the SSH key check schedule in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER Name
A string containing the name for the new SSH key check schedule.

.PARAMETER Description
A string containing the description for the new SSH key check schedule.

.PARAMETER ChangeSshKeyOnMismatch
Whether to change the SSH key if a key mismatch is found (does not apply to manual check tasks).

.PARAMETER NotifyOwnersOnMismatch
Whether to notify delegated owners if a key mismatch is found (does not apply to manual check tasks).

.PARAMETER Schedule
A Safeguard schedule object of when to run SSH key checks, see New-SafeguardSchedule and associated cmdlets.

.EXAMPLE
New-SafeguardSshKeyCheckSchedule "Daily Check at Noon" -Schedule (New-SafeguardScheduleDaily -StartTime "12:00")
#>
function New-SafeguardSshKeyCheckSchedule
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
        [Parameter(Mandatory=$false)]
        [switch]$ChangeSshKeyOnMismatch,
        [Parameter(Mandatory=$false)]
        [switch]$NotifyOwnersOnMismatch,
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
        "Description" = $Description;
        "ResetSshKeyOnMismatch" = [bool]$ChangeSshKeyOnMismatch;
        "NotifyOwnersOnMismatch" = [bool]$NotifyOwnersOnMismatch;
    }

    if ($Schedule)
    {
        Import-Module -Name "$PSScriptRoot\schedules.psm1" -Scope Local
        $local:Body = (Copy-ScheduleToDto -Schedule $Schedule -Dto $local:Body)
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
        POST "AssetPartitions/$($local:AssetPartitionId)/SshKeyCheckSchedules" -Body $local:Body
}

<#
.SYNOPSIS
Edit an existing SSH key check schedule in Safeguard via the Web API.

.DESCRIPTION
Edit an existing SSH key check schedule that can be associated to an SSH key profile
which can be assigned to partitions, assets, and accounts.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to edit the SSH key check schedule in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to edit the SSH key check schedule in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER CheckScheduleToEdit
An integer containing the ID of the SSH key check schedule to edit or a string containing the name.

.PARAMETER Description
A string containing the description for the SSH key check schedule.

.PARAMETER ChangeSshKeyOnMismatch
Whether to change the SSH key if a key mismatch is found (does not apply to manual check tasks).

.PARAMETER NotifyOwnersOnMismatch
Whether to notify delegated owners if a key mismatch is found (does not apply to manual check tasks).

.PARAMETER Schedule
A Safeguard schedule object of when to run SSH key checks, see New-SafeguardSchedule and associated cmdlets.

.PARAMETER ScheduleObject
An object representing an SSH key check schedule to be used to update an existing schedule.

.EXAMPLE
Edit-SafeguardSshKeyCheckSchedule "Daily Check at Noon" -ChangeSshKeyOnMismatch -Schedule (New-SafeguardScheduleDaily -StartTime "12:00")
#>
function Edit-SafeguardSshKeyCheckSchedule
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
        [Parameter(ParameterSetName="Attributes",Mandatory=$false,Position=0)]
        [object]$CheckScheduleToEdit,
        [Parameter(Mandatory=$false)]
        [string]$Description,
        [Parameter(Mandatory=$false)]
        [switch]$ChangeSshKeyOnMismatch,
        [Parameter(Mandatory=$false)]
        [switch]$NotifyOwnersOnMismatch,
        [Parameter(Mandatory=$false)]
        [HashTable]$Schedule,
        [Parameter(ParameterSetName="Object",Mandatory=$true,ValueFromPipeline=$true)]
        [object]$ScheduleObject
    )

    begin
    {
        if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
        if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    }

    process
    {
        if ($PsCmdlet.ParameterSetName -eq "Object")
        {
            if (-not $ScheduleObject) { throw "ScheduleObject must not be null" }
            Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                PUT "AssetPartitions/$($ScheduleObject.AssetPartitionId)/SshKeyCheckSchedules/$($ScheduleObject.Id)" -Body $ScheduleObject
            return
        }

        $local:CheckObj = (Get-SafeguardSshKeyCheckSchedule -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                               -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId $CheckScheduleToEdit)

        if ($PSBoundParameters.ContainsKey("Description")) { $local:CheckObj.Description = $Description }
        if ($PSBoundParameters.ContainsKey("ChangeSshKeyOnMismatch")) { $local:CheckObj.ResetSshKeyOnMismatch = [bool]$ChangeSshKeyOnMismatch }
        if ($PSBoundParameters.ContainsKey("NotifyOwnersOnMismatch")) { $local:CheckObj.NotifyOwnersOnMismatch = [bool]$NotifyOwnersOnMismatch }
        if ($PSBoundParameters.ContainsKey("Schedule"))
        {
            Import-Module -Name "$PSScriptRoot\schedules.psm1" -Scope Local
            $local:CheckObj = (Copy-ScheduleToDto -Schedule $Schedule -Dto $local:CheckObj)
        }

        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            PUT "AssetPartitions/$($local:CheckObj.AssetPartitionId)/SshKeyCheckSchedules/$($local:CheckObj.Id)" -Body $local:CheckObj
    }
}

<#
.SYNOPSIS
Delete an SSH key check schedule from Safeguard via the Web API.

.DESCRIPTION
Delete an SSH key check schedule. It must not be associated with an SSH key profile
in order to be able to delete it.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to delete the SSH key check schedule from.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to delete the SSH key check schedule from.
(If specified, this will override the AssetPartition parameter)

.PARAMETER CheckScheduleToDelete
An integer containing the ID of the SSH key check schedule to delete or a string containing the name.

.EXAMPLE
Remove-SafeguardSshKeyCheckSchedule "Old Schedule"
#>
function Remove-SafeguardSshKeyCheckSchedule
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
        [object]$CheckScheduleToDelete
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Remove-SafeguardSshKeyProfileItem -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
        -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -ItemType "CheckSchedule" -ItemToDelete $CheckScheduleToDelete
}

<#
.SYNOPSIS
Rename an SSH key check schedule in Safeguard via the Web API.

.DESCRIPTION
Rename an existing SSH key check schedule.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
that contains the SSH key check schedule.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID that contains the SSH key check schedule.
(If specified, this will override the AssetPartition parameter)

.PARAMETER CheckScheduleToEdit
An integer containing the ID of the SSH key check schedule to rename or a string containing the name.

.PARAMETER NewName
A string containing the new name for the SSH key check schedule.

.EXAMPLE
Rename-SafeguardSshKeyCheckSchedule "Old Name" "New Name"
#>
function Rename-SafeguardSshKeyCheckSchedule
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
        [object]$CheckScheduleToEdit,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$NewName
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Rename-SafeguardSshKeyProfileItem -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
        -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -ItemType "CheckSchedule" -ItemToEdit $CheckScheduleToEdit -NewName $NewName
}

<#
.SYNOPSIS
Copy an SSH key check schedule in Safeguard via the Web API.

.DESCRIPTION
Create a new SSH key check schedule by copying the settings of an existing one.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
that contains the SSH key check schedule.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID that contains the SSH key check schedule.
(If specified, this will override the AssetPartition parameter)

.PARAMETER CheckScheduleToCopy
An integer containing the ID of the SSH key check schedule to copy or a string containing the name.

.PARAMETER CopyName
A string containing the name for the new copy of the SSH key check schedule.

.EXAMPLE
Copy-SafeguardSshKeyCheckSchedule "Daily Check" "Daily Check Copy"
#>
function Copy-SafeguardSshKeyCheckSchedule
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
        [object]$CheckScheduleToCopy,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$CopyName
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Copy-SafeguardSshKeyProfileItem -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
        -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -ItemType "CheckSchedule" -ItemToCopy $CheckScheduleToCopy -CopyName $CopyName
}


# SSH key change schedules

<#
.SYNOPSIS
Get SSH key change schedules in Safeguard via the Web API.

.DESCRIPTION
Get one or all SSH key change schedules that can be associated to an SSH key profile
which can be assigned to partitions, assets, and accounts.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to get SSH key change schedules from.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to get SSH key change schedules from.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ChangeScheduleToGet
An integer containing the ID of the SSH key change schedule to get or a string containing the name.

.PARAMETER Fields
An array of the SSH key change schedule property names to return.

.EXAMPLE
Get-SafeguardSshKeyChangeSchedule

.EXAMPLE
Get-SafeguardSshKeyChangeSchedule -AssetPartition "Unix Servers" "Daily Change"
#>
function Get-SafeguardSshKeyChangeSchedule
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
        [object]$ChangeScheduleToGet,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Get-SafeguardSshKeyProfileItem -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
        -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -ItemType "ChangeSchedule" -ItemToGet $ChangeScheduleToGet -Fields $Fields
}

<#
.SYNOPSIS
Create a new SSH key change schedule in Safeguard via the Web API.

.DESCRIPTION
Create a new SSH key change schedule that can be associated to an SSH key profile
which can be assigned to partitions, assets, and accounts.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to create the SSH key change schedule in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to create the SSH key change schedule in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER Name
A string containing the name for the new SSH key change schedule.

.PARAMETER Description
A string containing the description for the new SSH key change schedule.

.PARAMETER ChangeSshKeyIfInUse
Whether or not to change the SSH key even if it is currently checked out.

.PARAMETER SuspendAccountWhenCheckedIn
Whether to disable the account when the SSH key is not checked out. (limited platform support)

.PARAMETER ChangeSshKeysManually
Whether or not to require asset administrators to change SSH keys manually.

.PARAMETER RescheduleForUnscheduledUpdate
Whether to reschedule the change schedule when an unscheduled SSH key update occurs.

.PARAMETER GeneratedKeyType
The type of SSH key to generate when changing keys. (Rsa, Dsa, Ed25519, Ecdsa)

.PARAMETER GeneratedKeyLength
The length in bits of the SSH key to generate when changing keys.

.PARAMETER GeneratedKeyComment
A string containing the comment to associate with generated SSH keys.

.PARAMETER Schedule
A Safeguard schedule object of when to run SSH key changes, see New-SafeguardSchedule and associated cmdlets.

.EXAMPLE
New-SafeguardSshKeyChangeSchedule "Daily Change at Noon" -GeneratedKeyType Rsa -GeneratedKeyLength 2048 -Schedule (New-SafeguardScheduleDaily -StartTime "12:00")
#>
function New-SafeguardSshKeyChangeSchedule
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
        [Parameter(Mandatory=$false)]
        [switch]$ChangeSshKeyIfInUse,
        [Parameter(Mandatory=$false)]
        [switch]$SuspendAccountWhenCheckedIn,
        [Parameter(Mandatory=$false)]
        [switch]$ChangeSshKeysManually,
        [Parameter(Mandatory=$false)]
        [switch]$RescheduleForUnscheduledUpdate,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Rsa", "Dsa", "Ed25519", "Ecdsa", IgnoreCase=$true)]
        [string]$GeneratedKeyType,
        [Parameter(Mandatory=$false)]
        [int]$GeneratedKeyLength,
        [Parameter(Mandatory=$false)]
        [string]$GeneratedKeyComment,
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
        "Description" = $Description;
        "AllowSshKeyChangeWhenReleased" = [bool]$ChangeSshKeyIfInUse;
        "SuspendAccountWhenCheckedIn" = [bool]$SuspendAccountWhenCheckedIn;
        "NotifyOwnersOnly" = [bool]$ChangeSshKeysManually;
        "RescheduleForUnscheduledSshKeyUpdate" = [bool]$RescheduleForUnscheduledUpdate;
    }
    if ($PSBoundParameters.ContainsKey("GeneratedKeyType")) { $local:Body.GeneratedKeyType = $GeneratedKeyType }
    if ($PSBoundParameters.ContainsKey("GeneratedKeyLength")) { $local:Body.GeneratedKeyLength = $GeneratedKeyLength }
    if ($PSBoundParameters.ContainsKey("GeneratedKeyComment")) { $local:Body.GeneratedKeyComment = $GeneratedKeyComment }

    if ($Schedule)
    {
        Import-Module -Name "$PSScriptRoot\schedules.psm1" -Scope Local
        $local:Body = (Copy-ScheduleToDto -Schedule $Schedule -Dto $local:Body)
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
        POST "AssetPartitions/$($local:AssetPartitionId)/SshKeyChangeSchedules" -Body $local:Body
}

<#
.SYNOPSIS
Edit an existing SSH key change schedule in Safeguard via the Web API.

.DESCRIPTION
Edit an existing SSH key change schedule that can be associated to an SSH key profile
which can be assigned to partitions, assets, and accounts.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to edit the SSH key change schedule in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to edit the SSH key change schedule in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ChangeScheduleToEdit
An integer containing the ID of the SSH key change schedule to edit or a string containing the name.

.PARAMETER Description
A string containing the description for the SSH key change schedule.

.PARAMETER ChangeSshKeyIfInUse
Whether or not to change the SSH key even if it is currently checked out.

.PARAMETER SuspendAccountWhenCheckedIn
Whether to disable the account when the SSH key is not checked out. (limited platform support)

.PARAMETER ChangeSshKeysManually
Whether or not to require asset administrators to change SSH keys manually.

.PARAMETER RescheduleForUnscheduledUpdate
Whether to reschedule the change schedule when an unscheduled SSH key update occurs.

.PARAMETER GeneratedKeyType
The type of SSH key to generate when changing keys. (Rsa, Dsa, Ed25519, Ecdsa)

.PARAMETER GeneratedKeyLength
The length in bits of the SSH key to generate when changing keys.

.PARAMETER GeneratedKeyComment
A string containing the comment to associate with generated SSH keys.

.PARAMETER Schedule
A Safeguard schedule object of when to run SSH key changes, see New-SafeguardSchedule and associated cmdlets.

.PARAMETER ScheduleObject
An object representing an SSH key change schedule to be used to update an existing schedule.

.EXAMPLE
Edit-SafeguardSshKeyChangeSchedule "Daily Change at Noon" -Schedule (New-SafeguardScheduleDaily -StartTime "12:00") -ChangeSshKeysManually
#>
function Edit-SafeguardSshKeyChangeSchedule
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
        [Parameter(ParameterSetName="Attributes",Mandatory=$false,Position=0)]
        [object]$ChangeScheduleToEdit,
        [Parameter(Mandatory=$false)]
        [string]$Description,
        [Parameter(Mandatory=$false)]
        [switch]$ChangeSshKeyIfInUse,
        [Parameter(Mandatory=$false)]
        [switch]$SuspendAccountWhenCheckedIn,
        [Parameter(Mandatory=$false)]
        [switch]$ChangeSshKeysManually,
        [Parameter(Mandatory=$false)]
        [switch]$RescheduleForUnscheduledUpdate,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Rsa", "Dsa", "Ed25519", "Ecdsa", IgnoreCase=$true)]
        [string]$GeneratedKeyType,
        [Parameter(Mandatory=$false)]
        [int]$GeneratedKeyLength,
        [Parameter(Mandatory=$false)]
        [string]$GeneratedKeyComment,
        [Parameter(Mandatory=$false)]
        [HashTable]$Schedule,
        [Parameter(ParameterSetName="Object",Mandatory=$true,ValueFromPipeline=$true)]
        [object]$ScheduleObject
    )

    begin
    {
        if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
        if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    }

    process
    {
        if ($PsCmdlet.ParameterSetName -eq "Object")
        {
            if (-not $ScheduleObject) { throw "ScheduleObject must not be null" }
            Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                PUT "AssetPartitions/$($ScheduleObject.AssetPartitionId)/SshKeyChangeSchedules/$($ScheduleObject.Id)" -Body $ScheduleObject
            return
        }

        $local:ChangeObj = (Get-SafeguardSshKeyChangeSchedule -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                                -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId $ChangeScheduleToEdit)

        if ($PSBoundParameters.ContainsKey("Description")) { $local:ChangeObj.Description = $Description }
        if ($PSBoundParameters.ContainsKey("ChangeSshKeyIfInUse")) { $local:ChangeObj.AllowSshKeyChangeWhenReleased = [bool]$ChangeSshKeyIfInUse }
        if ($PSBoundParameters.ContainsKey("SuspendAccountWhenCheckedIn")) { $local:ChangeObj.SuspendAccountWhenCheckedIn = [bool]$SuspendAccountWhenCheckedIn }
        if ($PSBoundParameters.ContainsKey("ChangeSshKeysManually")) { $local:ChangeObj.NotifyOwnersOnly = [bool]$ChangeSshKeysManually }
        if ($PSBoundParameters.ContainsKey("RescheduleForUnscheduledUpdate")) { $local:ChangeObj.RescheduleForUnscheduledSshKeyUpdate = [bool]$RescheduleForUnscheduledUpdate }
        if ($PSBoundParameters.ContainsKey("GeneratedKeyType")) { $local:ChangeObj.GeneratedKeyType = $GeneratedKeyType }
        if ($PSBoundParameters.ContainsKey("GeneratedKeyLength")) { $local:ChangeObj.GeneratedKeyLength = $GeneratedKeyLength }
        if ($PSBoundParameters.ContainsKey("GeneratedKeyComment")) { $local:ChangeObj.GeneratedKeyComment = $GeneratedKeyComment }
        if ($PSBoundParameters.ContainsKey("Schedule"))
        {
            Import-Module -Name "$PSScriptRoot\schedules.psm1" -Scope Local
            $local:ChangeObj = (Copy-ScheduleToDto -Schedule $Schedule -Dto $local:ChangeObj)
        }

        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            PUT "AssetPartitions/$($local:ChangeObj.AssetPartitionId)/SshKeyChangeSchedules/$($local:ChangeObj.Id)" -Body $local:ChangeObj
    }
}

<#
.SYNOPSIS
Delete an SSH key change schedule from Safeguard via the Web API.

.DESCRIPTION
Delete an SSH key change schedule. It must not be associated with an SSH key profile
in order to be able to delete it.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to delete the SSH key change schedule from.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to delete the SSH key change schedule from.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ChangeScheduleToDelete
An integer containing the ID of the SSH key change schedule to delete or a string containing the name.

.EXAMPLE
Remove-SafeguardSshKeyChangeSchedule "Old Schedule"
#>
function Remove-SafeguardSshKeyChangeSchedule
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
        [object]$ChangeScheduleToDelete
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Remove-SafeguardSshKeyProfileItem -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
        -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -ItemType "ChangeSchedule" -ItemToDelete $ChangeScheduleToDelete
}

<#
.SYNOPSIS
Rename an SSH key change schedule in Safeguard via the Web API.

.DESCRIPTION
Rename an existing SSH key change schedule.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
that contains the SSH key change schedule.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID that contains the SSH key change schedule.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ChangeScheduleToEdit
An integer containing the ID of the SSH key change schedule to rename or a string containing the name.

.PARAMETER NewName
A string containing the new name for the SSH key change schedule.

.EXAMPLE
Rename-SafeguardSshKeyChangeSchedule "Old Name" "New Name"
#>
function Rename-SafeguardSshKeyChangeSchedule
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
        [object]$ChangeScheduleToEdit,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$NewName
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Rename-SafeguardSshKeyProfileItem -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
        -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -ItemType "ChangeSchedule" -ItemToEdit $ChangeScheduleToEdit -NewName $NewName
}

<#
.SYNOPSIS
Copy an SSH key change schedule in Safeguard via the Web API.

.DESCRIPTION
Create a new SSH key change schedule by copying the settings of an existing one.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
that contains the SSH key change schedule.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID that contains the SSH key change schedule.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ChangeScheduleToCopy
An integer containing the ID of the SSH key change schedule to copy or a string containing the name.

.PARAMETER CopyName
A string containing the name for the new copy of the SSH key change schedule.

.EXAMPLE
Copy-SafeguardSshKeyChangeSchedule "Daily Change" "Daily Change Copy"
#>
function Copy-SafeguardSshKeyChangeSchedule
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
        [object]$ChangeScheduleToCopy,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$CopyName
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Copy-SafeguardSshKeyProfileItem -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
        -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -ItemType "ChangeSchedule" -ItemToCopy $ChangeScheduleToCopy -CopyName $CopyName
}


# SSH key discovery schedules

<#
.SYNOPSIS
Get SSH key discovery schedules in Safeguard via the Web API.

.DESCRIPTION
Get one or all SSH key discovery schedules that can be associated to an SSH key profile
which can be assigned to partitions, assets, and accounts.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to get SSH key discovery schedules from.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to get SSH key discovery schedules from.
(If specified, this will override the AssetPartition parameter)

.PARAMETER DiscoveryScheduleToGet
An integer containing the ID of the SSH key discovery schedule to get or a string containing the name.

.PARAMETER Fields
An array of the SSH key discovery schedule property names to return.

.EXAMPLE
Get-SafeguardSshKeyDiscoverySchedule

.EXAMPLE
Get-SafeguardSshKeyDiscoverySchedule -AssetPartition "Unix Servers" "Daily Discovery"
#>
function Get-SafeguardSshKeyDiscoverySchedule
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
        [object]$DiscoveryScheduleToGet,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Get-SafeguardSshKeyProfileItem -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
        -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -ItemType "DiscoverySchedule" -ItemToGet $DiscoveryScheduleToGet -Fields $Fields
}

<#
.SYNOPSIS
Create a new SSH key discovery schedule in Safeguard via the Web API.

.DESCRIPTION
Create a new SSH key discovery schedule that can be associated to an SSH key profile
which can be assigned to partitions, assets, and accounts.  A discovery schedule
controls when Safeguard discovers the SSH authorized keys present on managed accounts.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to create the SSH key discovery schedule in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to create the SSH key discovery schedule in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER Name
A string containing the name for the new SSH key discovery schedule.

.PARAMETER Description
A string containing the description for the new SSH key discovery schedule.

.PARAMETER Schedule
A Safeguard schedule object of when to run SSH key discovery, see New-SafeguardSchedule and associated cmdlets.

.EXAMPLE
New-SafeguardSshKeyDiscoverySchedule "Daily Discovery at Noon" -Schedule (New-SafeguardScheduleDaily -StartTime "12:00")
#>
function New-SafeguardSshKeyDiscoverySchedule
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
        "Description" = $Description;
    }

    if ($Schedule)
    {
        Import-Module -Name "$PSScriptRoot\schedules.psm1" -Scope Local
        $local:Body = (Copy-ScheduleToDto -Schedule $Schedule -Dto $local:Body)
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
        POST "AssetPartitions/$($local:AssetPartitionId)/SshKeyDiscoverySchedules" -Body $local:Body
}

<#
.SYNOPSIS
Edit an existing SSH key discovery schedule in Safeguard via the Web API.

.DESCRIPTION
Edit an existing SSH key discovery schedule that can be associated to an SSH key profile
which can be assigned to partitions, assets, and accounts.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to edit the SSH key discovery schedule in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to edit the SSH key discovery schedule in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER DiscoveryScheduleToEdit
An integer containing the ID of the SSH key discovery schedule to edit or a string containing the name.

.PARAMETER Description
A string containing the description for the SSH key discovery schedule.

.PARAMETER Schedule
A Safeguard schedule object of when to run SSH key discovery, see New-SafeguardSchedule and associated cmdlets.

.PARAMETER ScheduleObject
An object representing an SSH key discovery schedule to be used to update an existing schedule.

.EXAMPLE
Edit-SafeguardSshKeyDiscoverySchedule "Daily Discovery at Noon" -Schedule (New-SafeguardScheduleDaily -StartTime "12:00")
#>
function Edit-SafeguardSshKeyDiscoverySchedule
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
        [Parameter(ParameterSetName="Attributes",Mandatory=$false,Position=0)]
        [object]$DiscoveryScheduleToEdit,
        [Parameter(Mandatory=$false)]
        [string]$Description,
        [Parameter(Mandatory=$false)]
        [HashTable]$Schedule,
        [Parameter(ParameterSetName="Object",Mandatory=$true,ValueFromPipeline=$true)]
        [object]$ScheduleObject
    )

    begin
    {
        if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
        if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    }

    process
    {
        if ($PsCmdlet.ParameterSetName -eq "Object")
        {
            if (-not $ScheduleObject) { throw "ScheduleObject must not be null" }
            Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                PUT "AssetPartitions/$($ScheduleObject.AssetPartitionId)/SshKeyDiscoverySchedules/$($ScheduleObject.Id)" -Body $ScheduleObject
            return
        }

        $local:DiscoveryObj = (Get-SafeguardSshKeyDiscoverySchedule -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                                   -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId $DiscoveryScheduleToEdit)

        if ($PSBoundParameters.ContainsKey("Description")) { $local:DiscoveryObj.Description = $Description }
        if ($PSBoundParameters.ContainsKey("Schedule"))
        {
            Import-Module -Name "$PSScriptRoot\schedules.psm1" -Scope Local
            $local:DiscoveryObj = (Copy-ScheduleToDto -Schedule $Schedule -Dto $local:DiscoveryObj)
        }

        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            PUT "AssetPartitions/$($local:DiscoveryObj.AssetPartitionId)/SshKeyDiscoverySchedules/$($local:DiscoveryObj.Id)" -Body $local:DiscoveryObj
    }
}

<#
.SYNOPSIS
Delete an SSH key discovery schedule from Safeguard via the Web API.

.DESCRIPTION
Delete an SSH key discovery schedule. It must not be associated with an SSH key profile
in order to be able to delete it.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to delete the SSH key discovery schedule from.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to delete the SSH key discovery schedule from.
(If specified, this will override the AssetPartition parameter)

.PARAMETER DiscoveryScheduleToDelete
An integer containing the ID of the SSH key discovery schedule to delete or a string containing the name.

.EXAMPLE
Remove-SafeguardSshKeyDiscoverySchedule "Old Schedule"
#>
function Remove-SafeguardSshKeyDiscoverySchedule
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
        [object]$DiscoveryScheduleToDelete
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Remove-SafeguardSshKeyProfileItem -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
        -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -ItemType "DiscoverySchedule" -ItemToDelete $DiscoveryScheduleToDelete
}

<#
.SYNOPSIS
Rename an SSH key discovery schedule in Safeguard via the Web API.

.DESCRIPTION
Rename an existing SSH key discovery schedule.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
that contains the SSH key discovery schedule.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID that contains the SSH key discovery schedule.
(If specified, this will override the AssetPartition parameter)

.PARAMETER DiscoveryScheduleToEdit
An integer containing the ID of the SSH key discovery schedule to rename or a string containing the name.

.PARAMETER NewName
A string containing the new name for the SSH key discovery schedule.

.EXAMPLE
Rename-SafeguardSshKeyDiscoverySchedule "Old Name" "New Name"
#>
function Rename-SafeguardSshKeyDiscoverySchedule
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
        [object]$DiscoveryScheduleToEdit,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$NewName
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Rename-SafeguardSshKeyProfileItem -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
        -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -ItemType "DiscoverySchedule" -ItemToEdit $DiscoveryScheduleToEdit -NewName $NewName
}

<#
.SYNOPSIS
Copy an SSH key discovery schedule in Safeguard via the Web API.

.DESCRIPTION
Create a new SSH key discovery schedule by copying the settings of an existing one.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
that contains the SSH key discovery schedule.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID that contains the SSH key discovery schedule.
(If specified, this will override the AssetPartition parameter)

.PARAMETER DiscoveryScheduleToCopy
An integer containing the ID of the SSH key discovery schedule to copy or a string containing the name.

.PARAMETER CopyName
A string containing the name for the new copy of the SSH key discovery schedule.

.EXAMPLE
Copy-SafeguardSshKeyDiscoverySchedule "Daily Discovery" "Daily Discovery Copy"
#>
function Copy-SafeguardSshKeyDiscoverySchedule
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
        [object]$DiscoveryScheduleToCopy,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$CopyName
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Copy-SafeguardSshKeyProfileItem -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
        -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -ItemType "DiscoverySchedule" -ItemToCopy $DiscoveryScheduleToCopy -CopyName $CopyName
}
