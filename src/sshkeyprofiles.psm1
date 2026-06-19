<# Copyright (c) 2026 One Identity LLC. All rights reserved. #>

# SSH key profiles

<#
.SYNOPSIS
Get SSH key profiles in Safeguard via the Web API.

.DESCRIPTION
Get one or all SSH key profiles that can be assigned to partitions, assets, and accounts.
An SSH key profile bundles an SSH key check schedule, change schedule, and discovery schedule.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to get SSH key profiles from.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to get SSH key profiles from.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ProfileToGet
An integer containing the ID of the SSH key profile to get or a string containing the name.

.PARAMETER Fields
An array of the SSH key profile property names to return.

.EXAMPLE
Get-SafeguardSshKeyProfile

.EXAMPLE
Get-SafeguardSshKeyProfile -AssetPartition "Unix Servers" "Default SSH Key Profile"
#>
function Get-SafeguardSshKeyProfile
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
        [object]$ProfileToGet,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    Import-Module -Name "$PSScriptRoot\sshkeyschedules.psm1" -Scope Local

    Get-SafeguardSshKeyProfileItem -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
        -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -ItemType "Profile" -ItemToGet $ProfileToGet -Fields $Fields
}

<#
.SYNOPSIS
Create a new SSH key profile in Safeguard via the Web API.

.DESCRIPTION
Create a new SSH key profile that can be assigned to partitions, assets, and accounts.
The profile bundles an SSH key check schedule, change schedule, and discovery schedule.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to create the SSH key profile in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to create the SSH key profile in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER Name
A string containing the name for the new SSH key profile.

.PARAMETER Description
A string containing the description for the new SSH key profile.

.PARAMETER CheckScheduleToSet
An integer containing the ID of the SSH key check schedule to set in the profile
or a string containing the name.

.PARAMETER ChangeScheduleToSet
An integer containing the ID of the SSH key change schedule to set in the profile
or a string containing the name.

.PARAMETER DiscoveryScheduleToSet
An integer containing the ID of the SSH key discovery schedule to set in the profile
or a string containing the name.

.EXAMPLE
New-SafeguardSshKeyProfile "Default SSH Key Profile" -CheckScheduleToSet "Daily Check" -ChangeScheduleToSet "Daily Change" -DiscoveryScheduleToSet "Daily Discovery"
#>
function New-SafeguardSshKeyProfile
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
        [Parameter(Mandatory=$false,Position=1)]
        [string]$Description,
        [Parameter(Mandatory=$true)]
        [object]$CheckScheduleToSet,
        [Parameter(Mandatory=$true)]
        [object]$ChangeScheduleToSet,
        [Parameter(Mandatory=$true)]
        [object]$DiscoveryScheduleToSet
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    Import-Module -Name "$PSScriptRoot\sshkeyschedules.psm1" -Scope Local

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                            -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -UseDefault)

    $local:Body = @{
        "Name" = $Name;
        "Description" = $Description
    }

    $local:Body.CheckScheduleId = (Resolve-SafeguardSshKeyCheckScheduleId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                                       -AssetPartitionId $AssetPartitionId -SshKeyCheckSchedule $CheckScheduleToSet)
    $local:Body.ChangeScheduleId = (Resolve-SafeguardSshKeyChangeScheduleId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                                        -AssetPartitionId $AssetPartitionId -SshKeyChangeSchedule $ChangeScheduleToSet)
    $local:Body.DiscoveryScheduleId = (Resolve-SafeguardSshKeyDiscoveryScheduleId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                                           -AssetPartitionId $AssetPartitionId -SshKeyDiscoverySchedule $DiscoveryScheduleToSet)

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
        POST "AssetPartitions/$($local:AssetPartitionId)/SshKeyProfiles" -Body $local:Body
}

<#
.SYNOPSIS
Edit an existing SSH key profile in Safeguard via the Web API.

.DESCRIPTION
Edit an existing SSH key profile to change which check schedule, change schedule,
or discovery schedule it is using.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
that contains the SSH key profile.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID that contains the SSH key profile.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ProfileToEdit
An integer containing the ID of the SSH key profile to edit or a string containing the name.

.PARAMETER Description
A string containing a description for the profile.

.PARAMETER CheckScheduleToSet
An integer containing the ID of the SSH key check schedule to set in the profile
or a string containing the name.

.PARAMETER ChangeScheduleToSet
An integer containing the ID of the SSH key change schedule to set in the profile
or a string containing the name.

.PARAMETER DiscoveryScheduleToSet
An integer containing the ID of the SSH key discovery schedule to set in the profile
or a string containing the name.

.PARAMETER ProfileObject
An object representing an SSH key profile to be used to update an existing profile.

.EXAMPLE
Edit-SafeguardSshKeyProfile "Default SSH Key Profile" -CheckScheduleToSet "Daily Check"

.EXAMPLE
Edit-SafeguardSshKeyProfile -AssetPartition "Unix Servers" -ProfileToEdit "Custom Profile" -DiscoveryScheduleToSet "Daily Discovery"
#>
function Edit-SafeguardSshKeyProfile
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
        [Parameter(ParameterSetName="Attributes",Mandatory=$true,Position=0)]
        [object]$ProfileToEdit,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false,Position=1)]
        [string]$Description,
        [Parameter(Mandatory=$false)]
        [object]$CheckScheduleToSet,
        [Parameter(Mandatory=$false)]
        [object]$ChangeScheduleToSet,
        [Parameter(Mandatory=$false)]
        [object]$DiscoveryScheduleToSet,
        [Parameter(ParameterSetName="Object",Mandatory=$true,ValueFromPipeline=$true)]
        [object]$ProfileObject
    )

    begin
    {
        if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
        if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    }

    process
    {
        Import-Module -Name "$PSScriptRoot\sshkeyschedules.psm1" -Scope Local
        if ($PsCmdlet.ParameterSetName -eq "Object")
        {
            if (-not $ProfileObject) { throw "ProfileObject must not be null" }
            Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                PUT "AssetPartitions/$($ProfileObject.AssetPartitionId)/SshKeyProfiles/$($ProfileObject.Id)" -Body $ProfileObject
            return
        }

        $local:ProfileObj = (Get-SafeguardSshKeyProfile -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                                 -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId $ProfileToEdit)

        if ($PSBoundParameters.ContainsKey("Description")) { $local:ProfileObj.Description = $Description }

        if ($PSBoundParameters.ContainsKey("CheckScheduleToSet"))
        {
            $local:ProfileObj.CheckScheduleId = (Resolve-SafeguardSshKeyCheckScheduleId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                                                     -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -SshKeyCheckSchedule $CheckScheduleToSet)
        }
        if ($PSBoundParameters.ContainsKey("ChangeScheduleToSet"))
        {
            $local:ProfileObj.ChangeScheduleId = (Resolve-SafeguardSshKeyChangeScheduleId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                                                      -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -SshKeyChangeSchedule $ChangeScheduleToSet)
        }
        if ($PSBoundParameters.ContainsKey("DiscoveryScheduleToSet"))
        {
            $local:ProfileObj.DiscoveryScheduleId = (Resolve-SafeguardSshKeyDiscoveryScheduleId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                                                         -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -SshKeyDiscoverySchedule $DiscoveryScheduleToSet)
        }

        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            PUT "AssetPartitions/$($local:ProfileObj.AssetPartitionId)/SshKeyProfiles/$($local:ProfileObj.Id)" -Body $local:ProfileObj
    }
}

<#
.SYNOPSIS
Delete an SSH key profile from Safeguard via the Web API.

.DESCRIPTION
Delete an SSH key profile. It must not be the default SSH key profile of an asset partition
in order to be able to delete it.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to delete the SSH key profile from.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to delete the SSH key profile from.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ProfileToDelete
An integer containing the ID of the SSH key profile to delete or a string containing the name.

.EXAMPLE
Remove-SafeguardSshKeyProfile "Old Profile"
#>
function Remove-SafeguardSshKeyProfile
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
        [object]$ProfileToDelete
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    Import-Module -Name "$PSScriptRoot\sshkeyschedules.psm1" -Scope Local

    Remove-SafeguardSshKeyProfileItem -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
        -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -ItemType "Profile" -ItemToDelete $ProfileToDelete
}

<#
.SYNOPSIS
Rename an SSH key profile in Safeguard via the Web API.

.DESCRIPTION
Rename an existing SSH key profile.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
that contains the SSH key profile.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID that contains the SSH key profile.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ProfileToEdit
An integer containing the ID of the SSH key profile to rename or a string containing the name.

.PARAMETER NewName
A string containing the new name for the SSH key profile.

.EXAMPLE
Rename-SafeguardSshKeyProfile "Old Name" "New Name"
#>
function Rename-SafeguardSshKeyProfile
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
        [object]$ProfileToEdit,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$NewName
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    Import-Module -Name "$PSScriptRoot\sshkeyschedules.psm1" -Scope Local

    Rename-SafeguardSshKeyProfileItem -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
        -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -ItemType "Profile" -ItemToEdit $ProfileToEdit -NewName $NewName
}

<#
.SYNOPSIS
Copy an SSH key profile in Safeguard via the Web API.

.DESCRIPTION
Create a new SSH key profile by copying the settings of an existing one.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
that contains the SSH key profile.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID that contains the SSH key profile.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ProfileToCopy
An integer containing the ID of the SSH key profile to copy or a string containing the name.

.PARAMETER CopyName
A string containing the name for the new copy of the SSH key profile.

.EXAMPLE
Copy-SafeguardSshKeyProfile "Default SSH Key Profile" "Default SSH Key Profile Copy"
#>
function Copy-SafeguardSshKeyProfile
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
        [object]$ProfileToCopy,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$CopyName
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    Import-Module -Name "$PSScriptRoot\sshkeyschedules.psm1" -Scope Local

    Copy-SafeguardSshKeyProfileItem -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
        -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -ItemType "Profile" -ItemToCopy $ProfileToCopy -CopyName $CopyName
}


# SSH key profile asset assignment

<#
.SYNOPSIS
Get the assets assigned to an SSH key profile in Safeguard via the Web API.

.DESCRIPTION
SSH key profiles control how Safeguard manages SSH keys for assets and accounts.
This cmdlet gets the assets currently assigned to a specific SSH key profile.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to find the SSH key profile in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to find the SSH key profile in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ProfileToGet
An integer containing the ID of the SSH key profile or a string containing the name.

.PARAMETER Fields
An array of the asset property names to return.

.EXAMPLE
Get-SafeguardSshKeyProfileAsset "Default SSH Key Profile"
#>
function Get-SafeguardSshKeyProfileAsset
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
        [object]$ProfileToGet,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    Import-Module -Name "$PSScriptRoot\sshkeyschedules.psm1" -Scope Local

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                             -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -UseDefault)

    $local:ProfileId = (Resolve-SafeguardSshKeyProfileId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                             -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId $ProfileToGet)

    $local:Parameters = $null
    if ($Fields)
    {
        $local:Parameters = @{ fields = ($Fields -join ",")}
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure core GET `
        "AssetPartitions/$AssetPartitionId/SshKeyProfiles/$($local:ProfileId)/Assets" -Parameters $local:Parameters
}

<#
.SYNOPSIS
Add assets to an SSH key profile in Safeguard via the Web API.

.DESCRIPTION
SSH key profiles control how Safeguard manages SSH keys for assets and accounts.
This cmdlet adds assets to a specific SSH key profile so the profile settings
apply to those assets.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to find the SSH key profile in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to find the SSH key profile in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ProfileToEdit
An integer containing the ID of the SSH key profile or a string containing the name.

.PARAMETER AssetList
A list of integers or strings containing the IDs or names of the assets to add.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Add-SafeguardSshKeyProfileAsset "Default SSH Key Profile" -AssetList "linux-server1","linux-server2"
#>
function Add-SafeguardSshKeyProfileAsset
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
        [object]$ProfileToEdit,
        [Parameter(Mandatory=$true,Position=1)]
        [object[]]$AssetList
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    Import-Module -Name "$PSScriptRoot\sshkeyschedules.psm1" -Scope Local

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                             -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -UseDefault)

    $local:ProfileId = (Resolve-SafeguardSshKeyProfileId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                             -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId $ProfileToEdit)

    [object[]]$local:Assets = $null
    foreach ($local:Asset in $AssetList)
    {
        $local:ResolvedAsset = (Get-SafeguardAsset -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $local:Asset)
        $local:Assets += $($local:ResolvedAsset)
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure core POST `
        "AssetPartitions/$AssetPartitionId/SshKeyProfiles/$($local:ProfileId)/Assets/Add" -Body $local:Assets
}

<#
.SYNOPSIS
Remove assets from an SSH key profile in Safeguard via the Web API.

.DESCRIPTION
SSH key profiles control how Safeguard manages SSH keys for assets and accounts.
This cmdlet removes assets from a specific SSH key profile so the profile settings
no longer apply to those assets.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to find the SSH key profile in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to find the SSH key profile in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ProfileToEdit
An integer containing the ID of the SSH key profile or a string containing the name.

.PARAMETER AssetList
A list of integers or strings containing the IDs or names of the assets to remove.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardSshKeyProfileAsset "Default SSH Key Profile" -AssetList "linux-server1"
#>
function Remove-SafeguardSshKeyProfileAsset
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
        [object]$ProfileToEdit,
        [Parameter(Mandatory=$true,Position=1)]
        [object[]]$AssetList
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    Import-Module -Name "$PSScriptRoot\sshkeyschedules.psm1" -Scope Local

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                             -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -UseDefault)

    $local:ProfileId = (Resolve-SafeguardSshKeyProfileId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                             -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId $ProfileToEdit)

    [object[]]$local:Assets = $null
    foreach ($local:Asset in $AssetList)
    {
        $local:ResolvedAsset = (Get-SafeguardAsset -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $local:Asset)
        $local:Assets += $($local:ResolvedAsset)
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure core POST `
        "AssetPartitions/$AssetPartitionId/SshKeyProfiles/$($local:ProfileId)/Assets/Remove" -Body $local:Assets
}


# SSH key profile account assignment

<#
.SYNOPSIS
Get the accounts assigned to an SSH key profile in Safeguard via the Web API.

.DESCRIPTION
SSH key profiles control how Safeguard manages SSH keys for assets and accounts.
This cmdlet gets the accounts currently assigned to a specific SSH key profile.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to find the SSH key profile in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to find the SSH key profile in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ProfileToGet
An integer containing the ID of the SSH key profile or a string containing the name.

.PARAMETER Fields
An array of the account property names to return.

.EXAMPLE
Get-SafeguardSshKeyProfileAccount "Default SSH Key Profile"
#>
function Get-SafeguardSshKeyProfileAccount
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
        [object]$ProfileToGet,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    Import-Module -Name "$PSScriptRoot\sshkeyschedules.psm1" -Scope Local

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                             -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -UseDefault)

    $local:ProfileId = (Resolve-SafeguardSshKeyProfileId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                             -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId $ProfileToGet)

    $local:Parameters = $null
    if ($Fields)
    {
        $local:Parameters = @{ fields = ($Fields -join ",")}
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure core GET `
        "AssetPartitions/$AssetPartitionId/SshKeyProfiles/$($local:ProfileId)/Accounts" -Parameters $local:Parameters
}

<#
.SYNOPSIS
Add accounts to an SSH key profile in Safeguard via the Web API.

.DESCRIPTION
SSH key profiles control how Safeguard manages SSH keys for assets and accounts.
This cmdlet adds accounts to a specific SSH key profile so the profile settings
apply to those accounts.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to find the SSH key profile in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to find the SSH key profile in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ProfileToEdit
An integer containing the ID of the SSH key profile or a string containing the name.

.PARAMETER AccountList
A list of integers or strings containing the IDs or names of the accounts to add.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Add-SafeguardSshKeyProfileAccount "Default SSH Key Profile" -AccountList 123,456
#>
function Add-SafeguardSshKeyProfileAccount
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
        [object]$ProfileToEdit,
        [Parameter(Mandatory=$true,Position=1)]
        [object[]]$AccountList
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    Import-Module -Name "$PSScriptRoot\sshkeyschedules.psm1" -Scope Local

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                             -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -UseDefault)

    $local:ProfileId = (Resolve-SafeguardSshKeyProfileId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                             -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId $ProfileToEdit)

    [object[]]$local:Accounts = $null
    foreach ($local:Account in $AccountList)
    {
        $local:ResolvedAccount = (Get-SafeguardAssetAccount -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                                      -AccountToGet $local:Account)
        $local:Accounts += $($local:ResolvedAccount)
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure core POST `
        "AssetPartitions/$AssetPartitionId/SshKeyProfiles/$($local:ProfileId)/Accounts/Add" -Body $local:Accounts
}

<#
.SYNOPSIS
Remove accounts from an SSH key profile in Safeguard via the Web API.

.DESCRIPTION
SSH key profiles control how Safeguard manages SSH keys for assets and accounts.
This cmdlet removes accounts from a specific SSH key profile so the profile settings
no longer apply to those accounts.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to find the SSH key profile in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to find the SSH key profile in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ProfileToEdit
An integer containing the ID of the SSH key profile or a string containing the name.

.PARAMETER AccountList
A list of integers or strings containing the IDs or names of the accounts to remove.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardSshKeyProfileAccount "Default SSH Key Profile" -AccountList 123
#>
function Remove-SafeguardSshKeyProfileAccount
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
        [object]$ProfileToEdit,
        [Parameter(Mandatory=$true,Position=1)]
        [object[]]$AccountList
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    Import-Module -Name "$PSScriptRoot\sshkeyschedules.psm1" -Scope Local

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                             -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -UseDefault)

    $local:ProfileId = (Resolve-SafeguardSshKeyProfileId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                             -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId $ProfileToEdit)

    [object[]]$local:Accounts = $null
    foreach ($local:Account in $AccountList)
    {
        $local:ResolvedAccount = (Get-SafeguardAssetAccount -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                                      -AccountToGet $local:Account)
        $local:Accounts += $($local:ResolvedAccount)
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure core POST `
        "AssetPartitions/$AssetPartitionId/SshKeyProfiles/$($local:ProfileId)/Accounts/Remove" -Body $local:Accounts
}
