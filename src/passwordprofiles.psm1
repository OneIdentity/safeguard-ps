<# Copyright (c) 2026 One Identity LLC. All rights reserved. #>

# password profiles

<#
.SYNOPSIS
Get password profiles in Safeguard via the Web API.

.DESCRIPTION
Get one or all password profiles that can be assigned to partitions, assets, and accounts.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to get password profiles from.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to get password profiles.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ProfileToGet
An integer containing the ID of the password profiles to get or a string containing the name.

.PARAMETER Fields
An array of the password profile property names to return.

.EXAMPLE
Get-SafeguardPasswordProfile

.EXAMPLE
Get-SafeguardPasswordProfile -AssetPartition "Unix Servers" "Default Profile"

.EXAMPLE
Get-SafeguardPasswordProfile -AllPartitions
#>
function Get-SafeguardPasswordProfile
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
    Import-Module -Name "$PSScriptRoot\passwordschedules.psm1" -Scope Local

    Get-SafeguardProfileItem -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
        -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -ItemType "Profile" -ItemToGet $ProfileToGet -Fields $Fields
}

<#
.SYNOPSIS
Create a new password profile in Safeguard via the Web API.

.DESCRIPTION
Create a new password profile. You must have already created the password rule,
check schedule, and change schedule so they can be set in the new password
profile.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to create the password profile in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to the create password profile in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER Name
A string containing the name for the new profile.

.PARAMETER Description
A string containing a description for the new profile.

.PARAMETER PasswordRuleToSet
An integer containing the ID of the account password rule to set in the new profile
or a string containing the name.

.PARAMETER CheckScheduleToSet
An integer containing the ID of the password check schedule to set in the new profile
or a string containing the name.

.PARAMETER ChangeScheduleToSet
An integer containing the ID of the password change schedule to set in the new profile
or a string containing the name.

.EXAMPLE
New-SafeguardPasswordProfile "My New Profile"

.EXAMPLE
New-SafeguardPasswordProfile -AssetPartition "Unix Servers" -Name "Custom Profile" -PasswordRuleToUse "Strong Rule"
#>
function New-SafeguardPasswordProfile
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
        [object]$PasswordRuleToSet,
        [Parameter(Mandatory=$true)]
        [object]$CheckScheduleToSet,
        [Parameter(Mandatory=$true)]
        [object]$ChangeScheduleToSet
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    Import-Module -Name "$PSScriptRoot\passwordschedules.psm1" -Scope Local

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                            -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -UseDefault)

    $local:Body = @{
        "Name" = $Name;
        "Description" = $Description
    }

    $local:Body.AccountPasswordRuleId = (Resolve-SafeguardAccountPasswordRuleId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                                             -AssetPartitionId $AssetPartitionId -AccountPasswordRule $PasswordRuleToSet)
    $local:Body.CheckScheduleId  = (Resolve-SafeguardPasswordCheckScheduleId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                                        -AssetPartitionId $AssetPartitionId -PasswordCheckSchedule $CheckScheduleToSet)
    $local:Body.ChangeScheduleId = (Resolve-SafeguardPasswordChangeScheduleId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                                        -AssetPartitionId $AssetPartitionId -PasswordChangeSchedule $ChangeScheduleToSet)

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
        POST "AssetPartitions/$($local:AssetPartitionId)/Profiles" -Body $local:Body
}

<#
.SYNOPSIS
Edit an existing password profile in Safeguard via the Web API.

.DESCRIPTION
Edit an existing password profile to change which password rule, check schedule,
or change schedule it is using.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to delete the password profile from.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to the delete password profile from.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ProfileToEdit
An integer containing the ID of the password profile to edit or a string containing the name.

.PARAMETER Description
A string containing a description for the new profile.

.PARAMETER PasswordRuleToSet
An integer containing the ID of the account password rule to set in the profile
or a string containing the name.

.PARAMETER CheckScheduleToSet
An integer containing the ID of the password check schedule to set in the profile
or a string containing the name.

.PARAMETER ChangeScheduleToSet
An integer containing the ID of the password change schedule to set in the profile
or a string containing the name.

.EXAMPLE
Edit-SafeguardPasswordProfile "Default Profile" -PasswordRuleToUse "Strong Rule"

.EXAMPLE
Edit-SafeguardPasswordProfile -AssetPartition "Unix Servers" -ProfileToEdit "Custom Profile" -CheckScheduleToUse "Daily Check"
#>
function Edit-SafeguardPasswordProfile
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
        [object]$PasswordRuleToSet,
        [Parameter(Mandatory=$false)]
        [object]$CheckScheduleToSet,
        [Parameter(Mandatory=$false)]
        [object]$ChangeScheduleToSet,
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
        Import-Module -Name "$PSScriptRoot\passwordschedules.psm1" -Scope Local
        if ($PsCmdlet.ParameterSetName -eq "Object")
        {
            if (-not $ProfileObject) { throw "ProfileObject must not be null" }
            Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                PUT "AssetPartitions/$($ProfileObject.AssetPartitionId)/Profiles/$($ProfileObject.Id)" -Body $ProfileObject
            return
        }

        $local:ProfileObj = (Get-SafeguardPasswordProfile -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                                 -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId $ProfileToEdit)

        if ($PSBoundParameters.ContainsKey("Description")) { $local:ProfileObj.Description = $Description }

        if ($PSBoundParameters.ContainsKey("PasswordRuleToSet"))
        {
            $local:ProfileObj.AccountPasswordRuleId = (Resolve-SafeguardAccountPasswordRuleId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                                                           -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -AccountPasswordRule $PasswordRuleToSet)
        }
        if ($PSBoundParameters.ContainsKey("CheckScheduleToSet"))
        {
            $local:ProfileObj.CheckScheduleId  = (Resolve-SafeguardPasswordCheckScheduleId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                                                      -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -PasswordCheckSchedule $CheckScheduleToSet)
        }
        if ($PSBoundParameters.ContainsKey("ChangeScheduleToSet"))
        {
            $local:ProfileObj.ChangeScheduleId = (Resolve-SafeguardPasswordChangeScheduleId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                                                      -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -PasswordChangeSchedule $ChangeScheduleToSet)
        }

        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            PUT "AssetPartitions/$($local:ProfileObj.AssetPartitionId)/Profiles/$($local:ProfileObj.Id)" -Body $local:ProfileObj
    }
}

<#
.SYNOPSIS
Delete a password profile from Safeguard via the Web API.

.DESCRIPTION
Delete a password profile. It must not the default password profile of an asset partition
in order to be able to delete it.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to delete the password profile from.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to the delete password profile from.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ProfileToDelete
An integer containing the ID of the password profile to delete or a string containing the name.

.EXAMPLE
Remove-SafeguardPasswordProfile "Old Profile"

.EXAMPLE
Remove-SafeguardPasswordProfile -AssetPartition "Unix Servers" "Deprecated Profile"
#>
function Remove-SafeguardPasswordProfile
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
    Import-Module -Name "$PSScriptRoot\passwordschedules.psm1" -Scope Local

    Remove-SafeguardProfileItem -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
        -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -ItemType "Profile" -ItemToDelete $ProfileToDelete
}

<#
.SYNOPSIS
Rename a password profile in Safeguard via the Web API.

.DESCRIPTION
Rename a password profile without changing any of its configuration.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to rename the password profile in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to rename the password profile in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ProfileToEdit
An integer containing the ID of the password profile to rename or a string containing the name.

.PARAMETER NewName
A string containing the new name for the password profile.

.EXAMPLE
Rename-SafeguardPasswordProfile "Old Name" -NewName "New Name"

.EXAMPLE
Rename-SafeguardPasswordProfile -AssetPartition "Unix Servers" "Old Name" -NewName "New Name"
#>
function Rename-SafeguardPasswordProfile
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
    Import-Module -Name "$PSScriptRoot\passwordschedules.psm1" -Scope Local

    Rename-SafeguardProfileItem -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetPartition $AssetPartition `
        -AssetPartitionId $AssetPartitionId -ItemType "Profile" -ItemToEdit $ProfileToEdit -NewName $NewName
}

<#
.SYNOPSIS
Copy a password profile in Safeguard via the Web API.

.DESCRIPTION
Copy a password profile without changing any of its configuration.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to copy the password profile in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to copy the password profile in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ProfileToCopy
An integer containing the ID of the password profile to copy or a string containing the name.

.PARAMETER CopyName
A string containing the name for the new password profile.

.PARAMETER DeepCopy
Whether to deep copy the profile, meaning make a copy of the account password rule, check password
schedule, and change password schedule, which will be given names based on the CopyName parameter
that is provided.

.EXAMPLE
Copy-SafeguardPasswordProfile "Existing Profile" -CopyName "Copy of Profile"

.EXAMPLE
Copy-SafeguardPasswordProfile -AssetPartition "Unix Servers" "Source Profile" -CopyName "New Profile"
#>
function Copy-SafeguardPasswordProfile
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
        [string]$CopyName,
        [Parameter(Mandatory=$false)]
        [switch]$DeepCopy
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    Import-Module -Name "$PSScriptRoot\passwordschedules.psm1" -Scope Local

    $local:Copy = (Copy-SafeguardProfileItem -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetPartition $AssetPartition `
                       -AssetPartitionId $AssetPartitionId -ItemType "Profile" -ItemToCopy $ProfileToCopy -CopyName $CopyName)
    if ($DeepCopy)
    {
        $local:APR = (Copy-SafeguardAccountPasswordRule -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetPartition $AssetPartition `
                          -AssetPartitionId $AssetPartitionId -PasswordRuleToCopy $local:Copy.AccountPasswordRule.Id -CopyName "$CopyName Password Rule")
        $local:Chk = (Copy-SafeguardPasswordCheckSchedule -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetPartition $AssetPartition `
                          -AssetPartitionId $AssetPartitionId -CheckScheduleToCopy $local:Copy.CheckSchedule.Id -CopyName "$CopyName Check Schedule")
        $local:Chg = (Copy-SafeguardPasswordChangeSchedule -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetPartition $AssetPartition `
                          -AssetPartitionId $AssetPartitionId -ChangeScheduleToCopy $local:Copy.ChangeSchedule.Id -CopyName "$CopyName Change Schedule")

        $local:Copy = (Edit-SafeguardPasswordProfile -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetPartition $AssetPartition `
                           -AssetPartitionId $AssetPartitionId $local:Copy.Id -PasswordRuleToSet $local:APR.Id -CheckScheduleToSet $local:Chk.Id -ChangeScheduleToSet $local:Chg.Id)
    }

    $local:Copy
}

<#
.SYNOPSIS
Get assets directly assigned to a password profile in Safeguard via the Web API.

.DESCRIPTION
Password profiles control how Safeguard manages passwords for assets and accounts.
This cmdlet gets the list of assets that are directly assigned to a specific
password profile.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to find the password profile in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to find the password profile in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ProfileToGet
An integer containing the ID of the password profile or a string containing the name.

.PARAMETER Fields
An array of the asset property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardPasswordProfileAsset "Default Partition Profile"

.EXAMPLE
Get-SafeguardPasswordProfileAsset -AssetPartition "Unix Servers" "Custom Profile"
#>
function Get-SafeguardPasswordProfileAsset
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
    Import-Module -Name "$PSScriptRoot\passwordschedules.psm1" -Scope Local

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                             -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -UseDefault)

    $local:ProfileId = (Resolve-SafeguardPasswordProfileId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                             -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId $ProfileToGet)

    $local:Parameters = $null
    if ($Fields)
    {
        $local:Parameters = @{ fields = ($Fields -join ",")}
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure core GET `
        "AssetPartitions/$AssetPartitionId/Profiles/$($local:ProfileId)/Assets" -Parameters $local:Parameters
}
<#
.SYNOPSIS
Add assets to a password profile in Safeguard via the Web API.

.DESCRIPTION
Password profiles control how Safeguard manages passwords for assets and accounts.
This cmdlet adds assets to a specific password profile so the profile settings
apply to those assets.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to find the password profile in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to find the password profile in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ProfileToEdit
An integer containing the ID of the password profile or a string containing the name.

.PARAMETER AssetList
A list of integers or strings containing the IDs or names of the assets to add.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Add-SafeguardPasswordProfileAsset "Daily Check Profile" -AssetList "linux-server1","linux-server2"

.EXAMPLE
Add-SafeguardPasswordProfileAsset -AssetPartition "Unix Servers" "Custom Profile" "my-asset"
#>
function Add-SafeguardPasswordProfileAsset
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
    Import-Module -Name "$PSScriptRoot\passwordschedules.psm1" -Scope Local

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                             -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -UseDefault)

    $local:ProfileId = (Resolve-SafeguardPasswordProfileId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                             -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId $ProfileToEdit)

    [object[]]$local:Assets = $null
    foreach ($local:Asset in $AssetList)
    {
        $local:ResolvedAsset = (Get-SafeguardAsset -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $local:Asset)
        $local:Assets += $($local:ResolvedAsset)
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure core POST `
        "AssetPartitions/$AssetPartitionId/Profiles/$($local:ProfileId)/Assets/Add" -Body $local:Assets
}
<#
.SYNOPSIS
Remove assets from a password profile in Safeguard via the Web API.

.DESCRIPTION
Password profiles control how Safeguard manages passwords for assets and accounts.
This cmdlet removes assets from a specific password profile so the profile settings
no longer apply to those assets.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to find the password profile in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to find the password profile in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ProfileToEdit
An integer containing the ID of the password profile or a string containing the name.

.PARAMETER AssetList
A list of integers or strings containing the IDs or names of the assets to remove.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardPasswordProfileAsset "Daily Check Profile" -AssetList "linux-server1"

.EXAMPLE
Remove-SafeguardPasswordProfileAsset -AssetPartition "Unix Servers" "Custom Profile" "my-asset"
#>
function Remove-SafeguardPasswordProfileAsset
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
    Import-Module -Name "$PSScriptRoot\passwordschedules.psm1" -Scope Local

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                             -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -UseDefault)

    $local:ProfileId = (Resolve-SafeguardPasswordProfileId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                             -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId $ProfileToEdit)

    [object[]]$local:Assets = $null
    foreach ($local:Asset in $AssetList)
    {
        $local:ResolvedAsset = (Get-SafeguardAsset -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $local:Asset)
        $local:Assets += $($local:ResolvedAsset)
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure core POST `
        "AssetPartitions/$AssetPartitionId/Profiles/$($local:ProfileId)/Assets/Remove" -Body $local:Assets
}
<#
.SYNOPSIS
Get accounts directly assigned to a password profile in Safeguard via the Web API.

.DESCRIPTION
Password profiles control how Safeguard manages passwords for assets and accounts.
This cmdlet gets the list of accounts that are directly assigned to a specific
password profile.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to find the password profile in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to find the password profile in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ProfileToGet
An integer containing the ID of the password profile or a string containing the name.

.PARAMETER Fields
An array of the account property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardPasswordProfileAccount "Default Partition Profile"

.EXAMPLE
Get-SafeguardPasswordProfileAccount -AssetPartition "Unix Servers" "Custom Profile"
#>
function Get-SafeguardPasswordProfileAccount
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
    Import-Module -Name "$PSScriptRoot\passwordschedules.psm1" -Scope Local

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                             -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -UseDefault)

    $local:ProfileId = (Resolve-SafeguardPasswordProfileId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                             -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId $ProfileToGet)

    $local:Parameters = $null
    if ($Fields)
    {
        $local:Parameters = @{ fields = ($Fields -join ",")}
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure core GET `
        "AssetPartitions/$AssetPartitionId/Profiles/$($local:ProfileId)/Accounts" -Parameters $local:Parameters
}
<#
.SYNOPSIS
Add accounts to a password profile in Safeguard via the Web API.

.DESCRIPTION
Password profiles control how Safeguard manages passwords for assets and accounts.
This cmdlet adds accounts to a specific password profile so the profile settings
apply to those accounts.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to find the password profile in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to find the password profile in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ProfileToEdit
An integer containing the ID of the password profile or a string containing the name.

.PARAMETER AccountList
A list of integers or strings containing the IDs or names of the accounts to add.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Add-SafeguardPasswordProfileAccount "Daily Check Profile" -AccountList 123,456

.EXAMPLE
Add-SafeguardPasswordProfileAccount -AssetPartition "Unix Servers" "Custom Profile" 789
#>
function Add-SafeguardPasswordProfileAccount
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
    Import-Module -Name "$PSScriptRoot\passwordschedules.psm1" -Scope Local

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                             -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -UseDefault)

    $local:ProfileId = (Resolve-SafeguardPasswordProfileId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                             -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId $ProfileToEdit)

    [object[]]$local:Accounts = $null
    foreach ($local:Account in $AccountList)
    {
        $local:ResolvedAccount = (Get-SafeguardAssetAccount -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                                      -AccountToGet $local:Account)
        $local:Accounts += $($local:ResolvedAccount)
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure core POST `
        "AssetPartitions/$AssetPartitionId/Profiles/$($local:ProfileId)/Accounts/Add" -Body $local:Accounts
}
<#
.SYNOPSIS
Remove accounts from a password profile in Safeguard via the Web API.

.DESCRIPTION
Password profiles control how Safeguard manages passwords for assets and accounts.
This cmdlet removes accounts from a specific password profile so the profile settings
no longer apply to those accounts.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to find the password profile in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to find the password profile in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ProfileToEdit
An integer containing the ID of the password profile or a string containing the name.

.PARAMETER AccountList
A list of integers or strings containing the IDs or names of the accounts to remove.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardPasswordProfileAccount "Daily Check Profile" -AccountList 123

.EXAMPLE
Remove-SafeguardPasswordProfileAccount -AssetPartition "Unix Servers" "Custom Profile" 789
#>
function Remove-SafeguardPasswordProfileAccount
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
    Import-Module -Name "$PSScriptRoot\passwordschedules.psm1" -Scope Local

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                             -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -UseDefault)

    $local:ProfileId = (Resolve-SafeguardPasswordProfileId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                             -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId $ProfileToEdit)

    [object[]]$local:Accounts = $null
    foreach ($local:Account in $AccountList)
    {
        $local:ResolvedAccount = (Get-SafeguardAssetAccount -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                                      -AccountToGet $local:Account)
        $local:Accounts += $($local:ResolvedAccount)
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure core POST `
        "AssetPartitions/$AssetPartitionId/Profiles/$($local:ProfileId)/Accounts/Remove" -Body $local:Accounts
}
