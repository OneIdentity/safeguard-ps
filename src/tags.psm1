<#
#------------------------------------------------------------------------------#
# Module for handling Tag objects in the SPP
#------------------------------------------------------------------------------#
# This module has been contributed by iC Consult.
# Author: alexfungafoek-icc
#
# The code for Tags is structured similarly to the Asset.psm1 module.
# All functions require an active session to the Safeguard SPP. 
# Use Connect-Safeguard cmdlet to get a session, without an active session Web API calls are not possible. 
# This module relies on assetpartitions.psm1, assets.psm1 and users.psm1 from the safeguard-ps module.
#>


<#
.SYNOPSIS
Helper function to resolve the AssetPartitionId

.DESCRIPTION
Helper function which returns the asset partition id.
If the asset partition name is specified, then the id is looked up.
If AssetPartitionId is specified, then this value is returned. 
This function does not check if the specified asset partion id exists.
If neither is specified, then the macrocosm partition id -1 is returned.
This function is only used internally in the tags.psm1 module. Should not be exported.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition to get tags from.
If this value is empty, the Macrocosm partition will be used.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to get tags from.
(If specified, this will override the AssetPartition parameter)

.EXAMPLE
Resolve-AssetPartitionId -AssetPartition "Macrocosm"

.INPUTS
None.

.OUTPUTS
The id of the asset partition

.NOTES
Visibility: Internal
Access: Private
Intended Use: Internal module use only
#>
function Resolve-AssetPartitionId {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [object]$AssetPartition = $null,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    # if AssetPartition is passed in and AssetPartitionID is empty, then lookup based on AssetPartition name
    if ($PSBoundParameters.ContainsKey('AssetPartition') -and (-not $PSBoundParameters.ContainsKey('AssetPartitionId'))) {
        # we need to use Resolve-AssetPartitionIdFromSafeguardSession from the assetpartitions.psm1 module to get the AssetPartition ID so check if the module is loaded
        if (-not (Get-Module assetpartitions)) {
            Import-module "$PSScriptRoot\assetpartitions.psm1"
        }
        $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId)
    }
    if (-not $AssetPartitionId) {
        # AssetPartition and AssetPartitionId param are both empty so use Macrocosm.
        $AssetPartitionId = -1
    }
    return $AssetPartitionId
}


<#
.SYNOPSIS
Helper function to get the ID of a tag based on tag name or tag id

.DESCRIPTION
Helper function which returns the tag id.
Accepts either name or ID of the tag. If the tag does not exist, nothing is returned.
This function is only used internally in the tags.psm1 module. Should not be exported.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition to get tags from.
If this value is empty, the Macrocosm partition will be used.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to get tags from.
(If specified, this will override the AssetPartition parameter)

.PARAMETER Tag
An integer containing the ID of the tag or a string containing the name of the tag to get.

.INPUTS
None.

.OUTPUTS
The id of the tag

.NOTES
Visibility: Internal
Access: Private
Intended Use: Internal module use only
#>
function Resolve-SafeguardTagId {
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
        [object]$Tag
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($Tag.Id -as [int]) {
        $Tag = $Tag.Id
    }

    # use the helper function Resolve-AssetPartitionId to get the asset partition id.
    $AssetPartitionId = Resolve-AssetPartitionId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId
    $local:RelPath = "AssetPartitions/$AssetPartitionId/Tags"

    if (-not ($Tag -as [int])) {
        # get tag based on name
        $escapedTagName = $Tag -replace "'", "\'"
        $local:Tags = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" -Parameters @{ filter = "Name ieq '$escapedTagName'"; fields = "Id" })
    } else {
        # Tag ID was supplied as param, not tag name
        # Confirm that the tag with this ID actually exists.
        $local:Tags = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" -Parameters @{ filter = "Id eq $Tag and AssetPartitionId eq $AssetPartitionId"; fields = "Id" })
    }
    if ($local:Tags.Count -eq 0){
        # If no tag found then return nothing
        return
    } else {
        # return the ID of the tag.
        $local:Tags[0].Id
    }
}


<#
.SYNOPSIS
Get tag from Safeguard via the Web API.

.DESCRIPTION
Get the tag from Safeguard. A tag can be added to Assets or Accounts.
If the tag does not exist, nothing is returned.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition to get tags from.
If this value is empty, the Macrocosm partition will be used.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to get tags from.
(If specified, this will override the AssetPartition parameter)

.PARAMETER TagToGet
An integer containing the ID of the Tag to get or a string containing the name of the tag (case insensitive).
If this value is empty, all tags on the Asset Partition will be returned.

.PARAMETER Field
An array of the tag property names to return.
(can be one of the following Id, AssetPartitionId, AssetPartitionName, Name, Description, AssetTaggingRule, AssetAccountTaggingRule, ManagedBy)

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardTag -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardTag "tagname" -Field "Id","Name","ManagedBy"
#>
function Get-SafeguardTag {
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
        [object]$TagToGet,
        [Parameter(Mandatory=$false)]
        [string[]]$Field
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Parameters = $null
    if ($Field) {
        $local:Parameters = @{ fields = ($Field -join ",")}
    }

    # use the helper function Resolve-AssetPartitionId to get the asset partition id.
    $AssetPartitionId = Resolve-AssetPartitionId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId
    $local:RelPath = "AssetPartitions/$AssetPartitionId/Tags"

    if ($PSBoundParameters.ContainsKey("TagToGet")) {
        # tag specified, so get single tag
        $local:TagId = (Resolve-SafeguardTagId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetPartitionId $AssetPartitionId -Tag $TagToGet)
        if ($local:TagId) {
            Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$local:RelPath/$($local:TagId)" -Parameters $local:Parameters
        }
    } else {
        # if no Tag is specified, return all tags.
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" -Parameters $local:Parameters
    }
}


<#
.SYNOPSIS
Get the objects with this tag from Safeguard via the Web API.

.DESCRIPTION
Get the tagged objects from Safeguard (a tag can be assigned to Assets or Accounts).

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition to get tags from.
If this value is empty, the Macrocosm partition will be used.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to get tags from.
(If specified, this will override the AssetPartition parameter)

.PARAMETER Tag
Mandatory parameter. An integer containing the ID of the tag to get or a string containing the name of the tag.

.PARAMETER Field
An array of the tag property names to return (can be one of the following Id, Name, DomainName, Type, AssetId, AssetName, IsStatic)

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardTagOccurence 2

.EXAMPLE
Get-SafeguardTagOccurence "tagname"
#>
function Get-SafeguardTagOccurence {
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
        [object]$Tag,
        [Parameter(Mandatory=$false)]
        [string[]]$Field
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Parameters = $null
    if ($Field) {
        $local:Parameters = @{ fields = ($Field -join ",")}
    } 

    # use the helper function Resolve-AssetPartitionId to get the asset partition id.
    $AssetPartitionId = Resolve-AssetPartitionId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId
    $local:RelPath = "AssetPartitions/$AssetPartitionId/Tags"

    if ($PSBoundParameters.ContainsKey("Tag")) {
        # tag specified, so get the ID based on name
        $local:TagId = ( Resolve-SafeguardTagId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetPartitionId $AssetPartitionId $Tag)
        # get all assigned 
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$local:RelPath/$local:TagId/Occurrences" -Parameters $local:Parameters
    }
}


<#
.SYNOPSIS
Get the tags from a specific asset via the Web API.

.DESCRIPTION
Get the assigned tags for a specific asset.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition to get tags from an asset.
If this value is empty, the Macrocosm partition will be used.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to get the asset's tags from.
(If specified, this will override the AssetPartition parameter)

.PARAMETER Asset
Required parameter. An integer containing the ID of the asset or a string containing the name of the asset to get the tags for.

.PARAMETER Field
An array of the tag property names to return.
(Can be one of the following: Id, Name, Description, AdminAssigned)

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardAssetTag "assetname" 

.EXAMPLE
Get-SafeguardAssetTag 14 

.EXAMPLE
Get-SafeguardAssetTag "assetname" -Field Id,Name,Description

#>
function Get-SafeguardAssetTag {
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
        [object]$Asset,
        [Parameter(Mandatory=$false)]
        [string[]]$Field
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Parameters = $null
    if ($Field) {
        $local:Parameters = @{ fields = ($Field -join ",")}
    }
    
    # we need to use function Resolve-SafeguardAssetId from the asset.psm1 module to get the Asset ID so check if the module is load
    if (-not (Get-Module assets)) {
        Import-module "$PSScriptRoot\assets.psm1"
    }
    $AssetId = (Resolve-SafeguardAssetId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -Asset $Asset)
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Assets/$AssetId/Tags" -Parameters $local:Parameters
}


<#
.SYNOPSIS
Update the tags on a specific asset via the Web API.

.DESCRIPTION
Update the assigned tags on a specific asset.
Currently assigned tags are replaced with the tags specified.
If an empty Tags array is passed in, then all tags will be removed from the asset.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition to get tags from an asset.
If this value is empty, the Macrocosm partition will be used.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to get the asset's tags from.
(If specified, this will override the AssetPartition parameter)

.PARAMETER Asset
Mandatory parameter. An integer containing the ID of the asset or a string containing the name of the asset to update the tags for.

.PARAMETER Tag
Mandatory parameter. An array of integers with the tag Ids or a string array of tag names to assign to the asset.
If an empty array is passed in, then all tags will be removed from the asset.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Update-SafeguardAssetTag assetname -Tag @("Prod,VM,DMZ")

.EXAMPLE
Update-SafeguardAssetTag assetname -Tag @(1,2,3)

.EXAMPLE
Update-SafeguardAssetTag 8 -Tag @("Prod,VM,DMZ")

.EXAMPLE
$tags = @("VM","Prod","DMZ")
Update-SafeguardAssetTags -Asset "assetName" -Tag $tags

#>
function Update-SafeguardAssetTag {
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
        [object]$Asset,
        [Parameter(Mandatory=$false)]
        [object[]]$Tag
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
   
    # we need to use function Resolve-SafeguardAssetId from the asset.psm1 module to get the Asset ID so check if the module is load
    if (-not (Get-Module assets)) {
        Import-module "$PSScriptRoot\assets.psm1"
    }
    $AssetId = (Resolve-SafeguardAssetId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -Asset $Asset)    
    $local:body =@() # empty array to store the tag IDs.
    if ($Tag.Count -gt 0) {
        foreach ($tagObj in $Tag) {
            $tagId = Resolve-SafeguardTagId $tagObj
            if ($tagId) {
                # found the tag so add the ID to the body
                $local:body += [PSCustomObject]@{ Id = $tagId }
            }
        }
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "Assets/$AssetId/Tags" -Body $local:body
    } else {
        # No tags specified so remove all tags. Send empty json body.
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "Assets/$AssetId/Tags" -JsonBody "[]"
    }
}


<#
.SYNOPSIS
Get the tags from a specific account via the Web API.

.DESCRIPTION
Get the assigned tags for a specific asset account.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition to get tags from an asset account.
If this value is empty, the Macrocosm partition will be used.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to get the asset account's tags from.
(If specified, this will override the AssetPartition parameter)

.PARAMETER Account
Mandatory parameter. An integer containing the ID of the account or a string containing the name of the account to get the tags for.

.PARAMETER Field
String array with the tag property names to return.
(Can be one of the following: Id,Name,Description,AdminAssigned

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardAssetAccountTag "accountname" 

.EXAMPLE
Get-SafeguardAssetAccountTag "accountname" -Field Id,Name,Description

#>
function Get-SafeguardAssetAccountTag {
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
        [object]$Account,
        [Parameter(Mandatory=$false)]
        [string[]]$Field
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Parameters = $null
    if ($Field) {
        $local:Parameters = @{ fields = ($Field -join ",")}
    }
   
    # we need to use function Resolve-SafeguardAssetAccountId from the asset.psm1 module to get the Asset Account ID so check if the module is load
    if (-not (Get-Module assets)) {
        Import-module "$PSScriptRoot\assets.psm1"
    }
    $AccountId = (Resolve-SafeguardAssetAccountId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -Account $Account)
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "AssetAccounts/$AccountId/Tags" -Parameters $local:Parameters
}


<#
.SYNOPSIS
Update the tags on a specific account via the Web API.

.DESCRIPTION
Update the assigned tags on a specific account. Currently assigned tags are replaced by the tags specified.
If an empty Tags array is passed in, all tags will be removed from the account.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition to get tags from an asset.
If this value is empty, the Macrocosm partition will be used.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to get the asset's tags from.
(If specified, this will override the AssetPartition parameter)

.PARAMETER Account
Mandatory parameter. An integer containing the ID of the account or a string containing the name of the account to update the tags for.

.PARAMETER Tag
Mandatory parameter. An array of integers with the Tag Ids or a string array with the Tag names to assign to the account.
If an empty array is passed in, all tags will be removed from the account.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Update-SafeguardAssetAccountTag "accountName" -Tag @("Prod","DMZ","Tier1")

.EXAMPLE
Update-SafeguardAssetAccountTag "accountName" -Tag @(1,2,3)

.EXAMPLE
$tags = @("TagName1", "TagName2", "TagName3")
Update-SafeguardAssetAccountTag -Account 8 -Tag $tags

#>
function Update-SafeguardAssetAccountTag {
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
        [object]$Account,
        [Parameter(Mandatory=$false)]
        [object[]]$Tag
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
   
    # we need to use function Resolve-SafeguardAssetAccountId from the asset.psm1 module to get the Asset Account ID so check if the module is load
    if (-not (Get-Module assets)) {
        Import-module "$PSScriptRoot\assets.psm1"
    }
    $AccountId = (Resolve-SafeguardAssetAccountId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -Account $Account)

    $local:body =@() # empty array to store the tag IDs.
    if ($Tag.Count -gt 0) {
        foreach ($tagObj in $Tag) {
            $tagId = Resolve-SafeguardTagId $tagObj
            if ($tagId) {
                # found the tag so add the ID to the body
                $local:body += [PSCustomObject]@{ Id = $tagId }
            }
        }
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "AssetAccounts/$AccountId/Tags" -Body $local:body
    } else {
        # No tags specified so remove all tags. Send empty json body.
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "AssetAccounts/$AccountId/Tags" -JsonBody "[]"
    }    
}


<#
.SYNOPSIS
Search for a tag in Safeguard via the Web API.

.DESCRIPTION
Search for a tag in Safeguard for any string fields containing the SearchString.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition to the find tag in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to find the tag in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER SearchString
A string to search for in the tag.

.PARAMETER QueryFilter
A string to pass to the -filter query parameter in the Safeguard Web API.
Example: Name ieq 'prod'
Available operators: eq, ne, gt, ge, lt, le, and, or, not, contains, ieq, icontains, sw, isw, ew, iew, in [ {item1}, {item2}, etc], (). Use \ to escape quotes, asterisks and backslashes in strings.

.PARAMETER Field
An array of the tag property names to return.
(can be one of the following Id, AssetPartitionId, AssetPartitionName, Name, Description, AssetTaggingRule, AssetAccountTaggingRule, ManagedBy)

.PARAMETER OrderBy
An array of the tag property names to order by.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Find-SafeguardTag -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Find-SafeguardTag "production"

.EXAMPLE
Find-SafeguardTag -QueryFilter "Description eq 'locations'"

.EXAMPLE
Find-SafeguardTag -QueryFilter "AssetTaggingRule.Description eq 'WindowsServers'"

.EXAMPLE
Find-SafeguardTag -QueryFilter "Name contains 'prod'" -Field Id,Name,Description -OrderBy Name
#>
function Find-SafeguardTag {
    [CmdletBinding(DefaultParameterSetName="Search")]
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
        [Parameter(Mandatory=$true,Position=0,ParameterSetName="Search")]
        [string]$SearchString,
        [Parameter(Mandatory=$true,Position=0,ParameterSetName="Query")]
        [string]$QueryFilter,
        [Parameter(Mandatory=$false)]
        [string[]]$Field,
        [Parameter(Mandatory=$false)]
        [string[]]$OrderBy
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    # use the helper function Resolve-AssetPartitionId to get the asset partition id.
    $AssetPartitionId = Resolve-AssetPartitionId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId
    $local:RelPath = "AssetPartitions/$AssetPartitionId/Tags"

    if ($PSCmdlet.ParameterSetName -eq "Search") {
        $local:Parameters = @{ q = $SearchString }
    } else {
        $local:Parameters = @{ filter = $QueryFilter }
    }

    if ($Field) {
        $local:Parameters["fields"] = ($Field -join ",")
    }
    if ($OrderBy) {
        $local:Parameters["orderby"] = ($OrderBy -join ",")
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" -Parameters $local:Parameters
}


<#
.SYNOPSIS
Create a new tag via the Web API.

.DESCRIPTION
Tags are text values which can be assigned to an asset or account. They serve as meta data on an asset or account 
and can be used to store extra information such and the environment (e.g dev,test,acceptance,prod).
Each tag can have a list of owners.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition where the tag should be created.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID where the tag should be created.
If specified, this will override the AssetPartition parameter.
If not specified, the default AssetPartition Id -1 (macrocosm) will be used.

.PARAMETER Name
A mandatory string containing the name for the new tag.

.PARAMETER Description
An optional string containing the description for the new tag.

.PARAMETER AssetTaggingRule
An optional PSCustomObject containing the JSON for the Asset Tagging Rule.
For example:'{
  "Description": null,
  "Enabled": true,
  "RuleConditionGroup": {
    "LogicalJoinType": "And",
    "Children": [
      {
        "TaggingGroupingCondition": {
          "ObjectAttribute": "Name",
          "CompareType": "Contains",
          "CompareValue": "prd.local"
        },
        "TaggingGroupingConditionGroup": null
      }
    ]
  }
}' | ConvertFrom-Json

.PARAMETER AssetAccountTaggingRule
An optional PSCustomObject containing the JSON for the Asset Account Tagging rule.
For example:'{
  "Description": null,
  "Enabled": true,
  "RuleConditionGroup": {
    "LogicalJoinType": "And",
    "Children": [
      {
        "TaggingGroupingCondition": {
          "ObjectAttribute": "Name",
          "CompareType": "Contains",
          "CompareValue": "domadm"
        },
        "TaggingGroupingConditionGroup": null
      }
    ]
  }
}' | ConvertFrom-Json

.PARAMETER Owner
An optional string array containing the names of the owners for the new tag.
Note: an owner cannot be a system account such as admin.
If you specify an owner name who does not exist, a RuntimeException will be thrown.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
New-SafeguardTag "prod"

.EXAMPLE
New-SafeguardTag "prod" "environment"

.EXAMPLE
New-SafeguardTag -Name "Non-prod" -Description "server environment" -Owner "Admin1","Admin2"

#>
function New-SafeguardTag {
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
        [int]$AssetPartitionId=$null,
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [string]$Description=$null,
        [Parameter(Mandatory=$false)]
        [PSCustomObject]$AssetTaggingRule=$null,
        [Parameter(Mandatory=$false)]
        [PSCustomObject]$AssetAccountTaggingRule=$null,
        [Parameter(Mandatory=$false)]
        [string[]]$Owner=@()
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    # use the helper function Resolve-AssetPartitionId to get the asset partition id.
    $AssetPartitionId = Resolve-AssetPartitionId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId
    $local:RelPath = "AssetPartitions/$AssetPartitionId/Tags"

    $local:Body = @{
        AssetPartitionId = $AssetPartitionId;
        Name = "$Name";
    }
    if ($PSBoundParameters.ContainsKey("Description")) { $local:Body.Description = $Description }
    if ($PSBoundParameters.ContainsKey("AssetTaggingRule")) { $local:Body.AssetTaggingRule = $AssetTaggingRule }
    if ($PSBoundParameters.ContainsKey("AssetAccountTaggingRule")) { $local:Body.AssetAccountTaggingRule = $AssetAccountTaggingRule }    
    if ($PSBoundParameters.ContainsKey("Owner")) {
        if (-not (Get-Module users)) {
            Import-module "$PSScriptRoot\users.psm1"
        }
        $local:Body.ManagedBy = @()
        $Owner | ForEach-Object {
            $local:Body.ManagedBy += (Resolve-SafeguardUserObject -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $_)
        }
    }
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "$local:RelPath" -Body $local:Body
}


<#
.SYNOPSIS
Update an existing tag via the Web API.

.DESCRIPTION
Update an existing tag. The tag is retrieved based on the ID of tag (not the name of the tag).
This allows the Name parameter to be used to set a new name for tag.
Please note that changing a Tag name may impact dynamic asset groups and dynamic account groups which use "Contains" in the rule.
If a value is set on the tag in Safeguard but is not passed in as a parameter, then the value will be cleared.
For example if the AssetTaggingRule is set on the tag but is not specified as a parameter when calling the Update-SafeguardTag function, then it will be cleared.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition where the tag should be updated.

.PARAMETER AssetPartitionId
An integer value containing the asset partition ID to update the tag in.

.PARAMETER TagId
Mandatory integer with the ID of the tag. 
The tag is retrieved based on the ID so that changing the name is possible.

.PARAMETER Name
A mandatory string containing the name for the tag.

.PARAMETER Description
An optional string containing the description for the tag.

.PARAMETER AssetTaggingRule
An optional string containing the JSON format of the Asset Tagging Rule.
For example:'{
  "Description": null,
  "Enabled": true,
  "RuleConditionGroup": {
    "LogicalJoinType": "And",
    "Children": [
      {
        "TaggingGroupingCondition": {
          "ObjectAttribute": "Name",
          "CompareType": "Contains",
          "CompareValue": "prd.local"
        },
        "TaggingGroupingConditionGroup": null
      }
    ]
  }
}' | ConvertFrom-Json

.PARAMETER AssetAccountTaggingRule
An optional PSCustomObject containing the JSON object for the Asset Account Tagging rule.
Note: this needs to be a PSCustomObject, not a string!
For example:'{
  "Description": null,
  "Enabled": true,
  "RuleConditionGroup": {
    "LogicalJoinType": "And",
    "Children": [
      {
        "TaggingGroupingCondition": {
          "ObjectAttribute": "Name",
          "CompareType": "Contains",
          "CompareValue": "domadm"
        },
        "TaggingGroupingConditionGroup": null
      }
    ]
  }
}' | ConvertFrom-Json

.PARAMETER Owner
An optional string array containing the names of the owners for the tag.
Note: an owner cannot be a system account such as admin.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Update-SafeguardTag -TagId 1 -Name "prod"
Any parameters not passed in will be cleared (eg: description, asset and account tagging rules, owners).

.EXAMPLE
Update-SafeguardTag -TagId 1 -Name "new Tag Name" -Description "Some new description" -Owner "Admin1","Admin2","New Owner3"
Any parameters not passed in will be cleared (eg: asset and account tagging rules).

TODO: code to move tag to new partition.
#>
function Update-SafeguardTag {
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
        [int]$AssetPartitionId = -1,
        [Parameter(Mandatory=$true, Position=0)]
        [int]$TagId,
        [Parameter(Mandatory=$true, Position=1)]
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [string]$Description=$null,
        [Parameter(Mandatory=$false)]
        [PSCustomObject]$AssetTaggingRule=$null,
        [Parameter(Mandatory=$false)]
        [PSCustomObject]$AssetAccountTaggingRule=$null,
        [Parameter(Mandatory=$false)]
        [string[]]$Owner
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $emptyTaggingRule = '{"Description":null,"Enabled":false,"RuleConditionGroup":{"LogicalJoinType":"And","Children":[{"TaggingGroupingCondition":{"ObjectAttribute":"Name","CompareType":"Contains","CompareValue":""},"TaggingGroupingConditionGroup":null}]}}' | ConvertFrom-Json

    # use the helper function Resolve-AssetPartitionId to get the asset partition id.
    $AssetPartitionId = Resolve-AssetPartitionId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId
    $local:RelPath = "AssetPartitions/$AssetPartitionId/Tags/$tagId"

    $local:tagObj = Get-SafeguardTag $TagId
    if ($local:tagObj) {
        $local:tagObj.Name = $Name # Name is mandatory, may not be empty
        $local:tagObj.Description = $Description
        # check if AssetTagging rule was passed in as a parameter
        if ($AssetTaggingRule) {
            $local:tagObj.AssetTaggingRule = $AssetTaggingRule 
        } else {
            # no AssetTaggingRule param specified so set the default empty one
            $local:tagObj.AssetTaggingRule = $emptyTaggingRule 
        }
        # check if AssetAccountTaggingRule was passed in as a parameter
        if ($AssetAccountTaggingRule) {
            $local:tagObj.AssetAccountTaggingRule = $AssetAccountTaggingRule 
        } else {
            $local:tagObj.AssetAccountTaggingRule = $emptyTaggingRule
        }

        if ($Owner) {
            if (-not (Get-Module users)) {
                Import-module "$PSScriptRoot\users.psm1"
            }

            # get owner object and add to ManagedBy
            $newOwners = @()
            $Owner | ForEach-Object {
                $newOwners += (Resolve-SafeguardUserObject -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $_) 
            }
            $local:tagObj.ManagedBy = $newOwners
        } else {
            $local:tagObj.ManagedBy = @() # clear owners
        }
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "$local:RelPath" -Body $local:tagObj
    } else {
        throw "The tag with id $TagId could not be found."
    }
}


<#
.SYNOPSIS
Remove a tag from Safeguard via the Web API.

.DESCRIPTION
Remove a tag from Safeguard. 
If the tag is assigned to an asset or an account, a SafeguardMethodException is thrown.
Make sure it is not in use before you remove it.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID  or a string containing the name of the asset partition to delete a tag form.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to delete a tag from.
(If specified, this will override the AssetPartition parameter)

.PARAMETER TagToDelete
An integer containing the ID of the tag to delete, or a string containing the name of the tag to delete.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardTag -AccessToken $token -Appliance 10.5.32.54 -Insecure 5

.EXAMPLE
Remove-SafeguardTag prod
#>
function Remove-SafeguardTag {
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
        [object]$TagToDelete
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    # use the helper function Resolve-AssetPartitionId to get the asset partition id.
    $AssetPartitionId = Resolve-AssetPartitionId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId
    $local:RelPath = "AssetPartitions/$AssetPartitionId/Tags"    
    $local:TagId = (Resolve-SafeguardTagId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId $TagToDelete)

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "$local:RelPath/$($local:TagId)"
}


<#
.SYNOPSIS
Test an AssetTaggingRule on a tag.

.DESCRIPTION
Test what an AssetTaggingRule would do. 
This can be used to verify which assets would be assigned this tag if the rule is set.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition where the tag exists.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID where the tag exists.
(If specified, this will override the AssetPartition parameter)

.PARAMETER Tag
An integer containing the ID of the tag or a string containing the name of the tag.

.PARAMETER TaggingRule
A PSCustomObject with the JSON for the asset tagging rule.
For example '{
  "Description": null,
  "Enabled": true,
  "RuleConditionGroup": {
    "LogicalJoinType": "And",
    "Children": [
      {
        "TaggingGroupingCondition": {
          "ObjectAttribute": "Name",
          "CompareType": "Contains",
          "CompareValue": "prd.local"
        },
        "TaggingGroupingConditionGroup": null
      }
    ]
  }
}' | ConvertFrom-Json

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
$taggingRule = '{"Description": null,"Enabled": true,"RuleConditionGroup": {"LogicalJoinType": "And","Children": [{"TaggingGroupingCondition": {"ObjectAttribute": "Name","CompareType": "Contains","CompareValue": ".demo"},"TaggingGroupingConditionGroup": null}]}}' | ConvertFrom-Json
Test-SafeguardAssetTaggingRule 5 -TaggingRule $taggingRule

.EXAMPLE
$taggingRule = '{"Description": null,"Enabled": true,"RuleConditionGroup": {"LogicalJoinType": "And","Children": [{"TaggingGroupingCondition": {"ObjectAttribute": "Name","CompareType": "Contains","CompareValue": ".demo"},"TaggingGroupingConditionGroup": null}]}}' | ConvertFrom-Json
Test-SafeguardAssetTaggingRule -AssetPartitionId 1 -Tag prod -TaggingRule $taggingRule
#>
function Test-SafeguardAssetTaggingRule {
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
        [object]$Tag,
        [Parameter(Mandatory=$true,Position=1)]
        [PSCustomObject]$TaggingRule
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    # use the helper function Resolve-AssetPartitionId to get the asset partition id.
    $AssetPartitionId = Resolve-AssetPartitionId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId
    $local:TagId = (Resolve-SafeguardTagId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId $Tag)
    if ($local:TagId) {
        $local:RelPath = "AssetPartitions/$AssetPartitionId/Tags/$local:TagId/TestAssetRule"

        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "$local:RelPath" -Body $TaggingRule
    } else {
        throw "The tag with id $TagId could not be found."
    }
}



<#
.SYNOPSIS
Test an AssetAccountTaggingRule on a tag.

.DESCRIPTION
Test what an AssetAccountTaggingRule would do. 
This can be used to verify which accounts would be assigned this tag if the rule is set.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition where the tag exists.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID where the tag exists.
(If specified, this will override the AssetPartition parameter)

.PARAMETER Tag
An integer containing the ID of the tag or a string containing the name of the tag.

.PARAMETER TaggingRule
A PSCustomObject with the JSON for the asset account tagging rule.
For example '{
  "Description": null,
  "Enabled": true,
  "RuleConditionGroup": {
    "LogicalJoinType": "And",
    "Children": [
      {
        "TaggingGroupingCondition": {
          "ObjectAttribute": "Name",
          "CompareType": "Contains",
          "CompareValue": "domadmin"
        },
        "TaggingGroupingConditionGroup": null
      }
    ]
  }
}' | ConvertFrom-Json

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
$taggingRule = '{"Description": null,"Enabled": true,"RuleConditionGroup": {"LogicalJoinType": "And","Children": [{"TaggingGroupingCondition": {"ObjectAttribute": "Name","CompareType": "Contains","CompareValue": "domadmin"},"TaggingGroupingConditionGroup": null}]}}' | ConvertFrom-Json
Test-SafeguardAssetAccountTaggingRule 5 -TaggingRule $taggingRule

.EXAMPLE
$taggingRule = '{"Description": null,"Enabled": true,"RuleConditionGroup": {"LogicalJoinType": "And","Children": [{"TaggingGroupingCondition": {"ObjectAttribute": "Name","CompareType": "Contains","CompareValue": "domadmin"},"TaggingGroupingConditionGroup": null}]}}' | ConvertFrom-Json
Test-SafeguardAssetAccountTaggingRule -AssetPartitionId 1 -Tag prod -TaggingRule $taggingRule
#>
function Test-SafeguardAssetAccountTaggingRule {
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
        [object]$Tag,
        [Parameter(Mandatory=$true,Position=1)]
        [PSCustomObject]$TaggingRule
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    # use the helper function Resolve-AssetPartitionId to get the asset partition id.
    $AssetPartitionId = Resolve-AssetPartitionId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId
    $local:TagId = (Resolve-SafeguardTagId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId $Tag)
    if ($local:TagId) {
        $local:RelPath = "AssetPartitions/$AssetPartitionId/Tags/$local:TagId/TestAssetAccountRule"

        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "$local:RelPath" -Body $TaggingRule
    } else {
        throw "The tag with id $TagId could not be found."
    }
}


#======================= end of module =======================