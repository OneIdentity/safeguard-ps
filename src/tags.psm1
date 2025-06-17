<#
#------------------------------------------------------------------------------#
# Module for handling Tag objects in the SPP
#------------------------------------------------------------------------------#
# This module has been contributed by iC Consult.
# Author: alexfungafoek-icc
#
# The code for Tags is structured similarly to the Asset.psm1 module.
# All functions require an active session to the Safeguard SPP. 
# Use Connect-Safeguard cmdlet to get a session, without an active session REST-API calls are not possible. 
# This module relies on assetpartitions.psm1 and assets.psm1 from the safeguard-ps module.
#>


<#
.SYNOPSIS
Helper function used to get the ID of a tag based on tag name or tag id

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
An integer containing the asset partition ID to get assets from.
(If specified, this will override the AssetPartition parameter)

.PARAMETER Tag
An integer containing the ID of the Tag or a string containing the name of the tag to get.

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

    # we need to use Resolve-AssetPartitionIdFromSafeguardSession from the assetpartitions.psm1 module to get the AssetPartition ID so check if the module is loaded
    if (-not (Get-Module assetpartitions)) {
        $sgModulePath = (Get-Module safeguard-ps).Path
        if (-not $sgModulePath) {
            # looks like safeguard-ps is not loaded. Makes no sense to continue as there is no session so throw exception
            throw "The module safeguard-ps is not loaded. Please load the module first and establish a session to the SPP."
        } else {
            # get the folder path for the safeguard-ps module and load the assetpartitions.psm1 module
            $sgModuleFolder = Split-Path -Path $sgModulePath
            Import-module "$sgModuleFolder\assetpartitions.psm1"
        }
    }

    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId)
    if (-not $AssetPartitionId) {
        $AssetPartitionId = -1
    }
    $local:RelPath = "AssetPartitions/$AssetPartitionId/Tags"

    if (-not ($Tag -as [int])) {
        # get tag based on name
        $local:Tags = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" -Parameters @{ filter = "Name ieq '$Tag'"; fields = "Id" })
    } 
    else {
        # Tag ID was supplied as param, not tag name
        if ($AssetPartitionId) {
            # Confirm that the tag with this ID actually exists.
            $local:Tags = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" -Parameters @{ filter = "Id eq $Tag and AssetPartitionId eq $AssetPartitionId"; fields = "Id" })
        }       
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
Get tag from Safeguard via the REST-API.

.DESCRIPTION
Get the tag from Safeguard. A tag can be added to Assets or Accounts.

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
An integer containing the asset partition ID to get assets from.
(If specified, this will override the AssetPartition parameter)

.PARAMETER TagToGet
An integer containing the ID of the Tag to get or a string containing the name of the tag.
If this value is empty, all tags on the Asset Partition will be returned.

.PARAMETER Fields
An array of the tag property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardTag -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardTag "tagname"
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
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Parameters = $null
    if ($Fields) {
        $local:Parameters = @{ fields = ($Fields -join ",")}
    }

    # we need to use Resolve-AssetPartitionIdFromSafeguardSession from the assetpartitions.psm1 module to get the AssetPartition ID so check if the module is loaded
    if (-not (Get-Module assetpartitions)) {
        $sgModulePath = (Get-Module safeguard-ps).Path
        if (-not $sgModulePath) {
            # looks like safeguard-ps is not loaded. Makes no sense to continue as there is no session so throw exception
            throw "The module safeguard-ps is not loaded. Please load the module first and establish a session to the SPP."
        } else {
            # get the folder path for the safeguard-ps module and load the assetpartitions.psm1 module
            $sgModuleFolder = Split-Path -Path $sgModulePath
            Import-module "$sgModuleFolder\assetpartitions.psm1"
        }
    }

    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId)
    if (-not $AssetPartitionId) {
        $AssetPartitionId = -1
    }
    $local:RelPath = "AssetPartitions/$AssetPartitionId/Tags"

    if ($PSBoundParameters.ContainsKey("TagToGet")) {
        # tag specified, so get single tag
        $local:TagId = (Resolve-SafeguardTagId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetPartitionId $AssetPartitionId $TagToGet)
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$local:RelPath/$($local:TagId)" -Parameters $local:Parameters
    } else {
        # if no Tag is specified, return all tags.
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" -Parameters $local:Parameters
    }
}


<#
.SYNOPSIS
Get the objects with this tag from Safeguard via the REST-API.

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
An integer containing the asset partition ID to get assets from.
(If specified, this will override the AssetPartition parameter)

.PARAMETER Tag
Mandatory parameter. An integer containing the ID of the Tag to get or a string containing the name of the tag.

.PARAMETER Fields
An array of the tag property names to return (can be one of the following Id, Name, DomainName, Type, AssetId, AssetName)

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardTagOccurences 2

.EXAMPLE
Get-SafeguardTagOccurences "tagname"
#>
function Get-SafeguardTagOccurences {
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
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Parameters = $null
    if ($Fields) {
        $local:Parameters = @{ fields = ($Fields -join ",")}
    }

    # we need to use Resolve-AssetPartitionIdFromSafeguardSession from the assetpartitions.psm1 module to get the AssetPartition ID so check if the module is loaded
    if (-not (Get-Module assetpartitions)) {
        $sgModulePath = (Get-Module safeguard-ps).Path
        if (-not $sgModulePath) {
            # looks like safeguard-ps is not loaded. Makes no sense to continue as there is no session so throw exception
            throw "The module safeguard-ps is not loaded. Please load the module first and establish a session to the SPP."
        } else {
            # get the folder path for the safeguard-ps module and load the assetpartitions.psm1 module
            $sgModuleFolder = Split-Path -Path $sgModulePath
            Import-module "$sgModuleFolder\assetpartitions.psm1"
        }
    }

    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId)
    if (-not $AssetPartitionId) {
        $AssetPartitionId = -1
    }
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
Get the tags from a specific asset via the REST-API.

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

.PARAMETER Fields
An array of the tag property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardAssetTags "assetname" 

.EXAMPLE
Get-SafeguardAssetTags 14 

.EXAMPLE
Get-SafeguardAssetTags "assetname" -Fields Id,Name,Description

#>
function Get-SafeguardAssetTags {
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
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Parameters = $null
    if ($Fields) {
        $local:Parameters = @{ fields = ($Fields -join ",")}
    }
    
    # we need to use function Resolve-SafeguardAssetId from the asset.psm1 module to get the Asset ID so check if the module is load
    if (-not (Get-Module assets)) {
        $local:sgModulePath = (Get-Module safeguard-ps).Path
        if (-not $local:sgModulePath) {
            # looks like safeguard-ps is not loaded. Makes no sense to continue as there is no session so throw exception
            throw "The module safeguard-ps is not loaded. Please load the module first and establish a session to the SPP."
        } else {
            # get the folder path for the safeguard-ps module and load the assetpartitions.psm1 module
            $sgModuleFolder = Split-Path -Path $local:sgModulePath
            Import-module "$sgModuleFolder\assets.psm1"
        }
    }

    $AssetId = (Resolve-SafeguardAssetId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -Asset $Asset)
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Assets/$AssetId/Tags" -Parameters $local:Parameters
}


<#
.SYNOPSIS
Update the tags on a specific asset via the REST-API.

.DESCRIPTION
Update the assigned tags on a specific asset.
Currently assigned tags are replaced with the tags specified.

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

.PARAMETER Tags
Mandatory parameter. A non-empty array of integers with the tag Ids or a non-empty string array of Tag names to assign to the asset. 

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Update-SafeguardAssetTags assetname -Tags @("Prod,VM,DMZ")

.EXAMPLE
Update-SafeguardAssetTags assetname -Tags @(1,2,3)

.EXAMPLE
Update-SafeguardAssetTags 8 -Tags @("Prod,VM,DMZ")

.EXAMPLE
$tags = @("VM","Prod","DMZ")
Update-SafeguardAssetTags -Asset "assetName" -Tags $tags

#>
function Update-SafeguardAssetTags {
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
        [object[]]$Tags
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
   
    # we need to use function Resolve-SafeguardAssetId from the asset.psm1 module to get the Asset ID so check if the module is load
    if (-not (Get-Module assets)) {
        $local:sgModulePath = (Get-Module safeguard-ps).Path
        if (-not $local:sgModulePath) {
            # looks like safeguard-ps is not loaded. Makes no sense to continue as there is no session so throw exception
            throw "The module safeguard-ps is not loaded. Please load the module first and establish a session to the SPP."
        } else {
            # get the folder path for the safeguard-ps module and load the assetpartitions.psm1 module
            $sgModuleFolder = Split-Path -Path $local:sgModulePath
            Import-module "$sgModuleFolder\assets.psm1"
        }
    }
    $AssetId = (Resolve-SafeguardAssetId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -Asset $Asset)    
    $local:body =@() # empty array to store the tag IDs.
    foreach ($tag in $Tags) {
        $tagId = Resolve-SafeguardTagId $tag
        if ($tagId) {
            # found the tag so add the ID to the body
            $local:body += [PSCustomObject]@{ Id = $tagId }
        }
    }            
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "Assets/$AssetId/Tags" -Body $local:body
}


<#
.SYNOPSIS
Get the tags from a specific account via the REST-API.

.DESCRIPTION
Get the assigned tags for a specific account.

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
Mandatory parameter. An integer containing the ID of the account or a string containing the name of the account to get the tags for.

.PARAMETER Fields
String array with the tag property names to return.
Example: Id,Name,Description

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardAccountTags "assetname" 

.EXAMPLE
Get-SafeguardAccountTags "accountname" -Fields Id,Name,Description

#>
function Get-SafeguardAccountTags {
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
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Parameters = $null
    if ($Fields) {
        $local:Parameters = @{ fields = ($Fields -join ",")}
    }
   
    # we need to use function Resolve-SafeguardAssetAccountId from the asset.psm1 module to get the Asset Account ID so check if the module is load
    if (-not (Get-Module assets)) {
        $local:sgModulePath = (Get-Module safeguard-ps).Path
        if (-not $local:sgModulePath) {
            # looks like safeguard-ps is not loaded. Makes no sense to continue as there is no session so throw exception
            throw "The module safeguard-ps is not loaded. Please load the module first and establish a session to the SPP."
        } else {
            # get the folder path for the safeguard-ps module and load the assetpartitions.psm1 module
            $sgModuleFolder = Split-Path -Path $local:sgModulePath
            Import-module "$sgModuleFolder\assets.psm1"
        }
    }

    $AccountId = (Resolve-SafeguardAssetAccountId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -Account $Account)
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "AssetAccounts/$AccountId/Tags" -Parameters $local:Parameters
}


<#
.SYNOPSIS
Update the tags on a specific account via the REST-API.

.DESCRIPTION
Update the assigned tags on a specific account. Currently assigned tags are replaced by the tags specified.

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

.PARAMETER Tags
Mandatory parameter. A non-empty array of integers with the Tag Ids or a non-empty string array with the Tag names to assign to the account

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Update-SafeguardAccountTags "accountName" -Tags @("Prod","DMZ","Tier1")

.EXAMPLE
Update-SafeguardAccountTags "accountName" -Tags @(1,2,3)

.EXAMPLE
$tags = @("TagName1", "TagName2", "TagName3")
Update-SafeguardAccountTags -Account 8 -Tags $tags

#>
function Update-SafeguardAccountTags {
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
        [Parameter(Mandatory=$true)]
        [object[]]$Tags
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
   
    # we need to use function Resolve-SafeguardAssetAccountId from the asset.psm1 module to get the Asset Account ID so check if the module is load
    if (-not (Get-Module assets)) {
        $local:sgModulePath = (Get-Module safeguard-ps).Path
        if (-not $local:sgModulePath) {
            # looks like safeguard-ps is not loaded. Makes no sense to continue as there is no session so throw exception
            throw "The module safeguard-ps is not loaded. Please load the module first and establish a session to the SPP."
        } else {
            # get the folder path for the safeguard-ps module and load the assetpartitions.psm1 module
            $sgModuleFolder = Split-Path -Path $local:sgModulePath
            Import-module "$sgModuleFolder\assets.psm1"
        }
    }
    $AccountId = (Resolve-SafeguardAssetAccountId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -Account $Account)

    $local:body =@() # empty array to store the tag IDs.
    if ($Tags) {
        # convert tag names to array and get the ID for each tag.
        $local:TagsArray = $Tags -split ","
        foreach ($tagName in $local:TagsArray) {
            $tagId = Resolve-SafeguardTagId $tagName
            if ($tagId) {
                # found the tag so add the ID to the body
                $local:body += [PSCustomObject]@{ Id = $tagId }
            }
        }
    }
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "AssetAccounts/$AccountId/Tags" -Body $local:body
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

.PARAMETER Fields
An array of the tag property names to return.
Example: Id,Name

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
Find-SafeguardTag -QueryFilter "Name contains 'prod'" -Fields Id,Name,Description -OrderBy Name
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
        [string[]]$Fields,
        [Parameter(Mandatory=$false)]
        [string[]]$OrderBy
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    # we need to use Resolve-AssetPartitionIdFromSafeguardSession from the assetpartitions.psm1 module to get the Asset Partition ID so check if the module is loaded
    if (-not (Get-Module assetpartitions)) {
        $sgModulePath = (Get-Module safeguard-ps).Path
        if (-not $sgModulePath) {
            # looks like safeguard-ps is not loaded. Makes no sense to continue as there is no session so throw exception
            throw "The module safeguard-ps is not loaded. Please load the module first and establish a session to the SPP."
        } else {
            # get the folder path for the safeguard-ps module and load the assetpartitions.psm1 module
            $sgModuleFolder = Split-Path -Path $sgModulePath
            Import-module "$sgModuleFolder\assetpartitions.psm1"
        }
    }

    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId)
    if (-not $AssetPartitionId) {
        $AssetPartitionId = -1
    }
    $local:RelPath = "AssetPartitions/$AssetPartitionId/Tags"

    if ($PSCmdlet.ParameterSetName -eq "Search") {
        $local:Parameters = @{ q = $SearchString }
    } else {
        $local:Parameters = @{ filter = $QueryFilter }
    }

    if ($Fields) {
        $local:Parameters["fields"] = ($Fields -join ",")
    }
    if ($OrderBy) {
        $local:Parameters["orderby"] = ($OrderBy -join ",")
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" -Parameters $local:Parameters
}


<#`
.SYNOPSIS
Create a new tag via the Web API.

.DESCRIPTION
Tags are text values which can be assed to an asset or account. They serve as meta data on an asset or account 
and can be used to store extra information such and the environment (e.g dev,test,acceptance,prod).
Each tag can have a list of owners.
The asset rule on a tag cannot be set via this powershell module.
The account rule on a tag cannot be set via this powershell module.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID  or a string containing the name of the asset partition where the tag should be created.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID where the tag should be created. (If specified, this will override the AssetPartition parameter)

.PARAMETER Name
A mandatory string containing the name for the new tag.

.PARAMETER Description
An optional string containing the description for the new tag.

.PARAMETER AssetTaggingRule
An optional string containing the JSON format of the Asset Tagging Rule

.PARAMETER AssetAccountTaggingRule
An optional string containing the JSON format of the Asset Account Tagging rule.
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
}'

.PARAMETER Owners
An optional string array containing the names of the owners for the new tag.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
New-SafeguardTag "prod"

.EXAMPLE
New-SafeguardTag "prod" "environment"

.EXAMPLE
New-SafeguardTag -Name "Non-prod" -Description "server environment" -Owners "Admin1","Admin2"

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
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [string]$Description,
        [Parameter(Mandatory=$false)]
        [string]$AssetTaggingRule,
        [Parameter(Mandatory=$false)]
        [string]$AssetAccountTaggingRule,
        [Parameter(Mandatory=$false)]
        [string[]]$Owners
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    # we need to use Resolve-AssetPartitionIdFromSafeguardSession from the assetpartitions.psm1 module so check if the module is loaded
    if (-not (Get-Module assetpartitions)) {
        $sgModulePath = (Get-Module safeguard-ps).Path
        if (-not $sgModulePath) {
            # looks like safeguard-ps is not loaded. Makes no sense to continue as there is no session so throw exception
            throw "The module safeguard-ps is not loaded. Please load the module first and establish a session to the SPP."
        } else {
            # get the folder path for the safeguard-ps module and load the assetpartitions.psm1 module
            $sgModuleFolder = Split-Path -Path $sgModulePath
            Import-module "$sgModuleFolder\assetpartitions.psm1"
        }
    }

    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId)
    if (-not $AssetPartitionId) {
        $AssetPartitionId = -1
    }

    $local:RelPath = "AssetPartitions/$AssetPartitionId/Tags"

    $local:Body = @{
        AssetPartitionId = $AssetPartitionId;
        Name = "$Name";
    }
    if ($PSBoundParameters.ContainsKey("Description")) { $local:Body.Description = $Description }
    if ($PSBoundParameters.ContainsKey("AssetTaggingRule")) { $local:Body.AssetTaggingRule = $AssetTaggingRule }
    if ($PSBoundParameters.ContainsKey("AssetAccountTaggingRule")) { $local:Body.AssetAccountTaggingRule = $AssetAccountTaggingRule }    
    if ($PSBoundParameters.ContainsKey("Owners")) {
        if (-not (Get-Module users)) {
            $sgModulePath = (Get-Module safeguard-ps).Path
            if (-not $sgModulePath) {
                # looks like safeguard-ps is not loaded. Makes no sense to continue as there is no session so throw exception
                throw "The module safeguard-ps is not loaded. Please load the module first and establish a session to the SPP."
            } else {
                # get the folder path for the safeguard-ps module and load the assetpartitions.psm1 module
                $sgModuleFolder = Split-Path -Path $sgModulePath
                Import-module "$sgModuleFolder\users.psm1"
                $local:Body.ManagedBy = @()
                $Owners | ForEach-Object {
                    $local:Body.ManagedBy += (Resolve-SafeguardUserObject -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $_)
                }        
            }
        }
    }
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "$local:RelPath" -Body $local:Body
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
An integer containing the asset partition ID to delete a tag form.
(If specified, this will override the AssetPartition parameter)

.PARAMETER TagToDelete
An integer containing the ID of the asset to remove or a string containing the name of the tag.

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

    # we need to use Resolve-AssetPartitionIdFromSafeguardSession from the assetpartitions.psm1 module to get the AssetPartition ID so check if the module is loaded
    if (-not (Get-Module assetpartitions)) {
        $sgModulePath = (Get-Module safeguard-ps).Path
        if (-not $sgModulePath) {
            # looks like safeguard-ps is not loaded. Makes no sense to continue as there is no session so throw exception
            throw "The module safeguard-ps is not loaded. Please load the module first and establish a session to the SPP."
        } else {
            # get the folder path for the safeguard-ps module and load the assetpartitions.psm1 module
            $sgModuleFolder = Split-Path -Path $sgModulePath
            Import-module "$sgModuleFolder\assetpartitions.psm1"
        }
    }

    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId)
    if (-not $AssetPartitionId) {
        $AssetPartitionId = -1
    }

    $local:RelPath = "AssetPartitions/$AssetPartitionId/Tags"    
    $local:TagId = (Resolve-SafeguardTagId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId $TagToDelete)

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "$local:RelPath/$($local:TagId)"
}


#======================= end of module =======================