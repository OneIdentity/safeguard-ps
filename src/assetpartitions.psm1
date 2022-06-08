# Helpers
function Resolve-SafeguardAssetPartitionId
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$AssetPartition
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($AssetPartition.Id -as [int])
    {
        $AssetPartition = $AssetPartition.Id
    }

    if (-not ($AssetPartition -as [int]))
    {
        try
        {
            $local:Partitions = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET AssetPartitions `
                                 -Parameters @{ filter = "Name ieq '$AssetPartition'"; fields = "Id" })
        }
        catch
        {
            Write-Verbose $_
            Write-Verbose "Caught exception with ieq filter, trying with q parameter"
            $local:Partitions = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET AssetPartitions `
                                     -Parameters @{ q = $AssetPartition; fields = "Id" })
        }
        if (-not $local:Partitions)
        {
            throw "Unable to find asset partition matching '$AssetPartition'"
        }
        if ($local:Partitions.Count -ne 1)
        {
            throw "Found $($local:Partitions.Count) asset partitions matching '$AssetPartition'"
        }
        $local:Partitions[0].Id
    }
    else
    {
        $AssetPartition
    }
}
function Resolve-AssetPartitionIdFromSafeguardSession
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
        [Parameter(Mandatory=$false)]
        [switch]$UseDefault = $false
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $AssetPartitionId -and $AssetPartition)
    {
        $AssetPartitionId = (Resolve-SafeguardAssetPartitionId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AssetPartition)
    }

    if (-not $AssetPartitionId)
    {
        if ($SafeguardSession -and $SafeguardSession["AssetPartitionId"])
        {
            $AssetPartitionId = $SafeguardSession["AssetPartitionId"]
        }
        else
        {
            if ($UseDefault)
            {
                # Default behavior is Macrocosm
                $AssetPartitionId = -1
            }
        }
    }

    $AssetPartitionId
}


<#
.SYNOPSIS
Get asset partitions via the Web API.

.DESCRIPTION
Asset partitions are an administrative container for Safeguard assets.  Asset
partitions may be given owners who can manage only the assets within that
asset partition.  This cmdlet gets the asset partitions that the caller has
access to.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartitionToGet
An integer containing an ID  or a string containing the name of the asset partition to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardAssetPartition -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardAssetPartition "Unix Servers"
#>
function Get-SafeguardAssetPartition
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [object]$AssetPartitionToGet
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSBoundParameters.ContainsKey("AssetPartitionToGet"))
    {
        $local:PartitionId = Resolve-SafeguardAssetPartitionId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AssetPartitionToGet
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "AssetPartitions/$($local:PartitionId)"
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "AssetPartitions"
    }
}

<#
.SYNOPSIS
Create a new asset partitions via the Web API.

.DESCRIPTION
Asset partitions are an administrative container for Safeguard assets.  Asset
partitions may be given owners who can manage only the assets within that
asset partition.  This cmdlet creates an asset partitions and can also assign
the owners.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Name
A string containing the name for the new asset partition.

.PARAMETER Description
A string containing the description for the new asset partition.

.PARAMETER Owners
A list strings containing the names of the owners for the new asset partition.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardAssetPartition -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
New-SafeguardAssetPartition "Unix Servers"

.EXAMPLE
New-SafeguardAssetPartition "Unix Servers" -Description "Servers for the Unix team" -Owners "Admin1","Admin2"
#>
function New-SafeguardAssetPartition
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [string]$Description,
        [Parameter(Mandatory=$false)]
        [string[]]$Owners
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Body = @{
        Name = $Name
    }
    if ($PSBoundParameters.ContainsKey("Description")) { $local:Body.Description = $Description }
    if ($PSBoundParameters.ContainsKey("Owners"))
    {
        Import-Module -Name "$PSScriptRoot\users.psm1" -Scope Local
        $local:Body.ManagedBy = @()
        $Owners | ForEach-Object {
            $local:Body.ManagedBy += (Resolve-SafeguardUserObject -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $_)
        }
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "AssetPartitions" -Body $local:Body
}

<#
.SYNOPSIS
Create a new asset partitions via the Web API.

.DESCRIPTION
Asset partitions are an administrative container for Safeguard assets.  Asset
partitions may be given owners who can manage only the assets within that
asset partition.  This cmdlet removes an asset partitions and can also assign
any existing assets to another asset partition.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartitionToDelete
An integer containing an ID  or a string containing the name of the asset partition to remove.

.PARAMETER FailoverPartition
An integer containing an ID  or a string containing the name of the asset partition to move
existing assets to. (Default: Macrocosm)

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardAssetPartition -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Remove-SafeguardAssetPartition "Unix Servers"

.EXAMPLE
Remove-SafeguardAssetPartition "Unix Servers" -FailoverPartition "Other Partition"
#>
function Remove-SafeguardAssetPartition
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [object]$AssetPartitionToDelete,
        [Parameter(Mandatory=$false)]
        [object]$FailoverPartition
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $PSBoundParameters.ContainsKey("AssetPartitionToDelete"))
    {
        $AssetPartitionToDelete = (Read-Host "AssetPartitionToDelete")
    }
    $local:PartitionId = (Resolve-SafeguardAssetPartitionId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AssetPartitionToDelete)

    if ($PSBoundParameters.ContainsKey("FailoverPartition"))
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "AssetPartitions/$($local:PartitionId)" `
            -Parameters @{
                failoverPartitionId = (Resolve-SafeguardAssetPartitionId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $FailoverPartition)
            }
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "AssetPartitions/$($local:PartitionId)"
    }
}

<#
.SYNOPSIS
Edit existing asset partition in Safeguard via the Web API.

.DESCRIPTION
Asset partitions are an administrative container for Safeguard assets. Asset
partitions may be given owners who can manage only the assets within that
asset partition. This cmdlet edits an existing asset partition.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartitionToEdit
An integer containing the ID of the asset partition to edit or a string containing the name.

.PARAMETER Name
A string containing the name for this asset partition.

.PARAMETER Description
A string containing a description for this asset.

.PARAMETER Owners
A list strings containing the names of the owners for the asset partition.

.PARAMETER AssetPartitionObject
An object containing the existing asset partition with desired properties set.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Edit-SafeguardAssetPartition -AccessToken $token -Appliance 10.5.32.54 -Insecure -AssetPartitionObject $obj

.EXAMPLE
Edit-SafeguardAssetPartition "Unix Servers" -Description "Servers for the Unix team" -Owners "Admin3","Admin4"
#>
function Edit-SafeguardAssetPartition
{
    [CmdletBinding(DefaultParameterSetName="Attributes")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false,Position=0)]
        [object]$AssetPartitionToEdit,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$Name,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$Description,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string[]]$Owners,
        [Parameter(ParameterSetName="Object",Mandatory=$true,ValueFromPipeline=$true)]
        [object]$AssetPartitionObject
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PsCmdlet.ParameterSetName -eq "Object" -and -not $AssetPartitionObject)
    {
        throw "AssetPartitionObject must not be null"
    }

    if ($PsCmdlet.ParameterSetName -eq "Attributes")
    {
        if (-not $PSBoundParameters.ContainsKey("AssetPartitionToEdit"))
        {
            $AssetPartitionToEdit = (Read-Host "AssetPartitionToEdit")
        }
        $local:AssetPartitionId = Resolve-SafeguardAssetPartitionId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AssetPartitionToEdit
    }

    if (-not ($PsCmdlet.ParameterSetName -eq "Object"))
    {
        $AssetPartitionObject = (Get-SafeguardAssetPartition -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $local:AssetPartitionId)

        if ($PSBoundParameters.ContainsKey("Name")) { $AssetPartitionObject.Name = $Name }
        if ($PSBoundParameters.ContainsKey("Description")) { $AssetPartitionObject.Description = $Description }
        if ($PSBoundParameters.ContainsKey("Owners"))
        {
            Import-Module -Name "$PSScriptRoot\users.psm1" -Scope Local
            $AssetPartitionObject.ManagedBy = @()
            $Owners | ForEach-Object {
                $AssetPartitionObject.ManagedBy += (Resolve-SafeguardUserObject -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $_)
            }
        }
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "AssetPartitions/$($AssetPartitionObject.Id)" -Body $AssetPartitionObject
}

<#
.SYNOPSIS
Get owners of an asset partition in Safeguard via the Web API.

.DESCRIPTION
Asset partitions are an administrative container for Safeguard assets. Asset
partitions may be given owners who can manage only the assets within that
asset partition. This cmdlet gets the list of owners of an asset partition.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartitionToGet
An integer containing the ID of the asset partition to edit or a string containing the name.

.PARAMETER Fields
An array of the user property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardAssetPartitionOwner

.EXAMPLE
Get-SafeguardAssetPartitionOwner "Unix Servers"
#>
function Get-SafeguardAssetPartitionOwner
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [object]$AssetPartitionToGet,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:PartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                                   -AssetPartition $AssetPartitionToGet)
    if (-not $local:PartitionId)
    {
        $AssetPartitionToGet = (Read-Host "AssetPartitionToGet")
        $local:PartitionId = (Resolve-SafeguardAssetPartitionId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                                       -AssetPartition $AssetPartitionToGet)
    }

    $local:Parameters = $null
    if ($Fields)
    {
        $local:Parameters = @{ fields = ($Fields -join ",")}
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure core GET "AssetPartitions/$($local:PartitionId)/ManagedBy" `
        -Parameters $local:Parameters
}

<#
.SYNOPSIS
Add owners to an asset partition in Safeguard via the Web API.

.DESCRIPTION
Asset partitions are an administrative container for Safeguard assets. Asset
partitions may be given owners who can manage only the assets within that
asset partition. This cmdlet adds users to the list of owners of an asset partition.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartitionToEdit
An integer containing the ID of the asset partition to edit or a string containing the name.

.PARAMETER UserList
A list strings containing the names of the owners to add to the asset partition.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Add-SafeguardAssetPartitionOwner -UserList "local\Dave","example.com\user1"

.EXAMPLE
Add-SafeguardAssetPartitionOwner "Unix Servers" "local\Dave","example.com\user1"
#>
function Add-SafeguardAssetPartitionOwner
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [object]$AssetPartitionToEdit,
        [Parameter(Mandatory=$true, Position=1)]
        [object[]]$UserList
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:PartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                                   -AssetPartition $AssetPartitionToEdit)
    if (-not $local:PartitionId)
    {
        $AssetPartitionToEdit = (Read-Host "AssetPartitionToEdit")
        $local:PartitionId = (Resolve-SafeguardAssetPartitionId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                                       -AssetPartition $AssetPartitionToEdit)
    }

    [object[]]$local:Users = $null
    foreach ($local:User in $UserList)
    {
        $local:ResolvedUser = (Get-SafeguardUser -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -UserToGet $local:User -Fields Id,Name,PrimaryAuthenticationProviderId)
        $local:Users += $($local:ResolvedUser)
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure core POST "AssetPartitions/$($local:PartitionId)/ManagedBy/Add" -Body $local:Users
}

<#
.SYNOPSIS
Remove owners from an asset partition in Safeguard via the Web API.

.DESCRIPTION
Asset partitions are an administrative container for Safeguard assets. Asset
partitions may be given owners who can manage only the assets within that
asset partition. This cmdlet removes users from the list of owners of an asset partition.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartitionToEdit
An integer containing the ID of the asset partition to edit or a string containing the name.

.PARAMETER UserList
A list strings containing the names of the owners to remove from the asset partition.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardAssetPartitionOwner -UserList "local\Dave","example.com\user1"

.EXAMPLE
Remove-SafeguardAssetPartitionOwner "Unix Servers" "local\Dave","example.com\user1"
#>
function Remove-SafeguardAssetPartitionOwner
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [object]$AssetPartitionToEdit,
        [Parameter(Mandatory=$true, Position=1)]
        [object[]]$UserList
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:PartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                                   -AssetPartition $AssetPartitionToEdit)
    if (-not $local:PartitionId)
    {
        $AssetPartitionToEdit = (Read-Host "AssetPartitionToGet")
        $local:PartitionId = (Resolve-SafeguardAssetPartitionId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                                       -AssetPartition $AssetPartitionToEdit)
    }

    [object[]]$local:Users = $null
    foreach ($local:User in $UserList)
    {
        $local:ResolvedUser = (Get-SafeguardUser -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -UserToGet $local:User -Fields Id,Name,PrimaryAuthenticationProviderId)
        $local:Users += $($local:ResolvedUser)
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure core POST "AssetPartitions/$($local:PartitionId)/ManagedBy/Remove" -Body $local:Users
}

<#
.SYNOPSIS
Enter an asset partition so that asset administration is done in that context.

.DESCRIPTION
Asset partitions are an administrative container for Safeguard assets.  Asset
partitions may be given owners who can manage only the assets within that
asset partition.  This cmdlet places the session in the context of an asset
partition so that subsequent operations are done in that context.

.PARAMETER AssetPartitionToEnter
An integer containing the ID of the asset partition to enter or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Enter-SafeguardAssetPartition "Unix Servers"

.EXAMPLE
Enter-SafeguardAssetPartition 15
#>
function Enter-SafeguardAssetPartition
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,Position=0)]
        [object]$AssetPartitionToEnter
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $SafeguardSession)
    {
        throw "This cmdlet requires that you log in with the Connect-Safeguard cmdlet"
    }

    if (-not $PSBoundParameters.ContainsKey("AssetPartitionToEnter"))
    {
        $AssetPartitionToEnter = (Read-Host "AssetPartitionToEnter")
    }

    $local:Partition = (Get-SafeguardAssetPartition -Appliance $AccessToken -AccessToken $AccessToken -Insecure:$Insecure $AssetPartitionToEnter)
    if ($local:Partition)
    {
        $SafeguardSession["AssetPartitionId"] = $local:Partition.Id
        Write-Host "Entering [$($local:Partition.Id)] $($local:Partition.Name)"
        if ($local:Partition.Description)
        {
            Write-Host "  Description: $($local:Partition.Description)"
        }
    }
}

<#
.SYNOPSIS
Exit an asset partition so that asset administration is done globally.

.DESCRIPTION
Asset partitions are an administrative container for Safeguard assets.  Asset
partitions may be given owners who can manage only the assets within that
asset partition.  This cmdlet moves the session back out of  the context of an
asset partition so that subsequent operations are done globally.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Exit-SafeguardAssetPartition
#>
function Exit-SafeguardAssetPartition
{
    [CmdletBinding()]
    Param(
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $SafeguardSession)
    {
        throw "This cmdlet requires that you log in with the Connect-Safeguard cmdlet"
    }

    if (-not $SafeguardSession["AssetPartitionId"])
    {
        throw "You have not entered an asset partition"
    }

    $local:Partition = (Get-SafeguardCurrentAssetPartition)
    Write-Host "Leaving [$($local:Partition.Id)] $($local:Partition.Name)"
    $SafeguardSession["AssetPartitionId"] = $null
}

<#
.SYNOPSIS
Display the asset partition context of your current session.

.DESCRIPTION
Asset partitions are an administrative container for Safeguard assets.  Asset
partitions may be given owners who can manage only the assets within that
asset partition.  This cmdlet reports on the asset partition that has been
entered or it returns nothing if you have not entered an asset partition.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardCurrentAssetPartition
#>
function Get-SafeguardCurrentAssetPartition
{
    [CmdletBinding()]
    Param(
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $SafeguardSession)
    {
        throw "This cmdlet requires that you log in with the Connect-Safeguard cmdlet"
    }

    if ($SafeguardSession["AssetPartitionId"])
    {
        Get-SafeguardAssetPartition $SafeguardSession["AssetPartitionId"]
    }
}
