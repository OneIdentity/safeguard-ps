# Helper
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

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not ($AssetPartition -as [int]))
    {
        try
        {
            $local:Partitions = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET AssetPartitions `
                                 -Parameters @{ filter = "Name ieq '$AssetPartition'" })
        }
        catch
        {
            Write-Verbose $_
            Write-Verbose "Caught exception with ieq filter, trying with q parameter"
            $local:Partitions = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET AssetPartitions `
                                     -Parameters @{ q = $AssetPartition })
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

    $ErrorActionPreference = "Stop"
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

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Body = @{
        Name = $Name
    }
    if ($PSBoundParameters.ContainsKey("Description")) { $local:Body.Description = $Description }
    if ($PSBoundParameters.ContainsKey("Owners")) 
    {
        Import-Module -Name "$PSScriptRoot\users.psm1" -Scope Local
        $local:Body.Owners = @()
        $Owners | ForEach-Object {
            $local:Body.Owners += (Resolve-SafeguardUserObject -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $_)
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

    $ErrorActionPreference = "Stop"
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
