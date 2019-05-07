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