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
        [object]$Partition
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not ($Partition -as [int]))
    {
        try
        {
            $local:Partitions = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET AssetPartitions `
                                 -Parameters @{ filter = "Name ieq '$Partition'" })
        }
        catch
        {
            Write-Verbose $_
            Write-Verbose "Caught exception with ieq filter, trying with q parameter"
            $local:Partitions = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET AssetPartitions `
                                     -Parameters @{ q = $Partition })
        }
        if (-not $local:Partitions)
        {
            throw "Unable to find asset partition matching '$Partition'"
        }
        if ($local:Partitions.Count -ne 1)
        {
            throw "Found $($local:Partitions.Count) asset partitions matching '$Partition'"
        }
        $local:Partitions[0].Id
    }
    else
    {
        $Partitions
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
        [object]$PartitionToGet
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSBoundParameters.ContainsKey("PartitionToGet"))
    {
        $local:PartitionId = Resolve-SafeguardAssetPartitionId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AssetToGet
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "AssetPartitions/$($local:PartitionId)"
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "AssetPartitions"
    }
}