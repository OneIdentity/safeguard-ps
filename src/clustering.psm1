# Helper
function Resolve-MemberAppliance
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
        [string]$Member,
        [Parameter(Mandatory=$false)]
        [switch]$WithHealth
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:GetHealth = ""
    if ($WithHealth)
    {
        $local:GetHealth = ",Health"
    }
    try
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Cluster/Members/$Member" `
            -Parameters @{ fields = "Id,IsLeader,Name,Ipv4Address,Ipv6Address,SslCertificateThumbprint,EnrolledSince$($local:GetHealth)" }
    }
    catch
    {
        $local:Members = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Cluster/Members" `
                              -Parameters @{ filter = "(Id ieq '$Member') or (Name ieq '$Member') or (Ipv4Address eq '$Member') or (Ipv6Address ieq '$Member')";
                                             fields = "Id,IsLeader,Name,Ipv4Address,Ipv6Address,SslCertificateThumbprint,EnrolledSince$($local:GetHealth)" })
        if (-not $local:Members)
        {
            throw "Unable to find cluster member matching '$Member'"
        }
        $local:Members[0]
    }
}
function Resolve-MemberApplianceId
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
        [string]$Member
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    (Resolve-MemberAppliance -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Member).Id
}
function Get-ClusterConnectivityReachabilityError
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [object]$HealthObjectSpecific
    )

    $local:Error = ""
    $HealthObjectSpecific.NodeConnectivity | ForEach-Object {
        if ($_.IsReachable -eq $false)
        {
            if (-not [string]::IsNullOrEmpty($local:Error))
            {
                $local:Error += ", "
            }
            $local:Error += "$($_.ApplianceId) is unreachable"
        }
    }
    $local:Error
}
function Get-ClusterHealthError
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Id,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$Name,
        [Parameter(Mandatory=$true,Position=2)]
        [string]$HealthType,
        [Parameter(Mandatory=$true,Position=3)]
        [object]$State,
        [Parameter(Mandatory=$true,Position=4)]
        [object]$HealthObjectSpecific
    )

    if ($State -eq "Quarantine")
    {
        "$Id ($Name) $HealthType Error: $Id is in Quarantine"
    }
    elseif ($State -eq "Offline")
    {
        "$Id ($Name) $HealthType Error: $Id is in Offline"
    }
    else
    {
        if ($HealthType -eq "Cluster Connectivity")
        {
            "$Id ($Name) $HealthType Error: $(Get-ClusterConnectivityReachabilityError $HealthObjectSpecific)"
        }
        else
        {
            "$Id ($Name) $HealthType Error: $($HealthObjectSpecific.Error)"
        }
    }
}

<#
.SYNOPSIS
Get cluster members from Safeguard via the Web API.

.DESCRIPTION
Retrieve the list of Safeguard appliances in this cluster from the Web API.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Member
A string containing an ID, name, or network address for the member appliance.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardClusterMember -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
Get-SafeguardClusterMember

.EXAMPLE
Get-SafeguardClusterMember 10.5.33.144

.EXAMPLE
Get-SafeguardClusterMember SG-00155D26E38A
#>
function Get-SafeguardClusterMember
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
        [string]$Member
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($Member)
    {
        Write-Verbose "Getting specific appliance '$AccessToken' '$Appliance' '$Insecure' '$Member'"
        Resolve-MemberAppliance -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Member
    }
    else
    {
        (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Cluster/Members").Health
    }
}

<#
.SYNOPSIS
Get health of cluster members from Safeguard via the Web API.

.DESCRIPTION
Retrieve the information based on most recent health check for all Safeguard appliances 
in this cluster via the Web API.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Member
A string containing an ID, name, or network address for the member appliance.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardClusterHealth -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
Get-SafeguardClusterHealth 10.5.33.144
#>
function Get-SafeguardClusterHealth
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
        [string]$Member
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($Member)
    {
        Write-Verbose "Getting specific appliance '$AccessToken' '$Appliance' '$Insecure' '$Member'"
        (Resolve-MemberAppliance -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Member -WithHealth).Health
    }
    else
    {
        (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Cluster/Members").Health
    }
}

<#
.SYNOPSIS
Add a new replica to the cluster via the Safeguard Web API.

.DESCRIPTION
Enroll a new replica into the cluster.  This cmdlet kicks off the enrollment process and
waits for it to complete unless the -NoWait flag is specified.  In order for enrollment
to work you have to be able to authenticate to the new replica as well.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER ReplicaNetworkAddress
A string containing the network address of the replica to add to the cluster.

.PARAMETER ReplicaAccessToken
A string containing the access token for the replica.

.PARAMETER ReplicaGui
Specify this flag to display the GUI login experience to authenticate to the replica (required for 2FA).

.PARAMETER NoWait
Specify this flag to continue immediately without waiting for the enrollment to complete.

.PARAMETER Timeout
A timeout value in seconds for adding cluster member (default: 1800s or 30m)

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Add-SafeguardClusterMember -AccessToken $token -Appliance 10.5.32.54 -ReplicaNetworkAddress 10.5.33.144

.EXAMPLE
Add-SafeguardClusterMember 10.5.33.144 -ReplicaAccessToken $tok -NoWait

.EXAMPLE
Add-SafeguardClusterMember 10.5.33.144 -ReplicaGui
#>
function Add-SafeguardClusterMember
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
        [string]$ReplicaNetworkAddress,
        [Parameter(Mandatory=$false)]
        [object]$ReplicaAccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$ReplicaGui,
        [Parameter(Mandatory=$false)]
        [switch]$NoWait,
        [Parameter(Mandatory=$false)]
        [int]$Timeout = 1800
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Import-Module -Name "$PSScriptRoot\sg-utilities.psm1" -Scope Local

    if (-not $PSBoundParameters.ContainsKey("ReplicaAccessToken"))
    {
        Write-Host "Authenticating to new replica appliance '$ReplicaNetworkAddress'..."
        if (-not ($PSBoundParameters.ContainsKey("Insecure")) -and $SafeguardSession)
        {
            # This only covers the case where Invoke-SafeguardMethod is called directly.
            # All script callers in the module will specify the flag, e.g. -Insecure:$Insecure
            # which will not hit this code.
            $Insecure = $SafeguardSession["Insecure"]
        }
        $ReplicaAccessToken = (Connect-Safeguard -Insecure:$Insecure $ReplicaNetworkAddress -Gui:$ReplicaGui -NoSessionVariable)
    }

    if (-not $ReplicaAccessToken)
    {
        throw "Failed to authenticate to replica '$ReplicaNetworkAddress'"
    }

    if (-not $Appliance -and $SafeguardSession)
    {
        $Appliance = $SafeguardSession["Appliance"]
    }

    Write-Host "Joining '$ReplicaNetworkAddress' to cluster (primary: '$Appliance')..."
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "Cluster/Members" `
        -Body @{ Hostname = $ReplicaNetworkAddress; AuthenticationToken = $ReplicaAccessToken }

    if (-not $NoWait)
    {
        Wait-ForClusterOperation -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -Timeout $Timeout
    }
    else
    {
        Write-Host "Not waiting for completion--use Get-SafeguardClusterMember and Get-SafeguardClusterOperationStatus to see status"
    }
}

<#
.SYNOPSIS
Remove a replica from the cluster via the Safeguard Web API.

.DESCRIPTION
Remove a replica from the cluster.  This cmdlet kicks off the removal process but
does not wait for it to complete.  Unjoining takes very little time for the remaining
cluster members but it takes a long time for the unjoined replica to reconfigure itself
outside the cluster.  Use Get-SafeguardStatus to see when the unjoined replica is ready.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Member
A string containing an ID, name, or network address for the member appliance.

.PARAMETER Force
Specify this flag to force remove the an appliance without quorum.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardClusterMember SG-00155D26E38D

.EXAMPLE
Remove-SafeguardClusterMember 10.5.33.144 -Force
#>
function Remove-SafeguardClusterMember
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
        [string]$Member,
        [Parameter(Mandatory=$false)]
        [switch]$Force
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:MemberId = (Resolve-MemberApplianceId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Member)
    if (-not $Force)
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "Cluster/Members/$MemberId"
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "Cluster/Members/Reset" `
            -JsonBody "{`"Members`": [{`"Id`": `"$($local:MemberId)`",`"IsLeader`": true}],`"PrimaryId`": `"$($local:MemberId)`"}"
    }

    Write-Host "Not waiting for completion--use Get-SafeguardStatus and Get-SafeguardClusterOperationStatus to see status"
}

<#
.SYNOPSIS
Get cluster primary from Safeguard via the Web API.

.DESCRIPTION
Retrieve current primary appliance in this cluster from the Web API.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Member
A string containing an ID, name, or network address for the member appliance.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardClusterPrimary -AccessToken $SafeguardSession.AccessToken -Appliance 10.5.32.54

.EXAMPLE
Get-SafeguardClusterPrimary
#>
function Get-SafeguardClusterPrimary
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Cluster/Members" `
            -Parameters @{fields = "Id,IsLeader,Name,Ipv4Address,Ipv6Address,SslCertificateThumbprint,EnrolledSince"
                          filter = "IsLeader eq true"}
}

<#
.SYNOPSIS
Set appliance as primary for the cluster via the Safeguard Web API.

.DESCRIPTION
This cmdlet can be used to perform replica failover.  This cmdlet starts the process
of reconfiguring the specified appliance as the primary.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Member
A string containing an ID, name, or network address for the member appliance.

.PARAMETER NoWait
Specify this flag to continue immediately without waiting for the failover to complete.

.PARAMETER Timeout
A timeout value in seconds for setting cluster primary (default: 600s or 10m)

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Set-SafeguardClusterPrimary -AccessToken $token -Appliance 10.5.33.144 10.5.33.144

.EXAMPLE
Set-SafeguardClusterPrimary SG-00155D26E38D

.EXAMPLE
Set-SafeguardClusterPrimary 10.5.33.144 -Force
#>
function Set-SafeguardClusterPrimary
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
        [string]$Member,
        [Parameter(Mandatory=$false)]
        [switch]$NoWait,
        [Parameter(Mandatory=$false)]
        [int]$Timeout = 600
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Import-Module -Name "$PSScriptRoot\sg-utilities.psm1" -Scope Local

    $MemberId = (Resolve-MemberApplianceId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Member)
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "Cluster/Members/$MemberId/Promote"

    if (-not $NoWait)
    {
        Wait-ForClusterOperation -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -Timeout $Timeout
    }
    else
    {
        Write-Host "Not waiting for completion--use Get-SafeguardClusterMember and Get-SafeguardClusterOperationStatus to see status"
    }
}

<#
.SYNOPSIS
Enable current primary appliance in the cluster via the Safeguard Web API.

.DESCRIPTION
This cmdlet can be used to activate a primary that is in StandaloneReadOnly mode.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER NoWait
Specify this flag to continue immediately without waiting for the restore to complete.

.PARAMETER Timeout
A timeout value in seconds for enable (default: 600s or 10m)

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Enable-SafeguardClusterPrimary -AccessToken $token -Appliance 10.5.33.144

.EXAMPLE
Enable-SafeguardClusterPrimary
#>
function Enable-SafeguardClusterPrimary
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
        [switch]$NoWait,
        [Parameter(Mandatory=$false)]
        [int]$Timeout = 600
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Import-Module -Name "$PSScriptRoot\sg-utilities.psm1" -Scope Local

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "Cluster/Members/ActivatePrimary"

    if (-not $NoWait)
    {
        Wait-ForSafeguardOnlineStatus -Appliance $Appliance -Insecure:$Insecure -Timeout $Timeout
    }
}

<#
.SYNOPSIS
Get the status of a currently running Safeguard cluster operation via the Safeguard Web API.

.DESCRIPTION
This cmdlet can be used to determine if any cluster operation has completed.  When return value
reports the current operation as None, then the operation is complete.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardClusterOperationStatus -AccessToken $token -Appliance 10.5.33.144

.EXAMPLE
Get-SafeguardClusterOperationStatus
#>
function Get-SafeguardClusterOperationStatus
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure
    )

    Import-Module -Name "$PSScriptRoot\sg-utilities.psm1" -Scope Local

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET ClusterStatus
}

<#
.SYNOPSIS
Attempt to force the completion of a currently running Safeguard cluster operation via the Safeguard Web API.

.DESCRIPTION
This cmdlet can be used to force a cluster operation to complete that is not being acknowledged by all 
appliances in the cluster.  This is not always possible with the current connection.  You may need to
connect to a different appliance in the cluster to perform this operation depending on which appliance is
having trouble.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Timeout
A timeout value in seconds for unlocking cluster (default: 600s or 10m)

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Unlock-SafeguardCluster -AccessToken $token -Appliance 10.5.33.144

.EXAMPLE
Unlock-SafeguardCluster
#>
function Unlock-SafeguardCluster
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
        [int]$Timeout = 600
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:OpStatus = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET ClusterStatus)
    if ($local:OpStatus.Operation -eq "None")
    {
        Write-Host "No cluster operation is currently running."
        $local:OpStatus
    }
    else
    {
        Import-Module -Name "$PSScriptRoot\sg-utilities.psm1" -Scope Local
        Write-Host "Attempting to force completion of $($local:OpStatus.Operation) operation..."
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST ClusterStatus/ForceComplete
        Wait-ForClusterOperation -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -Timeout $Timeout
    }
}

<#
.SYNOPSIS
Get summary of information about the Safeguard cluster via the Safeguard Web API.

.DESCRIPTION
This cmdlet will report on the current cluster primary and all of the members.  It will
report on any errors currently found in cluster health as well as the status of any
on-going cluster operations.  All information is taken from the perspective of the
connected appliance.  All of the health information is reported from the cache.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardClusterSummary -AccessToken $token -Appliance 10.5.33.144

.EXAMPLE
Get-SafeguardClusterSummary
#>
function Get-SafeguardClusterSummary
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure
    )

    $ApplianceId = (Invoke-SafeguardMethod -Anonymous -Appliance $Appliance -Insecure:$Insecure Notification GET Status).ApplianceId
    Write-Host "Cluster Health Summary from perspective of Appliance ID: $ApplianceId"

    Write-Host "`n---Primary---"
    Write-Host (
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Cluster/Members" `
            -Parameters @{fields = "Id,Name,Ipv4Address,Ipv6Address"
                          filter = "IsLeader eq true"} | Format-Table | Out-String)

    Write-Host "---Cluster---"
    $local:Members = Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Cluster/Members" `
                             -Parameters @{fields = "Id,Name,Ipv4Address,Ipv6Address,Health"}
    $local:Errors = @()
    Write-Host (
    $local:Members | ForEach-Object {
        $local:Object = (New-Object -TypeName PSObject -Property @{
            Id = $_.Id
            Name = $_.Name
            State = $_.Health.State
            Ipv4Address = $_.Ipv4Address
            Ipv6Address = $_.Ipv6Address
        })
        if ($_.Health.ClusterCommunication.Status -eq "Healthy")
        {
            $local:Object | Add-Member -MemberType NoteProperty -Name "Communication" -Value "$([Char]8730)"
        }
        else
        {
            $local:Object | Add-Member -MemberType NoteProperty -Name "Communication" -Value "$($_.Health.ClusterCommunication.Status)"
            $local:Errors += (Get-ClusterHealthError $_.Id $_.Name "Cluster Communication" $_.Health.State $_.Health.ClusterCommunication)
        }
        if ($_.Health.ClusterConnectivity.Status -eq "Healthy")
        {
            $local:Object | Add-Member -MemberType NoteProperty -Name "Connectivity" -Value "$([Char]8730)"
        }
        else
        {
            $local:Object | Add-Member -MemberType NoteProperty -Name "Connectivity" -Value "$($_.Health.ClusterConnectivity.Status)"
            $local:Errors += (Get-ClusterHealthError $_.Id $_.Name "Cluster Connectivity" $_.Health.State $_.Health.ClusterConnectivity)
        }
        if ($_.Health.AccessWorkflow.Status -eq "Healthy")
        {
            $local:Object | Add-Member -MemberType NoteProperty -Name "Workflow" -Value "$([Char]8730)"
        }
        else
        {
            $local:Object | Add-Member -MemberType NoteProperty -Name "Workflow" -Value "$($_.Health.AccessWorkflow.Status)"
            $local:Errors += (Get-ClusterHealthError $_.Id $_.Name "Access Workflow" $_.Health.State $_.Health.AccessWorkflow)
        }
        if ($_.Health.PolicyData.Status -eq "Healthy")
        {
            $local:Object | Add-Member -MemberType NoteProperty -Name "Policy" -Value "$([Char]8730)"
        }
        else
        {
            $local:Object | Add-Member -MemberType NoteProperty -Name "Policy" -Value "$($_.Health.PolicyData.Status)"
            $local:Errors += (Get-ClusterHealthError $_.Id $_.Name "Policy Data" $_.Health.State $_.Health.PolicyData)
        }
        if ($_.Health.SessionsModule.Status -eq "Healthy")
        {
            $local:Object | Add-Member -MemberType NoteProperty -Name "Sessions" -Value "$([Char]8730)"
        }
        else
        {
            $local:Object | Add-Member -MemberType NoteProperty -Name "Sessions" -Value "$($_.Health.SessionsModule.Status)"
            $local:Errors += (Get-ClusterHealthError $_.Id $_.Name "Sessions Module" $_.Health.State $_.Health.SessionsModule)
        }
        $local:Object
    } | Format-Table Id,Name,State,Ipv4Address,Ipv6Address,Communication,Connectivity,Workflow,Policy,Sessions -AutoSize | Out-String)

    Write-Host "---Cluster Errors---`n"
    Write-Host(
    $local:Errors | Out-String)

    Write-Host "`n`n---Operation Status---"
    Write-Host(
    Get-SafeguardClusterOperationStatus -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure | Format-Table | Out-String)
}
