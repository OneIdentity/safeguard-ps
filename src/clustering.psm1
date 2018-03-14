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
        [string]$Member
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    try
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "ClusterMembers/$Member" `
            -Parameters @{ fields = "Id,IsLeader,Name,Ipv4Address,Ipv6Address,SslCertificateThumbprint,EnrolledSince" }
    }
    catch
    {
        $local:Members = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET ClusterMembers `
                              -Parameters @{ filter = "(Id ieq '$Member') or (Name ieq '$Member') or (Ipv4Address eq '$Member') or (Ipv6Address ieq '$Member')";
                                             fields = "Id,IsLeader,Name,Ipv4Address,Ipv6Address,SslCertificateThumbprint,EnrolledSince" })
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
A string containing an ID, name, or address for the member appliance.

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
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET ClusterMembers `
            -Parameters @{fields = "Id,IsLeader,Name,Ipv4Address,Ipv6Address,SslCertificateThumbprint,EnrolledSince"}
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

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardClusterHealth -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
Get-SafeguardClusterHealth
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
        [switch]$Insecure
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET ClusterMembers).Health
}

<#
.SYNOPSIS
Get health (with forced update) of this appliance in the cluster from Safeguard via the Web API.

.DESCRIPTION
Force a health check on the currently connected appliance via the Web API and report its cluster health.
Running the health check synchronously makes this take more time than the normal cluster health call.

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
Get-SafeguardClusterApplianceHealth -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
Get-SafeguardClusterApplianceHealth
#>
function Get-SafeguardClusterApplianceHealth
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

    (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET ClusterMembers/Self).Health
}
