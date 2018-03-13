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

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardClusterMember -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
Get-SafeguardClusterMember
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
        [switch]$Insecure
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET ClusterMembers `
        -Parameters @{fields = "Id,IsLeader,Name,Ipv4Address,Ipv6Address,SslCertificateThumbprint,EnrolledSince"}
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