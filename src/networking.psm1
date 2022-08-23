<#
.SYNOPSIS
Get the networking information for one of the appliance's network interfaces.

.DESCRIPTION
Either get all network interfaces or one network interface as specified by the
Interface parameter.  This will display networking information such as
IP address, netmask, gateway, and DNS servers.  Supports IPv4 and IPv6.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Interface
A string containing the name of the network interface to get (e.g. X0, X1).

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardNetworkInterface X0

.EXAMPLE
Get-SafeguardNetworkInterface
#>
function Get-SafeguardNetworkInterface
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
        [ValidateSet("Mgmt", "X0", "X1", IgnoreCase=$true)]
        [string]$Interface
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSBoundParameters.ContainsKey("Interface"))
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance GET "NetworkInterfaces/$($Interface.ToUpper())"
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance GET NetworkInterfaces
    }
}

<#
.SYNOPSIS
Change the networking information for the appliance's network interfaces.

.DESCRIPTION
Change the IP address, netmask, gateway, or DNS servers associated with a
Safeguard appliance network interface.  Supports IPv4 and IPv6.  If you
modify X0, you this script will wait until the interface becomes available
at the new address.  You can turn off this behavior with a switch.  You
may need to reconnect after modifying X0 using the Connect-Safeguard
cmdlet.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Interface
A string containing the name of the network interface to set (e.g. X0, X1).

.PARAMETER Ipv4Address
A string containing the new address.

.PARAMETER Ipv4NetMask
A string containing the netmask (e.g. 255.255.255.0).

.PARAMETER Ipv4Gateway
A string containing the address of a gateway.

.PARAMETER Ipv6Address
A string containing the new address.

.PARAMETER Ipv6PrefixLength
An integer containing the prefix length (e.g. 48).

.PARAMETER Ipv6Gateway
A string containing the address of a gateway.

.PARAMETER DnsServers
An array of strings containing addresses for DNS servers.

.PARAMETER NetworkObject
An object containing the existing network interface object with desired properties set.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Set-SafeguardNetworkInterface X0 -Ipv4Address "10.1.1.162" -Ipv4NetMask "255.255.255.0" -Ipv4Gateway "10.1.1.1" -DnsServers @("10.1.1.37","10.1.1.10")

.EXAMPLE
 Set-SafeguardNetworkInterface X0 -Ipv4Address "10.1.1.162"
#>
function Set-SafeguardNetworkInterface
{
    [CmdletBinding(DefaultParameterSetName="Attributes")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [ValidateSet("Mgmt", "X0", "X1", IgnoreCase=$true)]
        [string]$Interface,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false,Position=1)]
        [string]$Ipv4Address,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false,Position=2)]
        [string]$Ipv4NetMask,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false,Position=3)]
        [string]$Ipv4Gateway,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$Ipv6Address,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [int]$Ipv6PrefixLength,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$Ipv6Gateway,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string[]]$DnsServers,
        [Parameter(ParameterSetName="Object",Mandatory=$true)]
        [object]$NetworkObject,
        [Parameter(Mandatory=$false)]
        [switch]$NoWait
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local
    Import-Module -name "$PSScriptRoot\sg-utilities.psm1" -Scope Local

    if (-not ($PsCmdlet.ParameterSetName -eq "Object"))
    {
        $NetworkObject = (Get-SafeguardNetworkInterface -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Interface)

        if ($PSBoundParameters.ContainsKey("Ipv4Address")) { $NetworkObject.Ipv4Address = $Ipv4Address }
        if ($PSBoundParameters.ContainsKey("Ipv4NetMask")) { $NetworkObject.Ipv4NetMask = $Ipv4NetMask }
        if ($PSBoundParameters.ContainsKey("Ipv4Gateway")) { $NetworkObject.Ipv4Gateway = $Ipv4Gateway }
        if ($PSBoundParameters.ContainsKey("Ipv6Address")) { $NetworkObject.Ipv6Address = $Ipv6Address }
        if ($PSBoundParameters.ContainsKey("Ipv6PrefixLength")) { $NetworkObject.Ipv6PrefixLength = $Ipv6PrefixLength }
        if ($PSBoundParameters.ContainsKey("Ipv6Gateway")) { $NetworkObject.Ipv6Gateway = $Ipv6Gateway }
        if ($PSBoundParameters.ContainsKey("DnsServers")) { $NetworkObject.DnsServers = $DnsServers }
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance PUT "NetworkInterfaces/$($Interface.ToUpper())" -Body $NetworkObject

    if ($Interface -ieq "X0" -and -not $NoWait)
    {
        if ($PSBoundParameters.ContainsKey("Insecure"))
        {
            $Insecure = $true
        }
        elseif (-not $Appliance -and $SafeguardSession)
        {
            $Insecure = $SafeguardSession["Insecure"]
        }
        Write-Host "Waiting up to 5 minutes for Safeguard to come back online at new IP address."
        if ($NetworkObject.Ipv4Address)
        {
            Wait-ForSafeguardOnlineStatus -Appliance $NetworkObject.Ipv4Address -Insecure:$Insecure -Timeout 300
        }
        else
        {
            Wait-ForSafeguardOnlineStatus -Appliance $NetworkObject.Ipv6Address -Insecure:$Insecure -Timeout 300
        }
        Write-Host "You may need to re-run Connect-Safeguard to connect to the new address."
    }
}

<#
.SYNOPSIS
Get the DNS suffixes for one of the appliance's network interfaces.

.DESCRIPTION
Get the currently configured DNS suffixes for a single network interface.

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
Get-SafeguardDnsSuffix
#>
function Get-SafeguardDnsSuffix
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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance GET "NetworkDnsSuffixConfig"
}

<#
.SYNOPSIS
Set the DNS suffixes for one of the appliance's network interfaces.

.DESCRIPTION
Set the DNS suffixes for a single network interface.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER DnsSuffixes
An array of strings containing the DNS suffixes to set.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Set-SafeguardDnsSuffix example.com

.EXAMPLE
Set-SafeguardDnsSuffix "example.com","help.com"
#>
function Set-SafeguardDnsSuffix
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
        [string[]]$DnsSuffixes
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance PUT "NetworkDnsSuffixConfig" -Body @{
        DomainNames = $DnsSuffixes
    }
}
