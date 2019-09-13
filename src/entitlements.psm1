# Helpers
function Resolve-SafeguardEntitlementId
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
        [object]$Entitlement
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not ($Entitlement -as [int]))
    {
        try
        {
            $local:Entitlements = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Roles `
                                 -Parameters @{ filter = "Name ieq '$Entitlement'" })
        }
        catch
        {
            Write-Verbose $_
            Write-Verbose "Caught exception with ieq filter, trying with q parameter"
            $local:Entitlements = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Roles `
                                 -Parameters @{ q = $Entitlement })
        }
        if (-not $local:Entitlements)
        {
            throw "Unable to find Entitlement matching '$Entitlement'"
        }
        if ($local:Entitlements.Count -ne 1)
        {
            throw "Found $($local:Entitlements.Count) Entitlements matching '$Entitlement'"
        }
        $local:Entitlements[0].Id
    }
    else
    {
        $Entitlement
    }
}

<#
.SYNOPSIS
Get entitlements in Safeguard via the Web API.

.DESCRIPTION
Entitlement is a set of access request policies that restrict system access to authorized users

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER EntitlementToGet
An integer containing the ID or a string containing the name of the entitlement to get.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardEntitlement -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardEntitlement testEntitlement

.EXAMPLE
Get-SafeguardEntitlement 123
#>
function Get-SafeguardEntitlement
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
        [object]$EntitlementToGet
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSBoundParameters.ContainsKey("EntitlementToGet"))
    {
        $local:EntitlementId = Resolve-SafeguardEntitlementId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $EntitlementToGet
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Roles/$($local:EntitlementId)"
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Roles
    }
}

<#
.SYNOPSIS
Create a new Entitlement in Safeguard via the Web API.

.DESCRIPTION
Create a new Entitlement in Safeguard. Access policies can be attached 
to Entitlements. Users and groups can be  

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Name
The name of the entitlement.

.PARAMETER $MemberUsers
Array of Id or name of the users to be added to the entitlement

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
New-SafeguardEntitlement "Lab Administrator"
#>
function New-SafeguardEntitlement
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
        [string]$Name,
        [Parameter(Mandatory=$false,Position=1)]
        [object[]]$MemberUsers
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    [object[]]$Members = $null
    ForEach($user in $MemberUsers)
    {
        $local:ResolvedUserId = (Get-SafeguardUser -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -UserToGet $User).Id
        $local:Member = @{
            Id = $ResolvedUserId
        }
        $local:Members += $($local:Member)
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
        Core POST Roles -Body @{ Name = $Name; Members = $local:Members}
}

<#
.SYNOPSIS
Remove entitlements in Safeguard via the Web API.

.DESCRIPTION
Entitlement is a set of access request policies that restrict system access to authorized users

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER EntitlementToDelete
An integer containing the ID or a string containing the name of the entitlement to delete.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardEntitlement -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Remove-SafeguardEntitlement testEntitlement

.EXAMPLE
Remove-SafeguardEntitlement 123
#>
function Remove-SafeguardEntitlement
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
        [object]$EntitlementToDelete
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:EntitlementId = Resolve-SafeguardEntitlementId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $EntitlementToDelete
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "Roles/$($local:EntitlementId)"

}
