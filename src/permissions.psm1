# Helper
function Resolve-SafeguardAccessPolicyId
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
        [object]$AccessPolicy
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not ($AccessPolicy -as [int]))
    {
        try
        {
            $local:AccessPolicies = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET AccessPolicies `
                                 -Parameters @{ filter = "Name ieq '$AccessPolicy'" })
        }
        catch
        {
            Write-Verbose $_
            Write-Verbose "Caught exception with ieq filter, trying with q parameter"
            $local:AccessPolicies = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET AccessPolicies `
                                 -Parameters @{ q = $AccessPolicy })
        }
        if (-not $local:AccessPolicies)
        {
            throw "Unable to find access policy matching '$AccessPolicy'"
        }
        if ($local:AccessPolicies.Count -ne 1)
        {
            throw "Found $($local:AccessPolicies.Count) access policies matching '$AccessPolicy'"
        }
        $local:AccessPolicies[0].Id
    }
    else
    {
        $AccessPolicy
    }
}

function Resolve-SafeguardRoleId
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
        [object]$Role
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not ($Role -as [int]))
    {
        try
        {
            $local:Roles = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Roles `
                                 -Parameters @{ filter = "Name ieq '$Role'" })
        }
        catch
        {
            Write-Verbose $_
            Write-Verbose "Caught exception with ieq filter, trying with q parameter"
            $local:Roles = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Roles `
                                 -Parameters @{ q = $Role })
        }
        if (-not $local:Roles)
        {
            throw "Unable to find Role matching '$Role'"
        }
        if ($local:Roles.Count -ne 1)
        {
            throw "Found $($local:Roles.Count) Roles matching '$Role'"
        }
        $local:Roles[0].Id
    }
    else
    {
        $Role
    }
}

<#
.SYNOPSIS
Get access policies in Safeguard via the Web API.

.DESCRIPTION
Policy assets are created by policy administrators to grant privileged access to Safeguard users.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER PolicyToGet
An integer containing the ID of the access policy to get or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardAccessPolicy -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardAccessPolicy testAccessPolicy

.EXAMPLE
Get-SafeguardAccessPolicy 123
#>
function Get-SafeguardAccessPolicy
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
        [object]$PolicyToGet
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSBoundParameters.ContainsKey("PolicyToGet"))
    {
        $local:AccessPolicyId = Resolve-SafeguardAccessPolicyId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $PolicyToGet
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "AccessPolicies/$($local:AccessPolicyId)"
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET AccessPolicies
    }
}

<#
.SYNOPSIS
Get scope items of an access policy in Safeguard via the Web API.

.DESCRIPTION
Scope items is a set of accounts, assets, account groups and asset groups that are explicitely assigned to an access policy 

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER PolicyToGet
An integer containing the ID  or a string containing the name of the access policy for which scope item to get.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardAccessPolicyScopeItem testAccessPolicy

.EXAMPLE
Get-SafeguardAccessPolicyScopeItem 123
#>
function Get-SafeguardAccessPolicyScopeItem
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
        [object]$PolicyToGet
    )

    $local:AccessPolicy
    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSBoundParameters.ContainsKey("PolicyToGet"))
    {
        $local:AccessPolicyId = Resolve-SafeguardAccessPolicyId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $PolicyToGet
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "AccessPolicies/$($local:AccessPolicyId)/ScopeItems"
    }
    else
    {
        throw "'AccessPolicy' paramter is required"
    }
}

<#
.SYNOPSIS
Get access request properties of an access policies in Safeguard via the Web API.

.DESCRIPTION
Access request properties of an access policy are the settings configured for the access being requested.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER PolicyToGet
An integer containing the ID or a string containing the name of the access policy for which access request properties to get.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardAccessPolicyAccessRequestProperty testAccessPolicy

.EXAMPLE
Get-SafeguardAccessPolicyAccessRequestProperty 123
#>
function Get-SafeguardAccessPolicyAccessRequestProperty
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
        [object]$PolicyToGet
    )

    $local:AccessPolicy
    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSBoundParameters.ContainsKey("PolicyToGet"))
    {
        $local:AccessPolicyId = Resolve-SafeguardAccessPolicyId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $PolicyToGet
        $local:AccessPolicy = Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "AccessPolicies/$($local:AccessPolicyId)"
    }
    else
    {
        throw "'AccessPolicy' paramter is required"
    }

    return $($local:AccessPolicy).AccessRequestProperties
}

<#
.SYNOPSIS
Get session properties of an access policies in Safeguard via the Web API.

.DESCRIPTION
Session properties are the settings confugured for sessions access request.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER PolicyToGet
An integer containing the ID or a string containing the name of the access policy for which session properties to get.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardAccessPolicySessionProperty testAccessPolicy

.EXAMPLE
Get-SafeguardAccessPolicySessionProperty 123
#>
function Get-SafeguardAccessPolicySessionProperty
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
        [object]$PolicyToGet
    )

    $local:AccessPolicy
    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSBoundParameters.ContainsKey("PolicyToGet"))
    {
        $local:AccessPolicyId = Resolve-SafeguardAccessPolicyId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $PolicyToGet
        $local:AccessPolicy = Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "AccessPolicies/$($local:AccessPolicyId)"
    }
    else
    {
        throw "'AccessPolicy' paramter is required"
    }

    return $($local:AccessPolicy).SessionProperties
}

<#
.SYNOPSIS
Get roles in Safeguard via the Web API.

.DESCRIPTION
Role or entitlement is a set of access request policies that restrict system access to authorized users

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER RoleToGet
An integer containing the ID  or a string containing the name of the entitlement to get.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardRole -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardRole testEntitlement

.EXAMPLE
Get-SafeguardRole 123
#>
function Get-SafeguardRole
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
        [object]$RoleToGet
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSBoundParameters.ContainsKey("RoleToGet"))
    {
        $local:RoleId = Resolve-SafeguardRoleId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $RoleToGet
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Roles/$($local:RoleId)"
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Roles
    }
}

<#
.SYNOPSIS
Generates user entitlement report for a set of users in Safeguard via the Web API.

.DESCRIPTION
User entitlement report is a report of what accounts can be accessed by a set of users.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER PolicyToGet
An integer containing the ID of the access policy to get or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardUserRoleReport -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardUserRoleReport testUser1,testUser2

.EXAMPLE
Get-SafeguardUserRoleReport 123
#>
function Get-SafeguardUserRoleReport
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
        [object[]]$UsersToGet
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    [object[]]$Users = $null
    if ($PSBoundParameters.ContainsKey("UsersToGet"))
    {
        foreach ($User in $UsersToGet)
        {
            $local:ResolvedUser = (Get-SafeguardUser -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -UserToGet $User)
            $local:Users += $($local:ResolvedUser).Id
        }
        $local:Report = Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "Reports/Entitlements/UserEntitlement" -Body $Users
        return $local:Report.UserEntitlements
    }
    else
    {
        # If not User is provided, get the entitlements for logged in user
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Me/Entitlements"
    }
}