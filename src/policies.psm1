# Helper
function Resolve-SafeguardPolicyAssetId
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
        [object]$Asset
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not ($Asset -as [int]))
    {
        try
        {
            $local:Assets = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET PolicyAssets `
                                 -Parameters @{ filter = "Name ieq '$Asset'" })
            if (-not $local:Assets)
            {
                $local:Assets = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET PolicyAssets `
                                     -Parameters @{ filter = "NetworkAddress ieq '$Asset'" })
            }
        }
        catch
        {
            Write-Verbose $_
            Write-Verbose "Caught exception with ieq filter, trying with q parameter"
            $local:Assets = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET PolicyAssets `
                                 -Parameters @{ q = $Asset })
        }
        if (-not $local:Assets)
        {
            throw "Unable to find policy asset matching '$Asset'"
        }
        if ($local:Assets.Count -ne 1)
        {
            throw "Found $($local:Assets.Count) policy assets matching '$Asset'"
        }
        $local:Assets[0].Id
    }
    else
    {
        $Asset
    }
}
function Resolve-SafeguardPolicyAccountId
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
        [int]$AssetId,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$Account
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not ($Account -as [int]))
    {
        if ($PSBoundParameters.ContainsKey("AssetId"))
        {
            $local:RelativeUrl = "PolicyAssets/$AssetId/Accounts"
        }
        else
        {
            $local:RelativeUrl = "PolicyAccounts"
        }
        try
        {
            $local:Accounts = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET $local:RelativeUrl `
                                   -Parameters @{ filter = "Name ieq '$Account'" })
        }
        catch
        {
            Write-Verbose $_
            Write-Verbose "Caught exception with ieq filter, trying with q parameter"
            $local:Accounts = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET $local:RelativeUrl `
                                   -Parameters @{ q = $Account })
        }
        if (-not $local:Accounts)
        {
            throw "Unable to find policy account matching '$Account'"
        }
        if ($local:Accounts.Count -ne 1)
        {
            throw "Found $($local:Accounts.Count) policy accounts matching '$Account'"
        }
        $local:Accounts[0].Id
    }
    else
    {
        $Account
    }
}
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

    $ErrorActionPreference = "Stop"
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
Get assets and directories managed by Safeguard for which policy can be created
via the Web API.

.DESCRIPTION
Policy assets are those that may be used by policy administrators to create entitlements
and access policies to grant privileged access to Safeguard users.  Policy assets include
both assets and directories.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetToGet
An integer containing the ID of the asset or directory to get or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardPolicyAsset -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardPolicyAsset "example.domain"
#>
function Get-SafeguardPolicyAsset
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
        [object]$AssetToGet
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSBoundParameters.ContainsKey("AssetToGet"))
    {
        $local:AssetId = Resolve-SafeguardPolicyAssetId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AssetToGet
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "PolicyAssets/$($local:AssetId)"
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET PolicyAssets
    }
}

<#
.SYNOPSIS
Search for a policy asset in Safeguard via the Web API.

.DESCRIPTION
Search for a policy asset in Safeguard for any string fields containing the SearchString.
Policy assets are those that may be used by policy administrators to create entitlements
and access policies to grant privileged access to Safeguard users.  Policy assets include
both assets and directories.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER SearchString
A string to search for in the policy asset.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Find-SafeguardPolicyAsset -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Find-SafeguardPolicyAsset "HP-UX"
#>
function Find-SafeguardPolicyAsset
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
        [string]$SearchString
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET PolicyAssets `
        -Parameters @{ q = $SearchString }
}

<#
.SYNOPSIS
Get accounts from assets and directories managed by Safeguard for which policy can be created
via the Web API.

.DESCRIPTION
Policy accounts are those that may be used by policy administrators to create entitlements
and access policies to grant privileged access to Safeguard users.  Policy assets include
both assets and directories.  Policy accounts contain both asset accounts and directory accounts.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetToGet
An integer containing the ID of the asset or directory to get or a string containing the name.

.PARAMETER AccountToGet
An integer containing the ID of the account to get or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardPolicyAccount -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardPolicyAccount "example.domain" "Administrator"

.EXAMPLE
Get-SafeguardPolicyAccount "aix232lc.my.domain" "dbadmin"
#>
function Get-SafeguardPolicyAccount
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
        [object]$AssetToGet,
        [Parameter(Mandatory=$false,Position=1)]
        [object]$AccountToGet
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSBoundParameters.ContainsKey("AssetToGet"))
    {
        $local:AssetId = (Resolve-SafeguardPolicyAssetId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AssetToGet)
        if ($PSBoundParameters.ContainsKey("AccountToGet"))
        {
            $local:AccountId = (Resolve-SafeguardPolicyAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetId $local:AssetId $AccountToGet)
            Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "PolicyAccounts/$($local:AccountId)"
        }
        else
        {
            Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "PolicyAssets/$($local:AssetId)/Accounts"
        }
    }
    else
    {
        if ($PSBoundParameters.ContainsKey("AccountToGet"))
        {
            $local:AccountId = (Resolve-SafeguardPolicyAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AccountToGet)
            Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "PolicyAccounts/$($local:AccountId)"
        }
        else
        {
            Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET PolicyAccounts
        }
    }
}

<#
.SYNOPSIS
Search for a policy account in Safeguard via the Web API.

.DESCRIPTION
Search for a policy account in Safeguard for any string fields containing the SearchString.
Policy accounts are those that may be used by policy administrators to create entitlements
and access policies to grant privileged access to Safeguard users.  Policy assets include
both assets and directories.  Policy accounts contain both asset accounts and directory accounts.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER SearchString
A string to search for in the policy account.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Find-SafeguardPolicyAccount -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Find-SafeguardPolicyAccount "root"
#>
function Find-SafeguardPolicyAccount
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
        [string]$SearchString
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET PolicyAccounts `
        -Parameters @{ q = $SearchString }
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
        [Parameter(Mandatory=$true,Position=0)]
        [object]$PolicyToGet
    )

    $local:AccessPolicy
    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:AccessPolicyId = Resolve-SafeguardAccessPolicyId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $PolicyToGet
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "AccessPolicies/$($local:AccessPolicyId)/ScopeItems"
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
        [Parameter(Mandatory=$true,Position=0)]
        [object]$PolicyToGet
    )

    $local:AccessPolicy
    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:AccessPolicyId = Resolve-SafeguardAccessPolicyId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $PolicyToGet
    $local:AccessPolicy = Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "AccessPolicies/$($local:AccessPolicyId)"
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
        [Parameter(Mandatory=$true,Position=0)]
        [object]$PolicyToGet
    )

    $local:AccessPolicy
    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:AccessPolicyId = Resolve-SafeguardAccessPolicyId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $PolicyToGet
    $local:AccessPolicy = Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "AccessPolicies/$($local:AccessPolicyId)"
    return $($local:AccessPolicy).SessionProperties
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

    $ErrorActionPreference = "Stop"
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
Generates user entitlement report for a set of users in Safeguard via the Web API.

.DESCRIPTION
User entitlement report is a report of what accounts can be accessed by a set of users.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER UserList
An integer containing the ID of the access policy to get or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardUserEntitlementReport -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardUserEntitlementReport testUser1,testUser2

.EXAMPLE
Get-SafeguardUserEntitlementReport 123
#>
function Get-SafeguardUserEntitlementReport
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
        [object[]]$UserList
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    [object[]]$Users = $null
    foreach ($User in $UserList)
    {
        $local:ResolvedUser = (Get-SafeguardUser -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -UserToGet $User)
        $local:Users += $($local:ResolvedUser).Id
    }
    $local:Report = Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "Reports/Entitlements/UserEntitlement" -Body $Users
    return $local:Report.UserEntitlements
}

<#
.SYNOPSIS
Get linked accounts for a user in Safeguard via the Web API.

.DESCRIPTION
Get the linked accounts for a user that have been added to Safeguard. Users can log into Safeguard. All
users can request access to passwords or sessions based on policy. Depending
on permissions (admin roles) some users can manage different aspects of Safeguard.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER UserToGet
An integer containing an ID  or a string containing the name of the user for which the linked accounts to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardUser -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardUserLinkedAccount petrsnd

.EXAMPLE
Get-SafeguardUserLinkedAccount 123
#>
function Get-SafeguardUserLinkedAccount
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
        [object]$UserToGet
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    [object[]]$UserLinkedAccounts = $null
    $local:UserId = (Get-SafeguardUser -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $UserToGet).Id
    $local:LinkedAccounts = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Users/$local:UserId/LinkedPolicyAccounts")
    ForEach ($LinkedAccount in $LinkedAccounts)
    {
        $UserLinkedAccounts += (Get-SafeguardDirectoryAccount -DirectoryToGet $LinkedAccount.SystemId -AccountToGet $LinkedAccount.Name)
    }
    return $UserLinkedAccounts
}