# Copyright (c) 2026 One Identity LLC. All rights reserved.
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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($Asset.Id -as [int])
    {
        $Asset = $Asset.Id
    }

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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($Account.Id -as [int])
    {
        $Account = $Account.Id
    }

    if (-not ($Account -as [int]))
    {
        $local:RelativeUrl = "PolicyAccounts"
        $local:PreFilter = ""
        if ($AssetId)
        {
            $local:PreFilter = "Asset.Id eq $AssetId and "
        }
        # Support asset\account syntax (e.g. "ubtu2404-agnt.dan.test\root")
        $local:Pair = ($Account -split "\\")
        if ($local:Pair.Length -eq 2)
        {
            $local:ResolvedAssetId = (Resolve-SafeguardPolicyAssetId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $local:Pair[0])
            $local:PreFilter = "Asset.Id eq $($local:ResolvedAssetId) and "
            $Account = $local:Pair[1]
        }
        try
        {
            $local:Accounts = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET $local:RelativeUrl `
                                   -Parameters @{ filter = "$($local:PreFilter)Name ieq '$Account'" })
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
        [Parameter(Mandatory=$false)]
        [int]$EntitlementId,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$AccessPolicy
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($AccessPolicy.Id -as [int])
    {
        $AccessPolicy = $AccessPolicy.Id
    }

    if (-not ($AccessPolicy -as [int]))
    {
        $local:Filter = "Name ieq '$AccessPolicy'"
        if ($PSBoundParameters.ContainsKey("EntitlementId"))
        {
            $local:Filter = "RoleId eq $EntitlementId and $($local:Filter)"
        }
        try
        {
            $local:AccessPolicies = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET AccessPolicies `
                                 -Parameters @{ filter = $local:Filter })
        }
        catch
        {
            Write-Verbose $_
            Write-Verbose "Caught exception with ieq filter, trying with q parameter"
            $local:Params = @{ q = $AccessPolicy }
            if ($PSBoundParameters.ContainsKey("EntitlementId"))
            {
                $local:Params["filter"] = "RoleId eq $EntitlementId"
            }
            $local:AccessPolicies = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET AccessPolicies `
                                 -Parameters $local:Params)
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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
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

.PARAMETER QueryFilter
A string to pass to the -filter query parameter in the Safeguard Web API.

.PARAMETER Fields
An array of the policy asset property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Find-SafeguardPolicyAsset -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Find-SafeguardPolicyAsset "HP-UX"

.EXAMPLE
Find-SafeguardPolicyAsset -QueryFilter "AllowSessionRequests eq False"

.EXAMPLE
Find-SafeguardPolicyAsset -QueryFilter "Disabled eq True" -Fields Id,Name
#>
function Find-SafeguardPolicyAsset
{
    [CmdletBinding(DefaultParameterSetName="Search")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0,ParameterSetName="Search")]
        [string]$SearchString,
        [Parameter(Mandatory=$true,Position=0,ParameterSetName="Query")]
        [string]$QueryFilter,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSCmdlet.ParameterSetName -eq "Search")
    {
        $local:Parameters = @{ q = $SearchString }
        if ($Fields)
        {
            $local:Parameters["fields"] = ($Fields -join ",")
        }
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET PolicyAssets `
            -Parameters $local:Parameters
    }
    else
    {
        $local:Parameters = @{ filter = $QueryFilter }
        if ($Fields)
        {
            $local:Parameters["fields"] = ($Fields -join ",")
        }
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET PolicyAssets `
            -Parameters $local:Parameters
    }
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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
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
            Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "PolicyAccounts" `
                -Parameters @{ Filter = "Asset.Id eq $($local:AssetId)"}
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

.PARAMETER QueryFilter
A string to pass to the -filter query parameter in the Safeguard Web API.

.PARAMETER Fields
An array of the event property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Find-SafeguardPolicyAccount -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Find-SafeguardPolicyAccount "root"

.EXAMPLE
Find-SafeguardPolicyAccount -QueryFilter "IsServiceAccount eq True"
#>
function Find-SafeguardPolicyAccount
{
    [CmdletBinding(DefaultParameterSetName="Search")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0,ParameterSetName="Search")]
        [string]$SearchString,
        [Parameter(Mandatory=$true,Position=0,ParameterSetName="Query")]
        [string]$QueryFilter,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSCmdlet.ParameterSetName -eq "Search")
    {
        $local:Parameters = @{ q = $SearchString }
        if ($Fields)
        {
            $local:Parameters["fields"] = ($Fields -join ",")
        }
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET PolicyAccounts `
            -Parameters $local:Parameters
    }
    else
    {
        $local:Parameters = @{ filter = $QueryFilter }
        if ($Fields)
        {
            $local:Parameters["fields"] = ($Fields -join ",")
        }
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET PolicyAccounts `
            -Parameters $local:Parameters
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

.PARAMETER EntitlementToGet
An integer containing the ID of the entitlement to get or a string containing the name.

.PARAMETER PolicyToGet
An integer containing the ID of the access policy to get or a string containing the name.

.PARAMETER Fields
An array of the access policy property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardAccessPolicy -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardAccessPolicy "Test Access Policy"

.EXAMPLE
Get-SafeguardAccessPolicy -EntitlementToGet "Domain Administrator"

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
        [Parameter(Mandatory=$false)]
        [object]$EntitlementToGet,
        [Parameter(Mandatory=$false,Position=0)]
        [object]$PolicyToGet,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Parameters = $null
    if ($PSBoundParameters.ContainsKey("EntitlementToGet") -and $EntitlementToGet)
    {
        Import-Module -Name "$PSScriptRoot\entitlements.psm1" -Scope Local
        $local:EntitlementId = Resolve-SafeguardEntitlementId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $EntitlementToGet
        $local:Parameters = @{ Filter = "RoleId eq $($local:EntitlementId)" }
    }
    if ($Fields)
    {
        if ($local:Parameters)
        {
            $local:Parameters["fields"] = ($Fields -join ",")
        }
        else
        {
            $local:Parameters = @{ fields = ($Fields -join ",")}
        }
    }

    if ($PSBoundParameters.ContainsKey("PolicyToGet") -and $PolicyToGet)
    {
        $local:AccessPolicyId = Resolve-SafeguardAccessPolicyId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $PolicyToGet
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            GET "AccessPolicies/$($local:AccessPolicyId)" -Parameters $local:Parameters
    }
    else
    {
        if ($PSBoundParameters.ContainsKey("EntitlementToGet") -and $EntitlementToGet)
        {
            Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                GET AccessPolicies -Parameters $local:Parameters
        }
        else
        {
            Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                GET AccessPolicies -Parameters $local:Parameters
        }
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
    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
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
    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
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
    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:AccessPolicyId = Resolve-SafeguardAccessPolicyId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $PolicyToGet
    $local:AccessPolicy = Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "AccessPolicies/$($local:AccessPolicyId)"
    return $($local:AccessPolicy).SessionProperties
}

<#
.SYNOPSIS
Get linked accounts for a user in Safeguard via the Web API.

.DESCRIPTION
Get the linked accounts for a user that have been added to Safeguard. Users can log into Safeguard.
All users can request access to passwords or sessions based on policy. Depending
on policy some users can request access via linked accounts.

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
Get-SafeguardUserLinkedAccount -AccessToken $token -Appliance 10.5.32.54 -Insecure

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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:UserId = (Get-SafeguardUser -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $UserToGet).Id
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Users/$local:UserId/LinkedPolicyAccounts"
}

<#
.SYNOPSIS
Add a linked account for a user in Safeguard via the Web API.

.DESCRIPTION
Add a linked account to a Safeguard user. Users can log into Safeguard. All
users can request access to passwords or sessions based on policy. Depending
on policy some users can request access via linked accounts.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER UserToSet
An integer containing an ID or a string containing the name of the user for which to add a linked account.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Add-SafeguardUser -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Add-SafeguardUserLinkedAccount petrsnd testdirectory.corp petrsnd-adm
#>
function Add-SafeguardUserLinkedAccount
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
        [object]$UserToSet,
        [Parameter(Mandatory=$true,Position=1)]
        [object]$DirectoryToAdd,
        [Parameter(Mandatory=$true,Position=2)]
        [object]$AccountToAdd
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:PolicyAccount = (Get-SafeguardPolicyAccount -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $DirectoryToAdd $AccountToAdd)
    if (-not $local:PolicyAccount)
    {
        throw "Unable to locate specified policy account"
    }
    $local:UserId = (Get-SafeguardUser -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $UserToSet).Id

    $local:LinkedAccounts = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
        GET "Users/$local:UserId/LinkedPolicyAccounts")

    $local:LinkedAccounts += $local:PolicyAccount[0]

     Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
        PUT "Users/$local:UserId/LinkedPolicyAccounts" -Body $local:LinkedAccounts
}

<#
.SYNOPSIS
Remove a linked account from a user in Safeguard via the Web API.

.DESCRIPTION
Remove a linked account from a Safeguard user. Users can log into Safeguard. All
users can request access to passwords or sessions based on policy. Depending
on policy some users can request access via linked accounts.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER UserToSet
An integer containing an ID or a string containing the name of the user for which to add a linked account.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardUser -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Remove-SafeguardUserLinkedAccount petrsnd testdirectory.corp petrsnd-adm
#>
function Remove-SafeguardUserLinkedAccount
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
        [object]$UserToSet,
        [Parameter(Mandatory=$true,Position=1)]
        [object]$DirectoryToRemove,
        [Parameter(Mandatory=$true,Position=2)]
        [object]$AccountToRemove
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:PolicyAccount = (Get-SafeguardPolicyAccount -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $DirectoryToRemove $AccountToRemove)
    if (-not $local:PolicyAccount)
    {
        throw "Unable to locate specified policy account"
    }
    $local:UserId = (Get-SafeguardUser -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $UserToSet).Id

    $local:LinkedAccounts = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
        GET "Users/$local:UserId/LinkedPolicyAccounts")

    $local:LinkedAccountsToSet = @()
    $local:LinkedAccounts | ForEach-Object {
        if (-not ($_.Asset.Id -eq $local:PolicyAccount.Asset.Id -and $_.Id -eq $local:PolicyAccount.Id))
        {
            $local:LinkedAccountsToSet += $_
        }
     }

    if (-not $local:LinkedAccountsToSet)
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            PUT "Users/$local:UserId/LinkedPolicyAccounts" -JsonBody "[]"
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            PUT "Users/$local:UserId/LinkedPolicyAccounts" -Body $local:LinkedAccountsToSet
    }
}

# Helper to build ScopeItems array from convenience parameters
function Resolve-SafeguardAccessPolicyScopeItems
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
        [object[]]$ScopeAccounts,
        [Parameter(Mandatory=$false)]
        [object[]]$ScopeAssets,
        [Parameter(Mandatory=$false)]
        [object[]]$ScopeAccountGroups,
        [Parameter(Mandatory=$false)]
        [object[]]$ScopeAssetGroups
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    [object[]]$local:ScopeItems = @()

    foreach ($local:Account in $ScopeAccounts)
    {
        $local:AccountId = (Resolve-SafeguardPolicyAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $local:Account)
        $local:ScopeItems += @{ Id = $local:AccountId; ScopeItemType = "Account" }
    }

    foreach ($local:Asset in $ScopeAssets)
    {
        $local:AssetId = (Resolve-SafeguardPolicyAssetId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $local:Asset)
        $local:ScopeItems += @{ Id = $local:AssetId; ScopeItemType = "Asset" }
    }

    foreach ($local:AccountGroup in $ScopeAccountGroups)
    {
        Import-Module -Name "$PSScriptRoot\groups.psm1" -Scope Local
        $local:GroupId = (Get-SafeguardAccountGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $local:AccountGroup).Id
        $local:ScopeItems += @{ Id = $local:GroupId; ScopeItemType = "AccountGroup" }
    }

    foreach ($local:AssetGroup in $ScopeAssetGroups)
    {
        Import-Module -Name "$PSScriptRoot\groups.psm1" -Scope Local
        $local:GroupId = (Get-SafeguardAssetGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $local:AssetGroup).Id
        $local:ScopeItems += @{ Id = $local:GroupId; ScopeItemType = "AssetGroup" }
    }

    $local:ScopeItems
}

<#
.SYNOPSIS
Add an access policy to an entitlement in Safeguard via the Web API.

.DESCRIPTION
Add an access policy to an existing entitlement in Safeguard. Access policies define what
assets and accounts can be requested and the type of access (password, session, etc.).

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Entitlement
An integer containing the ID or a string containing the name of the entitlement to add the policy to.

.PARAMETER Name
The name of the new access policy.

.PARAMETER AccessRequestType
The type of access being granted (Password, RemoteDesktop, Ssh, Telnet, SshKey, RemoteDesktopApplication, ApiKey, File).

.PARAMETER Description
A string containing a description of the access policy.

.PARAMETER ScopeAccounts
An array of account IDs or names to include in the policy scope.

.PARAMETER ScopeAssets
An array of asset IDs or names to include in the policy scope.

.PARAMETER ScopeAccountGroups
An array of account group IDs or names to include in the policy scope.

.PARAMETER ScopeAssetGroups
An array of asset group IDs or names to include in the policy scope.

.PARAMETER ApproverUsers
An array of user IDs or names to add as approvers. When specified, approval will be required.
A single approver set is created with all specified users and groups.

.PARAMETER ApproverGroups
An array of user group IDs or names to add as approvers. When specified, approval will be required.
A single approver set is created with all specified users and groups.

.PARAMETER AccessPolicyObject
An object containing the access policy to create. Use this for advanced configuration
(multiple approver sets, session properties, hourly restrictions, etc.).

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Add-SafeguardAccessPolicy -Entitlement "Lab Administrator" -Name "SSH Access" -AccessRequestType Ssh

.EXAMPLE
Add-SafeguardAccessPolicy -Entitlement 5 -Name "Password Access" -AccessRequestType Password -ScopeAccounts "root","admin"

.EXAMPLE
Add-SafeguardAccessPolicy -Entitlement 5 -Name "Approved Access" -AccessRequestType Password -ApproverUsers "admin1","admin2"

.EXAMPLE
Add-SafeguardAccessPolicy -AccessPolicyObject $policyObj
#>
function Add-SafeguardAccessPolicy
{
    [CmdletBinding(DefaultParameterSetName="Attributes")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(ParameterSetName="Attributes",Mandatory=$true,Position=0)]
        [object]$Entitlement,
        [Parameter(ParameterSetName="Attributes",Mandatory=$true,Position=1)]
        [string]$Name,
        [Parameter(ParameterSetName="Attributes",Mandatory=$true,Position=2)]
        [ValidateSet("Password","RemoteDesktop","Ssh","Telnet","SshKey","RemoteDesktopApplication","ApiKey","File",IgnoreCase=$true)]
        [string]$AccessRequestType,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$Description,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [object[]]$ScopeAccounts,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [object[]]$ScopeAssets,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [object[]]$ScopeAccountGroups,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [object[]]$ScopeAssetGroups,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [object[]]$ApproverUsers,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [object[]]$ApproverGroups,
        [Parameter(ParameterSetName="Object",Mandatory=$true,ValueFromPipeline=$true)]
        [object]$AccessPolicyObject
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PsCmdlet.ParameterSetName -eq "Object")
    {
        if (-not $AccessPolicyObject)
        {
            throw "AccessPolicyObject must not be null"
        }
    }
    else
    {
        Import-Module -Name "$PSScriptRoot\entitlements.psm1" -Scope Local
        $local:EntitlementId = Resolve-SafeguardEntitlementId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Entitlement

        $AccessPolicyObject = @{
            Name = $Name;
            RoleId = $local:EntitlementId;
            AccessRequestProperties = @{
                AccessRequestType = $AccessRequestType
            }
        }

        if ($PSBoundParameters.ContainsKey("Description")) { $AccessPolicyObject.Description = $Description }

        if ($PSBoundParameters.ContainsKey("ScopeAccounts") -or $PSBoundParameters.ContainsKey("ScopeAssets") -or `
            $PSBoundParameters.ContainsKey("ScopeAccountGroups") -or $PSBoundParameters.ContainsKey("ScopeAssetGroups"))
        {
            $AccessPolicyObject.ScopeItems = @(Resolve-SafeguardAccessPolicyScopeItems -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                -ScopeAccounts $ScopeAccounts -ScopeAssets $ScopeAssets -ScopeAccountGroups $ScopeAccountGroups -ScopeAssetGroups $ScopeAssetGroups)
        }

        if ($PSBoundParameters.ContainsKey("ApproverUsers") -or $PSBoundParameters.ContainsKey("ApproverGroups"))
        {
            # Build a single approver set from all specified users and groups
            [object[]]$local:Approvers = @()
            foreach ($local:User in $ApproverUsers)
            {
                $local:ResolvedUser = (Get-SafeguardUser -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -UserToGet $local:User)
                $local:Approvers += @{ Id = $local:ResolvedUser.Id; PrincipalKind = "User" }
            }
            foreach ($local:Group in $ApproverGroups)
            {
                Import-Module -Name "$PSScriptRoot\groups.psm1" -Scope Local
                $local:ResolvedGroup = (Get-SafeguardUserGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -GroupToGet $local:Group)
                $local:Approvers += @{ Id = $local:ResolvedGroup.Id; PrincipalKind = "Group" }
            }
            $AccessPolicyObject.ApproverProperties = @{ RequireApproval = $true }
            $AccessPolicyObject.ApproverSets = @(@{
                RequiredApprovers = 1;
                Approvers = @($local:Approvers)
            })
        }
        else
        {
            # Default to automatic approval when no approvers are specified
            $AccessPolicyObject.ApproverProperties = @{ RequireApproval = $false }
        }
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST AccessPolicies -Body $AccessPolicyObject
}

<#
.SYNOPSIS
Remove an access policy from Safeguard via the Web API.

.DESCRIPTION
Remove an access policy from Safeguard. The access policy will be permanently deleted.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER PolicyToDelete
An integer containing the ID or a string containing the name of the access policy to delete.

.PARAMETER Entitlement
An integer containing the ID or a string containing the name of the entitlement to qualify
the access policy lookup in case multiple policies share the same name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardAccessPolicy "SSH Access"

.EXAMPLE
Remove-SafeguardAccessPolicy "SSH Access" -Entitlement "Lab Administrator"

.EXAMPLE
Remove-SafeguardAccessPolicy 123
#>
function Remove-SafeguardAccessPolicy
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
        [object]$PolicyToDelete,
        [Parameter(Mandatory=$false)]
        [object]$Entitlement
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:ResolveParams = @{}
    if ($PSBoundParameters.ContainsKey("Entitlement"))
    {
        Import-Module -Name "$PSScriptRoot\entitlements.psm1" -Scope Local
        $local:ResolveParams["EntitlementId"] = (Resolve-SafeguardEntitlementId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Entitlement)
    }

    $local:AccessPolicyId = Resolve-SafeguardAccessPolicyId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure @local:ResolveParams $PolicyToDelete
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "AccessPolicies/$($local:AccessPolicyId)"
}

<#
.SYNOPSIS
Edit an existing access policy in Safeguard via the Web API.

.DESCRIPTION
Edit an existing access policy in Safeguard. Access policies define what assets and accounts
can be requested and the type of access (password, session, etc.).

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER PolicyToEdit
An integer containing the ID or a string containing the name of the access policy to edit.

.PARAMETER Name
A string containing the new name for the access policy.

.PARAMETER Description
A string containing the new description for the access policy.

.PARAMETER AccessRequestType
The type of access being granted (Password, RemoteDesktop, Ssh, Telnet, SshKey, RemoteDesktopApplication, ApiKey, File).

.PARAMETER ScopeAccounts
An array of account IDs or names to set as the policy scope (replaces existing scope accounts).

.PARAMETER ScopeAssets
An array of asset IDs or names to set as the policy scope (replaces existing scope assets).

.PARAMETER ScopeAccountGroups
An array of account group IDs or names to set as the policy scope (replaces existing scope account groups).

.PARAMETER ScopeAssetGroups
An array of asset group IDs or names to set as the policy scope (replaces existing scope asset groups).

.PARAMETER AccessPolicyObject
An object containing the existing access policy with desired properties set.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Edit-SafeguardAccessPolicy -PolicyToEdit "SSH Access" -Description "Updated description"

.EXAMPLE
Edit-SafeguardAccessPolicy -PolicyToEdit 123 -ScopeAccounts "root","admin"

.EXAMPLE
$obj = Get-SafeguardAccessPolicy "SSH Access"; $obj.Description = "New desc"; Edit-SafeguardAccessPolicy -AccessPolicyObject $obj
#>
function Edit-SafeguardAccessPolicy
{
    [CmdletBinding(DefaultParameterSetName="Attributes")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(ParameterSetName="Attributes",Mandatory=$true,Position=0)]
        [object]$PolicyToEdit,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$Name,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$Description,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [ValidateSet("Password","RemoteDesktop","Ssh","Telnet","SshKey","RemoteDesktopApplication","ApiKey","File",IgnoreCase=$true)]
        [string]$AccessRequestType,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [object[]]$ScopeAccounts,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [object[]]$ScopeAssets,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [object[]]$ScopeAccountGroups,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [object[]]$ScopeAssetGroups,
        [Parameter(ParameterSetName="Object",Mandatory=$true,ValueFromPipeline=$true)]
        [object]$AccessPolicyObject
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PsCmdlet.ParameterSetName -eq "Object" -and -not $AccessPolicyObject)
    {
        throw "AccessPolicyObject must not be null"
    }

    if ($PsCmdlet.ParameterSetName -eq "Attributes")
    {
        $local:AccessPolicyId = Resolve-SafeguardAccessPolicyId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $PolicyToEdit
        $AccessPolicyObject = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "AccessPolicies/$($local:AccessPolicyId)")

        if ($PSBoundParameters.ContainsKey("Name")) { $AccessPolicyObject.Name = $Name }
        if ($PSBoundParameters.ContainsKey("Description")) { $AccessPolicyObject.Description = $Description }
        if ($PSBoundParameters.ContainsKey("AccessRequestType"))
        {
            if (-not $AccessPolicyObject.AccessRequestProperties) { $AccessPolicyObject.AccessRequestProperties = @{} }
            $AccessPolicyObject.AccessRequestProperties.AccessRequestType = $AccessRequestType
        }

        if ($PSBoundParameters.ContainsKey("ScopeAccounts") -or $PSBoundParameters.ContainsKey("ScopeAssets") -or `
            $PSBoundParameters.ContainsKey("ScopeAccountGroups") -or $PSBoundParameters.ContainsKey("ScopeAssetGroups"))
        {
            $AccessPolicyObject.ScopeItems = @(Resolve-SafeguardAccessPolicyScopeItems -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                -ScopeAccounts $ScopeAccounts -ScopeAssets $ScopeAssets -ScopeAccountGroups $ScopeAccountGroups -ScopeAssetGroups $ScopeAssetGroups)
        }
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "AccessPolicies/$($AccessPolicyObject.Id)" -Body $AccessPolicyObject
}
