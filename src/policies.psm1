<# Copyright (c) 2026 One Identity LLC. All rights reserved. #>
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

.PARAMETER DirectoryToAdd
An integer containing the ID of the directory or a string containing the name of the directory for the account to add.

.PARAMETER AccountToAdd
An integer containing the ID of the account or a string containing the name of the account to add.

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

.PARAMETER DirectoryToRemove
An integer containing the ID of the directory or a string containing the name of the directory for the account to remove.

.PARAMETER AccountToRemove
An integer containing the ID of the account or a string containing the name of the account to remove.

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

.PARAMETER Priority
An integer for the priority of this policy within its entitlement. Set to 0 for lowest priority.
Default is max priority plus 1 (highest).

.PARAMETER ScopeAccounts
An array of account IDs or names to include in the policy scope.

.PARAMETER ScopeAssets
An array of asset IDs or names to include in the policy scope.

.PARAMETER ScopeAccountGroups
An array of account group IDs or names to include in the policy scope.

.PARAMETER ScopeAssetGroups
An array of asset group IDs or names to include in the policy scope.

.PARAMETER SessionAccessAccountType
How to authenticate to assets for session access (None, UserSupplied, LinkedAccount, PolicySpecific).
Use LinkedAccount to use the requesting user's linked accounts.
Use PolicySpecific with -SessionAccessAccounts to specify shared or directory accounts.

.PARAMETER SessionAccessAccounts
An array of account IDs or asset\account names to use as session access accounts.
Only used when SessionAccessAccountType is PolicySpecific.
Use asset\account syntax (e.g. "server01\svc-account") to specify accounts.

.PARAMETER AllowLinkedAccountPasswordAccess
Switch to allow linked accounts to be requested for password access.

.PARAMETER AllowSimultaneousAccess
Whether to allow more than one access request to be active at the same time (default: false).

.PARAMETER MaximumSimultaneousReleases
Maximum number of times access can be granted during the same time period (1-99, default: 1).

.PARAMETER ChangePasswordAfterCheckin
Whether to change the account password after an access request is checked in (default: true).

.PARAMETER ChangeSshKeyAfterCheckin
Whether to change the SSH key pair after an access request is checked in (default: true).

.PARAMETER IncludePasswordRelease
Whether to include the password with session or file access requests (default: false).

.PARAMETER IncludeSshKeyRelease
Whether to include the SSH key with session or file access requests (default: false).

.PARAMETER TerminateExpiredSessions
Whether to terminate active sessions when the access request expires (default: false).

.PARAMETER PassphraseProtectSshKey
Whether the SSH private key will be encrypted upon check out (default: true).

.PARAMETER UseAltLoginName
Whether to use the AltLoginName AD attribute for a session connection launch string (default: false).

.PARAMETER LinkedAccountScopeFiltering
Whether to filter linked accounts using scope filtering (default: false).

.PARAMETER RdpApplicationHostAsset
An asset ID or name of the host asset for Remote Desktop Application sessions.
Use asset\account syntax for -RdpApplicationHostAccount to specify the login account.

.PARAMETER RdpApplicationHostAccount
An account ID or asset\account name for the login account on the RDP application host.

.PARAMETER RdpApplicationHostUserSupplied
Switch to indicate that the credentials for the application host are user-supplied.

.PARAMETER RdpApplicationDisplayName
The display name of the remote application.

.PARAMETER RdpApplicationAlias
The alias of the remote application (Windows Server).

.PARAMETER RdpApplicationProgram
The path to the remote application program (e.g. path to OI-SG-RemoteApp-Launcher.exe).

.PARAMETER RdpApplicationCmdLine
The command line arguments for the remote application.

.PARAMETER ApproverUsers
An array of user IDs or names to add as approvers. When specified, approval will be required.
A single approver set is created with all specified users and groups.
Use provider\user syntax (e.g. "local\admin") to uniquely identify users from a specific identity provider.

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
Add-SafeguardAccessPolicy -Entitlement "Lab Admin" -Name "SSH Linked" -AccessRequestType Ssh -ScopeAssets "server01" -SessionAccessAccountType LinkedAccount

.EXAMPLE
Add-SafeguardAccessPolicy -Entitlement "Lab Admin" -Name "SSH Shared" -AccessRequestType Ssh -ScopeAssets "server01" -SessionAccessAccountType PolicySpecific -SessionAccessAccounts "server01\svc-admin"

.EXAMPLE
Add-SafeguardAccessPolicy -Entitlement "Lab Admin" -Name "App Access" -AccessRequestType RDPApp -RdpApplicationHostAsset "rdphost01" -RdpApplicationHostAccount "rdphost01\svc-login" -RdpApplicationDisplayName "MyApp" -RdpApplicationAlias "myapp"

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
        [ValidateSet("Password","SSH","SSHKey","RemoteDesktop","RDP","Telnet","SshKey","RemoteDesktopApplication","RDPApplication","RDPApp","ApiKey","APIKey","File",IgnoreCase=$true)]
        [string]$AccessRequestType,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$Description,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [int]$Priority,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [object[]]$ScopeAccounts,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [object[]]$ScopeAssets,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [object[]]$ScopeAccountGroups,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [object[]]$ScopeAssetGroups,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [ValidateSet("None","UserSupplied","LinkedAccount","PolicySpecific",IgnoreCase=$true)]
        [string]$SessionAccessAccountType,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [object[]]$SessionAccessAccounts,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [switch]$AllowLinkedAccountPasswordAccess,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [bool]$AllowSimultaneousAccess,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [ValidateRange(1,99)]
        [int]$MaximumSimultaneousReleases,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [bool]$ChangePasswordAfterCheckin,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [bool]$ChangeSshKeyAfterCheckin,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [bool]$IncludePasswordRelease,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [bool]$IncludeSshKeyRelease,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [bool]$TerminateExpiredSessions,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [bool]$PassphraseProtectSshKey,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [bool]$UseAltLoginName,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [bool]$LinkedAccountScopeFiltering,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [object]$RdpApplicationHostAsset,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [object]$RdpApplicationHostAccount,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [switch]$RdpApplicationHostUserSupplied,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$RdpApplicationDisplayName,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$RdpApplicationAlias,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$RdpApplicationProgram,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$RdpApplicationCmdLine,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [object[]]$ApproverUsers,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [object[]]$ApproverGroups,
        [Parameter(ParameterSetName="Object",Mandatory=$true,ValueFromPipeline=$true)]
        [object]$AccessPolicyObject
    )

    process
    {
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

            # Normalize access request type aliases
            if ($AccessRequestType -ieq "RDP") { $AccessRequestType = "RemoteDesktop" }
            elseif ($AccessRequestType -ieq "RDPApplication" -or $AccessRequestType -ieq "RDPApp") { $AccessRequestType = "RemoteDesktopApplication" }
            elseif ($AccessRequestType -ieq "SSH") { $AccessRequestType = "Ssh" }
            elseif ($AccessRequestType -ieq "SSHKey") { $AccessRequestType = "SshKey" }
            elseif ($AccessRequestType -ieq "APIKey") { $AccessRequestType = "ApiKey" }

            $AccessPolicyObject = @{
                Name = $Name;
                RoleId = $local:EntitlementId;
                AccessRequestProperties = @{
                    AccessRequestType = $AccessRequestType
                }
            }

            if ($PSBoundParameters.ContainsKey("Description")) { $AccessPolicyObject.Description = $Description }
            if ($PSBoundParameters.ContainsKey("Priority")) { $AccessPolicyObject.Priority = $Priority }

            if ($PSBoundParameters.ContainsKey("ScopeAccounts") -or $PSBoundParameters.ContainsKey("ScopeAssets") -or `
                $PSBoundParameters.ContainsKey("ScopeAccountGroups") -or $PSBoundParameters.ContainsKey("ScopeAssetGroups"))
            {
                $AccessPolicyObject.ScopeItems = @(Resolve-SafeguardAccessPolicyScopeItems -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                    -ScopeAccounts $ScopeAccounts -ScopeAssets $ScopeAssets -ScopeAccountGroups $ScopeAccountGroups -ScopeAssetGroups $ScopeAssetGroups)
            }

            if ($PSBoundParameters.ContainsKey("SessionAccessAccountType"))
            {
                $AccessPolicyObject.AccessRequestProperties.SessionAccessAccountType = $SessionAccessAccountType
            }
            if ($PSBoundParameters.ContainsKey("SessionAccessAccounts"))
            {
                [object[]]$local:SessionAccounts = @()
                foreach ($local:SessionAccount in $SessionAccessAccounts)
                {
                    $local:AccountId = (Resolve-SafeguardPolicyAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $local:SessionAccount)
                    $local:SessionAccounts += @{ Id = $local:AccountId }
                }
                $AccessPolicyObject.AccessRequestProperties.SessionAccessAccountType = "PolicySpecific"
                $AccessPolicyObject.AccessRequestProperties.SessionAccessAccounts = @($local:SessionAccounts)
            }
            if ($AllowLinkedAccountPasswordAccess)
            {
                $AccessPolicyObject.AccessRequestProperties.AllowLinkedAccountPasswordAccess = $true
            }
            if ($PSBoundParameters.ContainsKey("AllowSimultaneousAccess")) { $AccessPolicyObject.AccessRequestProperties.AllowSimultaneousAccess = $AllowSimultaneousAccess }
            if ($PSBoundParameters.ContainsKey("MaximumSimultaneousReleases")) { $AccessPolicyObject.AccessRequestProperties.MaximumSimultaneousReleases = $MaximumSimultaneousReleases }
            if ($PSBoundParameters.ContainsKey("ChangePasswordAfterCheckin")) { $AccessPolicyObject.AccessRequestProperties.ChangePasswordAfterCheckin = $ChangePasswordAfterCheckin }
            if ($PSBoundParameters.ContainsKey("ChangeSshKeyAfterCheckin")) { $AccessPolicyObject.AccessRequestProperties.ChangeSshKeyAfterCheckin = $ChangeSshKeyAfterCheckin }
            if ($PSBoundParameters.ContainsKey("IncludePasswordRelease")) { $AccessPolicyObject.AccessRequestProperties.IncludePasswordRelease = $IncludePasswordRelease }
            if ($PSBoundParameters.ContainsKey("IncludeSshKeyRelease")) { $AccessPolicyObject.AccessRequestProperties.IncludeSshKeyRelease = $IncludeSshKeyRelease }
            if ($PSBoundParameters.ContainsKey("TerminateExpiredSessions")) { $AccessPolicyObject.AccessRequestProperties.TerminateExpiredSessions = $TerminateExpiredSessions }
            if ($PSBoundParameters.ContainsKey("PassphraseProtectSshKey")) { $AccessPolicyObject.AccessRequestProperties.PassphraseProtectSshKey = $PassphraseProtectSshKey }
            if ($PSBoundParameters.ContainsKey("UseAltLoginName")) { $AccessPolicyObject.AccessRequestProperties.UseAltLoginName = $UseAltLoginName }
            if ($PSBoundParameters.ContainsKey("LinkedAccountScopeFiltering")) { $AccessPolicyObject.AccessRequestProperties.LinkedAccountScopeFiltering = $LinkedAccountScopeFiltering }

            # Remote Desktop Application properties
            if ($PSBoundParameters.ContainsKey("RdpApplicationHostAsset") -or $PSBoundParameters.ContainsKey("RdpApplicationHostAccount") -or `
                $PSBoundParameters.ContainsKey("RdpApplicationDisplayName") -or $PSBoundParameters.ContainsKey("RdpApplicationAlias") -or `
                $PSBoundParameters.ContainsKey("RdpApplicationProgram") -or $PSBoundParameters.ContainsKey("RdpApplicationCmdLine") -or `
                $RdpApplicationHostUserSupplied)
            {
                if ($AccessRequestType -ne "RemoteDesktopApplication")
                {
                    throw "RDP application properties can only be set when AccessRequestType is RemoteDesktopApplication (or RDPApplication/RDPApp)"
                }
                $local:RdpAppProps = @{}
                if ($PSBoundParameters.ContainsKey("RdpApplicationHostAsset"))
                {
                    $local:RdpAppProps.ApplicationHostAssetId = (Resolve-SafeguardPolicyAssetId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $RdpApplicationHostAsset)
                }
                if ($PSBoundParameters.ContainsKey("RdpApplicationHostAccount"))
                {
                    $local:RdpAppProps.ApplicationHostAccountId = (Resolve-SafeguardPolicyAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $RdpApplicationHostAccount)
                }
                if ($RdpApplicationHostUserSupplied) { $local:RdpAppProps.ApplicationHostUserSupplied = $true }
                if ($PSBoundParameters.ContainsKey("RdpApplicationDisplayName")) { $local:RdpAppProps.ApplicationDisplayName = $RdpApplicationDisplayName }
                if ($PSBoundParameters.ContainsKey("RdpApplicationAlias")) { $local:RdpAppProps.ApplicationAlias = $RdpApplicationAlias }
                if ($PSBoundParameters.ContainsKey("RdpApplicationProgram")) { $local:RdpAppProps.ApplicationProgram = $RdpApplicationProgram }
                if ($PSBoundParameters.ContainsKey("RdpApplicationCmdLine")) { $local:RdpAppProps.ApplicationCmdLine = $RdpApplicationCmdLine }
                $AccessPolicyObject.SessionProperties = @{
                    RemoteDesktopApplicationProperties = $local:RdpAppProps
                }
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

.PARAMETER EntitlementToEdit
An integer containing the ID or a string containing the name of the entitlement to qualify
the access policy lookup in case multiple policies share the same name.

.PARAMETER Name
A string containing the new name for the access policy.

.PARAMETER Description
A string containing the new description for the access policy.

.PARAMETER Priority
An integer for the priority of this policy within its entitlement. Set to 0 for lowest priority.

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

.PARAMETER SessionAccessAccountType
How to authenticate to assets for session access (None, UserSupplied, LinkedAccount, PolicySpecific).
Use LinkedAccount to use the requesting user's linked accounts.
Use PolicySpecific with -SessionAccessAccounts to specify shared or directory accounts.

.PARAMETER SessionAccessAccounts
An array of account IDs or asset\account names to use as session access accounts.
Only used when SessionAccessAccountType is PolicySpecific.
Use asset\account syntax (e.g. "server01\svc-account") to specify accounts.

.PARAMETER AllowLinkedAccountPasswordAccess
Switch to allow linked accounts to be requested for password access.

.PARAMETER AllowSimultaneousAccess
Whether to allow more than one access request to be active at the same time.

.PARAMETER MaximumSimultaneousReleases
Maximum number of times access can be granted during the same time period (1-99).

.PARAMETER ChangePasswordAfterCheckin
Whether to change the account password after an access request is checked in.

.PARAMETER ChangeSshKeyAfterCheckin
Whether to change the SSH key pair after an access request is checked in.

.PARAMETER IncludePasswordRelease
Whether to include the password with session or file access requests.

.PARAMETER IncludeSshKeyRelease
Whether to include the SSH key with session or file access requests.

.PARAMETER TerminateExpiredSessions
Whether to terminate active sessions when the access request expires.

.PARAMETER PassphraseProtectSshKey
Whether the SSH private key will be encrypted upon check out.

.PARAMETER UseAltLoginName
Whether to use the AltLoginName AD attribute for a session connection launch string.

.PARAMETER LinkedAccountScopeFiltering
Whether to filter linked accounts using scope filtering.

.PARAMETER RdpApplicationHostAsset
An asset ID or name of the host asset for Remote Desktop Application sessions.

.PARAMETER RdpApplicationHostAccount
An account ID or asset\account name for the login account on the RDP application host.

.PARAMETER RdpApplicationHostUserSupplied
Switch to indicate that the credentials for the application host are user-supplied.

.PARAMETER RdpApplicationDisplayName
The display name of the remote application.

.PARAMETER RdpApplicationAlias
The alias of the remote application (Windows Server).

.PARAMETER RdpApplicationProgram
The path to the remote application program (e.g. path to OI-SG-RemoteApp-Launcher.exe).

.PARAMETER RdpApplicationCmdLine
The command line arguments for the remote application.

.PARAMETER ApproverUsers
An array of user IDs or names to set as approvers. When specified, approval will be required.
A single approver set is created with all specified users and groups (replaces existing approver sets).
Use provider\user syntax (e.g. "local\admin") to uniquely identify users from a specific identity provider.

.PARAMETER ApproverGroups
An array of user group IDs or names to set as approvers. When specified, approval will be required.
A single approver set is created with all specified users and groups (replaces existing approver sets).

.PARAMETER NoApproval
Switch to disable approval requirement (automatic approval). Removes existing approver sets.

.PARAMETER AccessPolicyObject
An object containing the existing access policy with desired properties set.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Edit-SafeguardAccessPolicy -PolicyToEdit "SSH Access" -Description "Updated description"

.EXAMPLE
Edit-SafeguardAccessPolicy -PolicyToEdit "SSH Access" -EntitlementToEdit "Lab Administrator" -Description "Updated"

.EXAMPLE
Edit-SafeguardAccessPolicy -PolicyToEdit 123 -ScopeAccounts "root","admin"

.EXAMPLE
Edit-SafeguardAccessPolicy -PolicyToEdit "SSH Access" -ApproverUsers "admin1","admin2"

.EXAMPLE
Edit-SafeguardAccessPolicy -PolicyToEdit "SSH Access" -NoApproval

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
        [object]$EntitlementToEdit,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$Name,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$Description,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [int]$Priority,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [ValidateSet("Password","SSH","SSHKey","RemoteDesktop","RDP","Telnet","SshKey","RemoteDesktopApplication","RDPApplication","RDPApp","ApiKey","APIKey","File",IgnoreCase=$true)]
        [string]$AccessRequestType,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [object[]]$ScopeAccounts,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [object[]]$ScopeAssets,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [object[]]$ScopeAccountGroups,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [object[]]$ScopeAssetGroups,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [ValidateSet("None","UserSupplied","LinkedAccount","PolicySpecific",IgnoreCase=$true)]
        [string]$SessionAccessAccountType,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [object[]]$SessionAccessAccounts,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [switch]$AllowLinkedAccountPasswordAccess,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [bool]$AllowSimultaneousAccess,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [ValidateRange(1,99)]
        [int]$MaximumSimultaneousReleases,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [bool]$ChangePasswordAfterCheckin,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [bool]$ChangeSshKeyAfterCheckin,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [bool]$IncludePasswordRelease,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [bool]$IncludeSshKeyRelease,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [bool]$TerminateExpiredSessions,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [bool]$PassphraseProtectSshKey,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [bool]$UseAltLoginName,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [bool]$LinkedAccountScopeFiltering,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [object]$RdpApplicationHostAsset,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [object]$RdpApplicationHostAccount,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [switch]$RdpApplicationHostUserSupplied,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$RdpApplicationDisplayName,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$RdpApplicationAlias,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$RdpApplicationProgram,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$RdpApplicationCmdLine,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [object[]]$ApproverUsers,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [object[]]$ApproverGroups,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [switch]$NoApproval,
        [Parameter(ParameterSetName="Object",Mandatory=$true,ValueFromPipeline=$true)]
        [object]$AccessPolicyObject
    )

    process
    {
        if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
        if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

        if ($PsCmdlet.ParameterSetName -eq "Object" -and -not $AccessPolicyObject)
        {
            throw "AccessPolicyObject must not be null"
        }

        if ($PsCmdlet.ParameterSetName -eq "Attributes")
        {
            $local:ResolveParams = @{}
            if ($PSBoundParameters.ContainsKey("EntitlementToEdit"))
            {
                Import-Module -Name "$PSScriptRoot\entitlements.psm1" -Scope Local
                $local:ResolveParams["EntitlementId"] = (Resolve-SafeguardEntitlementId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $EntitlementToEdit)
            }

            $local:AccessPolicyId = Resolve-SafeguardAccessPolicyId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure @local:ResolveParams $PolicyToEdit
            $AccessPolicyObject = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "AccessPolicies/$($local:AccessPolicyId)")

            if ($PSBoundParameters.ContainsKey("Name")) { $AccessPolicyObject.Name = $Name }
            if ($PSBoundParameters.ContainsKey("Description")) { $AccessPolicyObject.Description = $Description }
            if ($PSBoundParameters.ContainsKey("Priority")) { $AccessPolicyObject.Priority = $Priority }
            if ($PSBoundParameters.ContainsKey("AccessRequestType"))
            {
                # Normalize access request type aliases
                if ($AccessRequestType -ieq "RDP") { $AccessRequestType = "RemoteDesktop" }
                elseif ($AccessRequestType -ieq "RDPApplication" -or $AccessRequestType -ieq "RDPApp") { $AccessRequestType = "RemoteDesktopApplication" }
                elseif ($AccessRequestType -ieq "SSH") { $AccessRequestType = "Ssh" }
                elseif ($AccessRequestType -ieq "SSHKey") { $AccessRequestType = "SshKey" }
                elseif ($AccessRequestType -ieq "APIKey") { $AccessRequestType = "ApiKey" }

                if (-not $AccessPolicyObject.AccessRequestProperties) { $AccessPolicyObject.AccessRequestProperties = @{} }
                $AccessPolicyObject.AccessRequestProperties.AccessRequestType = $AccessRequestType
            }

            if ($PSBoundParameters.ContainsKey("ScopeAccounts") -or $PSBoundParameters.ContainsKey("ScopeAssets") -or `
                $PSBoundParameters.ContainsKey("ScopeAccountGroups") -or $PSBoundParameters.ContainsKey("ScopeAssetGroups"))
            {
                $AccessPolicyObject.ScopeItems = @(Resolve-SafeguardAccessPolicyScopeItems -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                    -ScopeAccounts $ScopeAccounts -ScopeAssets $ScopeAssets -ScopeAccountGroups $ScopeAccountGroups -ScopeAssetGroups $ScopeAssetGroups)
            }

            if ($PSBoundParameters.ContainsKey("SessionAccessAccountType") -or $PSBoundParameters.ContainsKey("SessionAccessAccounts") -or $AllowLinkedAccountPasswordAccess)
            {
                if (-not $AccessPolicyObject.AccessRequestProperties) { $AccessPolicyObject.AccessRequestProperties = @{} }
            }
            if ($PSBoundParameters.ContainsKey("SessionAccessAccountType"))
            {
                $AccessPolicyObject.AccessRequestProperties.SessionAccessAccountType = $SessionAccessAccountType
            }
            if ($PSBoundParameters.ContainsKey("SessionAccessAccounts"))
            {
                [object[]]$local:SessionAccounts = @()
                foreach ($local:SessionAccount in $SessionAccessAccounts)
                {
                    $local:AccountId = (Resolve-SafeguardPolicyAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $local:SessionAccount)
                    $local:SessionAccounts += @{ Id = $local:AccountId }
                }
                $AccessPolicyObject.AccessRequestProperties.SessionAccessAccountType = "PolicySpecific"
                $AccessPolicyObject.AccessRequestProperties.SessionAccessAccounts = @($local:SessionAccounts)
            }
            if ($AllowLinkedAccountPasswordAccess)
            {
                $AccessPolicyObject.AccessRequestProperties.AllowLinkedAccountPasswordAccess = $true
            }
            if ($PSBoundParameters.ContainsKey("AllowSimultaneousAccess")) { $AccessPolicyObject.AccessRequestProperties.AllowSimultaneousAccess = $AllowSimultaneousAccess }
            if ($PSBoundParameters.ContainsKey("MaximumSimultaneousReleases")) { $AccessPolicyObject.AccessRequestProperties.MaximumSimultaneousReleases = $MaximumSimultaneousReleases }
            if ($PSBoundParameters.ContainsKey("ChangePasswordAfterCheckin")) { $AccessPolicyObject.AccessRequestProperties.ChangePasswordAfterCheckin = $ChangePasswordAfterCheckin }
            if ($PSBoundParameters.ContainsKey("ChangeSshKeyAfterCheckin")) { $AccessPolicyObject.AccessRequestProperties.ChangeSshKeyAfterCheckin = $ChangeSshKeyAfterCheckin }
            if ($PSBoundParameters.ContainsKey("IncludePasswordRelease")) { $AccessPolicyObject.AccessRequestProperties.IncludePasswordRelease = $IncludePasswordRelease }
            if ($PSBoundParameters.ContainsKey("IncludeSshKeyRelease")) { $AccessPolicyObject.AccessRequestProperties.IncludeSshKeyRelease = $IncludeSshKeyRelease }
            if ($PSBoundParameters.ContainsKey("TerminateExpiredSessions")) { $AccessPolicyObject.AccessRequestProperties.TerminateExpiredSessions = $TerminateExpiredSessions }
            if ($PSBoundParameters.ContainsKey("PassphraseProtectSshKey")) { $AccessPolicyObject.AccessRequestProperties.PassphraseProtectSshKey = $PassphraseProtectSshKey }
            if ($PSBoundParameters.ContainsKey("UseAltLoginName")) { $AccessPolicyObject.AccessRequestProperties.UseAltLoginName = $UseAltLoginName }
            if ($PSBoundParameters.ContainsKey("LinkedAccountScopeFiltering")) { $AccessPolicyObject.AccessRequestProperties.LinkedAccountScopeFiltering = $LinkedAccountScopeFiltering }

            # Remote Desktop Application properties
            if ($PSBoundParameters.ContainsKey("RdpApplicationHostAsset") -or $PSBoundParameters.ContainsKey("RdpApplicationHostAccount") -or `
                $PSBoundParameters.ContainsKey("RdpApplicationDisplayName") -or $PSBoundParameters.ContainsKey("RdpApplicationAlias") -or `
                $PSBoundParameters.ContainsKey("RdpApplicationProgram") -or $PSBoundParameters.ContainsKey("RdpApplicationCmdLine") -or `
                $RdpApplicationHostUserSupplied)
            {
                $local:EffectiveType = $AccessPolicyObject.AccessRequestProperties.AccessRequestType
                if ($local:EffectiveType -ne "RemoteDesktopApplication")
                {
                    throw "RDP application properties can only be set when AccessRequestType is RemoteDesktopApplication (current type: $($local:EffectiveType))"
                }
                if (-not $AccessPolicyObject.SessionProperties) { $AccessPolicyObject.SessionProperties = @{} }
                if (-not $AccessPolicyObject.SessionProperties.RemoteDesktopApplicationProperties) { $AccessPolicyObject.SessionProperties.RemoteDesktopApplicationProperties = @{} }
                $local:RdpAppProps = $AccessPolicyObject.SessionProperties.RemoteDesktopApplicationProperties
                if ($PSBoundParameters.ContainsKey("RdpApplicationHostAsset"))
                {
                    $local:RdpAppProps.ApplicationHostAssetId = (Resolve-SafeguardPolicyAssetId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $RdpApplicationHostAsset)
                }
                if ($PSBoundParameters.ContainsKey("RdpApplicationHostAccount"))
                {
                    $local:RdpAppProps.ApplicationHostAccountId = (Resolve-SafeguardPolicyAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $RdpApplicationHostAccount)
                }
                if ($RdpApplicationHostUserSupplied) { $local:RdpAppProps.ApplicationHostUserSupplied = $true }
                if ($PSBoundParameters.ContainsKey("RdpApplicationDisplayName")) { $local:RdpAppProps.ApplicationDisplayName = $RdpApplicationDisplayName }
                if ($PSBoundParameters.ContainsKey("RdpApplicationAlias")) { $local:RdpAppProps.ApplicationAlias = $RdpApplicationAlias }
                if ($PSBoundParameters.ContainsKey("RdpApplicationProgram")) { $local:RdpAppProps.ApplicationProgram = $RdpApplicationProgram }
                if ($PSBoundParameters.ContainsKey("RdpApplicationCmdLine")) { $local:RdpAppProps.ApplicationCmdLine = $RdpApplicationCmdLine }
            }

            if ($PSBoundParameters.ContainsKey("ApproverUsers") -or $PSBoundParameters.ContainsKey("ApproverGroups"))
            {
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
            elseif ($NoApproval)
            {
                $AccessPolicyObject.ApproverProperties = @{ RequireApproval = $false }
                $AccessPolicyObject.ApproverSets = @()
            }
        }

        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "AccessPolicies/$($AccessPolicyObject.Id)" -Body $AccessPolicyObject
    }
}
