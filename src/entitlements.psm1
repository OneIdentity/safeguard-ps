<# Copyright (c) 2026 One Identity LLC. All rights reserved. #>
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

    if ($Entitlement.Id -as [int])
    {
        $Entitlement = $Entitlement.Id
    }

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
Entitlement is a set of access request policies that restrict privileged access to authorized users

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER EntitlementToGet
An integer containing the ID or a string containing the name of the entitlement to get.

.PARAMETER Fields
An array of the entitlement property names to return.

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
        [object]$EntitlementToGet,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Parameters = $null
    if ($Fields)
    {
        $local:Parameters = @{ fields = ($Fields -join ",")}
    }

    if ($PSBoundParameters.ContainsKey("EntitlementToGet"))
    {
        $local:EntitlementId = Resolve-SafeguardEntitlementId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $EntitlementToGet
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            GET "Roles/$($local:EntitlementId)" -Parameters $local:Parameters
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            GET Roles -Parameters $local:Parameters
    }
}

<#
.SYNOPSIS
Create a new Entitlement in Safeguard via the Web API.

.DESCRIPTION
Create a new Entitlement in Safeguard. Access policies can be attached
to Entitlements. Users and groups can be created using separate cmdlets
and added as members via this cmdlet.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Name
The name of the entitlement.

.PARAMETER Description
A string containing the description of the entitlement.

.PARAMETER MemberUsers
Array of IDs or names of the users to set as the initial members of the entitlement.
This sets the complete member list. To incrementally add or remove members after creation,
use Add-SafeguardEntitlementMember and Remove-SafeguardEntitlementMember.
Use 'provider\user' syntax to uniquely identify users from a specific identity provider
(e.g. 'local\admin', 'ad.corp\jsmith').

.PARAMETER MemberGroups
Array of IDs or names of the user groups to set as the initial members of the entitlement.
This sets the complete member list. To incrementally add or remove members after creation,
use Add-SafeguardEntitlementMember and Remove-SafeguardEntitlementMember.

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
        [Parameter(Mandatory=$false)]
        [string]$Description,
        [Parameter(Mandatory=$false,Position=1)]
        [object[]]$MemberUsers,
        [Parameter(Mandatory=$false,Position=2)]
        [object[]]$MemberGroups
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    [object[]]$Members = $null
    foreach ($local:User in $MemberUsers)
    {
        $local:ResolvedUserId = (Get-SafeguardUser -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -UserToGet $local:User).Id
        $local:Member = @{
            Id = $local:ResolvedUserId;
            PrincipalKind = "User"
        }
        $local:Members += $($local:Member)
    }

    foreach ($local:Group in $MemberGroups)
    {
        $local:ResolvedGroupId = (Get-SafeguardUserGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -GroupToGet $local:Group).Id
        $local:Member = @{
            Id = $local:ResolvedGroupId;
            PrincipalKind = "Group"
        }
        $local:Members += $($local:Member)
    }

    $local:Body = @{ Name = $Name; Members = $local:Members }
    if ($PSBoundParameters.ContainsKey("Description")) { $local:Body.Description = $Description }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST Roles `
        -Body $local:Body
}



<#
.SYNOPSIS
Remove entitlements in Safeguard via the Web API.

.DESCRIPTION
Entitlement is a set of access request policies that restrict privileged access to authorized users

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

<#
.SYNOPSIS
Edit an existing entitlement in Safeguard via the Web API.

.DESCRIPTION
Edit an existing entitlement in Safeguard. Entitlements are sets of access request
policies that restrict privileged access to authorized users.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER EntitlementToEdit
An integer containing the ID or a string containing the name of the entitlement to edit.

.PARAMETER Name
A string containing the new name for the entitlement.

.PARAMETER Description
A string containing the new description for the entitlement.

.PARAMETER MemberUsers
Array of IDs or names of the users to set as members of the entitlement. This replaces the
entire member list -- any existing members not included will be removed. Use 'provider\user'
syntax to uniquely identify users from a specific identity provider (e.g. 'local\admin',
'ad.corp\jsmith'). To incrementally add or remove individual members, use
Add-SafeguardEntitlementMember and Remove-SafeguardEntitlementMember instead.

.PARAMETER MemberGroups
Array of IDs or names of the user groups to set as members of the entitlement. This replaces
the entire member list -- any existing members not included will be removed. To incrementally
add or remove individual members, use Add-SafeguardEntitlementMember and
Remove-SafeguardEntitlementMember instead.

.PARAMETER EntitlementObject
An object containing the existing entitlement with desired properties set.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Edit-SafeguardEntitlement -EntitlementToEdit "Lab Administrator" -Description "Updated description"

.EXAMPLE
Edit-SafeguardEntitlement -EntitlementToEdit 123 -Name "New Name"

.EXAMPLE
$obj = Get-SafeguardEntitlement "Lab Administrator"; $obj.Description = "New desc"; Edit-SafeguardEntitlement -EntitlementObject $obj
#>
function Edit-SafeguardEntitlement
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
        [object]$EntitlementToEdit,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$Name,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$Description,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [object[]]$MemberUsers,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [object[]]$MemberGroups,
        [Parameter(ParameterSetName="Object",Mandatory=$true,ValueFromPipeline=$true)]
        [object]$EntitlementObject
    )

    process
    {
        if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
        if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

        if ($PsCmdlet.ParameterSetName -eq "Object" -and -not $EntitlementObject)
        {
            throw "EntitlementObject must not be null"
        }

        if ($PsCmdlet.ParameterSetName -eq "Attributes")
        {
            $local:EntitlementId = Resolve-SafeguardEntitlementId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $EntitlementToEdit
            $EntitlementObject = (Get-SafeguardEntitlement -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $local:EntitlementId)

            if ($PSBoundParameters.ContainsKey("Name")) { $EntitlementObject.Name = $Name }
            if ($PSBoundParameters.ContainsKey("Description")) { $EntitlementObject.Description = $Description }

            if ($PSBoundParameters.ContainsKey("MemberUsers") -or $PSBoundParameters.ContainsKey("MemberGroups"))
            {
                [object[]]$local:Members = $null
                foreach ($local:User in $MemberUsers)
                {
                    $local:ResolvedUserId = (Get-SafeguardUser -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -UserToGet $local:User).Id
                    $local:Member = @{
                        Id = $local:ResolvedUserId;
                        PrincipalKind = "User"
                    }
                    $local:Members += $($local:Member)
                }
                foreach ($local:Group in $MemberGroups)
                {
                    $local:ResolvedGroupId = (Get-SafeguardUserGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -GroupToGet $local:Group).Id
                    $local:Member = @{
                        Id = $local:ResolvedGroupId;
                        PrincipalKind = "Group"
                    }
                    $local:Members += $($local:Member)
                }
                $EntitlementObject.Members = $local:Members
            }
        }

        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "Roles/$($EntitlementObject.Id)" -Body $EntitlementObject
    }
}

<#
.SYNOPSIS
Add one or more users or groups to an entitlement in Safeguard via the Web API.

.DESCRIPTION
Incrementally add members to an entitlement without affecting existing members. When
entitlement membership changes, it affects which users can request access through the
access policies attached to that entitlement. To replace the entire member list at once,
use Edit-SafeguardEntitlement with -MemberUsers and -MemberGroups instead.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Entitlement
An integer containing the ID or a string containing the name of the entitlement.

.PARAMETER Users
An array of user IDs or names to add to the entitlement. Existing members are not affected.
Use 'provider\user' syntax to uniquely identify users from a specific identity provider
(e.g. 'local\admin', 'ad.corp\jsmith').

.PARAMETER Groups
An array of user group IDs or names to add to the entitlement. Existing members are not affected.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Add-SafeguardEntitlementMember "Lab Entitlement" -Users user1,user2

.EXAMPLE
Add-SafeguardEntitlementMember "Lab Entitlement" -Groups "Lab Users"

.EXAMPLE
Add-SafeguardEntitlementMember "Lab Entitlement" -Users user1 -Groups "Lab Users"

.EXAMPLE
Add-SafeguardEntitlementMember "Lab Entitlement" -Users "local\admin","ad.corp\jsmith"
#>
function Add-SafeguardEntitlementMember
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
        [object]$Entitlement,
        [Parameter(Mandatory=$false)]
        [object[]]$Users,
        [Parameter(Mandatory=$false)]
        [object[]]$Groups
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $PSBoundParameters.ContainsKey("Users") -and -not $PSBoundParameters.ContainsKey("Groups"))
    {
        throw "You must specify -Users, -Groups, or both"
    }

    $local:EntitlementId = (Resolve-SafeguardEntitlementId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Entitlement)

    [object[]]$local:Members = @()
    foreach ($local:User in $Users)
    {
        $local:ResolvedUserId = (Get-SafeguardUser -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -UserToGet $local:User).Id
        $local:Members += @{
            Id = $local:ResolvedUserId;
            PrincipalKind = "User"
        }
    }
    foreach ($local:Group in $Groups)
    {
        $local:ResolvedGroupId = (Get-SafeguardUserGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -GroupToGet $local:Group).Id
        $local:Members += @{
            Id = $local:ResolvedGroupId;
            PrincipalKind = "Group"
        }
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST `
        "Roles/$($local:EntitlementId)/Members/Add" -Body $local:Members | Out-Null

    Get-SafeguardEntitlement -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $local:EntitlementId
}

<#
.SYNOPSIS
Remove one or more users or groups from an entitlement in Safeguard via the Web API.

.DESCRIPTION
Incrementally remove members from an entitlement without affecting other existing members.
When entitlement membership changes, it affects which users can request access through the
access policies attached to that entitlement. To replace the entire member list at once,
use Edit-SafeguardEntitlement with -MemberUsers and -MemberGroups instead.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Entitlement
An integer containing the ID or a string containing the name of the entitlement.

.PARAMETER Users
An array of user IDs or names to remove from the entitlement. Other members are not affected.
Use 'provider\user' syntax to uniquely identify users from a specific identity provider
(e.g. 'local\admin', 'ad.corp\jsmith').

.PARAMETER Groups
An array of user group IDs or names to remove from the entitlement. Other members are not affected.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardEntitlementMember "Lab Entitlement" -Users user1,user2

.EXAMPLE
Remove-SafeguardEntitlementMember "Lab Entitlement" -Groups "Lab Users"

.EXAMPLE
Remove-SafeguardEntitlementMember "Lab Entitlement" -Users user1 -Groups "Lab Users"

.EXAMPLE
Remove-SafeguardEntitlementMember "Lab Entitlement" -Users "local\admin","ad.corp\jsmith"
#>
function Remove-SafeguardEntitlementMember
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
        [object]$Entitlement,
        [Parameter(Mandatory=$false)]
        [object[]]$Users,
        [Parameter(Mandatory=$false)]
        [object[]]$Groups
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $PSBoundParameters.ContainsKey("Users") -and -not $PSBoundParameters.ContainsKey("Groups"))
    {
        throw "You must specify -Users, -Groups, or both"
    }

    $local:EntitlementId = (Resolve-SafeguardEntitlementId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Entitlement)

    [object[]]$local:Members = @()
    foreach ($local:User in $Users)
    {
        $local:ResolvedUserId = (Get-SafeguardUser -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -UserToGet $local:User).Id
        $local:Members += @{
            Id = $local:ResolvedUserId;
            PrincipalKind = "User"
        }
    }
    foreach ($local:Group in $Groups)
    {
        $local:ResolvedGroupId = (Get-SafeguardUserGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -GroupToGet $local:Group).Id
        $local:Members += @{
            Id = $local:ResolvedGroupId;
            PrincipalKind = "Group"
        }
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST `
        "Roles/$($local:EntitlementId)/Members/Remove" -Body $local:Members | Out-Null

    Get-SafeguardEntitlement -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $local:EntitlementId
}
