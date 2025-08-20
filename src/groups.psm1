# Helper
function Resolve-SafeguardGroupId
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
        [ValidateSet("User", "Asset", "Account", IgnoreCase=$true)]
        [string]$GroupType,
        [Parameter(Mandatory=$true,Position=1)]
        [object]$Group
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    # Allow case insensitive group types to translate to appropriate case sensitive URL path
    switch ($GroupType)
    {
        "user" { $GroupType = "User"; break }
        "asset" { $GroupType = "Asset"; break }
        "account" { $GroupType = "Account"; break }
    }

    $local:RelativeUrl = "$($GroupType)Groups"

    if ($Group.Id -as [int])
    {
        $Group = $Group.Id
    }

    if (-not ($Group -as [int]))
    {
        $local:EscapedName = $Group -replace "'", "\'"
        $local:Groups = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET $local:RelativeUrl `
                                                -Parameters @{ filter = "Name ieq '$($local:EscapedName)'" })
        if (-not $local:Groups)
        {
            throw "Unable to find $($GroupType.ToLower()) group matching '$Group'"
        }
        if ($local:Groups.Count -ne 1)
        {
            throw "Found $($local:Groups.Count) $($GroupType.ToLower()) groups matching '$Group'"
        }
        $local:Groups[0].Id
    }
    else
    {
        $Group
    }
}
function Get-SafeguardGroup
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
        [ValidateSet("User", "Asset", "Account", IgnoreCase=$true)]
        [string]$GroupType,
        [Parameter(Mandatory=$false,Position=1)]
        [object]$GroupToGet,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields,
        [Parameter(Mandatory=$false)]
        [switch]$DynamicOnly
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    # Allow case insensitive group types to translate to appropriate case sensitive URL path
    switch ($GroupType)
    {
        "user" { $GroupType = "User"; break }
        "asset" { $GroupType = "Asset"; break }
        "Account" { $GroupType = "Account"; break }
    }
    $local:RelativeUrl = "$($GroupType)Groups"

    $local:Parameters = $null
    if ($Fields)
    {
        $local:Parameters = @{ fields = ($Fields -join ",")}
    }

    if ($DynamicOnly)
    {
        if (-not $local:Parameters) { $local:Parameters = @{} }
        $local:Parameters.filter = "IsDynamic eq true"
    }

    if ($PSBoundParameters.ContainsKey("GroupToGet") -and $GroupToGet)
    {
        $local:GroupId = Resolve-SafeguardGroupId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $GroupType $GroupToGet
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$local:RelativeUrl/$($local:GroupId)" `
            -Parameters $local:Parameters
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET $local:RelativeUrl `
            -Parameters $local:Parameters
    }
}
function New-SafeguardGroup
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
        [ValidateSet("User", "Asset", "Account", IgnoreCase=$true)]
        [string]$GroupType,
        [Parameter(Mandatory=$false,Position=1)]
        [string]$Name,
        [Parameter(Mandatory=$false,Position=2)]
        [string]$Description
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    # Allow case insensitive group types to translate to appropriate case sensitive URL path
    switch ($GroupType)
    {
        "user" { $GroupType = "User"; break }
        "asset" { $GroupType = "Asset"; break }
        "Account" { $GroupType = "Account"; break }
    }
    $local:RelativeUrl = "$($GroupType)Groups"

    $local:Body = @{ Name = $Name }
    if ($PSBoundParameters.ContainsKey("Description")) { $local:Body.Description = $Description }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST $local:RelativeUrl `
        -Body $local:Body
}
function Remove-SafeguardGroup
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
        [ValidateSet("User", "Asset", "Account", IgnoreCase=$true)]
        [string]$GroupType,
        [Parameter(Mandatory=$true,Position=1)]
        [object]$GroupToDelete
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    # Allow case insensitive group types to translate to appropriate case sensitive URL path
    switch ($GroupType)
    {
        "user" { $GroupType = "User"; break }
        "asset" { $GroupType = "Asset"; break }
        "Account" { $GroupType = "Account"; break }
    }
    $local:RelativeUrl = "$($GroupType)Groups"
    $local:GroupId = (Resolve-SafeguardGroupId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $GroupType $GroupToDelete)

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "$($local:RelativeUrl)/$($local:GroupId)" `
        -Body $local:Body
}
function Edit-SafeguardGroup
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
        [ValidateSet("User", "Asset", "Account", IgnoreCase=$true)]
        [string]$GroupType,
        [Parameter(Mandatory=$true,Position=1)]
        [object]$GroupToEdit,
        [Parameter(Mandatory=$true,Position=2)]
        [string]$Operation,
        [Parameter(Mandatory=$true,Position=3)]
        [object]$ObjectToOperate
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    # Allow case insensitive group types to translate to appropriate case sensitive URL path
    $local:UrlPart = "Members"
    switch ($GroupType)
    {
        "user" { $GroupType = "User"; $local:UrlPart = "Members"; break }
        "asset" { $GroupType = "Asset"; $local:UrlPart = "Assets"; break }
        "Account" { $GroupType = "Account"; $local:UrlPart = "Accounts"; break }
    }

    $local:RelativeUrl = "$($GroupType)Groups"
    $local:GroupId = (Resolve-SafeguardGroupId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $GroupType $GroupToEdit)

    # Modify the group using add or remove endpoint
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST `
        "$($local:RelativeUrl)/$($local:GroupId)/$($local:UrlPart)/$Operation" -Body $ObjectToOperate | Out-Null

    # Get the result by fetching the group
    Get-SafeguardGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -GroupType $GroupType -GroupToGet $local:GroupId
}

<#
.SYNOPSIS
Get user groups as defined by policy administrators that can added to entitlement membership
via the Web API.

.DESCRIPTION
User groups are collections of users that can be added to an entitlement with access policies
granting access to privileged passwords and privileged sessions.  This cmdlet returns user
groups that have been defined by policy administrators

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER GroupToGet
An integer containing the ID of the user group to get or a string containing the name.

.PARAMETER Fields
An array of the user group property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardUserGroup -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardUserGroup "Web Server Admins"
#>
function Get-SafeguardUserGroup
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
        [object]$GroupToGet,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Get-SafeguardGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure User $GroupToGet -Fields $Fields
}

<#
.SYNOPSIS
Get user group members as defined by policy administrators that can added to entitlement membership
via the Web API.

.DESCRIPTION
User groups are collections of users that can be added to an entitlement with access policies
granting access to privileged passwords and privileged sessions.  This cmdlet returns user
group members that have been defined by policy administrators

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER GroupToGet
An integer containing the ID of the user group to get or a string containing the name.

.PARAMETER Fields
An array of the user property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardUserGroupMember -AccessToken $token -Appliance 10.5.32.54 -Insecure "Group1"

.EXAMPLE
Get-SafeguardUserGroupMember "Web Server Admins"
#>
function Get-SafeguardUserGroupMember
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
        [object]$GroupToGet,
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

    $local:GroupId = (Resolve-SafeguardGroupId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure User $GroupToGet)
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure core GET "UserGroups/$($local:GroupId)/Members" -Parameters $local:Parameters
}

<#
.SYNOPSIS
Create a user group that can added to entitlement membership via the Web API.

.DESCRIPTION
User groups are collections of users that can be added to an entitlement with access policies
granting access to privileged passwords and privileged sessions.  This cmdlet creates a user
group that may be specific to Safeguard or based on a directory group.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Name
A string containing the name for the new group.  For groups based on a directory, this must
match the sAMAccountName for Active Directory or the unique naming attribute of the group
for LDAP.

.PARAMETER Description
A string containing the description for a new group specific to Safeguard.

.PARAMETER Directory
An integer containing the ID of the directory identity provider Id to get or a string containing the name.

.PARAMETER DomainName
A string containing the name of the domain within the directory where necessary.  A directory
a single domain does not require this parameter.

.PARAMETER AdminRoles
An array of strings containing the permissions (admin roles) to assign to the members of this directory
group.  You may also specify 'All' to grant all permissions. Other permissions are: 'GlobalAdmin',
'ApplicationAuditor', 'SystemAuditor', 'Auditor', 'AssetAdmin', 'ApplianceAdmin', 'PolicyAdmin', 'UserAdmin',
'HelpdeskAdmin', 'OperationsAdmin'.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
New-SafeguardUserGroup -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
New-SafeguardUserGroup "Web Server Admins" -Directory "singledomain.corp"

.EXAMPLE
New-SafeguardUserGroup "Web Server Admins" -Directory "demo.corp" -Domain "us.demo.corp" -AdminRoles UserAdmin,PolicyAdmin
#>
function New-SafeguardUserGroup
{
    [CmdletBinding(DefaultParameterSetName="Local")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Name,
        [Parameter(ParameterSetName="Local",Mandatory=$false,Position=1)]
        [string]$Description,
        [Parameter(ParameterSetName="Directory",Mandatory=$true,Position=1)]
        [object]$Directory,
        [Parameter(ParameterSetName="Directory",Mandatory=$false,Position=2)]
        [string]$DomainName,
        [Parameter(Mandatory=$false)]
        [ValidateSet('GlobalAdmin','DirectoryAdmin','Auditor','ApplicationAuditor','SystemAuditor','AssetAdmin','ApplianceAdmin',
                     'PolicyAdmin','UserAdmin','HelpdeskAdmin','OperationsAdmin','All',IgnoreCase=$true)]
        [string[]]$AdminRoles
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    Import-Module -Name "$PSScriptRoot\users.psm1" -Scope Local

    $local:Body = @{ Name = $Name }
    if ($PSCmdlet.ParameterSetName -eq "Local")
    {
        if ($PSBoundParameters.ContainsKey("Description")) { $local:Body.Description = $Description }
    }
    else
    {
        $local:DirectoryIdentityProvider = (Get-SafeguardDirectoryIdentityProvider -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Directory)
        if (-not $local:DirectoryIdentityProvider)
        {
            throw "Unable to find directory identity provider for '$Directory'"
        }

        if (-not $PSBoundParameters.ContainsKey("DomainName"))
        {
            Import-Module -Name "$PSScriptRoot\sg-utilities.psm1" -Scope Local
            $DomainName = (Resolve-DomainNameFromIdentityProvider -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Directory)
        }
        $local:Body.DirectoryProperties = @{ DirectoryId = $local:DirectoryIdentityProvider.Id; DomainName = $local:DomainName }
    }

    if ($AdminRoles)
    {
        if ($AdminRoles -contains "All")
        {
            Import-Module -Name "$PSScriptRoot\sg-utilities.psm1" -Scope Local
            if (Test-SafeguardMinVersionInternal -Appliance $Appliance -Insecure:$Insecure -MinVersion "2.7")
            {
                $AdminRoles = @('GlobalAdmin','Auditor','AssetAdmin','ApplianceAdmin','PolicyAdmin','UserAdmin','HelpdeskAdmin','OperationsAdmin')
            }
            else
            {
                $AdminRoles = @('GlobalAdmin','DirectoryAdmin','Auditor','AssetAdmin','ApplianceAdmin','PolicyAdmin','UserAdmin','HelpdeskAdmin','OperationsAdmin')
            }
        }
        if ($local:Body.DirectoryGroupSyncProperties)
        {
            $local:Body.DirectoryGroupSyncProperties.AdminRoles = $AdminRoles
        }
        else
        {
            $local:Body.DirectoryGroupSyncProperties = @{ AdminRoles = $AdminRoles }
        }
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST UserGroups -Body $local:Body
}

<#
.SYNOPSIS
Delete a user group from Safeguard via the Web API.

.DESCRIPTION
When a user group is deleted it is also removed from any entitlements where it may have
been used.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER GroupToDelete
An integer containing the ID of the user group to delete or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardAssetGroup -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Remove-SafeguardAssetGroup "Server Admins"
#>
function Remove-SafeguardUserGroup
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
        [object]$GroupToDelete
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Remove-SafeguardGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure User $GroupToDelete
}


<#
.SYNOPSIS
Edits a user group to add or remove an existing user in Safeguard via the Web API.

.DESCRIPTION
When a user group is edited the changes also propagates to any entitlements where it may have been used.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER GroupToEdit
Name of the user group to edit.

.PARAMETER Description
A string containing the new description for the user group.

.PARAMETER AdminRoles
An array of strings containing the permissions (admin roles) to assign to the members of this directory
group.  You may also specify 'All' to grant all permissions. Other permissions are: 'GlobalAdmin',
'ApplicationAuditor', 'SystemAuditor', 'Auditor', 'AssetAdmin', 'ApplianceAdmin', 'PolicyAdmin', 'UserAdmin',
'HelpdeskAdmin', 'OperationsAdmin'.

.PARAMETER Operation
String of type of operation to be perfomed on the user group. 'Add' to add users to the user group
'Remove' to removed users from the user group.

.PARAMETER UserList
An array of user IDs or names of the users to be added or removed in the user group.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Edit-SafeguardUserGroup testusergroup add testuser1,testuser2

.EXAMPLE
Edit-SafeguardUserGroup testusergroup remove testuser1
#>
function Edit-SafeguardUserGroup
{
    [CmdletBinding(DefaultParameterSetName="Operation")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [object]$GroupToEdit,
        [Parameter(Mandatory=$false, ParameterSetName="Attributes")]
        [string]$Description,
        [Parameter(Mandatory=$false, ParameterSetName="Attributes")]
        [ValidateSet('GlobalAdmin','DirectoryAdmin','Auditor','ApplicationAuditor','SystemAuditor','AssetAdmin','ApplianceAdmin',
                     'PolicyAdmin','UserAdmin','HelpdeskAdmin','OperationsAdmin','All',IgnoreCase=$true)]
        [string[]]$AdminRoles,
        [Parameter(Mandatory=$true, ParameterSetName="Operation", Position=1)]
        [ValidateSet("Add", "Remove", IgnoreCase=$true)]
        [string]$Operation,
        [Parameter(Mandatory=$true, ParameterSetName="Operation", Position=2)]
        [object[]]$UserList
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PsCmdlet.ParameterSetName -eq "Attributes")
    {
        $local:Group = (Get-SafeguardGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure User $GroupToEdit)
        if ($Description) { $local:Group.Description = $Description }
        if ($AdminRoles)
        {
            if ($AdminRoles -contains "All")
            {
                Import-Module -Name "$PSScriptRoot\sg-utilities.psm1" -Scope Local
                if (Test-SafeguardMinVersionInternal -Appliance $Appliance -Insecure:$Insecure -MinVersion "2.7")
                {
                    $AdminRoles = @('GlobalAdmin','Auditor','AssetAdmin','ApplianceAdmin','PolicyAdmin','UserAdmin','HelpdeskAdmin','OperationsAdmin')
                }
                else
                {
                    $AdminRoles = @('GlobalAdmin','DirectoryAdmin','Auditor','AssetAdmin','ApplianceAdmin','PolicyAdmin','UserAdmin','HelpdeskAdmin','OperationsAdmin')
                }
            }
            $local:Group.DirectoryGroupSyncProperties.AdminRoles = $AdminRoles
        }
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure core PUT "UserGroups/$($local:Group.Id)" -Body $local:Group
    }
    else
    {
        [object[]]$local:Users = $null
        foreach ($local:User in $UserList)
        {
            $local:ResolvedUser = (Get-SafeguardUser -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -UserToGet $local:User -Fields Id,Name,PrimaryAuthenticationProvider.Id)
            $local:Users += $($local:ResolvedUser)
        }

        Edit-SafeguardGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure User $GroupToEdit $Operation $local:Users
    }
}

<#
.SYNOPSIS
Add one or more users to a user group in Safeguard via the Web API.

.DESCRIPTION
When user group membership changes, it affects any entitlements where it may have been used.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Group
Name of the user group to add users to.

.PARAMETER UserList
An array of user IDs or names of the users to be added to the user group.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Add-SafeguardUserGroupMember testusergroup testuser1,testuser2

.EXAMPLE
Add-SafeguardUserGroupMember testusergroup testuser1
#>
function Add-SafeguardUserGroupMember
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [object]$Group,
        [Parameter(Mandatory=$true, Position=1)]
        [object[]]$UserList
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Edit-SafeguardUserGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Group Add $UserList
}

<#
.SYNOPSIS
Remove one or more users from a user group in Safeguard via the Web API.

.DESCRIPTION
When user group membership changes, it affects any entitlements where it may have been used.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Group
Name of the user group to remove users from.

.PARAMETER UserList
An array of user IDs or names of the users to be removed from the user group.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardUserGroupMember testusergroup testuser1,testuser2

.EXAMPLE
Remove-SafeguardUserGroupMember testusergroup testuser1
#>
function Remove-SafeguardUserGroupMember
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [object]$Group,
        [Parameter(Mandatory=$true, Position=1)]
        [object[]]$UserList
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Edit-SafeguardUserGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Group Remove $UserList
}

<#
.SYNOPSIS
Synchronize user group and update authentication providers for users.

.DESCRIPTION
Safeguard allows setting authentication providers that will be required for group members;
however, if this configuration has been changed after a user group was created, it requires
a manual process to force existing users to update.  This cmdlet forces synchronization of
the user group and updates the authentication requirements of every user.  New users that are
synchronized to Safeguard do not require this manual step.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER GroupToSync
Name of the user group to synchronize and update authentication providers.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Sync-SafeguardUserGroupAuthenticationProvider testusergroup
#>
function Sync-SafeguardUserGroupAuthenticationProvider
{
    [CmdletBinding(DefaultParameterSetName="Operation")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [object]$GroupToSync
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:GroupId = (Resolve-SafeguardGroupId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure User $GroupToSync)
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure core POST `
        "UserGroups/$($local:GroupId)/SynchronizeAndUpdateProviders"
}

<#
.SYNOPSIS
Get asset groups as defined by policy administrators that can added to access policy scopes
via the Web API.

.DESCRIPTION
Asset groups are collections of assets that can be added to an access policy to target
privileged session access that uses directory accounts or linked accounts.  This cmdlet returns
asset groups that have been defined by policy administrators.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER GroupToGet
An integer containing the ID of the asset group to get or a string containing the name.

.PARAMETER Fields
An array of the asset group property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardAssetGroup -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardAssetGroup "Linux Servers"
#>
function Get-SafeguardAssetGroup
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
        [object]$GroupToGet,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Get-SafeguardGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Asset $GroupToGet -Fields $Fields
}

<#
.SYNOPSIS
Get asset group members as defined by policy administrators that can added to
access policy scopes via the Web API.

.DESCRIPTION
Asset groups are collections of assets that can be added to an access policy to target
privileged session access that uses directory accounts or linked accounts.  This cmdlet returns
asset group members that have been defined by policy administrators.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER GroupToGet
An integer containing the ID of the asset group to get or a string containing the name.

.PARAMETER Fields
An array of the user property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardAssetGroupMember -AccessToken $token -Appliance 10.5.32.54 -Insecure "Group1"

.EXAMPLE
Get-SafeguardAssetGroupMember "Linux Servers"
#>
function Get-SafeguardAssetGroupMember
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
        [object]$GroupToGet,
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

    $local:GroupId = (Resolve-SafeguardGroupId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Asset $GroupToGet)
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure core GET "AssetGroups/$($local:GroupId)/Assets" -Parameters $local:Parameters
}

<#
.SYNOPSIS
Create an asset group that can be added to access policy scope via the Web API.

.DESCRIPTION
Asset groups are collections of assets that can be added to an access policy to target
privileged session access that uses directory accounts or linked accounts.  This cmdlet creates
an asset group.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Name
A string containing the name for the new group.

.PARAMETER Description
A string containing the description for a new group specific to Safeguard.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
New-SafeguardAssetGroup -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
New-SafeguardAssetGroup "LinuxMachines" "Some machines in my lab running Ubuntu"
#>
function New-SafeguardAssetGroup
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
        [string]$Description
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    New-SafeguardGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Asset $Name $Description
}

<#
.SYNOPSIS
Delete an asset group from Safeguard via the Web API.

.DESCRIPTION
When an asset group is deleted it is also removed from any access policies where it may have
been used.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER GroupToDelete
An integer containing the ID of the asset group to delete or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardAssetGroup -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Remove-SafeguardAssetGroup "Linux Servers"
#>
function Remove-SafeguardAssetGroup
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
        [object]$GroupToDelete
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Remove-SafeguardGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Asset $GroupToDelete
}

<#
.SYNOPSIS
Edits an asset group to add or remove an existing assets in Safeguard via the Web API.

.DESCRIPTION
When an asset group is edited the changes also propagates to any entitlements where it may have been used.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER GroupToEdit
Name of the asset group to edit.

.PARAMETER Operation
String of type of operation to be perfomed on the asset group. 'Add' to add assets to the asset group
'Remove' to removed assets from the asset group.

.PARAMETER AssetList
An array of names or IDs of the assets to be added or removed in the asset group.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Edit-SafeguardAssetGroup testassetgroup add testasset1,testasset2

.EXAMPLE
Edit-SafeguardAssetGroup testassetgroup remove testasset1
#>
function Edit-SafeguardAssetGroup
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [object]$GroupToEdit,
        [Parameter(Mandatory=$true, Position=1)]
        [ValidateSet("Add", "Remove", IgnoreCase=$true)]
        [string]$Operation,
        [Parameter(Mandatory=$true, Position=2)]
        [object[]]$AssetList
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    [object[]]$local:Assets = $null
    foreach ($local:Asset in $AssetList)
    {
        $local:ResolvedAsset = (Get-SafeguardAsset -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetToGet $local:Asset -Fields Id,Name)
        $local:Assets += $($local:ResolvedAsset)
    }

    Edit-SafeguardGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Asset $GroupToEdit $Operation $local:Assets
}

<#
.SYNOPSIS
Add one or more assets to an asset group in Safeguard via the Web API.

.DESCRIPTION
When asset group membership changes, it affects any entitlements where it may have been used.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Group
Name of the asset group to add assets to.

.PARAMETER AssetList
An array of asset IDs or names of the assets to be added to the asset group.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Add-SafeguardAssetGroupMember testassetgroup testasset1,testasset2

.EXAMPLE
Add-SafeguardAssetGroupMember testassetgroup testasset1
#>
function Add-SafeguardAssetGroupMember
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [object]$Group,
        [Parameter(Mandatory=$true, Position=1)]
        [object[]]$AssetList
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Edit-SafeguardAssetGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Group Add $AssetList
}

<#
.SYNOPSIS
Remove one or more assets from an asset group in Safeguard via the Web API.

.DESCRIPTION
When asset group membership changes, it affects any entitlements where it may have been used.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Group
Name of the asset group to remove assets from.

.PARAMETER AssetList
An array of asset IDs or names of the assets to be removed from the asset group.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardAssetGroupMember testassetgroup testasset1,testasset2

.EXAMPLE
Remove-SafeguardAssetGroupMember testassetgroup testasset1
#>
function Remove-SafeguardAssetGroupMember
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [object]$Group,
        [Parameter(Mandatory=$true, Position=1)]
        [object[]]$AssetList
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Edit-SafeguardAssetGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Group Remove $AssetList
}

<#
.SYNOPSIS
Get account groups as defined by policy administrators that can added to access policy scopes
via the Web API.

.DESCRIPTION
Account groups are collections of accounts that can be added to an access policy to target
privileged password access, ssh key access, or privileged session access.  This cmdlet
returns account groups that have been defined by policy administrators.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER GroupToGet
An integer containing the ID of the account group to get or a string containing the name.

.PARAMETER Fields
An array of the account group property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardAccountGroup -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardAccountGroup "Linux Root Accounts"
#>
function Get-SafeguardAccountGroup
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
        [object]$GroupToGet,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Get-SafeguardGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Account $GroupToGet -Fields $Fields
}

<#
.SYNOPSIS
Get members of an account group as defined by policy administrators that can added
to access policy scopes via the Web API.

.DESCRIPTION
Account groups are collections of accounts that can be added to an access policy to target
privileged password access, ssh key access, or privileged session access.  This cmdlet
returns account group members that have been defined by policy administrators.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER GroupToGet
An integer containing the ID of the account group to get or a string containing the name.

.PARAMETER Fields
An array of the user property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardAccountGroupMember -AccessToken $token -Appliance 10.5.32.54 -Insecure "Group1"

.EXAMPLE
Get-SafeguardAccountGroupMember "Linux Root Accounts"
#>
function Get-SafeguardAccountGroupMember
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
        [object]$GroupToGet,
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

    $local:GroupId = (Resolve-SafeguardGroupId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Account $GroupToGet)
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure core GET "AccountGroups/$($local:GroupId)/Accounts" -Parameters $local:Parameters
}

<#
.SYNOPSIS
Create an account group that can be added to access policy scope via the Web API.

.DESCRIPTION
Account groups are collections of accounts that can be added to an access policy to target
privileged password access, ssh key access, or privileged session access.  This cmdlet
creates an account group.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Name
A string containing the name for the new group.

.PARAMETER Description
A string containing the description for a new group specific to Safeguard.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
New-SafeguardAccountGroup -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
New-SafeguardAccountGroup "B_OracleServerRoots" "Root accounts for all oracle servers in site B."
#>
function New-SafeguardAccountGroup
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
        [string]$Description
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    New-SafeguardGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Account $Name $Description
}

<#
.SYNOPSIS
Delete an account group from Safeguard via the Web API.

.DESCRIPTION
When an account group is deleted it is also removed from any access policies where it may have
been used.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER GroupToDelete
An integer containing the ID of the account group to delete or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardAccountGroup -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Remove-SafeguardAccountGroup "Linux Root Accounts"
#>
function Remove-SafeguardAccountGroup
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
        [object]$GroupToDelete
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Remove-SafeguardGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Account $GroupToDelete
}

<#
.SYNOPSIS
Edits an account group to add or remove an existing accounts in Safeguard via the Web API.

.DESCRIPTION
When an account group is edited the changes also propagates to any entitlements where it may have been used.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER GroupToEdit
Name of the account group to edit.

.PARAMETER Operation
String of type of operation to be perfomed on the account group. 'Add' to add accounts to the account group
'Remove' to removed accounts from the account group.

.PARAMETER AccountList
An array of ID or name pairs of the format '<asset>\<account>' to be added or removed in the account group.
For example: 23\55,asset1\account1,asset1\342

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Edit-SafeguardAccountGroup testaccountgroup add testasset1.domain.corp\testaccount1,testasset2.domain.corp\testaccount2

.EXAMPLE
Edit-SafeguardAccountGroup testaccountgroup remove testasset1.domain.corp\testaccount1
#>
function Edit-SafeguardAccountGroup
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [object]$GroupToEdit,
        [Parameter(Mandatory=$true, Position=1)]
        [ValidateSet("Add", "Remove", IgnoreCase=$true)]
        [string]$Operation,
        [Parameter(Mandatory=$true, Position=2)]
        [object[]]$AccountList
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    [object[]]$local:Accounts = $null
    foreach ($local:AccountPair in $AccountList)
    {
        $local:Pair = ($local:AccountPair -split "\\")
        if ($local:Pair.Length -ne 2)
        {
            throw "Unable to parse '$($local:AccountPair)' using expected format of 'asset\account'."
        }
        $local:ResolvedAccount = (Get-SafeguardAssetAccount -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
            -AssetToGet $local:Pair[0] -AccountToGet $local:Pair[1] -Fields Asset.Id,Id,Asset.Name,Name)
        $local:Accounts += $($local:ResolvedAccount)
    }

    Edit-SafeguardGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Account $GroupToEdit $Operation $local:Accounts
}

<#
.SYNOPSIS
Add one or more accounts to an account group in Safeguard via the Web API.

.DESCRIPTION
When account group membership changes, it affects any entitlements where it may have been used.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Group
Name of the account group to add accounts to.

.PARAMETER AccountList
An array of account IDs or names of the accounts to be added to the account group.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Add-SafeguardAccountGroupMember testaccountgroup testasset1.domain.corp\testaccount1,testasset2.domain.corp\testaccount2

.EXAMPLE
Add-SafeguardAccountGroupMember testaccountgroup testasset1.domain.corp\testaccount1
#>
function Add-SafeguardAccountGroupMember
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [object]$Group,
        [Parameter(Mandatory=$true, Position=1)]
        [object[]]$AccountList
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Edit-SafeguardAccountGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Group Add $AccountList
}

<#
.SYNOPSIS
Remove one or more accounts from an account group in Safeguard via the Web API.

.DESCRIPTION
When account group membership changes, it affects any entitlements where it may have been used.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Group
Name of the account group to remove accounts from.

.PARAMETER AccountList
An array of account IDs or names of the accounts to be removed from the account group.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardAccountGroupMember testaccountgroup testasset1.domain.corp\testaccount1,testasset2.domain.corp\testaccount2

.EXAMPLE
Remove-SafeguardAccountGroupMember testaccountgroup testasset1.domain.corp\testaccount1
#>
function Remove-SafeguardAccountGroupMember
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [object]$Group,
        [Parameter(Mandatory=$true, Position=1)]
        [object[]]$AccountList
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Edit-SafeguardAccountGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Group Remove $AccountList
}


# Dynamic Group cmdlets


<#
.SYNOPSIS
Get dynamic account groups as defined by policy administrators that can added to
access policy scopes via the Web API.

.DESCRIPTION
Account groups are collections of accounts that can be added to an access policy to target
privileged password access, ssh key access, or privileged session access. This cmdlet returns
dynamic account groups that have been defined by policy administrators.

This cmdlet does not report group members. Use Get-SafeguardAccountGroupMember for that. This
cmdlet is for showing how dynamic account groups are defined.

Dynamic account groups are defined by rules. A rule is a group of conditions. A condition
group logically joins together the items in the condition groups. The items in the condition
group may be nested condition groups or conditions. Conditions are made up of an objet attribute
a comparison type and a comparison value. The string syntax for condition groups are best shown
by example:

(([AssetName startswith 'slc'] or [AssetName starts with 'phx']) and [Name eq 'root'])

Condition groups must be surrounded by parentheses '()'. Conditions must be surrounded square
brackets '[]'.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER GroupToGet
An integer containing the ID of the account group to get or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardDynamicAccountGroup

.EXAMPLE
Get-SafeguardDynamicAccountGroup "Linux Root Accounts"
#>
function Get-SafeguardDynamicAccountGroup
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false, Position=0)]
        [object]$GroupToGet
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Import-Module -Name "$PSScriptRoot\grouptag-utilities.psm1" -Scope Local
    if ($GroupToGet)
    {
        $local:Groups = (Get-SafeguardGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Account $GroupToGet `
            -Fields "Id,Name,Description,IsDynamic,CreatedDate,CreatedByUserId,CreatedByUserDisplayName,GroupingRule" -DynamicOnly)
    }
    else
    {
        $local:Groups = (Get-SafeguardGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Account `
            -Fields "Id,Name,Description,IsDynamic,CreatedDate,CreatedByUserId,CreatedByUserDisplayName,GroupingRule" -DynamicOnly)
    }
    foreach ($local:Group in $local:Groups)
    {
        $local:Hash = [ordered]@{
            Id = $local:Group.Id;
            Name = $local:Group.Name;
            Description = $local:Group.Description;
            IsDynamic = $local:Group.IsDynamic;
            CreatedDate = $local:Group.CreatedDate;
            CreatedByUserId = $local:Group.CreatedByUserId;
            CreatedByUserDisplayName = $local:Group.CreatedByUserDisplayName;
            GroupingRule = (Convert-RuleToString $local:Group.GroupingRule "account");
        }
        New-Object PSObject -Property $local:Hash
    }
}

<#
.SYNOPSIS
Create a dynamic account group that can be added to access policy scope via the Web API.

.DESCRIPTION
Account groups are collections of accounts that can be added to an access policy to target
privileged password access, ssh key access, or privileged session access. This cmdlet creates
a dynamic account groups.

Dynamic account groups are defined by rules. A rule is a group of conditions. A condition
group logically joins together the items in the condition groups. The items in the condition
group may be nested condition groups or conditions. Conditions are made up of an objet attribute
a comparison type and a comparison value. The string syntax for condition groups are best shown
by example:

(([AssetName startswith 'slc'] or [AssetName starts with 'phx']) and [Name eq 'root'])

Condition groups must be surrounded by parentheses '()'. Conditions must be surrounded square
brackets '[]'.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Name
A string containing the name for the new group.

.PARAMETER Description
A string containing the description for a new group specific to Safeguard.

.PARAMETER GroupingRule
A string containing the rule with the conditions for matching accounts.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
New-SafeguardDynamicAccountGroup "Linux Servers" "([Platform startswith 'Linux'])"

.EXAMPLE
New-SafeguardDynamicAccountGroup "B_OracleServerRoots" -Description "Root accounts for all oracle servers in site B." "([Platform startswith 'Oracle'] and [Tag eq 'Site B'])"
#>
function New-SafeguardDynamicAccountGroup
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [string]$Description,
        [Parameter(Mandatory=$false, Position=1)]
        [string]$GroupingRule
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Import-Module -Name "$PSScriptRoot\grouptag-utilities.psm1" -Scope Local
    $local:Body = @{
        Name = $Name;
        Description = $Description;
        IsDynamic = $true;
    }
    if ($local:GroupingRule)
    {
        $local:Body.GroupingRule = (Convert-StringToRule $GroupingRule "account")
    }

    $local:Group = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST AccountGroups -Body $local:Body)
    $local:Hash = [ordered]@{
        Id = $local:Group.Id;
        Name = $local:Group.Name;
        Description = $local:Group.Description;
        IsDynamic = $local:Group.IsDynamic;
        CreatedDate = $local:Group.CreatedDate;
        CreatedByUserId = $local:Group.CreatedByUserId;
        CreatedByUserDisplayName = $local:Group.CreatedByUserDisplayName;
        GroupingRule = (Convert-RuleToString $local:Group.GroupingRule "account");
    }
    New-Object PSObject -Property $local:Hash
}

<#
.SYNOPSIS
Edit an existing dynamic account group that can be added to access policy scope via the Web API.

.DESCRIPTION
Account groups are collections of accounts that can be added to an access policy to target
privileged password access, ssh key access, or privileged session access. This cmdlet edits
a dynamic account group, including the rule that defines it.

Dynamic account groups are defined by rules. A rule is a group of conditions. A condition
group logically joins together the items in the condition groups. The items in the condition
group may be nested condition groups or conditions. Conditions are made up of an objet attribute
a comparison type and a comparison value. The string syntax for condition groups are best shown
by example:

(([AssetName startswith 'slc'] or [AssetName starts with 'phx']) and [Name eq 'root'])

Condition groups must be surrounded by parentheses '()'. Conditions must be surrounded square
brackets '[]'.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER GroupToEdit
Name of the dynamic account group to edit.

.PARAMETER Description
A string containing the description for a new group specific to Safeguard.

.PARAMETER GroupingRule
A string containing the rule with the conditions for matching accounts.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Edit-SafeguardDynamicAccountGroup "B_OracleServerRoots" "([Platform startswith 'Oracle'] and [Tag eq 'Site B'])"
#>
function Edit-SafeguardDynamicAccountGroup
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
        [object]$GroupToEdit,
        [Parameter(Mandatory=$false)]
        [string]$Description,
        [Parameter(Mandatory=$false, Position=1)]
        [string]$GroupingRule
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Group = (Get-SafeguardGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Account $GroupToEdit)
    if (-not $local:Group.IsDynamic)
    {
        throw "$($local:Group.Name) is not a dynamic account group"
    }

    Import-Module -Name "$PSScriptRoot\grouptag-utilities.psm1" -Scope Local
    if ($Description) { $local:Group.Description = $Description }
    if ($GroupingRule)
    {
        $local:Group.GroupingRule = (Convert-StringToRule $GroupingRule "account")
    }
    $local:Group = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT `
                        "AccountGroups/$($local:Group.Id)" -Body $local:Group)
    $local:Hash = [ordered]@{
        Id = $local:Group.Id;
        Name = $local:Group.Name;
        Description = $local:Group.Description;
        IsDynamic = $local:Group.IsDynamic;
        CreatedDate = $local:Group.CreatedDate;
        CreatedByUserId = $local:Group.CreatedByUserId;
        CreatedByUserDisplayName = $local:Group.CreatedByUserDisplayName;
        GroupingRule = (Convert-RuleToString $local:Group.GroupingRule "account");
    }
    New-Object PSObject -Property $local:Hash
}

<#
.SYNOPSIS
Get asset groups as defined by policy administrators that can added to access policy scopes
via the Web API.

.DESCRIPTION
Asset groups are collections of assets that can be added to an access policy to target
privileged session access that uses directory accounts or linked accounts.  This cmdlet returns
asset groups that have been defined by policy administrators.

This cmdlet does not report group members. Use Get-SafeguardAssetGroupMember for that. This
cmdlet is for showing how dynamic account groups are defined.

Dynamic asset groups are defined by rules. A rule is a group of conditions. A condition
group logically joins together the items in the condition groups. The items in the condition
group may be nested condition groups or conditions. Conditions are made up of an objet attribute
a comparison type and a comparison value. The string syntax for condition groups are best shown
by example:

(([AssetName startswith 'slc'] or [AssetName starts with 'phx']) and [Platform startswith 'Ubuntu'])

Condition groups must be surrounded by parentheses '()'. Conditions must be surrounded square
brackets '[]'.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER GroupToGet
An integer containing the ID of the asset group to get or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardDynamicAssetGroup

.EXAMPLE
Get-SafeguardDynamicAssetGroup "Linux Servers"
#>
function Get-SafeguardDynamicAssetGroup
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false, Position=0)]
        [object]$GroupToGet
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Import-Module -Name "$PSScriptRoot\grouptag-utilities.psm1" -Scope Local
    $local:Group = (Get-SafeguardGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Asset $GroupToGet `
        -Fields "Id,Name,Description,IsDynamic,CreatedDate,CreatedByUserId,CreatedByUserDisplayName,AssetGroupingRule" -DynamicOnly)
    $local:Hash = [ordered]@{
        Id = $local:Group.Id;
        Name = $local:Group.Name;
        Description = $local:Group.Description;
        IsDynamic = $local:Group.IsDynamic;
        CreatedDate = $local:Group.CreatedDate;
        CreatedByUserId = $local:Group.CreatedByUserId;
        CreatedByUserDisplayName = $local:Group.CreatedByUserDisplayName;
        AssetGroupingRule = (Convert-RuleToString $local:Group.AssetGroupingRule "asset");
    }
    New-Object PSObject -Property $local:Hash
}

<#
.SYNOPSIS
Create a dynamic asset group that can be added to access policy scope via the Web API.

.DESCRIPTION
Asset groups are collections of assets that can be added to an access policy to target
privileged session access that uses directory accounts or linked accounts.  This cmdlet creates
a dynamic asset group.

Dynamic asset groups are defined by rules. A rule is a group of conditions. A condition
group logically joins together the items in the condition groups. The items in the condition
group may be nested condition groups or conditions. Conditions are made up of an objet attribute
a comparison type and a comparison value. The string syntax for condition groups are best shown
by example:

(([AssetName startswith 'slc'] or [AssetName starts with 'phx']) and [Platform startswith 'Ubuntu'])

Condition groups must be surrounded by parentheses '()'. Conditions must be surrounded square
brackets '[]'.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Name
A string containing the name for the new group.

.PARAMETER Description
A string containing the description for a new group specific to Safeguard.

.PARAMETER GroupingRule
A string containing the rule with the conditions for matching assets.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
New-SafeguardDynamicAssetGroup "Oracle Databases" "([Platform startswith 'Oracle'])"

.EXAMPLE
New-SafeguardDynamicAssetGroup "LinuxMachines" -Description "Some machines in my lab running Ubuntu" "([Tag eq 'Linux'])"
#>
function New-SafeguardDynamicAssetGroup
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [string]$Description,
        [Parameter(Mandatory=$false, Position=1)]
        [string]$GroupingRule
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Import-Module -Name "$PSScriptRoot\grouptag-utilities.psm1" -Scope Local
    $local:Body = @{
        Name = $Name;
        Description = $Description;
        IsDynamic = $true;
    }
    if ($local:GroupingRule)
    {
        $local:Body.AssetGroupingRule = (Convert-StringToRule $GroupingRule "asset")
    }

    $local:Group = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST AssetGroups -Body $local:Body)
    $local:Hash = [ordered]@{
        Id = $local:Group.Id;
        Name = $local:Group.Name;
        Description = $local:Group.Description;
        IsDynamic = $local:Group.IsDynamic;
        CreatedDate = $local:Group.CreatedDate;
        CreatedByUserId = $local:Group.CreatedByUserId;
        CreatedByUserDisplayName = $local:Group.CreatedByUserDisplayName;
        AssetGroupingRule = (Convert-RuleToString $local:Group.AssetGroupingRule "asset");
    }
    New-Object PSObject -Property $local:Hash
}

<#
.SYNOPSIS
Edit an existing dynamic asset group that can be added to access policy scope via the Web API.

.DESCRIPTION
Asset groups are collections of assets that can be added to an access policy to target
privileged session access that uses directory accounts or linked accounts.  This cmdlet edits
a dynamic asset group, including the rule that defines it.

Dynamic asset groups are defined by rules. A rule is a group of conditions. A condition
group logically joins together the items in the condition groups. The items in the condition
group may be nested condition groups or conditions. Conditions are made up of an objet attribute
a comparison type and a comparison value. The string syntax for condition groups are best shown
by example:

(([AssetName startswith 'slc'] or [AssetName starts with 'phx']) and [Platform startswith 'Ubuntu'])

Condition groups must be surrounded by parentheses '()'. Conditions must be surrounded square
brackets '[]'.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER GroupToEdit
Name of the dynamic asset group to edit.

.PARAMETER Description
A string containing the description for a new group specific to Safeguard.

.PARAMETER GroupingRule
A string containing the rule with the conditions for matching assets.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Edit-SafeguardDynamicAssetGroup "LinuxMachines" "([Tag eq 'Linux'])"
#>
function Edit-SafeguardDynamicAssetGroup
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
        [object]$GroupToEdit,
        [Parameter(Mandatory=$false)]
        [string]$Description,
        [Parameter(Mandatory=$false, Position=1)]
        [string]$GroupingRule
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Group = (Get-SafeguardGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Asset $GroupToEdit)
    if (-not $local:Group.IsDynamic)
    {
        throw "$($local:Group.Name) is not a dynamic asset group"
    }

    Import-Module -Name "$PSScriptRoot\grouptag-utilities.psm1" -Scope Local
    if ($Description) { $local:Group.Description = $Description }
    if ($GroupingRule)
    {
        $local:Group.AssetGroupingRule = (Convert-StringToRule $GroupingRule "asset")
    }
    $local:Group = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT `
                        "AssetGroups/$($local:Group.Id)" -Body $local:Group)
    $local:Hash = [ordered]@{
        Id = $local:Group.Id;
        Name = $local:Group.Name;
        Description = $local:Group.Description;
        IsDynamic = $local:Group.IsDynamic;
        CreatedDate = $local:Group.CreatedDate;
        CreatedByUserId = $local:Group.CreatedByUserId;
        CreatedByUserDisplayName = $local:Group.CreatedByUserDisplayName;
        AssetGroupingRule = (Convert-RuleToString $local:Group.AssetGroupingRule "asset");
    }
    New-Object PSObject -Property $local:Hash
}