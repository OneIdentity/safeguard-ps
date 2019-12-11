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
        "Account" { $GroupType = "Account"; break }
    }

    $local:RelativeUrl = "$($GroupType)Groups"

    if ($Group.Id -as [int])
    {
        $Group = $Group.Id
    }

    if (-not ($Group -as [int]))
    {
        $local:Groups = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET $local:RelativeUrl `
                                                -Parameters @{ filter = "Name ieq '$Group'" } -RetryVersion 2 -RetryUrl "$local:RelativeUrl")
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
        [object]$GroupToGet
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

    if ($PSBoundParameters.ContainsKey("GroupToGet") -and $GroupToGet)
    {
        $local:GroupId = Resolve-SafeguardGroupId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $GroupType $GroupToGet
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$local:RelativeUrl/$($local:GroupId)" `
            -RetryVersion 2 -RetryUrl "$local:RelativeUrl/$($local:GroupId)"
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET $local:RelativeUrl `
            -RetryVersion 2 -RetryUrl "$local:RelativeUrl"
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
        -Body $local:Body -RetryVersion 2 -RetryUrl "$local:RelativeUrl"
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
        -Body $local:Body -RetryVersion 2 -RetryUrl "$($local:RelativeUrl)/$($local:GroupId)"
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
        "$($local:RelativeUrl)/$($local:GroupId)/$($local:UrlPart)/$Operation" -Body $ObjectToOperate `
        -RetryVersion 2 -RetryUrl "$($local:RelativeUrl)/$($local:GroupId)/$($local:UrlPart)/$Operation" | Out-Null

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
        [object]$GroupToGet
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Get-SafeguardGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure User $GroupToGet
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

.PARAMETER DirectoryIdentityProviderId
An integer containing the ID of the directory identity provider Id to get or a string containing the name.

.PARAMETER DomainName
A string containing the name of the domain within the directory where necessary.  A directory
a single domain does not require this parameter.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
New-SafeguardUserGroup -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
New-SafeguardUserGroup "Web Server Admins" -Directory "singledomain.corp"

.EXAMPLE
New-SafeguardUserGroup "Web Server Admins" -Directory "demo.corp" -Domain "us.demo.corp"
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
        [string]$DomainName
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
            $local:Domains = $local:DirectoryIdentityProvider.DirectoryProperties.Domains
            if($null -eq $local:Domains)
            {
                $local:Domains = $local:DirectoryIdentityProvider.Domains
            }

            if (-not ($local:Domains -is [array]))
            {
                $local:DomainName = $local:Domains.DomainName
            }
            else
            {
                if ($local:Domains.Count -eq 1)
                {
                    $local:DomainName = $local:Domains[0].DomainName
                }
                elseif ($local:Domains | Where-Object { $_.DomainName -ieq $Directory })
                {
                    $local:DomainName = ($local:Domains | Where-Object { $_.DomainName -ieq $Directory }).DomainName
                }
                else
                {
                    Write-Host "Domains in Directory ($Directory):"
                    Write-Host "["
                    $local:Domains | ForEach-Object -Begin { $index = 0 } -Process {  Write-Host ("    {0,3} - {1}" -f $index,$_.DomainName); $index++ }
                    Write-Host "]"
                    $local:DomainNameIndex = (Read-Host "Select a DomainName by number")
                    $local:DomainName = $local:Domains[$local:DomainNameIndex].DomainName
                }
            }
        }
        $local:Body.DirectoryProperties = @{ DirectoryId = $local:DirectoryIdentityProvider.Id; DomainName = $local:DomainName }
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST UserGroups -Body $local:Body -RetryVersion 2 -RetryUrl "UserGroups"
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
Name of the user group to edit

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
        [object[]]$UserList
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    [object[]]$local:Users = $null
    foreach ($local:User in $UserList)
    {
        $local:ResolvedUser = (Get-SafeguardUser -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -UserToGet $local:User -Fields Id,UserName,PrimaryAuthenticationProviderId)
        $local:Users += $($local:ResolvedUser)
    }

    Edit-SafeguardGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure User $GroupToEdit $Operation $local:Users
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
        [object]$GroupToGet
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Get-SafeguardGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Asset $GroupToGet
}

<#
.SYNOPSIS
Create an asset group that can added to entitlement membership via the Web API.

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
Get account groups as defined by policy administrators that can added to access policy scopes
via the Web API.

.DESCRIPTION
Account groups are collections of accounts that can be added to an access policy to target
privileged password access or privileged session access.  This cmdlet returns account groups
that have been defined by policy administrators.

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
        [object]$GroupToGet
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Get-SafeguardGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Account $GroupToGet
}

<#
.SYNOPSIS
Create an account group that can added to entitlement membership via the Web API.

.DESCRIPTION
Account groups are collections of accounts that can be added to an access policy to target
privileged password access or privileged session access.  This cmdlet creates an account group.

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
        [Parameter(Mandatory=$false,Position=0)]
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
Edit-SafeguardAccountGroup testaccountgroup add testasset1.domain.corp\testaccount1, testasset2.domain.corp\testaccount2

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
            -AssetToGet $local:Pair[0] -AccountToGet $local:Pair[1] -Fields AssetId,Id,AssetName,Name)
        $local:Accounts += $($local:ResolvedAccount)
    }

    Edit-SafeguardGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Account $GroupToEdit $Operation $local:Accounts
}
