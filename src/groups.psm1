# Helper
function Resolve-SafeguardGroupId
{
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

    $ErrorActionPreference = "Stop"

    # Allow case insensitive group types to translate to appropriate case sensitive URL path
    switch ($GroupType)
    {
        "user" { $GroupType = "User"; break }
        "asset" { $GroupType = "Asset"; break }
        "Account" { $GroupType = "Account"; break }
    }

    $local:RelativeUrl = "$($GroupType)Groups"

    if (-not ($Group -as [int]))
    {
        $local:Groups = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET $local:RelativeUrl `
                                                -Parameters @{ filter = "Name ieq '$Group'" })
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

    $ErrorActionPreference = "Stop"

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
        $local:GroupId = Resolve-SafeguardGroupId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure User $GroupToGet
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$local:RelativeUrl/$($local:GroupId)"
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET $local:RelativeUrl
    }
}
function New-SafeguardGroup
{
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

    $ErrorActionPreference = "Stop"

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

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST $local:RelativeUrl -Body $local:Body
}
function Remove-SafeguardGroup
{
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

    $ErrorActionPreference = "Stop"

    # Allow case insensitive group types to translate to appropriate case sensitive URL path
    switch ($GroupType)
    {
        "user" { $GroupType = "User"; break }
        "asset" { $GroupType = "Asset"; break }
        "Account" { $GroupType = "Account"; break }
    }
    $local:RelativeUrl = "$($GroupType)Groups"
    $local:GroupId = (Resolve-SafeguardGroupId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $GroupType $GroupToDelete)

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "$($local:RelativeUrl)/$($local:GroupId)" -Body $local:Body
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

    $ErrorActionPreference = "Stop"

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

.PARAMETER Directory
An integer containing the ID of the directory to get or a string containing the name.

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

    $ErrorActionPreference = "Stop"
    Import-Module -Name "$PSScriptRoot\directories.psm1" -Scope Local

    $local:Body = @{ Name = $Name }
    if ($PSCmdlet.ParameterSetName -eq "Local")
    {
        if ($PSBoundParameters.ContainsKey("Description")) { $local:Body.Description = $Description }
    }
    else
    {
        $local:DirectoryId = (Resolve-SafeguardDirectoryId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Directory)
        if (-not $PSBoundParameters.ContainsKey("DomainName"))
        {
            $local:Domains = (Get-SafeguardDirectoryDomains -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $DirectoryId)
            if (-not ($local:Domains -is [array]))
            {
                $DomainName = $local:Domains[0].DomainName
            }
            else
            {
                Write-Host "Domains in Directory ($Directory):"
                Write-Host "["
                $local:Domains | ForEach-Object -Begin { $index = 0 } -Process {  Write-Host ("    {0,3} - {1}" -f $index,$_.DomainName); $index++ }
                Write-Host "]"
                $local:DomainNameIndex = (Read-Host "Select a DomainName by number")
                $DomainName = $local:Domains[$local:DomainNameIndex].DomainName
            }
        }
        $local:Body.DirectoryProperties = @{ DirectoryId = $local:DirectoryId; DomainName = $DomainName }
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST UserGroups -Body $local:Body
}


function Remove-SafeguardUserGroup
{
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

    $ErrorActionPreference = "Stop"

    Remove-SafeguardGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure User $GroupToDelete
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
An integer containing the ID of the user group to get or a string containing the name.

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

    $ErrorActionPreference = "Stop"

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

    $ErrorActionPreference = "Stop"

    New-SafeguardGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Asset $Name $Description
}


function Remove-SafeguardAssetGroup
{
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

    $ErrorActionPreference = "Stop"

    Remove-SafeguardGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Asset $GroupToDelete
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
An integer containing the ID of the user group to get or a string containing the name.

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

    $ErrorActionPreference = "Stop"

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

    $ErrorActionPreference = "Stop"

    New-SafeguardGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Account $Name $Description
}


function Remove-SafeguardAccountGroup
{
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

    $ErrorActionPreference = "Stop"

    Remove-SafeguardGroup -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Account $GroupToDelete
}