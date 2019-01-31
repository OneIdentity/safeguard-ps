#Helpers
function Test-Permission
{
    [CmdletBinding(DefaultParameterSetName="File")]
    Param(
        [Parameter(Mandatory=$true, Position=0)]
        [string[]]$PossiblePermissions
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $SafeguardSession)
    {
        throw "This cmdlet requires that you log in with the Connect-Safeguard cmdlet"
    }

    $local:AdminRoles = (Invoke-SafeguardMethod Core GET "Me").AdminRoles
    $local:Intersection = ($PossiblePermissions | Where-Object { $local:AdminRoles -contains $_ })
    if (-not $local:Intersection)
    {
        throw "In order to run this command you must have one of the following permissions: $($PossiblePermissions -join ",")"
    }
}
function Get-AccessCertAccount
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Identifier,
        [Parameter(Mandatory=$false)]
        [switch]$AsLookupTable
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($AsLookupTable)
    {
        $local:Accounts = @{}
    }
    else
    {
        $local:Accounts = @()
    }

    # Get all Safeguard users from directory identity providers and report them as accounts with anchors
    # For now, we will report Local and Certificate users as identities
    (Invoke-SafeguardMethod Core GET "Users" -Parameters @{
        fields = "Id,UserName,EmailAddress,PrimaryAuthenticationIdentity,IdentityProviderTypeReferenceName,PrimaryAuthenticationProviderName,DirectoryProperties";
        filter = "Disabled eq false"
    }) | ForEach-Object {
        # Additional data sanity checking here? -- i.e. Are these really accounts? or Are these really identities?
        if ($false)
        {
            Write-Verbose "Skipping Safeguard user '$($_.UserName)' that does not have the proper information"
        }
        else
        {
            if ($_.IdentityProviderTypeReferenceName -eq "Local")
            {
                $local:Authority = "safeguard:$Identifier"
                $local:Id = $_.Id
                if ($_.EmailAddress)
                {
                    $local:Owner = $_.EmailAddress
                }
                else
                {
                    $local:Owner = $null
                }
            }
            elseif ($_.IdentityProviderTypeReferenceName -eq "ActiveDirectory")
            {
                $local:Authority = "ad:$($_.DirectoryProperties.DomainName)"
                $local:Id = $_.PrimaryAuthenticationIdentity # Object GUID
                $local:Owner = $_.PrimaryAuthenticationIdentity # Object GUID
            }
            else
            {
                $local:Authority = "ldap:$($_.DirectoryProperties.DirectoryName)"
                $local:Id = $_.DirectoryProperties.DistinguishedName # DN
                $local:Owner = $_.DirectoryProperties.DistinguishedName # DN
            }
            $local:Account = New-Object PSObject -Property @{
                authority = $local:Authority;
                id = $Local:Id;
                userName = $_.UserName;
                owner = $local:Owner
            }
            if ($AsLookupTable)
            {
                $local:Accounts[[int]$_.Id] = $local:Account # add to lookup table
            }
            else
            {
                $local:Accounts += $local:Account  # add to array
            }
        }
    }

    $local:Accounts
}
function Get-AccessCertGroup
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Identifier,
        [Parameter(Mandatory=$false)]
        [switch]$AsLookupTable
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($AsLookupTable)
    {
        $local:Groups = @{}
    }
    else
    {
        $local:Groups = @()
    }

    # Get user group entities from Safeguard, which can be added to entitlements
    (Invoke-SafeguardMethod Core GET "UserGroups" -Parameters @{
        fields = "Id,Name,Description,CreatedByUserId,DirectoryProperties"
    }) | ForEach-Object {
        # Additional data sanity checking here?
        if ($false)
        {
            Write-Verbose "Skipping Safeguard group '$($_.Name)' that does not have the proper information"
        }
        else
        {
            if (-not ($_.DirectoryProperties.DomainName)) # no directory info means local
            {
                $local:Authority = "safeguard:$Identifier"
                $local:Id = $_.Id
                $local:Owner = $null # TODO: Do we want to try to look up the owner using the created by user ID??
            }
            elseif ($_.DirectoryProperties.NetbiosName) # if it has net bios info it is AD
            {
                $local:Authority = "ad:$($_.DirectoryProperties.DomainName)"
                $local:Id = $_.DirectoryProperties.ObjectGuid
                $local:Owner = $null
            }
            else
            {
                $local:Authority = "ldap:$($_.DirectoryProperties.DirectoryName)"
                $local:Id = $_.DirectoryProperties.DistinguishedName
                $local:Owner = $null
            }
            $local:Group = New-Object PSObject -Property @{
                authority = $local:Authority;
                id = $local:Id;
                groupName = $_.Name;
                displayName = $_.Name;
                description = $_.Description;
                owner = $local:Owner
            }
            if ($AsLookupTable)
            {
                $local:Groups[[string]$_.Id] = $local:Group # add to lookup table
            }
            else
            {
                $local:Groups += $local:Group  # add to array
            }
        }
    }
    # Get entitlements from Safeguard, which can directly group together safeguard users and assign them to access policies
    (Invoke-SafeguardMethod Core GET "Roles" -Parameters @{
        fields = "Id,Name,Description,CreatedByUserId,Members";
        filter = "IsExpired eq false" # include all entitlements... we could limit to just those containing users with (Members.PrincipalKind eq 'User')
    }) | ForEach-Object {
        # Additional data sanity checking here?
        if ($false)
        {
            Write-Verbose "Skipping Safeguard entitlement '$($_.Name)' that does not have the proper information"
        }
        else
        {
            $local:Group = New-Object PSObject -Property @{
                authority = "safeguard:$Identifier"; # all entitlements are local
                id = "e/$($_.Id)";
                groupName = "e/$($_.Name)";
                displayName = "(Entitlement) $($_.Name)";
                description = $_.Description;
                owner = $null # TODO: Do we want to try to look up the owner using the created by user ID??
            }
            if ($AsLookupTable)
            {
                $local:Groups["$($local:Group.id)"] = $local:Group # add to lookup table
            }
            else
            {
                $local:Groups += $local:Group  # add to array
            }
        }
    }

    $local:Groups
}
function Get-AccountPermissionText
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Protocol,
        [Parameter(Mandatory=$true, Position=1)]
        [string]$SystemName,
        [Parameter(Mandatory=$true, Position=2)]
        [string]$AccountSystemName,
        [Parameter(Mandatory=$true, Position=3)]
        [string]$AccountName,
        [Parameter(Mandatory=$false)]
        [string]$AccountDomainName
    )

    if ($AccountSystemName -ine $SystemName)
    {
        if ($AccountDomainName)
        {
            $local:Permission = "$Protocol session as $AccountDomainName\$AccountName"
        }
        else
        {
            $local:Permission = "$Protocol session as $AccountSystemName\$AccountName"
        }
    }
    else
    {
        $local:Permission = "$Protocol session as $AccountName"
    }

    $local:Permission
}
function Get-NoAccountPermissionText
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Protocol,
        [Parameter(Mandatory=$true, Position=1)]
        [string]$SessionAccountType
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    switch ($SessionAccountType.ToLower())
    {
        "usersupplied" {
            $local:Permission = "$Protocol session with user-supplied credentials"
            break
        }
        "linkedaccount" {
            $local:Permission = "$Protocol session as linked account"
            break
        }
        default {
            $local:Permission = $null
            Write-Warning "Unrecognized session account type '$SessionAccountType'"
            break
        }
    }

    $local:Permission
}
function Get-PermissionText
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, Position=0)]
        [object]$PolEnt
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    switch ($PolEnt.Policy.AccessRequestProperties.AccessRequestType.ToLower())
    {
        "password" { $local:Permission = "checkout $($PolEnt.Account.Name) password"; break }
        "remotedesktop" {
            if ($PolEnt.Account)
            {
                $local:Permission = (Get-AccountPermissionText "RDP" $PolEnt.System.Name $PolEnt.Account.SystemName $PolEnt.Account.Name `
                                     -AccountDomainName $PolEnt.Account.DomainName)
            }
            else
            {
                $local:Permission = (Get-NoAccountPermissionText "RDP" $PolEnt.Policy.AccessRequestProperties.SessionAccessAccountType)
            }
            break
        }
        "ssh" {
            if ($PolEnt.Account)
            {
                $local:Permission = (Get-AccountPermissionText "SSH" $PolEnt.System.Name $PolEnt.Account.SystemName $PolEnt.Account.Name`
                                     -AccountDomainName $PolEnt.Account.DomainName)
            }
            else
            {
                $local:Permission = (Get-NoAccountPermissionText "SSH" $PolEnt.Policy.AccessRequestProperties.SessionAccessAccountType)
            }
            break
        }
        default {
            $local:Permission = $null
            Write-Warning "Unrecognized access request type '$($PolEnt.Policy.AccessRequestProperties.AccessRequestType)'"
            break
        }
    }

    $local:Permission
}
function Write-CsvOutput
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, Position=0)]
        [bool]$WriteToFile,
        [Parameter(Mandatory=$true, Position=1)]
        [string]$OutputFile,
        [Parameter(Mandatory=$true, Position=2)]
        [object[]]$Payload,
        [Parameter(Mandatory=$true, Position=3)]
        [string[]]$FormatList
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($WriteToFile)
    {
        $Payload | Select-Object $FormatList | Export-Csv -NoTypeInformation -Path $OutputFile
        Write-Host "Data written to $OutputFile"
    }
    else
    {
        $Payload | Select-Object $FormatList | ConvertTo-Csv -NoTypeInformation
    }
}

<#
.SYNOPSIS
Get identity comma-separated values (CSV) for access certification
via the Safeguard Web API.

.DESCRIPTION
This utility calls the Safeguard Web API and lists all of the identities from
the local Safeguard identity provider for which Safeguard is the identity
authority.

This cmdlet require an active Safeguard session which may be established using
the Connect-Safeguard cmdlet.

.PARAMETER Identifier
IP address or hostname of a Safeguard appliance.

.PARAMETER OutputDirectory
Output directory to store CSV file (default: current directory)

.PARAMETER StdOut
Print CSV to the console rather than to a file.

.INPUTS
None.

.OUTPUTS
A CSV file or CSV text.

.EXAMPLE
Get-SafeguardAccessCertificationIdentity "SG-US-Cluster1"

.EXAMPLE
Get-SafeguardAccessCertificationIdentity "SG-US-Cluster1" -StdOut
#>
function Get-SafeguardAccessCertificationIdentity
{
    [CmdletBinding(DefaultParameterSetName="File")]
    Param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Identifier,
        [Parameter(Mandatory=$false, ParameterSetName="File", Position=1)]
        [string]$OutputDirectory = (Get-Location),
        [Parameter(Mandatory=$false, ParameterSetName="StdOut")]
        [switch]$StdOut
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Test-Permission GlobalAdmin,UserAdmin,HelpdeskAdmin,Auditor

    $local:Identities = @()

    # Get all Safeguard users from the Local and Certificate providers and report them as identities
    # For now, we will report all directory identity providers as accounts with anchors
    (Invoke-SafeguardMethod Core GET "Users" -Parameters @{
        fields = "FirstName,LastName,UserName,EmailAddress,WorkPhone,MobilePhone,IdentityProviderTypeReferenceName,PrimaryAuthenticationIdentity,DirectoryProperties";
        filter = "(Disabled eq false) and ((PrimaryAuthenticationProviderName eq 'Local') or (PrimaryAuthenticationProviderName eq 'Certificate'))"
    }) | ForEach-Object {
        # Additional data sanity checking here? -- i.e. Are these really identities? or Are these really accounts?
        if ((-not $_.FirstName) -or (-not $_.LastName))
        {
            Write-Verbose "Skipping Safeguard user '$($_.UserName)' that does not have a proper first and last name"
        }
        else
        {
            $local:Identity = New-Object PSObject -Property @{
                givenName = $_.FirstName;
                familyName = $_.LastName;
                email = $_.EmailAddress;
                anchor = $_.UserName;
                manager = $null # Safeguard doesn't have the concept of organizational hierarchy (manager)
            }
            $local:Identities += $local:Identity
        }
    }
    Write-CsvOutput ($PSCmdlet.ParameterSetName -eq "File") (Join-Path $OutputDirectory "$Identifier-identities.csv") $local:Identities `
        "givenName","familyName","email","anchor","manager"
}

<#
.SYNOPSIS
Get account comma-separated values (CSV) for access certification
via the Safeguard Web API.

.DESCRIPTION
In the context of this cmdlet the term 'account' refers to identities that can
log into Safeguard as opposed to accounts being protected by Safeguard.  This
is how access certification uses the term.

This utility calls the Safeguard Web API and lists all of the accounts from
all Safeguard identity providers.  This will include everyone who can log into
this Safeguard cluster.

This cmdlet require an active Safeguard session which may be established using
the Connect-Safeguard cmdlet.

.PARAMETER Identifier
IP address or hostname of a Safeguard appliance.

.PARAMETER OutputDirectory
Output directory to store CSV file (default: current directory)

.PARAMETER StdOut
Print CSV to the console rather than to a file.

.INPUTS
None.

.OUTPUTS
A CSV file or CSV text.

.EXAMPLE
Get-SafeguardAccessCertificationAccount "SG-US-Cluster1"

.EXAMPLE
Get-SafeguardAccessCertificationAccount "SG-US-Cluster1" -StdOut
#>
function Get-SafeguardAccessCertificationAccount
{
    [CmdletBinding(DefaultParameterSetName="File")]
    Param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Identifier,
        [Parameter(Mandatory=$false, ParameterSetName="File", Position=1)]
        [string]$OutputDirectory = (Get-Location),
        [Parameter(Mandatory=$false, ParameterSetName="StdOut")]
        [switch]$StdOut
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Test-Permission GlobalAdmin,UserAdmin,HelpdeskAdmin,Auditor

    $local:Accounts = (Get-AccessCertAccount $Identifier)

    Write-CsvOutput ($PSCmdlet.ParameterSetName -eq "File") (Join-Path $OutputDirectory "$Identifier-accounts.csv") $local:Accounts `
        "authority","id","userName","owner"
}

<#
.SYNOPSIS
Get group comma-separated values (CSV) for access certification
via the Safeguard Web API.

.DESCRIPTION
In the context of this cmdlet the term 'group' includes both Safeguard user
groups and Safeguard entitlements because Safeguard users can be added
directly as members to assign access.

This utility calls the Safeguard Web API and lists all of the groups.  This will
be a list of all of the memberships that an account could be given that could
grant access.

This cmdlet require an active Safeguard session which may be established using
the Connect-Safeguard cmdlet.

.PARAMETER Identifier
IP address or hostname of a Safeguard appliance.

.PARAMETER OutputDirectory
Output directory to store CSV file (default: current directory)

.PARAMETER StdOut
Print CSV to the console rather than to a file.

.INPUTS
None.

.OUTPUTS
A CSV file or CSV text.

.EXAMPLE
Get-SafeguardAccessCertificationGroup "SG-US-Cluster1"

.EXAMPLE
Get-SafeguardAccessCertificationGroup "SG-US-Cluster1" -StdOut
#>
function Get-SafeguardAccessCertificationGroup
{
    [CmdletBinding(DefaultParameterSetName="File")]
    Param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Identifier,
        [Parameter(Mandatory=$false, ParameterSetName="File", Position=1)]
        [string]$OutputDirectory = (Get-Location),
        [Parameter(Mandatory=$false, ParameterSetName="StdOut")]
        [switch]$StdOut
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Test-Permission PolicyAdmin,Auditor

    $local:Groups = (Get-AccessCertGroup $Identifier)

    Write-CsvOutput ($PSCmdlet.ParameterSetName -eq "File") (Join-Path $OutputDirectory "$Identifier-groups.csv") $local:Groups `
        "authority","id","groupName","displayName","description","owner"
}

<#
.SYNOPSIS
Get entitlement comma-separated values (CSV) for access certification
via the Safeguard Web API.

.DESCRIPTION
In the context of this cmdlet the term 'entitlement' refers to individual access
rules that are more commonly called access policies in Safeguard.

This utility calls the Safeguard Web API and processes all access rules into
entitlements for use with access ceritfication.

This cmdlet require an active Safeguard session which may be established using
the Connect-Safeguard cmdlet.

.PARAMETER Identifier
IP address or hostname of a Safeguard appliance.

.PARAMETER OutputDirectory
Output directory to store CSV file (default: current directory)

.PARAMETER StdOut
Print CSV to the console rather than to a file.

.INPUTS
None.

.OUTPUTS
A CSV file or CSV text.

.EXAMPLE
Get-SafeguardAccessCertificationEntitlement "SG-US-Cluster1"

.EXAMPLE
Get-SafeguardAccessCertificationEntitlement "SG-US-Cluster1" -StdOut
#>
function Get-SafeguardAccessCertificationEntitlement
{
    [CmdletBinding(DefaultParameterSetName="File")]
    Param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Identifier,
        [Parameter(Mandatory=$false, ParameterSetName="File", Position=1)]
        [string]$OutputDirectory = (Get-Location),
        [Parameter(Mandatory=$false, ParameterSetName="StdOut")]
        [switch]$StdOut
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Test-Permission PolicyAdmin,Auditor

    $local:Entitlements = @()
    $local:AccountsTable = (Get-AccessCertAccount $Identifier -AsLookupTable)
    $local:GroupsTable = (Get-AccessCertGroup $Identifier -AsLookupTable)

    Write-Progress -Activity "Compiling entitlements" -Status "0 of $($local:AccountsTable.Count) accounts" -PercentComplete 0

    $local:AccountKeys = [string[]]$local:AccountsTable.Keys
    for ($i=0; $i -lt $local:AccountsTable.Count; $i++)
    {
        $local:Percent = [int]($i / $local:AccountsTable.Count * 100)
        Write-Progress -Activity "Compiling entitlements" -Status "$($i + 1) of $($local:AccountsTable.Count)" -PercentComplete $local:Percent

        [int]$local:AccountKey = $local:AccountKeys[$i]
        $local:Ent = (Invoke-SafeguardMethod Core POST "Reports/Entitlements/UserEntitlement" -Body (,$local:AccountKey) `
            -Parameters @{
                fields = "UserEntitlements.User,UserEntitlements.PolicyEntitlements"
            })

        if ($local:Ent.UserEntitlements.PolicyEntitlements)
        {
            $local:Ent.UserEntitlements.PolicyEntitlements | ForEach-Object {
                if ($_.RoleIdentity)
                {   # access derived from group membership
                    $local:GroupKey = "$($_.RoleIdentity.Id)"
                }
                else
                {   # access derived from entitlement membership
                    $local:GroupKey = "e/$($_.Policy.RoleId)"
                }

                $local:GroupAuthority = $local:GroupsTable[$local:GroupKey].authority
                $local:GroupId = $local:GroupsTable[$local:GroupKey].id

                $local:Resource = "$($_.System.Name)"
                if ($_.System.Name -ine $_.System.NetworkAddress)
                {   # add in the network address if it provides additional asset identification info
                    $local:Resource += " [$($_.System.NetworkAddress)]"
                }

                $local:Permission = (Get-PermissionText $_)
                if ($local:Permission)
                {
                    $local:Entitlement = New-Object PSObject -Property @{
                        accountAuthority = $local:AccountsTable[$local:AccountKey].authority;
                        accountId = $local:AccountsTable[$local:AccountKey].id;
                        permission = $local:Permission;
                        resource = $local:Resource;
                        groupAuthority = $local:GroupAuthority;
                        groupId = $local:GroupId
                    }
                    $local:Entitlements += $local:Entitlement
                }
            }
        }
        else
        {
            Write-Verbose "No entitlement information found for Safeguard user '$($local:Ent.UserEntitlements.User.UserName)'"
        }
    }

    Write-Progress -Activity "Compiling entitlements" -Status "Safeguard user $($local:AccountsTable.Count) of $($local:AccountsTable.Count)" `
        -PercentComplete 100 -Completed

    Write-CsvOutput ($PSCmdlet.ParameterSetName -eq "File") (Join-Path $OutputDirectory "$Identifier-entitlements.csv") $local:Entitlements `
        "accountAuthority","accountId","permission","resource","groupAuthority","groupId"
}

# AD only helpers
function Test-ADModuleAvailable
{
    try
    {
        Get-Command Get-ADUser | Out-Null
    }
    catch
    {
        throw "You must load the ActiveDirectory PowerShell module from Microsoft to use this cmdlet"
    }
}

function Get-ADAccountCertificationIdentity
{
    [CmdletBinding(DefaultParameterSetName="File")]
    Param(
        [Parameter(Mandatory=$false, ParameterSetName="File", Position=0)]
        [string]$OutputDirectory = (Get-Location),
        [Parameter(Mandatory=$false, ParameterSetName="StdOut")]
        [switch]$StdOut,
        [Parameter(Mandatory=$true)]
        [string]$DomainName,
        [Parameter(Mandatory=$false)]
        [PSCredential]$Credential = (Get-Credential -Message "Active Directory login ($DomainName)"),
        [Parameter(Mandatory=$false)]
        [string[]]$Groups
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Test-ADModuleAvailable

    $local:UsersTable = @{}
    if ($Groups)
    {
        for ($i=0; $i -lt $Groups.Count; $i++)
        {
            $local:GroupName = $Groups[$i]
            Write-Progress -Activity "Getting identity list from AD" -Status "Building identity index ($($i + 1) of $($Groups.Count))" `
                -PercentComplete ([int]($i / $Groups.Count * 100))
            try
            {
                $local:GroupDn = (Get-ADGroup -Identity $local:GroupName -Server $DomainName -Credential $Credential).DistinguishedName
            }
            catch
            {
                Write-Warning "Group '$($local:GroupName)' not found"
            }
            # all users with a sAMAccountName that are not disabled and a member of the group
            Get-ADUser -LDAPFilter "(&(objectCategory=Person)(sAMAccountName=*)(!userAccountControl:1.2.840.113556.1.4.803:=2)(memberOf=$($local:GroupDn)))" `
                       -Server $DomainName -Credential $Credential `
                       -Properties "Manager","GivenName","Surname","EmailAddress" | ForEach-Object {
                if ($_.GivenName -and $_.Surname)
                {
                    $local:UsersTable[$_.DistinguishedName] = $_
                }
                else
                {
                    Write-Verbose "Ignoring '$($_.SamAccountName)', because it doesn't have givenName and familyName"
                }
            }
        }
        Write-Progress -Activity "Getting identity list from AD" -Status "Building identity index" -PercentComplete 100 -Completed
    }
    else
    {
        Write-Progress -Activity "Getting identity list from AD" -Status "Building identity index" -PercentComplete 10
        # all users with a sAMAccountName that are not disabled
        Get-ADUser -LDAPFilter "(&(objectCategory=Person)(sAMAccountName=*)(!userAccountControl:1.2.840.113556.1.4.803:=2))" `
                   -Server $DomainName -Credential $Credential `
                   -Properties "Manager","GivenName","Surname","EmailAddress" | ForEach-Object {
            if ($_.GivenName -and $_.Surname)
            {
                $local:UsersTable[$_.DistinguishedName] = $_
            }
            else
            {
                Write-Verbose "Ignoring '$($_.SamAccountName)', because it doesn't have givenName and familyName"
            }
        }
        Write-Progress -Activity "Getting identity list from AD" -Status "Building identity index" -PercentComplete 100 -Completed
    }

    $local:Identities = @()
    $local:UserKeys = [string[]]$local:UsersTable.Keys
    for ($i=0; $i -lt $local:UsersTable.Count; $i++)
    {
        $local:Percent = [int]($i / $local:UsersTable.Count * 100)
        Write-Progress -Activity "Processing identities" -Status "$($i + 1) of $($local:UsersTable.Count)" -PercentComplete $local:Percent

        $local:UserKey = $local:UserKeys[$i]
        $local:User = $local:UsersTable[$local:UserKey]
        if ($local:User.Manager)
        {
            $local:Manager = $local:UsersTable[$local:User.Manager]
        }
        else
        {
            $local:Manager = $null
        }
        $local:Identity = New-Object PSObject -Property @{
            givenName = $local:User.GivenName;
            familyName = $local:User.Surname;
            email = $local:User.EmailAddress;
            anchor = $local:User.EmailAddress;
            manager = $null
        }
        if ($local:Manager)
        {
            $local:Identity.manager = $local:Manager.EmailAddress
        }
        $local:Identities += $local:Identity
    }

    Write-Progress -Activity "Processing identities" -Status "$($local:UsersTable.Count) of $($local:UsersTable.Count)" `
        -PercentComplete 100 -Completed

    Write-CsvOutput ($PSCmdlet.ParameterSetName -eq "File") (Join-Path $OutputDirectory "$DomainName-identities.csv") $local:Identities `
        "givenName","familyName","email","anchor","manager"
}