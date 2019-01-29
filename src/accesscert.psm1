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
        [string]$Identifier
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Accounts = @()

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
                $local:Owner = $_.UserName
            }
            elseif ($_.IdentityProviderTypeReferenceName -eq "ActiveDirectory")
            {
                $local:Authority = "ad:$($_.DirectoryProperties.DomainName)"
                $local:Owner = $_.PrimaryAuthenticationIdentity # Object GUID
            }
            else
            {
                $local:Authority = "ldap:$($_.DirectoryProperties.DirectoryName)"
                $local:Owner = $_.DirectoryProperties.DistinguishedName # DN
            }
            $local:Account = New-Object PSObject -Property @{
                authority = $local:Authority;
                id = $_.Id;
                userName = $_.UserName;
                owner = $local:Owner
            }
            $local:Accounts += $local:Account
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
                $local:Owner = $null # TODO: Do we want to try to look up the owner using the created by user ID??
            }
            elseif ($_.DirectoryProperties.NetbiosName) # if it has net bios info it is AD
            {
                $local:Authority = "ad:$($_.DirectoryProperties.DomainName)"
                $local:Owner = $null
            }
            else
            {
                $local:Authority = "ldap:$($_.DirectoryProperties.DirectoryName)"
                $local:Owner = $null
            }
            $local:Group = New-Object PSObject -Property @{
                authority = $local:Authority;
                id = $_.Id;
                groupName = $_.Name;
                displayName = $_.Name;
                description = $_.Description;
                owner = $local:Owner
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
    # Get entitlements from Safeguard, which can directly group together safeguard users and assign them to access policies
    (Invoke-SafeguardMethod Core GET "Roles" -Parameters @{
        fields = "Id,Name,Description,CreatedByUserId,Members";
        filter = "(Members.PrincipalKind eq 'User') and (IsExpired eq false)" # only those containing users
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
                displayName = "Entitlement: $($_.Name)";
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
        [string]$AccountName
    )

    if ($AccountSystemName -ine $SystemName)
    {
        $local:Permission = "$Protocol session as $AccountSystemName\$AccountName"
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
                $local:Permission = (Get-AccountPermissionText "RDP" $PolEnt.System.Name $PolEnt.Account.SystemName $PolEnt.Account.Name)
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
                $local:Permission = (Get-AccountPermissionText "SSH" $PolEnt.System.Name $PolEnt.Account.SystemName $PolEnt.Account.Name)
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
                manager = $null
            }
            $local:Identities += $local:Identity
        }
    }
    Write-CsvOutput ($PSCmdlet.ParameterSetName -eq "File") (Join-Path $OutputDirectory "$Identifier-identities.csv") $local:Identities `
        "givenName","familyName","email","anchor","manager"
}

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
    $local:Accounts = (Get-AccessCertAccount $Identifier)
    $local:Groups = (Get-AccessCertGroup $Identifier -AsLookupTable)

    Write-Progress -Activity "Compiling entitlements" -Status "0 of $($local:Accounts.Count)" -PercentComplete 0

    for ($i=0; $i -lt $local:Accounts.Count; $i++)
    {
        $local:Percent = [int]($i / $local:Accounts.Count * 100)
        Write-Progress -Activity "Compiling entitlements" -Status "$($i + 1) of $($local:Accounts.Count)" -PercentComplete $local:Percent

        $local:Ent = (Invoke-SafeguardMethod Core POST "Reports/Entitlements/UserEntitlement" -Body (,$local:Accounts[$i].id) `
            -Parameters @{
                fields = "UserEntitlements.User,UserEntitlements.PolicyEntitlements"
            })

        if ($local:Ent.UserEntitlements.PolicyEntitlements)
        {
            $local:Ent.UserEntitlements.PolicyEntitlements | ForEach-Object {
                if ($_.RoleIdentity)
                {   # access derived from group membership
                    $local:GroupIndex = "$($_.RoleIdentity.Id)"
                }
                else
                {   # access derived from entitlement membership
                    $local:GroupIndex = "e/$($_.Policy.RoleId)"
                }

                $local:GroupAuthority = $local:Groups[$local:GroupIndex].authority
                $local:GroupId = $local:Groups[$local:GroupIndex].id

                $local:Resource = "$($_.System.Name)"
                if ($_.System.Name -ine $_.System.NetworkAddress)
                {   # add in the network address if it provides additional asset identification info
                    $local:Resource += " [$($_.System.NetworkAddress)]"
                }

                $local:Permission = (Get-PermissionText $_)
                if ($local:Permission)
                {
                    $local:Entitlement = New-Object PSObject -Property @{
                        accountAuthority = $local:Accounts[$i].authority;
                        accountId = $local:Accounts[$i].id;
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

    Write-Progress -Activity "Compiling entitlements" -Status "Safeguard user $($local:Accounts.Count) of $($local:Accounts.Count)" `
        -PercentComplete 100 -Completed

    Write-CsvOutput ($PSCmdlet.ParameterSetName -eq "File") (Join-Path $OutputDirectory "$Identifier-entitlements.csv") $local:Entitlements `
        "accountAuthority","accountId","permission","resource","groupAuthority","groupId"
}
