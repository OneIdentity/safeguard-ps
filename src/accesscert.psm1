#Helper
function Test-SafeguardPermissions
{
    [CmdletBinding(DefaultParameterSetName="File")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true)]
        [string[]]$PossiblePermissions
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:AdminRoles = (Invoke-SafeguardMethod -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure Core Get "Me").AdminRoles
    $local:Intersection = ($PossiblePermissions | Where-Object { $local:AdminRoles -contains $_ })
    if (-not $local:Intersection)
    {
        throw "In order to run this command you must have one of the following permissions: $($PossiblePermissions -join ",")"
    }
}

function Get-SafeguardAccessCertificationIdentity
{
    [CmdletBinding(DefaultParameterSetName="File")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Identifier,
        [Parameter(Mandatory=$false, ParameterSetName="File", Position=1)]
        [string]$OutputDirectory = (Get-Location),
        [Parameter(Mandatory=$false, ParameterSetName="StdOut")]
        [switch]$StdOut
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Test-SafeguardPermissions -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure GlobalAdmin,UserAdmin,HelpdeskAdmin,Auditor

    $local:Identities = @()

    # Get all Safeguard users from the Local and Certificate providers and report them as identities
    # For now, we will report all directory identity providers as accounts with anchors
    (Invoke-SafeguardMethod -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure Core Get "Users" -Parameters @{
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
    if ($PSCmdlet.ParameterSetName -eq "File")
    {
        $local:OutputFile = (Join-Path $OutputDirectory "$Identifier-identities.csv")
        $local:Identities | Select-Object "givenName","familyName","email","anchor","manager" | Export-Csv -NoTypeInformation -Path $local:OutputFile
        Write-Host "Data written to $($local:OutputFile)"
    }
    else
    {
        $local:Identities | Select-Object "givenName","familyName","email","anchor","manager" | ConvertTo-Csv -NoTypeInformation
    }
}

function Get-SafeguardAccessCertificationAccount
{
    [CmdletBinding(DefaultParameterSetName="File")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Identifier,
        [Parameter(Mandatory=$false, Position=1)]
        [string]$OutputDirectory = (Get-Location),
        [Parameter(Mandatory=$false, ParameterSetName="StdOut")]
        [switch]$StdOut
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Test-SafeguardPermissions -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure GlobalAdmin,UserAdmin,HelpdeskAdmin,Auditor

    $local:Accounts = @()

    # Get all Safeguard users from directory identity providers and report them as accounts with anchors
    # For now, we will report Local and Certificate users as identities
    (Invoke-SafeguardMethod -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure Core Get "Users" -Parameters @{
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
    if ($PSCmdlet.ParameterSetName -eq "File")
    {
        $local:OutputFile = (Join-Path $OutputDirectory "$Identifier-accounts.csv")
        $local:Accounts | Select-Object "authority","id","userName","owner" | Export-Csv -NoTypeInformation -Path $local:OutputFile
        Write-Host "Data written to $($local:OutputFile)"
    }
    else
    {
        $local:Accounts | Select-Object "authority","id","userName","owner" | ConvertTo-Csv -NoTypeInformation
    }
}

function Get-SafeguardAccessCertificationGroup
{
    [CmdletBinding(DefaultParameterSetName="File")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Identifier,
        [Parameter(Mandatory=$false, Position=1)]
        [string]$OutputDirectory = (Get-Location),
        [Parameter(Mandatory=$false, ParameterSetName="StdOut")]
        [switch]$StdOut
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Test-SafeguardPermissions -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure PolicyAdmin,Auditor

    $local:Groups = @()

    # Get user group entities from Safeguard, which can be added to entitlements
    (Invoke-SafeguardMethod -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure Core Get "UserGroups" -Parameters @{
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
            $local:Groups += $local:Group
        }
    }
    # Get entitlements from Safeguard, which can directly group together safeguard users and assign them to access policies
    (Invoke-SafeguardMethod -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure Core Get "Roles" -Parameters @{
        fields = "Id,Name,Description,CreatedByUserId,Members";
        filter = "Members.PrincipalKind eq 'User'" # only those containing users
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
            $local:Groups += $local:Group
        }
    }
    # Write output
    if ($PSCmdlet.ParameterSetName -eq "File")
    {
        $local:OutputFile = (Join-Path $OutputDirectory "$Identifier-groups.csv")
        $local:Groups | Select-Object "authority","id","groupName","displayName","description","owner" | Export-Csv -NoTypeInformation -Path $local:OutputFile
        Write-Host "Data written to $($local:OutputFile)"
    }
    else
    {
        $local:Groups | Select-Object "authority","id","groupName","displayName","description","owner" | ConvertTo-Csv -NoTypeInformation
    }
}

function Get-SafeguardAccessCertificationEntitlement
{
    [CmdletBinding(DefaultParameterSetName="File")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Identifier,
        [Parameter(Mandatory=$false, Position=1)]
        [string]$OutputDirectory = (Get-Location),
        [Parameter(Mandatory=$false, ParameterSetName="StdOut")]
        [switch]$StdOut
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Test-SafeguardPermissions -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure PolicyAdmin,Auditor
}