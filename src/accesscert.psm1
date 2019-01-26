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
        fields = "FirstName,LastName,UserName,EmailAddress,WorkPhone,MobilePhone,IdentityProviderName,PrimaryAuthenticationIdentity,DirectoryProperties";
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
                anchor = $_.EmailAddress;
                manager = $null
            }
            $local:Identities += $local:Identity
        }
    }
    if ($PSCmdlet.ParameterSetName -eq "File")
    {
        $local:OutputFile = (Join-Path $OutputDirectory "$Identifier-identities.csv")
        $local:Identities | Export-Csv -NoTypeInformation -Path $local:OutputFile
        Write-Host "Data written to $($local:OutputFile)"
    }
    else
    {
        $local:Identities | ConvertTo-Csv -NoTypeInformation
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
        fields = "Id,UserName,EmailAddress,PrimaryAuthenticationIdentity,IdentityProviderTypeReferenceName,DirectoryProperties";
        filter = "(Disabled eq false) and ((PrimaryAuthenticationProviderName ne 'Local') and (PrimaryAuthenticationProviderName ne 'Certificate'))"
    }) | ForEach-Object {
        # Additional data sanity checking here? -- i.e. Are these really accounts? or Are these really identities?
        if ($false)
        {
            Write-Verbose "Skipping Safeguard user '$($_.UserName)' that does not have the proper information"
        }
        else
        {
            if ($_.IdentityProviderTypeReferenceName -eq "ActiveDirectory")
            {
                $local:Authority = "ad:$($_.DirectoryProperties.DomainName)"
                $local:Owner = $_.PrimaryAuthenticationIdentity # Object GUID
            }
            else
            {
                $local:Authority = "ldap:$($_.DirectoryProperties.DirectoryName)"
                $local:Owner = $_.PrimaryAuthenticationIdentity # DN
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
        $local:Accounts | Export-Csv -NoTypeInformation -Path $local:OutputFile
        Write-Host "Data written to $($local:OutputFile)"
    }
    else
    {
        $local:Accounts | ConvertTo-Csv -NoTypeInformation
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