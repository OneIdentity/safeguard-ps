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

    (Invoke-SafeguardMethod -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure Core Get "Users" -Parameters @{
        fields = "FirstName,LastName,UserName,EmailAddress,WorkPhone,MobilePhone,IdentityProviderName,PrimaryAuthenticationIdentity,DirectoryProperties";
        filter = "Disabled eq false"
    }) | ForEach-Object {
        # TODO: data sanity checking here--i.e. are these really identities?
        $local:Identity = New-Object PSObject -Property @{
            givenName = $_.FirstName;
            familyName = $_.LastName;
            email = $_.EmailAddress;
            anchor = $_.PrimaryAuthenticationIdentity;
            manager = $null
        }
        $local:Identities += $local:Identity
    }
    if ($PSCmdlet.ParameterSetName -eq "File")
    {
        $local:OutputFile = (Join-Path $OutputDirectory "identities.csv")
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