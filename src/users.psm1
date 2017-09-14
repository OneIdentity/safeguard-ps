# Helper
function Resolve-SafeguardUser
{
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [object]$User
    )

    $ErrorActionPreference = "Stop"

    if (-not ($User -as [int]))
    {
        $UserId = (Find-SafeguardUser -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $User)[0].Id
        if (-not $UserId)
        {
            throw "Unable to find user matching '$User'"
        }
        $UserId
    }
    else
    {
        $User
    }
}


function Get-SafeguardIdentityProvider
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [object]$Provider
    )

    if ($PSBoundParameters.ContainsKey("Provider"))
    {
        if ($Provider -as [int])
        {
            Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "IdentityProviders/$Provider"
        }
        else
        {
            Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET IdentityProviders `
                -Parameters @{ q = $Provider }
        }
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET IdentityProviders
    }
}


function Get-SafeguardUser
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [object]$User
    )

    $ErrorActionPreference = "Stop"

    if ($PSBoundParameters.ContainsKey("User"))
    {
        $UserId = Resolve-SafeguardUser $User
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Users/$UserId"
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Users
    }
}


function Find-SafeguardUser
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [string]$SearchString
    )

    $ErrorActionPreference = "Stop"

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Users `
        -Parameters @{ q = $SearchString }
}


function New-SafeguardUser
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [object]$Provider,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$NewUserName,
        [Parameter(Mandatory=$false)]
        [string]$FirstName,
        [Parameter(Mandatory=$false)]
        [string]$LastName,
        [Parameter(Mandatory=$false)]
        [string]$Description,
        [Parameter(Mandatory=$false)]
        [string]$EmailAddress,
        [Parameter(Mandatory=$false)]
        [string]$WorkPhone,
        [Parameter(Mandatory=$false)]
        [string]$MobilePhone,
        [Parameter(Mandatory=$false)]
        [ValidateSet('GlobalAdmin','DirectoryAdmin','Auditor','AssetAdmin','ApplianceAdmin','PolicyAdmin','UserAdmin','HelpdeskAdmin','OperationsAdmin')]
        [string[]]$AdminRoles
    )

    $ErrorActionPreference = "Stop"

    $AllProviders = (Get-SafeguardIdentityProvider -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure)
    $ProviderIds = ($AllProviders | ForEach-Object{ "$($_.Id): $($_.Name)" }) -join ", "
    $LocalProviderId = ($AllProviders | Where-Object { $_.Name -eq "Local" }).Id
    $CertificateProviderId = ($AllProviders | Where-Object { $_.Name -eq "Certificate" }).Id
    if (-not $PSBoundParameters.ContainsKey("Provider"))
    {
        Write-Host "Identity providers: [ $ProviderIds ]"
        $Provider = (Read-Host "Provider")
    }
    if (-not ($Provider -as [int]))
    {
        $ProviderResolved = (Get-SafeguardIdentityProvider -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Provider)[0].Id
        if (-not $ProviderResolved)
        {
            throw "Unable to find identity provider that matches '$Provider'"
        }
        $Provider = $ProviderResolved
    }

    if ($Provider -eq $LocalProviderId -or $Provider -eq $CertificateProviderId)
    {
        $NewUser = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST Users -Body @{
            PrimaryAuthenticationProviderId = $Provider;
            UserName = $NewUserName;
            FirstName = $FirstName;
            LastName = $LastName;
            Description = $Description;
            EmailAddress = $EmailAddress;
            WorkPhone = $WorkPhone;
            MobilePhone = $MobilePhone;
            AdminRoles = $AdminRoles
        })
        if ($Provider = $LocalProviderId)
        {
            Write-Host "Setting password for new user..."
            Set-SafeguardUserPassword -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $NewUser.Id
        }
        $NewUser
    }
    else
    {
        # For directory accounts, lots of attributes are mapped from the directory
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST Users -Body @{
            PrimaryAuthenticationProviderId = $Provider;
            UserName = $NewUserName;
            AdminRoles = $AdminRoles
        }
    }
}

function Remove-SafeguardUser
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [object]$User
    )

    $ErrorActionPreference = "Stop"

    if (-not $PSBoundParameters.ContainsKey("User"))
    {
        $User = (Read-Host "User to delete")

    }
    $UserId = Resolve-SafeguardUser $User

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "Users/$UserId"
}

function Set-SafeguardUserPassword
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [object]$User,
        [Parameter(Mandatory=$false,Position=1)]
        [SecureString]$Password
    )

    $ErrorActionPreference = "Stop"

    if (-not $PSBoundParameters.ContainsKey("User"))
    {
        $User = (Read-Host "User to delete")

    }
    $UserId = Resolve-SafeguardUser $User
    if (-not $PSBoundParameters.ContainsKey("Password"))
    { 
        $Password = (Read-Host "Password" -AsSecureString)
    }

    $local:PasswordPlainText = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "Users/$UserId/Password" `
        -Body $local:PasswordPlainText
}