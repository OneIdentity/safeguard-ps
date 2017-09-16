# Helper
function Resolve-SafeguardUser
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$User
    )

    $ErrorActionPreference = "Stop"

    if (-not ($User -as [int]))
    {
        $local:Users = @(Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Users `
                              -Parameters @{ filter = "UserName ieq '$User'" })
        if (-not $local:Users)
        {
            throw "Unable to find user matching '$User'"
        }
        if ($local:Users.Count -ne 1)
        {
            throw "Found $($local:Users.Count) users matching '$User'"
        }
        $local:Users[0].Id
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
                -Parameters @{ filter = "Name ieq '$Provider'" }
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
        $UserId = Resolve-SafeguardUser -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $User
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
        [string]$FirstName = $null,
        [Parameter(Mandatory=$false)]
        [string]$LastName = $null,
        [Parameter(Mandatory=$false)]
        [string]$Description = $null,
        [Parameter(Mandatory=$false)]
        [string]$EmailAddress = $null,
        [Parameter(Mandatory=$false)]
        [string]$WorkPhone = $null,
        [Parameter(Mandatory=$false)]
        [string]$MobilePhone = $null,
        [Parameter(Mandatory=$false)]
        [ValidateSet('GlobalAdmin','DirectoryAdmin','Auditor','AssetAdmin','ApplianceAdmin','PolicyAdmin','UserAdmin','HelpdeskAdmin','OperationsAdmin','All',IgnoreCase=$true)]
        [string[]]$AdminRoles = $null
    )

    $ErrorActionPreference = "Stop"

    $local:AllProviders = (Get-SafeguardIdentityProvider -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure)
    $local:LocalProviderId = ($AllProviders | Where-Object { $_.Name -eq "Local" }).Id
    $local:CertificateProviderId = ($AllProviders | Where-Object { $_.Name -eq "Certificate" }).Id
    if (-not $PSBoundParameters.ContainsKey("Provider"))
    {
        Write-Host "Identity providers:"
        Write-Host "["
        $local:AllProviders | ForEach-Object {
            Write-Host ("    {0,3} - {1}" -f $_.Id,$_.Name)
        }
        Write-Host "]"
        $Provider = (Read-Host "Select an identity provider")
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

    if ($AdminRoles -contains "All")
    {
        $AdminRoles = @('GlobalAdmin','DirectoryAdmin','Auditor','AssetAdmin','ApplianceAdmin','PolicyAdmin','UserAdmin','HelpdeskAdmin','OperationsAdmin')
    }

    if ($Provider -eq $LocalProviderId -or $Provider -eq $CertificateProviderId)
    {
        $Body = @{
            PrimaryAuthenticationProviderId = $Provider;
            UserName = $NewUserName;
            AdminRoles = $AdminRoles
        }
        if ($PSBoundParameters.ContainsKey("FirstName")) { $Body["FirstName"] = $FirstName }
        if ($PSBoundParameters.ContainsKey("LastName")) { $Body["LastName"] = $LastName }
        if ($PSBoundParameters.ContainsKey("Description")) { $Body["Description"] = $Description }
        if ($PSBoundParameters.ContainsKey("EmailAddress")) { $Body["EmailAddress"] = $EmailAddress }
        if ($PSBoundParameters.ContainsKey("WorkPhone")) { $Body["WorkPhone"] = $WorkPhone }
        if ($PSBoundParameters.ContainsKey("MobilePhone")) { $Body["MobilePhone"] = $MobilePhone }
        $NewUser = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST Users -Body $Body)
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
    $UserId = Resolve-SafeguardUser -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $User

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
    $UserId = Resolve-SafeguardUser -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $User
    if (-not $PSBoundParameters.ContainsKey("Password"))
    { 
        $Password = (Read-Host "Password" -AsSecureString)
    }

    $local:PasswordPlainText = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "Users/$UserId/Password" `
        -Body $local:PasswordPlainText
}