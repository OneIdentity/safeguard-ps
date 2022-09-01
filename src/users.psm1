# Helpers
function Resolve-SafeguardUserObject
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
        [object]$User
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($User.Id -as [int])
    {
        $User = $User.Id
    }

    if (-not ($User -as [int]))
    {
        $local:Filter = "Name ieq '$User'"
        $local:Pair = ($User -split "\\")
        if ($local:Pair.Length -eq 2)
        {
            $local:Filter = "IdentityProviderName ieq '$($local:Pair[0])' and Name ieq '$($local:Pair[1])'"
        }
        try
        {
            $local:Users = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Users `
                                -Parameters @{ filter = $local:Filter })
        }
        catch
        {
            Write-Verbose $_
            Write-Verbose "Caught exception with ieq filter, trying with q parameter"
            $local:Users = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Users `
                                -Parameters @{ q = $User })
        }
        if (-not $local:Users)
        {
            throw "Unable to find user matching '$User'"
        }
        if ($local:Users.Count -ne 1)
        {
            throw "Found $($local:Users.Count) users matching '$User'"
        }
        $local:Users[0]
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Users/$User"
    }
}
function Resolve-SafeguardUserId
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
        [object]$User
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($User.Id -as [int])
    {
        $User = $User.Id
    }

    if (-not ($User -as [int]))
    {
        $local:Filter = "Name ieq '$User'"
        $local:Pair = ($User -split "\\")
        if ($local:Pair.Length -eq 2)
        {
            $local:Filter = "IdentityProviderName ieq '$($local:Pair[0])' and Name ieq '$($local:Pair[1])'"
        }
        try
        {
            $local:Users = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Users `
                                -Parameters @{ filter = $local:Filter })
        }
        catch
        {
            Write-Verbose $_
            Write-Verbose "Caught exception with ieq filter, trying with q parameter"
            $local:Users = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Users `
                                -Parameters @{ q = $User })
        }
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

<#
.SYNOPSIS
Get identity providers configured in Safeguard via the Web API.

.DESCRIPTION
Get the identity providers that have been configured in Safeguard.  Based on
these identity providers you can add users that can log into Safeguard.  All
users can request access to passwords or sessions based on policy.  Depending
on permissions (admin roles) some users can manage different aspects of Safeguard.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER ProviderToGet
An integer containing an ID  or a string containing the name of the identity provider to return.

.PARAMETER Fields
An array of the identity provider property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardIdentityProvider

.EXAMPLE
Get-SafeguardIdentityProvider test.example.domain
#>
function Get-SafeguardIdentityProvider
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
        [object]$ProviderToGet,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Parameters = @{}
    if ($Fields)
    {
        $local:Parameters = @{ fields = ($Fields -join ",")}
    }

    if ($PSBoundParameters.ContainsKey("ProviderToGet"))
    {
        if ($ProviderToGet -as [int])
        {
            Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "IdentityProviders/$ProviderToGet" `
                -Parameters $local:Parameters
        }
        else
        {
            try
            {
                $local:Parameters["filter"] = "Name ieq '$ProviderToGet'"
                Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET IdentityProviders `
                    -Parameters $local:Parameters
            }
            catch
            {
                Write-Verbose $_
                Write-Verbose "Caught exception with ieq filter, trying with q parameter"
                $local:Parameters.Remove("filter")
                $local:Parameters["q"] = $ProviderToGet
                Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET IdentityProviders `
                    -Parameters $local:Parameters
            }
        }
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET IdentityProviders `
            -Parameters $local:Parameters
    }
}

<#
.SYNOPSIS
Get authentication providers configured in Safeguard via the Web API.

.DESCRIPTION
Get the authentication providers that have been configured in Safeguard.  Based on
these authentication providers you can configure authentication in Safeguard.  All
users can request access to passwords or sessions based on policy.  Depending
on permissions (admin roles) some users can manage different aspects of Safeguard.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER ProviderToGet
An integer containing an ID  or a string containing the name of the identity provider to return.

.PARAMETER Fields
An array of the authentication provider property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardAuthenticationProvider

.EXAMPLE
Get-SafeguardAuthenticationProvider subdomain.example.domain
#>
function Get-SafeguardAuthenticationProvider
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
        [object]$ProviderToGet,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Parameters = @{}
    if ($Fields)
    {
        $local:Parameters = @{ fields = ($Fields -join ",")}
    }

    if ($PSBoundParameters.ContainsKey("ProviderToGet"))
    {
        if ($ProviderToGet -as [int])
        {
            Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "AuthenticationProviders/$ProviderToGet" `
                -Parameters $local:Parameters
        }
        else
        {
            try
            {
                $local:Parameters["filter"] = "Name ieq '$ProviderToGet'"
                $local:Provider = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET AuthenticationProviders `
                                                          -Parameters $local:Parameters)
            }
            catch
            {
                Write-Verbose $_
                Write-Verbose "Caught exception with ieq filter"
            }
            if ($local:Provider)
            {
                $local:Provider
            }
            else
            {
                Write-Verbose "Trying with q parameter"
                $local:Parameters.Remove("filter")
                $local:Parameters["q"] = $ProviderToGet
                Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET AuthenticationProviders `
                    -Parameters $local:Parameters
            }
        }
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET AuthenticationProviders `
            -Parameters $local:Parameters
    }
}

<#
.SYNOPSIS
Set authentication provider as default in Safeguard.

.DESCRIPTION
This cmdlet will set the specified authentication provider as the default. The login page will not display a drop down list
of all available providers. Instead, the end user will be defaulted in to using the specified provider. Only one provider
can be marked as the default at a time. When updating the specified provider, any previously set default will be cleared.

If a default provider is set and you need to log in using some other provider, like the Safeguard Local provider in order
to log in as a local administrator user, a query string parameter can be appended to the login page URL, 'primaryProviderID',
where the value is set to the 'RstsProviderId' you need.

For example, "https://<safeguard>/RSTS/Login?response_type=token&redirect_uri=https%3A%2F%2F<safeguard>%2F&primaryProviderID=local".

You cannot set a provider that is used for two-factor authentication as the default.

This functionality is only applicable to web browser based logins, not programmatic API/OAuth2 logins.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER ProviderToGet
An integer containing an ID  or a string containing the name of the identity provider to set.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Set-SafeguardAuthenticationProviderAsDefault "Starling"

.EXAMPLE
Set-SafeguardAuthenticationProviderAsDefault "Azure AD"
#>
function Set-SafeguardAuthenticationProviderAsDefault
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
        [object]$ProviderToSet
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Provider = (Get-SafeguardAuthenticationProvider -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure -ProviderToGet $ProviderToSet)
    if ($local:Provider)
    {
        if ($local:Provider.Count -ne 1)
        {
            throw "More than one authentication provider matched '$ProviderToSet'"
        }
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "AuthenticationProviders/$($local:Provider.Id)/ForceAsDefault"
    }
    else
    {
        throw "Unable to find authentication provider '$ProviderToSet'"
    }
}

<#
.SYNOPSIS
Clear any authentication provider from being default in Safeguard.

.DESCRIPTION
This cmdlet will clear any authentication provider from being the default. This will restore the normal
provider selection behavior of Safeguard.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Clear-SafeguardAuthenticationProviderAsDefault
#>
function Clear-SafeguardAuthenticationProviderAsDefault
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "AuthenticationProviders/ClearDefault"
}

<#
.SYNOPSIS
Get users in Safeguard via the Web API.

.DESCRIPTION
Get the users that have been added to Safeguard.  Users can log into Safeguard.  All
users can request access to passwords or sessions based on policy.  Depending
on permissions (admin roles) some users can manage different aspects of Safeguard.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER UserToGet
An integer containing an ID  or a string containing the name of the user to return.

.PARAMETER Fields
An array of the user property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardUser -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardUser petrsnd -Fields IdentityProviderId,Id,Name

.EXAMPLE
Get-SafeguardUser 123
#>
function Get-SafeguardUser
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
        [object]$UserToGet,
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

    if ($PSBoundParameters.ContainsKey("UserToGet"))
    {
        $local:UserId = (Resolve-SafeguardUserId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $UserToGet)
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Users/$local:UserId" `
            -Parameters $local:Parameters
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Users `
            -Parameters $local:Parameters
    }
}

<#
.SYNOPSIS
Search for a user in Safeguard via the Web API.

.DESCRIPTION
Search for a user in Safeguard for any string fields containing
the SearchString.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER SearchString
A string to search for in the user.

.PARAMETER QueryFilter
A string to pass to the -filter query parameter in the Safeguard Web API.

.PARAMETER Fields
An array of the user property names to return.

.PARAMETER OrderBy
An array of the user property names to order by.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Find-SafeguardUser -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Find-SafeguardUser "Peterson"

.EXAMPLE
Find-SafeguardUser -QueryFilter "SecondaryAuthenticationProviderId eq null" | ft Id,PrimaryAuthenticationProviderName,Name,EmailAddress
#>
function Find-SafeguardUser
{
    [CmdletBinding(DefaultParameterSetName="Search")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0,ParameterSetName="Search")]
        [string]$SearchString,
        [Parameter(Mandatory=$true,Position=0,ParameterSetName="Query")]
        [string]$QueryFilter,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields,
        [Parameter(Mandatory=$false)]
        [string[]]$OrderBy
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSCmdlet.ParameterSetName -eq "Search")
    {
        $local:Parameters = @{ q = $SearchString }
    }
    else
    {
        $local:Parameters = @{ filter = $QueryFilter }
    }

    if ($Fields)
    {
        $local:Parameters["fields"] = ($Fields -join ",")
    }
    if ($OrderBy)
    {
        $local:Parameters["orderby"] = ($OrderBy -join ",")
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Users `
            -Parameters $local:Parameters
}

<#
.SYNOPSIS
Create a new user in Safeguard via the Web API.

.DESCRIPTION
Create a new user in Safeguard.  Users can log into Safeguard.  All
users can request access to passwords or sessions based on policy.  Depending
on permissions (admin roles) some users can manage different aspects of Safeguard.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Provider
An integer containing an ID  or a string containing the name of the identity provider.

.PARAMETER NewUserName
A string containing the name to give to the new user.  Names must be unique per identity provider.

.PARAMETER FirstName
A string containing the first name of the user.  Combined with last name to form a user's DisplayName.

.PARAMETER LastName
A string containing the last name of the user.  Combined with first name to form a user's DisplayName.

.PARAMETER Description
A string containing a description for the user.

.PARAMETER DomainName
A string containing the DNS name of the domain this user is in.

.PARAMETER EmailAddress
A string containing a email address for the user.

.PARAMETER WorkPhone
A string containing a work phone number for the user.

.PARAMETER MobilePhone
A string containing a mobile phone number for the user.

.PARAMETER AdminRoles
An array of strings containing the permissions (admin roles) to assign to the members of this directory
group.  You may also specify 'All' to grant all permissions. Other permissions are: 'GlobalAdmin',
'ApplicationAuditor', 'SystemAuditor', 'Auditor', 'AssetAdmin', 'ApplianceAdmin', 'PolicyAdmin', 'UserAdmin',
'HelpdeskAdmin', 'OperationsAdmin'.

.PARAMETER Password
SecureString containing the password.

.PARAMETER NoPassword
Do not promprt for a password for new local user

.PARAMETER Thumbprint
String containing a SHA-1 thumbprint of certificate to use for authentication.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
New-SafeguardUser -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
New-SafeguardUser local petrsnd -AdminRoles 'AssetAdmin','ApplianceAdmin'
#>
function New-SafeguardUser
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
        [string]$DomainName = $null,
        [Parameter(Mandatory=$false)]
        [string]$EmailAddress = $null,
        [Parameter(Mandatory=$false)]
        [string]$WorkPhone = $null,
        [Parameter(Mandatory=$false)]
        [string]$MobilePhone = $null,
        [Parameter(Mandatory=$false)]
        [ValidateSet('GlobalAdmin','DirectoryAdmin','Auditor','ApplicationAuditor','SystemAuditor','AssetAdmin','ApplianceAdmin',
                     'PolicyAdmin','UserAdmin','HelpdeskAdmin','OperationsAdmin','All',IgnoreCase=$true)]
        [string[]]$AdminRoles = $null,
        [Parameter(Mandatory=$false)]
        [SecureString]$Password,
        [Parameter(Mandatory=$false)]
        [switch]$NoPassword = $false,
        [Parameter(Mandatory=$false)]
        [string]$Thumbprint
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

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
        $local:ProviderResolved = (Get-SafeguardIdentityProvider -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Provider)[0].Id
        if (-not $local:ProviderResolved)
        {
            $local:ProviderResolved = (Get-SafeguardDirectoryIdentityProvider -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Provider)[0].Id
            if (-not $local:ProviderResolved)
            {
                throw "Unable to find identity provider that matches '$Provider'"
            }
        }
    }
    else
    {
        $local:ProviderResolved = ([int]$Provider)
    }

    if ($local:ProviderResolved -eq $local:CertificateProviderId -and -not ($PSBoundParameters.ContainsKey("Thumbprint")))
    {
        $Thumbprint = (Read-Host "Thumbprint")
    }

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

    if ($local:ProviderResolved -eq $local:LocalProviderId -and $PSBoundParameters.ContainsKey("Password"))
    {
        # Check the password complexity before creating the user so you don't end up with a user without a password
        try
        {
            $local:PasswordPlainText = [System.Net.NetworkCredential]::new("", $Password).Password
            Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "Users/ValidatePassword" -Body `
                $local:PasswordPlainText
            $local:PasswordPlainText = ""
        }
        catch
        {
            Write-Warning "Password for the new user failed to meet requirements"
            throw $_.Exception
        }
    }

    if ($local:ProviderResolved -eq $local:LocalProviderId -or $local:ProviderResolved -eq $local:CertificateProviderId)
    {
        $local:Body = @{
            PrimaryAuthenticationProvider = @{ Id = $local:ProviderResolved };
            Name = $NewUserName;
            AdminRoles = $AdminRoles
        }
        if ($PSBoundParameters.ContainsKey("FirstName")) { $local:Body.FirstName = $FirstName }
        if ($PSBoundParameters.ContainsKey("LastName")) { $local:Body.LastName = $LastName }
        if ($PSBoundParameters.ContainsKey("Description")) { $local:Body.Description = $Description }
        if ($PSBoundParameters.ContainsKey("EmailAddress")) { $local:Body.EmailAddress = $EmailAddress }
        if ($PSBoundParameters.ContainsKey("WorkPhone")) { $local:Body.WorkPhone = $WorkPhone }
        if ($PSBoundParameters.ContainsKey("MobilePhone")) { $local:Body.MobilePhone = $MobilePhone }
        if ($local:ProviderResolved -eq $local:CertificateProviderId)
        {
            $local:Body.PrimaryAuthenticationProvider.Identity = $Thumbprint
        }
        $local:NewUser = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST Users -Body $local:Body)
        if ($local:ProviderResolved -eq $local:LocalProviderId)
        {
            Write-Host "Setting password for new user..."
            if ($PSBoundParameters.ContainsKey("Password"))
            {
                Set-SafeguardUserPassword -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $local:NewUser.Id $Password
            }
            else
            {
                if (-not $NoPassword)
                {
                    Set-SafeguardUserPassword -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $local:NewUser.Id
                }
            }
        }
        $local:NewUser
    }
    else
    {
        if (-not $PSBoundParameters.ContainsKey("DomainName"))
        {
            Import-Module -Name "$PSScriptRoot\sg-utilities.psm1" -Scope Local
            $DomainName = (Resolve-DomainNameFromIdentityProvider -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Provider)
        }
        if (-not $DomainName)
        {
            $DomainName = (Read-Host "DomainName")
        }
        # For directory accounts, lots of attributes are mapped from the directory
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST Users -Body @{
            PrimaryAuthenticationProvider = @{ Id = $local:ProviderResolved };
            Name = $NewUserName;
            AdminRoles = $AdminRoles;
            DirectoryProperties = @{ DomainName = $DomainName }
        }
    }
}

<#
.SYNOPSIS
Delete a user from Safeguard via the Web API.

.DESCRIPTION
Delete a user from Safeguard.  The user will no longer be able tolog into Safeguard.
All audit history for that user will be retained.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER UserToDelete
An integer containing an ID  or a string containing the name of the user to delete.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardUser -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Remove-SafeguardUser petrsnd

.EXAMPLE
Remove-SafeguardUser 123
#>
function Remove-SafeguardUser
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
        [object]$UserToDelete
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $PSBoundParameters.ContainsKey("UserToDelete"))
    {
        $UserToDelete = (Read-Host "UserToDelete")

    }
    $local:UserId = (Resolve-SafeguardUserId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $UserToDelete)

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "Users/$($local:UserId)"
}

<#
.SYNOPSIS
Set the password for a user in Safeguard via the Web API.

.DESCRIPTION
Set the password for a user in Safeguard.  This operation only works for
users from the local identity provider.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER UserToEdit
An integer containing an ID or a string containing the name of the user.

.PARAMETER Password
SecureString containing the password.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Set-SafeguardUserPassword -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Set-SafeguardUserPassword petrsnd

.EXAMPLE
Set-SafeguardUserPassword 123 $newpassword
#>
function Set-SafeguardUserPassword
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
        [object]$UserToEdit,
        [Parameter(Mandatory=$false,Position=1)]
        [SecureString]$Password
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $PSBoundParameters.ContainsKey("UserToEdit"))
    {
        $UserToEdit = (Read-Host "UserToEdit")
    }
    $local:UserId = (Resolve-SafeguardUserId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $UserToEdit)
    if (-not $PSBoundParameters.ContainsKey("Password") -or $null -eq $Password)
    {
        $Password = (Read-Host "Password" -AsSecureString)
    }

    $local:PasswordPlainText = [System.Net.NetworkCredential]::new("", $Password).Password

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "Users/$($local:UserId)/Password" `
        -Body $local:PasswordPlainText
}

<#
.SYNOPSIS
Edit an existing user in Safeguard via the Web API.

.DESCRIPTION
Edit an existing user in Safeguard.  Users can log into Safeguard.  All
users can request access to passwords or sessions based on policy.  Depending
on permissions (admin roles) some users can manage different aspects of Safeguard.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER UserToEdit
An integer containing an ID or a string containing the name of the user.

.PARAMETER FirstName
A string containing the first name of the user.  Combined with last name to form a user's DisplayName.

.PARAMETER LastName
A string containing the last name of the user.  Combined with first name to form a user's DisplayName.

.PARAMETER Description
A string containing a description for the user.

.PARAMETER EmailAddress
A string containing a email address for the user.

.PARAMETER WorkPhone
A string containing a work phone number for the user.

.PARAMETER MobilePhone
A string containing a mobile phone number for the user.

.PARAMETER AdminRoles
An array of strings containing the permissions (admin roles) to assign to the members of this directory
group.  You may also specify 'All' to grant all permissions. Other permissions are: 'GlobalAdmin',
'ApplicationAuditor', 'SystemAuditor', 'Auditor', 'AssetAdmin', 'ApplianceAdmin', 'PolicyAdmin', 'UserAdmin',
'HelpdeskAdmin', 'OperationsAdmin'.

.PARAMETER UserObject
An object containing the existing user with desired properties set.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Edit-SafeguardUser -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Edit-SafeguardUser petrsnd -AdminRoles 'AssetAdmin','ApplianceAdmin' -FirstName 'Dan'

.EXAMPLE
Edit-SafeguardUser -UserObject $obj
#>
function Edit-SafeguardUser
{
    [CmdletBinding(DefaultParameterSetName="Attributes")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(ParameterSetName="Attributes",Mandatory=$true,Position=0)]
        [object]$UserToEdit,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$FirstName = $null,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$LastName = $null,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$Description = $null,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$EmailAddress = $null,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$WorkPhone = $null,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$MobilePhone = $null,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$AuthProvider = $null,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [ValidateSet('GlobalAdmin','DirectoryAdmin','Auditor','ApplicationAuditor','SystemAuditor','AssetAdmin','ApplianceAdmin',
                     'PolicyAdmin','UserAdmin','HelpdeskAdmin','OperationsAdmin','All',IgnoreCase=$true)]
        [string[]]$AdminRoles = $null,
        [Parameter(ParameterSetName="Object",Mandatory=$false)]
        [object]$UserObject
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PsCmdlet.ParameterSetName -eq "Object" -and -not $UserObject)
    {
        throw "UserObject must not be null"
    }

    if ($PsCmdlet.ParameterSetName -eq "Attributes")
    {
        if (-not $PSBoundParameters.ContainsKey("UserToEdit"))
        {
            $UserToEdit = (Read-Host "UserToEdit")
        }
        $local:UserId = (Resolve-SafeguardUserId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $UserToEdit)
    }

    if (-not ($PsCmdlet.ParameterSetName -eq "Object"))
    {
        $UserObject = (Get-SafeguardUser -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $local:UserId)

        if ($PSBoundParameters.ContainsKey("FirstName")) { $UserObject.FirstName = $FirstName }
        if ($PSBoundParameters.ContainsKey("LastName")) { $UserObject.LastName = $LastName }
        if ($PSBoundParameters.ContainsKey("Description")) { $UserObject.Description = $Description }
        if ($PSBoundParameters.ContainsKey("EmailAddress")) { $UserObject.EmailAddress = $EmailAddress }
        if ($PSBoundParameters.ContainsKey("WorkPhone")) { $UserObject.WorkPhone = $WorkPhone }
        if ($PSBoundParameters.ContainsKey("MobilePhone")) { $UserObject.MobilePhone = $MobilePhone }
        if ($PSBoundParameters.ContainsKey("AuthProvider"))
        {
            $local:ResolvedProvider = (Get-SafeguardAuthenticationProvider -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AuthProvider)[0]
            $UserObject.PrimaryAuthenticationProvider = @{ Id = $local:ResolvedProvider.Id }
        }

        if ($PSBoundParameters.ContainsKey("AdminRoles"))
        {
            if ($AdminRoles -contains "All")
            {
                $AdminRoles = @('GlobalAdmin','Auditor','AssetAdmin','ApplianceAdmin','PolicyAdmin','UserAdmin','HelpdeskAdmin','OperationsAdmin')
            }
            $UserObject.AdminRoles = $AdminRoles
        }
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "Users/$($UserObject.Id)" -Body $UserObject
}

<#
.SYNOPSIS
Enable a user in Safeguard via the Web API.

.DESCRIPTION
Enable a user in Safeguard.  This operation only works for
users from the local and certificate identity providers.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER UserToEdit
An integer containing an ID or a string containing the name of the user.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Enable-SafeguardUser -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Enable-SafeguardUser petrsnd

.EXAMPLE
Enable-SafeguardUser 123
#>
function Enable-SafeguardUser
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
        [object]$UserToEdit
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $PSBoundParameters.ContainsKey("UserToEdit"))
    {
        $UserToEdit = (Read-Host "UserToEdit")
    }
    $local:UserId = (Resolve-SafeguardUserId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $UserToEdit)
    $local:UserObject = (Get-SafeguardUser -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $local:UserId)
    $local:UserObject.Disabled = $false
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "Users/$($UserObject.Id)" -Body $local:UserObject
}

<#
.SYNOPSIS
Disable a user in Safeguard via the Web API.

.DESCRIPTION
Disable a user in Safeguard.  This operation only works for
users from the local and certificate identity providers.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER UserToEdit
An integer containing an ID or a string containing the name of the user.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Disable-SafeguardUser -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Disable-SafeguardUser petrsnd

.EXAMPLE
Disable-SafeguardUser 123
#>
function Disable-SafeguardUser
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
        [object]$UserToEdit
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $PSBoundParameters.ContainsKey("UserToEdit"))
    {
        $UserToEdit = (Read-Host "UserToEdit")
    }
    $local:UserId = (Resolve-SafeguardUserId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $UserToEdit)
    $local:UserObject = (Get-SafeguardUser -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $local:UserId)
    $local:UserObject.Disabled = $true
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "Users/$($UserObject.Id)" -Body $local:UserObject
}

<#
.SYNOPSIS
Rename a user in Safeguard via the Web API.

.DESCRIPTION
Rename a user in Safeguard.  This operation only works for
users from the local and certificate identity providers.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER UserToEdit
An integer containing an ID or a string containing the name of the user.

.PARAMETER NewUserName
A string containing the new name for the user.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Rename-SafeguardUser -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Rename-SafeguardUser petrsnd dpeterso

.EXAMPLE
Rename-SafeguardUser 123 "bob jackson"
#>
function Rename-SafeguardUser
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
        [object]$UserToEdit,
        [Parameter(Mandatory=$false,Position=1)]
        [string]$NewUserName
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $PSBoundParameters.ContainsKey("UserToEdit"))
    {
        $UserToEdit = (Read-Host "UserToEdit")
    }
    $local:UserId = (Resolve-SafeguardUserId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $UserToEdit)
    if (-not $PSBoundParameters.ContainsKey("NewUserName") -or -not $NewUserName)
    {
        $NewUserName = (Read-Host "NewUserName")
    }

    $local:UserObject = (Get-SafeguardUser -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $local:UserId)
    $local:UserObject.Name = $NewUserName
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "Users/$($local:UserObject.Id)" -Body $local:UserObject
}

<#
.SYNOPSIS
Get user's Preference in Safeguard via the Web API.

.DESCRIPTION
Get the users Preference.  UserAdmins and GlobalAdmins can use this to get the preferences of a user.
The PreferenceName parameter includes tab completion to easily specify the most common preferences.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER UserToGet
An integer containing an ID  or a string containing the name of the user to get the preference from.
You may specify the user as <identityprovidername>\<username>.

.PARAMETER PreferenceName
An string of the user's Preference to return.
Common preferences are settings.myrequests.calculate_in_use, settings.myrequests.userPreviousVersion,
settings.myrequests.show_web_launch_button, and settings.myrequests.show_launch_button

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardUserPreference petrsnd.corp\petrsnd settings.myrequests.show_launch_button

.EXAMPLE
Get-SafeguardUserPreference bob.ross settings.myrequests.show_launch_button
#>
function Get-SafeguardUserPreference
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
        [object]$UserToGet,
        [Parameter(Mandatory=$true,Position=1)]
        [ArgumentCompleter({
            Param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameters)
            return @("settings.myrequests.calculate_in_use",
                     "settings.myrequests.userPreviousVersion",
                     "settings.myrequests.show_web_launch_button",
                     "settings.myrequests.show_launch_button")
        })]
        [string]$PreferenceName
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:UserId = (Resolve-SafeguardUserId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $UserToGet)

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Users/$($local:UserId)/Preferences/$($local:PreferenceName)" -Parameters $local:Parameters
}


<#
.SYNOPSIS
Set the Preference in Safeguard for a user in Safeguard via the Web API.

.DESCRIPTION
Set the Preference for a user in Safeguard.  This operation only works for
users from the local identity provider.  The PreferenceName parameter includes
tab completion to easily specify the most common preferences.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER UserToEdit
An integer containing an ID or a string containing the name of the user to update.
You may specify the user as <identityprovidername>\<username>.

.PARAMETER PreferenceName
An string of the user's Preference to set.
Common preferences are settings.myrequests.calculate_in_use, settings.myrequests.userPreviousVersion,
settings.myrequests.show_web_launch_button, and settings.myrequests.show_launch_button

.PARAMETER PreferenceValue
An string of the value to set a user's Preference to.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Set-SafeguardUserPreference petrsnd.corp\petrsnd settings.myrequests.show_launch_button true

.EXAMPLE
Set-SafeguardUserPreference bob.ross settings.myrequests.show_launch_button false
#>
function Set-SafeguardUserPreference
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
        [object]$UserToEdit,
        [Parameter(Mandatory=$true,Position=1)]
        [ArgumentCompleter({
            Param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameters)
            return @("settings.myrequests.calculate_in_use",
                     "settings.myrequests.userPreviousVersion",
                     "settings.myrequests.show_web_launch_button",
                     "settings.myrequests.show_launch_button")
        })]
        [string]$PreferenceName,
        [Parameter(Mandatory=$false,Position=2)]
        [string]$PreferenceValue
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:UserId = (Resolve-SafeguardUserId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $UserToEdit)

    if (-not $PSBoundParameters.ContainsKey("PreferenceValue"))
    {
        $PreferenceValue = (Read-Host "PreferenceValue" -AsSecureString)
    }
    $local:Body = @{
        "Name" = $PreferenceName;
        "Value" = $PreferenceValue;
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "Users/$($local:UserId)/Preferences/$($local:PreferenceName)" -Body $local:Body
}

<#
.SYNOPSIS
Delete a Preference from a user from Safeguard via the Web API.

.DESCRIPTION
Delete a Preference from a user from Safeguard.  The user will no longer have that Preference.
All audit history for that Preference will be retained.  The PreferenceName parameter includes
tab completion to easily specify the most common preferences.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER UserToEdit
An integer containing an ID or a string containing the name of the user to delete a preference from.
You may specify the user as <identityprovidername>\<username>.

.PARAMETER PreferenceName
An string of the user's Preference to delete.
Common preferences are settings.myrequests.calculate_in_use, settings.myrequests.userPreviousVersion,
settings.myrequests.show_web_launch_button, and settings.myrequests.show_launch_button

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardUserPreference bob.ross settings.myrequests.show_launch_button

.EXAMPLE
Remove-SafeguardUserPreference petrsnd.corp\petrsnd settings.myrequests.show_launch_button
#>
function Remove-SafeguardUserPreference
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
        [object]$UserToEdit,
        [Parameter(Mandatory=$true,Position=1)]
        [ArgumentCompleter({
            Param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameters)
            return @("settings.myrequests.calculate_in_use",
                     "settings.myrequests.userPreviousVersion",
                     "settings.myrequests.show_web_launch_button",
                     "settings.myrequests.show_launch_button")
        })]
        [string]$PreferenceName
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:UserId = (Resolve-SafeguardUserId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $UserToEdit)

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "Users/$($local:UserId)/Preferences/$($local:PreferenceName)"
}

<#
.SYNOPSIS
Creates a template file containing the headers for importing users.

.DESCRIPTION
Creates a template file containing the headers for importing users. Specify the optional columns with parameters.

Default Columns

-Provider : An integer containing an ID  or a string containing the name of the identity provider.

-NewUserName : A string containing the name to give to the new user.  Names must be unique per identity provider.

.PARAMETER Path
A string containing the path of the template file.

.PARAMETER All
Adds all headers to the template file.

.PARAMETER FirstName
Adds the FirstName header to the template file. 
Value - A string containing the first name of the user.  Combined with last name to form a user's DisplayName.

.PARAMETER LastName
Adds the LastName header to the template file.
Value - A string containing the last name of the user.  Combined with first name to form a user's DisplayName.

.PARAMETER Description
Adds the Description header to the template file.
Value - A string containing a description for the user.

.PARAMETER DomainName
Adds the DomainName header to the template file.
Value - A string containing the DNS name of the domain this user is in.

.PARAMETER EmailAddress
Adds the EmailAddress header to the template file.
Value - A string containing a email address for the user.

.PARAMETER WorkPhone
Adds the WorkPhone header to the template file.
Value - A string containing a work phone number for the user.

.PARAMETER MobilePhone
Adds the MobilePhone header to the template file.
Value - A string containing a mobile phone number for the user.

.PARAMETER AdminRoles
An array of strings containing the permissions (admin roles) to assign to the user.  
You may also specify 'All' to grant all permissions. Other permissions are: 'GlobalAdmin',
'ApplicationAuditor', 'SystemAuditor', 'Auditor', 'AssetAdmin', 'ApplianceAdmin', 'PolicyAdmin', 'UserAdmin',
'HelpdeskAdmin', 'OperationsAdmin'.

.PARAMETER Password
Adds the Password header to the template file.
Value - A string containing the password.

.PARAMETER Thumbprint
Adds the Thumbprint header to the template file.
Value - A string containing a SHA-1 thumbprint of certificate to use for authentication.

.INPUTS
None.

.OUTPUTS
A CSV file with the headers.

.EXAMPLE
New-SafeguardUserImportTemplate -FirstName -LastName -Description

.EXAMPLE
New-SafeguardUserImportTemplate 'C:\tmp\template.csv' -FirstName -LastName -Description

#>
function New-SafeguardUserImportTemplate
{
    [CmdletBinding(DefaultParameterSetName="Specific")]
    Param(
        [Parameter(Mandatory=$false, Position=0)]
        [string]$Path = '.\SafeguardUserImportTemplate.csv',
        [Parameter(Mandatory=$false,ParameterSetName="All")]
        [switch]$All,
        [Parameter(Mandatory=$false,ParameterSetName="Specific")]
        [switch]$FirstName,
        [Parameter(Mandatory=$false,ParameterSetName="Specific")]
        [switch]$LastName,
        [Parameter(Mandatory=$false,ParameterSetName="Specific")]
        [switch]$Description,
        [Parameter(Mandatory=$false,ParameterSetName="Specific")]
        [switch]$DomainName,
        [Parameter(Mandatory=$false,ParameterSetName="Specific")]
        [switch]$EmailAddress,
        [Parameter(Mandatory=$false,ParameterSetName="Specific")]
        [switch]$WorkPhone,
        [Parameter(Mandatory=$false,ParameterSetName="Specific")]
        [switch]$MobilePhone,
        [Parameter(Mandatory=$false,ParameterSetName="Specific")]
        [switch]$AdminRoles,
        [Parameter(Mandatory=$false,ParameterSetName="Specific")]
        [switch]$Password,
        [Parameter(Mandatory=$false,ParameterSetName="Specific")]
        [switch]$Thumbprint
    )

    $local:Headers = '"Provider","NewUserName"'

    if ($PSBoundParameters.ContainsKey("FirstName") -or $PSBoundParameters.ContainsKey("All")) { $local:Headers = $local:Headers + ',"FirstName"' }
    if ($PSBoundParameters.ContainsKey("LastName") -or $PSBoundParameters.ContainsKey("All")) { $local:Headers = $local:Headers + ',"LastName"' }
    if ($PSBoundParameters.ContainsKey("Description") -or $PSBoundParameters.ContainsKey("All")) { $local:Headers = $local:Headers + ',"Description"' }
    if ($PSBoundParameters.ContainsKey("DomainName") -or $PSBoundParameters.ContainsKey("All")) { $local:Headers = $local:Headers + ',"DomainName"' }
    if ($PSBoundParameters.ContainsKey("EmailAddress") -or $PSBoundParameters.ContainsKey("All")) { $local:Headers = $local:Headers + ',"EmailAddress"' }
    if ($PSBoundParameters.ContainsKey("WorkPhone") -or $PSBoundParameters.ContainsKey("All")) { $local:Headers = $local:Headers + ',"WorkPhone"' }
    if ($PSBoundParameters.ContainsKey("MobilePhone") -or $PSBoundParameters.ContainsKey("All")) { $local:Headers = $local:Headers + ',"MobilePhone"' }
    if ($PSBoundParameters.ContainsKey("AdminRoles") -or $PSBoundParameters.ContainsKey("All")) { $local:Headers = $local:Headers + ',"AdminRoles"' }
    if ($PSBoundParameters.ContainsKey("Password") -or $PSBoundParameters.ContainsKey("All")) { $local:Headers = $local:Headers + ',"Password"' }
    if ($PSBoundParameters.ContainsKey("Thumbprint") -or $PSBoundParameters.ContainsKey("All")) { $local:Headers = $local:Headers + ',"Thumbprint"' }

    Set-Content -Path $Path -Value $local:Headers -Force
}

<#
.SYNOPSIS
Imports safeguard users.

.DESCRIPTION
Imports users into safeguard from a csv file.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Path
Specifies the path to the CSV file to import.

.INPUTS
None.

.OUTPUTS
A CSV file with any imports that failed.  If there are no failures no output file will be generated.

.EXAMPLE
Import-SafeguardUser -Path '<path to csv file>'

#>
function Import-SafeguardUser
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
        [string]$Path
    )

	# Intercept Read-Host and return an empty string
	function Read-Host {
		return ""
	}

    $local:Users = Import-Csv -Path $Path

    $local:FailedImports = New-Object System.Collections.ArrayList

    Write-Progress -Activity "Importing Users ..." -PercentComplete 0

    $local:CurrUser = 1;
    foreach($local:User in $local:Users)
    {
        try 
        {
            $local:Args = @{
                AccessToken = $AccessToken
                Appliance = $Appliance
                Insecure = $true
                Provider = $local:User.Provider
                NewUserName = $local:User.NewUserName
            }

            if($null -ne $local:User.FirstName) 
            {
                $local:Args.Add("FirstName", $local:User.FirstName)
            }

            if($null -ne $local:User.LastName) 
            {
                $local:Args.Add("LastName", $local:User.LastName)
            }

            if($null -ne $local:User.Description) 
            {
                $local:Args.Add("Description", $local:User.Description)
            }

            if($null -ne $local:User.DomainName) 
            {
                $local:Args.Add("DomainName", $local:User.DomainName)
            }

            if($null -ne $local:User.EmailAddress) 
            {
                $local:Args.Add("EmailAddress", $local:User.EmailAddress)
            }

            if($null -ne $local:User.WorkPhone) 
            {
                $local:Args.Add("WorkPhone", $local:User.WorkPhone)
            }

            if($null -ne $local:User.MobilePhone) 
            {
                $local:Args.Add("MobilePhone", $local:User.MobilePhone)
            }

            if($null -ne $local:User.AdminRoles) 
            {
                $local:Args.Add("AdminRoles", $local:User.AdminRoles)
            }

            if(![string]::IsNullOrEmpty($local:User.Password))
            {
                $local:SecurePassword = $local:User.Password | ConvertTo-SecureString -AsPlainText -Force
                $local:Args.Add("Password", $local:SecurePassword)
            }

            if($null -ne $local:User.Thumbprint) 
            {
                $local:Args.Add("Thumbprint", $local:User.Thumbprint)
            }

            New-SafeguardUser @local:Args
        }
        catch 
        {
            if ($local:User.PSobject.Properties.Name -contains "Error")
            {
                $local:User.Error = $_
            }
            else 
            {
                $local:User | Add-Member -MemberType NoteProperty -Name "Error" -Value  $_
            }
            $local:FailedImports.Add($local:User)
        }
        
        Write-Progress -Activity "Importing Users ..." -PercentComplete (($local:CurrUser/$local:Users.Count)*100)
        $local:CurrUser++
    }

    Write-Host ($local:Users.Count - $local:FailedImports.Count) "Successful Imports," $local:FailedImports.Count "Failed Imports"
    
    if ($local:FailedImports.Count -gt 0) 
    {
        Write-Host "Please refer to UserImportResults.csv for more information on failures."
        $local:FailedImports | Export-Csv -Path ".\UserImportResults.csv" -NoTypeInformation -Force
    }
}