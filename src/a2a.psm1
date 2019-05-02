# Helper
function Resolve-SafeguardA2aId
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
        [object]$A2a
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not ($A2a -as [int]))
    {
        try
        {
            $local:A2as = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET A2ARegistrations `
                                -Parameters @{ filter = "AppName ieq '$A2a'" })
            if (-not $local:A2as)
            {
                $local:A2as = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET A2ARegistrations `
                                    -Parameters @{ filter = "CertificateUser ieq '$A2a'" })
            }
        }
        catch
        {
            Write-Verbose $_
            Write-Verbose "Caught exception with ieq filter, trying with q parameter"
            $local:A2as = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET A2ARegistrations `
                                -Parameters @{ q = $A2as })
        }
        if (-not $local:A2as)
        {
            throw "Unable to find A2A registration matching '$A2a'"
        }
        if ($local:A2as.Count -ne 1)
        {
            throw "Found $($local:A2as.Count) A2A registration matching '$A2a'"
        }
        $local:A2as[0].Id
    }
    else
    {
        $A2a
    }
}

function Resolve-SafeguardA2aAccountId
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
        [int]$A2aId,
        [Parameter(Mandatory=$true,Position=1)]
        [object]$Account,
        [Parameter(Mandatory=$false)]
        [object]$System
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not ($A2a -as [int]))
    {
        $local:Filter = "AccountName ieq '$Account'"
        if ($PSBoundParameters.ContainsKey("System") -and $System)
        {
            $local:Filter += "and SystemName ieq '$System'"
        }
        try
        {
            $local:Accounts = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                                    Core GET "A2ARegistrations/$A2aId/RetrievableAccounts" -Parameters @{ filter = $local:Filter })
        }
        catch
        {
            Write-Verbose $_
            Write-Verbose "Caught exception with ieq filter, trying with q parameter"
            $local:Accounts = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                                    Core GET "A2ARegistrations/$A2aId/RetrievableAccounts" -Parameters @{ q = $Account })
        }
        if (-not $local:Accounts)
        {
            throw "Unable to find a2a account matching '$Account'"
        }
        if ($local:Accounts.Count -ne 1)
        {
            throw "Found $($local:Accounts.Count) a2a accounts matching '$Account'"
        }
        $local:Accounts[0].AccountId
    }
    else
    {
        $Account
    }
}

<#
.SYNOPSIS
Get status of the A2A service on this Safeguard appliance via the Web API.

.DESCRIPTION
By default the A2A service is not running on a Safeguard appliance.  It must be enabled
on the desired appliances in order to begin using any A2A registration configured in the
cluster.  This cmdlet gets the current status of the A2A service on this appliance.

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
Get-SafeguardA2aServiceStatus -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardA2aServiceStatus
#>
function Get-SafeguardA2aServiceStatus
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

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance GET "A2AService/Status"
}

<#
.SYNOPSIS
Enable the A2A service on this Safeguard appliance via the Web API.

.DESCRIPTION
By default the A2A service is not running on a Safeguard appliance.  It must be enabled
on the desired appliances in order to begin using any A2A registration configured in the
cluster.  This cmdlet enables the A2A service on this appliance.

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
Enable-SafeguardA2aService -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Enable-SafeguardA2aService
#>
function Enable-SafeguardA2aService
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

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance POST "A2AService/Enable"
}

<#
.SYNOPSIS
Disable the A2A service on this Safeguard appliance via the Web API.

.DESCRIPTION
By default the A2A service is not running on a Safeguard appliance.  It must be enabled
on the desired appliances in order to begin using any A2A registration configured in the
cluster.  This cmdlet disables the A2A service on this appliance.

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
Disable-SafeguardA2aService -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Disable-SafeguardA2aService
#>
function Disable-SafeguardA2aService
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

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance POST "A2AService/Disable"
}

<#
.SYNOPSIS
Get A2A registrations managed by Safeguard via the Web API.

.DESCRIPTION
Get the A2A registrations that have been added to Safeguard.  Accounts for
credential retrieval and an access request broker can be added to A2A registrations.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER A2aToGet
An integer containing the ID of the A2A registration to get or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardA2a -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardA2a "Ticket System"
#>
function Get-SafeguardA2a
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
        [object]$A2aToGet
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSBoundParameters.ContainsKey("A2aToGet"))
    {
        $local:A2aId = (Resolve-SafeguardA2aId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $A2aToGet)
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "A2ARegistrations/$($local:A2aId)"
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "A2ARegistrations"
    }
}

<#
.SYNOPSIS
Create new A2A registration in Safeguard via the Web API.

.DESCRIPTION
Create a new A2A registration in Safeguard that can be used to retrieve credentials
and an access request broker.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Name
A string containing the display name for this A2A registration.

.PARAMETER Description
A string containing a description for this A2A registration.

.PARAMETER CertificateUser
An integer containing the ID of the certificate user or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
New-SafeguardA2a -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
New-SafeguardA2a "Ticket System" TicketSystemUser -Description "Ticket System Requester"
#>
function New-SafeguardA2a
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
        [Parameter(Mandatory=$true,Position=1)]
        [object]$CertificateUser,
        [Parameter(Mandatory=$false)]
        [string]$Description
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Import-Module -Name "$PSScriptRoot\users.psm1" -Scope Local
    $local:UserId = (Resolve-SafeguardUserId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $CertificateUser)

    $local:Body = @{
        "CertificateUserId" = $local:UserId;
        "AppName" = $Name;
    }

    if ($PSBoundParameters.ContainsKey("Description")) { $local:Body.Description = $Description }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "A2ARegistrations" -Body $local:Body
}

<#
.SYNOPSIS
Remove an A2A registration from Safeguard via the Web API.

.DESCRIPTION
Remove an A2A registration from Safeguard. Make sure it is not in use before
you remove it.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER A2aToDelete
An integer containing the ID of the A2A registration to remove or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardA2a -AccessToken $token -Appliance 10.5.32.54 -Insecure 5

.EXAMPLE
Remove-SafeguardA2a "Ticket System"
#>
function Remove-SafeguardA2a
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
        [object]$A2aToDelete
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $PSBoundParameters.ContainsKey("A2aToDelete"))
    {
        $A2aToDelete = (Read-Host "A2aToDelete")
    }

    $local:A2aId = (Resolve-SafeguardA2aId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $A2aToDelete)
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "A2ARegistrations/$A2aId"
}

<#
.SYNOPSIS
Edit existing A2A registration in Safeguard via the Web API.

.DESCRIPTION
Edit an existing A2A registration in Safeguard that can be used to retrieve credentials
and an access request broker.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER A2aObject
An object containing the existing A2A registration with desired properties set.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Edit-SafeguardA2a -AccessToken $token -Appliance 10.5.32.54 -Insecure -A2aObject $obj
#>
function Edit-SafeguardA2a
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(ParameterSetName="Object",Mandatory=$true,Position=0,ValueFromPipeline=$true)]
        [object]$A2aObject
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    
    if (-not $A2aObject)
    {
        throw "A2aObject must not be null"
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
        Core PUT "A2ARegistrations/$($A2aObject.Id)" -Body $A2aObject
}

<#
.SYNOPSIS
Get configuration of credential retrieval for an account from an A2A registration in Safeguard
via the Web API.

.DESCRIPTION
Get all or one of the accounts configured for credential retrieval in an A2A registrations that have 
been added to Safeguard.  Accounts for credential retrieval are given API keys and may be configured
with IP address restrictions.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER ParentA2a
An integer containing the ID of the A2A registration to get or a string containing the name.

.PARAMETER AccountObj
An object representing the account to get the credential retrieval configuration for.

.PARAMETER System
An integer containing the ID of the system or a string containing the name.

.PARAMETER Account
An integer containing the ID of the account or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardA2aCredentialRetrieval -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardA2aCredentialRetrieval "Ticket System" linux.test.machine root
#>
function Get-SafeguardA2aCredentialRetrieval
{
    [CmdletBinding(DefaultParameterSetName="None")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$ParentA2a,
        [Parameter(ParameterSetName="Names",Mandatory=$false,Position=1)]
        [object]$System,
        [Parameter(ParameterSetName="Names",Mandatory=$true,Position=2)]
        [object]$Account,
        [Parameter(ParameterSetName="Object",Mandatory=$true)]
        [object]$AccountObj
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:A2aId = (Resolve-SafeguardA2aId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $ParentA2a)

    if ($PsCmdlet.ParameterSetName -eq "None")
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
            Core GET "A2ARegistrations/$($local:A2aId)/RetrievableAccounts"
    }
    else
    {
        if ($PsCmdlet.ParameterSetName -eq "Object")
        {
            if (-not $AccountObj)
            {
                throw "AccountObj must not be null"
            }
            if ($AccountObj.AccountId) { $local:AccountId = $AccountObj.AccountId }
            else { $local:AccountId = $AccountObj.Id }
        }
        else
        {
            $local:AccountId = (Resolve-SafeguardA2aAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                $local:A2aId $Account -System $System)
        }

        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                Core GET "A2ARegistrations/$($local:A2aId)/RetrievableAccounts/$($local:AccountId)"
    }
}

<#
.SYNOPSIS
Add configuration of account credential retrieval to an A2A registration in Safeguard
via the Web API.

.DESCRIPTION
Add an account credential retrieval to an A2A registration that has been added to Safeguard.
Accounts for credential retrieval are given API keys and may be configured with IP address 
restrictions.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER ParentA2a
An integer containing the ID of the A2A registration to get or a string containing the name.

.PARAMETER AccountObj
An object representing the account to get the credential retrieval configuration for.

.PARAMETER System
An integer containing the ID of the system or a string containing the name.

.PARAMETER Account
An integer containing the ID of the account or a string containing the name.

.PARAMETER IpRestrictions
A list of strings containing IP address that may use this credential retrieval configuration.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Add-SafeguardA2aCredentialRetrieval -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Add-SafeguardA2aCredentialRetrieval "Ticket System" linux.test.machine root -IpRestrictions "10.5.5.32","10.5.5.33"
#>
function Add-SafeguardA2aCredentialRetrieval
{
    [CmdletBinding(DefaultParameterSetName="Names")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$ParentA2a,
        [Parameter(ParameterSetName="Names",Mandatory=$false,Position=1)]
        [object]$System,
        [Parameter(ParameterSetName="Names",Mandatory=$true,Position=2)]
        [object]$Account,
        [Parameter(ParameterSetName="Object",Mandatory=$true)]
        [object]$AccountObj,
        [Parameter(Mandatory=$false)]
        [string[]]$IpRestrictions
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PsCmdlet.ParameterSetName -eq "Object" -and -not $AccountObj)
    {
        throw "AccountObj must not be null"
    }

    if ($IpRestrictions)
    {
        Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local
        $IpRestrictions | ForEach-Object {
            if (-not (Test-IpAddress $_))
            {
                throw "IP restriction '$_' is not an IP address"
            }
        }
    }

    $local:A2aId = (Resolve-SafeguardA2aId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $ParentA2a)

    $local:Body = @{}
    if ($PsCmdlet.ParameterSetName -eq "Object")
    {
        $local:Body.AccountId = $AccountObj.Id
        $local:Body.SystemId = $AccountObj.SystemId
    }
    else
    {
        Import-Module -Name "$PSScriptRoot\sg-utilities.psm1" -Scope Local
        if ($System)
        {
            $local:Body.SystemId = (Resolve-SafeguardSystemId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure $System)
            $local:Body.AccountId = (Resolve-SafeguardAccountIdWithSystemId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                $local:Body.SystemId $Account)
        }
        else
        {
            Import-Module -Name "$PSScriptRoot\assets.psm1" -Scope Local
            $local:Body.AccountId = (Resolve-SafeguardAccountIdWithoutSystemId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure $Account)
        }
    }

    if ($IpRestrictions)
    {
        $local:Body.IpRestrictions = $IpRestrictions 
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
        Core POST "A2ARegistrations/$($local:A2aId)/RetrievableAccounts" -Body $local:Body
}

<#
.SYNOPSIS
Remove configuration of an account credential retrieval from an A2A registration in Safeguard
via the Web API.

.DESCRIPTION
Remove an account credential retrieval from an A2A registration that has been added to Safeguard.
Accounts for credential retrieval are given API keys and may be configured with IP address 
restrictions.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER ParentA2a
An integer containing the ID of the A2A registration to get or a string containing the name.

.PARAMETER AccountObj
An object representing the account to get the credential retrieval configuration for.

.PARAMETER System
An integer containing the ID of the system or a string containing the name.

.PARAMETER Account
An integer containing the ID of the account or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardA2aCredentialRetrieval -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Remove-SafeguardA2aCredentialRetrieval "Ticket System" linux.test.machine root
#>
function Remove-SafeguardA2aCredentialRetrieval
{
    [CmdletBinding(DefaultParameterSetName="Names")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$ParentA2a,
        [Parameter(ParameterSetName="Names",Mandatory=$false,Position=1)]
        [object]$System,
        [Parameter(ParameterSetName="Names",Mandatory=$true,Position=2)]
        [object]$Account,
        [Parameter(ParameterSetName="Object",Mandatory=$true)]
        [object]$AccountObj
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PsCmdlet.ParameterSetName -eq "Object" -and -not $AccountObj)
    {
        throw "AccountObj must not be null"
    }

    $local:A2aId = (Resolve-SafeguardA2aId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $ParentA2a)
    if ($PsCmdlet.ParameterSetName -eq "Object")
    {
        if ($AccountObj.AccountId) { $local:AccountId = $AccountObj.AccountId }
        else { $local:AccountId = $AccountObj.Id }
    }
    else
    {
        $local:AccountId = (Resolve-SafeguardA2aAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
            $local:A2aId $Account -System $System)
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
            Core DELETE "A2ARegistrations/$($local:A2aId)/RetrievableAccounts/$($local:AccountId)"
}

<#
.SYNOPSIS
Get the IP address restrictions from an account credential retrieval from an A2A registration in Safeguard
via the Web API.

.DESCRIPTION
Get the IP addresses that are whitelisted for calling an account credential retrieval of an A2A registration
that has been added to Safeguard.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER ParentA2a
An integer containing the ID of the A2A registration to get or a string containing the name.

.PARAMETER AccountObj
An object representing the account to get the credential retrieval configuration for.

.PARAMETER System
An integer containing the ID of the system or a string containing the name.

.PARAMETER Account
An integer containing the ID of the account or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardA2aCredentialRetrievalIpRestriction -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardA2aCredentialRetrievalIpRestriction "Ticket System" linux.test.machine root
#>
function Get-SafeguardA2aCredentialRetrievalIpRestriction
{
    [CmdletBinding(DefaultParameterSetName="Names")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$ParentA2a,
        [Parameter(ParameterSetName="Names",Mandatory=$false,Position=1)]
        [object]$System,
        [Parameter(ParameterSetName="Names",Mandatory=$true,Position=2)]
        [object]$Account,
        [Parameter(ParameterSetName="Object",Mandatory=$true)]
        [object]$AccountObj
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:A2aId = (Resolve-SafeguardA2aId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $ParentA2a)
    if ($PsCmdlet.ParameterSetName -eq "Object")
    {
        if (-not $AccountObj)
        {
            throw "AccountObj must not be null"
        }
        (Get-SafeguardA2aCredentialRetrieval -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
            $local:A2aId -AccountObj $AccountObj).IpRestrictions
    }
    else
    {
        (Get-SafeguardA2aCredentialRetrieval -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
            $local:A2aId $System $Account).IpRestrictions
    }
}

<#
.SYNOPSIS
Set the IP address restrictions for an account credential retrieval for an A2A registration in Safeguard
via the Web API.

.DESCRIPTION
Set the IP addresses that are whitelisted for calling an account credential retrieval of an A2A registration
that has been added to Safeguard.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER ParentA2a
An integer containing the ID of the A2A registration to get or a string containing the name.

.PARAMETER AccountObj
An object representing the account to get the credential retrieval configuration for.

.PARAMETER System
An integer containing the ID of the system or a string containing the name.

.PARAMETER Account
An integer containing the ID of the account or a string containing the name.

.PARAMETER IpRestrictions
A list of strings containing IP address that may use this credential retrieval configuration.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Set-SafeguardA2aCredentialRetrievalIpRestriction -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Set-SafeguardA2aCredentialRetrievalIpRestriction "Ticket System" linux.test.machine root -IpRestrictions "10.0.0.11","10.0.0.12"
#>
function Set-SafeguardA2aCredentialRetrievalIpRestriction
{
    [CmdletBinding(DefaultParameterSetName="Names")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$ParentA2a,
        [Parameter(ParameterSetName="Names",Mandatory=$false,Position=1)]
        [object]$System,
        [Parameter(ParameterSetName="Names",Mandatory=$true,Position=2)]
        [object]$Account,
        [Parameter(ParameterSetName="Object",Mandatory=$true)]
        [object]$AccountObj,
        [Parameter(Mandatory=$true)]
        [string[]]$IpRestrictions
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $IpRestrictions)
    {
        throw "IpRestrictions cannot be null"
    }

    Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local
    $IpRestrictions | ForEach-Object {
        if (-not (Test-IpAddress $_))
        {
            throw "IP restriction '$_' is not an IP address"
        }
    }

    $local:A2aId = (Resolve-SafeguardA2aId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $ParentA2a)
    if ($PsCmdlet.ParameterSetName -eq "Object")
    {
        if (-not $AccountObj)
        {
            throw "AccountObj must not be null"
        }
        $local:A2aCr = (Get-SafeguardA2aCredentialRetrieval -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                            $local:A2aId -AccountObj $AccountObj)
    }
    else
    {
        $local:A2aCr = (Get-SafeguardA2aCredentialRetrieval -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                            $local:A2aId $System $Account)
    }

    $local:A2aCr.IpRestrictions = $IpRestrictions

    (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
        Core PUT "A2ARegistrations/$($local:A2aId)/RetrievableAccounts/$($local:A2aCr.AccountId)" -Body $local:A2aCr).IpRestrictions
}

<#
.SYNOPSIS
Remove all the IP address restrictions for an account credential retrieval for an A2A registration in Safeguard
via the Web API.

.DESCRIPTION
Remove all the IP addresses that are whitelisted for calling an account credential retrieval of an A2A registration
that has been added to Safeguard.  This means it can be called from anywhere.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER ParentA2a
An integer containing the ID of the A2A registration to get or a string containing the name.

.PARAMETER AccountObj
An object representing the account to get the credential retrieval configuration for.

.PARAMETER System
An integer containing the ID of the system or a string containing the name.

.PARAMETER Account
An integer containing the ID of the account or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Clear-SafeguardA2aCredentialRetrievalIpRestriction -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Clear-SafeguardA2aCredentialRetrievalIpRestriction "Ticket System" linux.test.machine root
#>
function Clear-SafeguardA2aCredentialRetrievalIpRestriction
{
    [CmdletBinding(DefaultParameterSetName="Names")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$ParentA2a,
        [Parameter(ParameterSetName="Names",Mandatory=$false,Position=1)]
        [object]$System,
        [Parameter(ParameterSetName="Names",Mandatory=$true,Position=2)]
        [object]$Account,
        [Parameter(ParameterSetName="Object",Mandatory=$true)]
        [object]$AccountObj
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:A2aId = (Resolve-SafeguardA2aId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $ParentA2a)
    if ($PsCmdlet.ParameterSetName -eq "Object")
    {
        if (-not $AccountObj)
        {
            throw "AccountObj must not be null"
        }
        $local:A2aCr = (Get-SafeguardA2aCredentialRetrieval -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                            $local:A2aId -AccountObj $AccountObj)
    }
    else
    {
        $local:A2aCr = (Get-SafeguardA2aCredentialRetrieval -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                            $local:A2aId $System $Account)
    }

    $local:A2aCr.IpRestrictions = $null

    (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
        Core PUT "A2ARegistrations/$($local:A2aId)/RetrievableAccounts/$($local:A2aCr.AccountId)" -Body $local:A2aCr).IpRestrictions
}

<#
.SYNOPSIS
Regenerate the API key for an account credential retrieval for an A2A registration in Safeguard
via the Web API.

.DESCRIPTION
Ask Safeguard to regenerate the API key used for calling an account credential retrieval of an A2A registration
that has been added to Safeguard.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER ParentA2a
An integer containing the ID of the A2A registration to get or a string containing the name.

.PARAMETER AccountObj
An object representing the account to get the credential retrieval configuration for.

.PARAMETER System
An integer containing the ID of the system or a string containing the name.

.PARAMETER Account
An integer containing the ID of the account or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Reset-SafeguardA2aCredentialRetrievalApiKey "Ticket System" linux.test.machine root
#>
function Reset-SafeguardA2aCredentialRetrievalApiKey
{
    [CmdletBinding(DefaultParameterSetName="Names")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$ParentA2a,
        [Parameter(ParameterSetName="Names",Mandatory=$false,Position=1)]
        [object]$System,
        [Parameter(ParameterSetName="Names",Mandatory=$true,Position=2)]
        [object]$Account,
        [Parameter(ParameterSetName="Object",Mandatory=$true)]
        [object]$AccountObj
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PsCmdlet.ParameterSetName -eq "Object" -and -not $AccountObj)
    {
        throw "AccountObj must not be null"
    }

    $local:A2aId = (Resolve-SafeguardA2aId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $ParentA2a)
    if ($PsCmdlet.ParameterSetName -eq "Object")
    {
        if ($AccountObj.AccountId) { $local:AccountId = $AccountObj.AccountId }
        else { $local:AccountId = $AccountObj.Id }
    }
    else
    {
        $local:AccountId = (Resolve-SafeguardA2aAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
            $local:A2aId $Account -System $System)
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
            Core POST "A2ARegistrations/$($local:A2aId)/RetrievableAccounts/$($local:AccountId)/ApiKey"
}

<#
.SYNOPSIS
Get the API key used for requesting an account credential retrieval configured in an A2A registration in Safeguard
via the Web API.

.DESCRIPTION
Ask Safeguard for the API key used for calling an account credential retrieval of an A2A registration
that has been added to Safeguard.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER ParentA2a
An integer containing the ID of the A2A registration to get or a string containing the name.

.PARAMETER AccountObj
An object representing the account to get the credential retrieval configuration for.

.PARAMETER System
An integer containing the ID of the system or a string containing the name.

.PARAMETER Account
An integer containing the ID of the account or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardA2aCredentialRetrievalApiKey "Ticket System" linux.test.machine root
#>
function Get-SafeguardA2aCredentialRetrievalApiKey
{
    [CmdletBinding(DefaultParameterSetName="Names")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$ParentA2a,
        [Parameter(ParameterSetName="Names",Mandatory=$false,Position=1)]
        [object]$System,
        [Parameter(ParameterSetName="Names",Mandatory=$true,Position=2)]
        [object]$Account,
        [Parameter(ParameterSetName="Object",Mandatory=$true)]
        [object]$AccountObj
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PsCmdlet.ParameterSetName -eq "Object" -and -not $AccountObj)
    {
        throw "AccountObj must not be null"
    }

    $local:A2aId = (Resolve-SafeguardA2aId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $ParentA2a)
    if ($PsCmdlet.ParameterSetName -eq "Object")
    {
        if ($AccountObj.AccountId) { $local:AccountId = $AccountObj.AccountId }
        else { $local:AccountId = $AccountObj.Id }
    }
    else
    {
        $local:AccountId = (Resolve-SafeguardA2aAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
            $local:A2aId $Account -System $System)
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
            Core GET "A2ARegistrations/$($local:A2aId)/RetrievableAccounts/$($local:AccountId)/ApiKey"
}

<#
.SYNOPSIS
Get summary information of A2A registrations in Safeguard via the Web API.

.DESCRIPTION
Get summary information of A2A registrations in Safeguard to make it easier to call
Safeguard A2A with the appropriate parameters.

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
Get-SafeguardA2aCredentialRetrievalInformation

.EXAMPLE
Get-SafeguardA2aCredentialRetrievalInformation linux.test.machine root
#>
function Get-SafeguardA2aCredentialRetrievalInformation
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false, Position = 0)]
        [string]$AssetName,
        [Parameter(Mandatory=$false, Position = 1)]
        [string]$AccountName,
        [Parameter(Mandatory=$false, Position = 2)]
        [string]$DomainName
    )

    $local:Infos = ((Get-SafeguardA2a -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure) | ForEach-Object {
        $local:A2a = $_
        (Get-SafeguardA2aCredentialRetrieval -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -ParentA2a $local:A2a.Id) | ForEach-Object {
            $local:Hash = [ordered]@{
                AppName = $local:A2a.AppName;
                Description = $local:A2a.Description;
                CertificateUserThumbPrint = $local:A2a.CertificateUserThumbPrint;
                ApiKey = $_.ApiKey;
                AssetName = $_.SystemName;
                AccountName = $_.AccountName;
                DomainName = $_.DomainName;
            }
            New-Object PSObject -Property $local:Hash
        }
    })
    if ($AssetName) { $local:Infos = ($local:Infos | Where-Object { $_.AssetName -ieq $AssetName }) }
    if ($AccountName) { $local:Infos = ($local:Infos | Where-Object { $_.AccountName -ieq $AccountName }) }
    if ($DomainName) { $local:Infos = ($local:Infos | Where-Object { $_.DomainName -ieq $DomainName }) }
    $local:Infos
}

<#
.SYNOPSIS
Get the configuration used for brokering access requests to an A2A registration in Safeguard
via the Web API.

.DESCRIPTION
Get an access request broker from an A2A registration that has been added to Safeguard.
There may be only one access request broker per A2A registration.  An access request broker
is given an API  and may be configured with IP address restrictions.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER ParentA2a
An integer containing the ID of the A2A registration to get or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardA2aAccessRequestBroker "Ticket System"
#>
function Get-SafeguardA2aAccessRequestBroker
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
        [object]$ParentA2a
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:A2aId = (Resolve-SafeguardA2aId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $ParentA2a)

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
        Core GET "A2ARegistrations/$($local:A2aId)/AccessRequestBroker"
}

<#
.SYNOPSIS
Add the configuration used for brokering access requests to an A2A registration in Safeguard
via the Web API.

.DESCRIPTION
Add an access request broker to an A2A registration that has been added to Safeguard.
There may be only one access request broker per A2A registration.  An access request broker
is given an API  and may be configured with IP address restrictions.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER ParentA2a
An integer containing the ID of the A2A registration to get or a string containing the name.

.PARAMETER Users
An array of integers containing user IDs or an array of strings containing user names.

.PARAMETER Groups
An array of integers containing user group IDs or an array of strings containing user group names.

.PARAMETER IpRestrictions
A list of strings containing IP address that may use this access request broker configuration.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Set-SafeguardA2aAccessRequestBroker "Ticket System" -Users BlueBoy,GreenMan

.EXAMPLE
Set-SafeguardA2aAccessRequestBroker "Ticket System" -Groups "My Admins",YourAdmins

.EXAMPLE
Set-SafeguardA2aAccessRequestBroker "Ticket System" -Users BlueBoy,GreenMan -Groups "My Admins",YourAdmins
#>
function Set-SafeguardA2aAccessRequestBroker
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
        [object]$ParentA2a,
        [Parameter(Mandatory=$false)]
        [object[]]$Users,
        [Parameter(Mandatory=$false)]
        [object[]]$Groups,
        [Parameter(Mandatory=$false)]
        [string[]]$IpRestrictions
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ((-not $Users) -and (-not $Groups))
    {
        throw "You must specify either Users or Groups or both"
    }

    $local:A2aId = (Resolve-SafeguardA2aId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $ParentA2a)
    $local:Body = @{}

    if ($Users)
    {
        Import-Module -Name "$PSScriptRoot\users.psm1" -Scope Local
        $local:Body.Users = @()
        $Users | ForEach-Object {
            $local:UserId = (Resolve-SafeguardUserId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $_)
            $local:Body.Users += @{ UserId = $local:UserId }
        }
    }

    if ($Groups)
    {
        Import-Module -Name "$PSScriptRoot\groups.psm1" -Scope Local
        $local:Body.Groups = @()
        $Groups | ForEach-Object {
            $local:GroupId = (Resolve-SafeguardGroupId  -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure User $_)
            $local:Body.Groups += @{ GroupId = $local:GroupId }
        }
    }

    if ($IpRestrictions)
    {
        Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local
        $IpRestrictions | ForEach-Object {
            if (-not (Test-IpAddress $_))
            {
                throw "IP restriction '$_' is not an IP address"
            }
        }
        $local:Body.IpRestrictions = $IpRestrictions
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
        Core PUT "A2ARegistrations/$($local:A2aId)/AccessRequestBroker" -Body $local:Body
}

<#
.SYNOPSIS
Remove the configuration used for brokering access requests from an A2A registration in Safeguard
via the Web API.

.DESCRIPTION
Remove an access request broker from an A2A registration that has been added to Safeguard.
There may be only one access request broker per A2A registration.  An access request broker
is given an API  and may be configured with IP address restrictions.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER ParentA2a
An integer containing the ID of the A2A registration to get or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Clear-SafeguardA2aAccessRequestBroker "Ticket System"
#>
function Clear-SafeguardA2aAccessRequestBroker
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
        [object]$ParentA2a
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:A2aId = (Resolve-SafeguardA2aId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $ParentA2a)

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
        Core DELETE "A2ARegistrations/$($local:A2aId)/AccessRequestBroker"
}

<#
.SYNOPSIS
Get the IP address restrictions for an access request broker for an A2A registration in Safeguard
via the Web API.

.DESCRIPTION
Get the IP addresses that are whitelisted for calling the access request broker of an A2A registration
that has been added to Safeguard.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER ParentA2a
An integer containing the ID of the A2A registration to get or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardA2aAccessRequestBrokerIpRestriction "Ticket System"
#>
function Get-SafeguardA2aAccessRequestBrokerIpRestriction
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
        [object]$ParentA2a
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    (Get-SafeguardA2aAccessRequestBroker -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $ParentA2a).IpRestrictions
}

<#
.SYNOPSIS
Set the IP address restrictions for an access request broker for an A2A registration in Safeguard
via the Web API.

.DESCRIPTION
Set the IP addresses that are whitelisted for calling the access request broker of an A2A registration
that has been added to Safeguard.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER ParentA2a
An integer containing the ID of the A2A registration to get or a string containing the name.

.PARAMETER IpRestrictions
A list of strings containing IP address that may use this access request broker configuration.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Set-SafeguardA2aAccessRequestBrokerIpRestriction "Ticket System" -IpRestrictions "10.0.0.11","10.0.0.12"
#>
function Set-SafeguardA2aAccessRequestBrokerIpRestriction
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
        [object]$ParentA2a,
        [Parameter(Mandatory=$true)]
        [string[]]$IpRestrictions
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $IpRestrictions)
    {
        throw "IpRestrictions cannot be null"
    }

    Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local
    $IpRestrictions | ForEach-Object {
        if (-not (Test-IpAddress $_))
        {
            throw "IP restriction '$_' is not an IP address"
        }
    }

    $local:A2aId = (Resolve-SafeguardA2aId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $ParentA2a)
    $local:A2aBroker = (Get-SafeguardA2aAccessRequestBroker -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $local:A2aId)

    $local:A2aBroker.IpRestrictions = $IpRestrictions

    (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
        Core PUT "A2ARegistrations/$($local:A2aId)/AccessRequestBroker" -Body $local:A2aBroker).IpRestrictions
}

<#
.SYNOPSIS
Remove all the IP address restrictions for an access request broker for an A2A registration in Safeguard
via the Web API.

.DESCRIPTION
Remove all the IP addresses that are whitelisted for calling the access request broker of an A2A registration
that has been added to Safeguard.  This means it can be called from anywhere.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER ParentA2a
An integer containing the ID of the A2A registration to get or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Clear-SafeguardA2aAccessRequestBrokerIpRestriction "Ticket System"
#>
function Clear-SafeguardA2aAccessRequestBrokerIpRestriction
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
        [object]$ParentA2a
    )

    $local:A2aId = (Resolve-SafeguardA2aId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $ParentA2a)
    $local:A2aBroker = (Get-SafeguardA2aAccessRequestBroker -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $local:A2aId)

    $local:A2aBroker.IpRestrictions = $null

    (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
        Core PUT "A2ARegistrations/$($local:A2aId)/AccessRequestBroker" -Body $local:A2aBroker).IpRestrictions
}

<#
.SYNOPSIS
Regenerate the API key used for brokering access requests using an A2A registration in Safeguard
via the Web API.

.DESCRIPTION
Ask Safeguard to regenerate the API key used for calling the A2A service for creating an access request
on behalf of another user.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER ParentA2a
An integer containing the ID of the A2A registration to get or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Reset-SafeguardA2aAccessRequestBrokerApiKey "Ticket System"
#>
function Reset-SafeguardA2aAccessRequestBrokerApiKey
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
        [object]$ParentA2a
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:A2aId = (Resolve-SafeguardA2aId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $ParentA2a)

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
        Core POST "A2ARegistrations/$($local:A2aId)/AccessRequestBroker/ApiKey"
}

<#
.SYNOPSIS
Get the API key used for brokering access requests using an A2A registration in Safeguard
via the Web API.

.DESCRIPTION
Ask Safeguard for the API key used for calling the A2A service for creating an access request
on behalf of another user.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER ParentA2a
An integer containing the ID of the A2A registration to get or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardA2aAccessRequestBrokerApiKey "Ticket System"
#>
function Get-SafeguardA2aAccessRequestBrokerApiKey
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
        [object]$ParentA2a
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:A2aId = (Resolve-SafeguardA2aId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $ParentA2a)

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
        Core GET "A2ARegistrations/$($local:A2aId)/AccessRequestBroker/ApiKey"
}
