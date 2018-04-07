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
        if ($PSBoundParameters.ContainsKey("System"))
        {
            $local:Filter += "and SystemName ieq '$System'"
        }
        try
        {
            $local:Accounts = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                                    Core GET "A2ARegistrations/$A2aId/Accounts" -Parameters @{ filter = $local:Filter })
        }
        catch
        {
            Write-Verbose $_
            Write-Verbose "Caught exception with ieq filter, trying with q parameter"
            $local:Accounts = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                                    Core GET "A2ARegistrations/$A2aId/Accounts" -Parameters @{ q = $Account })
        }
        if (-not $local:Accounts)
        {
            throw "Unable to find a3a account matching '$Account'"
        }
        if ($local:Accounts.Count -ne 1)
        {
            throw "Found $($local:Accounts.Count) a2a accounts matching '$Account'"
        }
        $local:Accounts[0].Id
    }
    else
    {
        $Account
    }
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
        [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true)]
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
        [Parameter(ParameterSetName="Object",Mandatory=$true,Position=1)]
        [object]$AccountObj,
        [Parameter(ParameterSetName="Names",Mandatory=$false,Position=1)]
        [object]$System,
        [Parameter(ParameterSetName="Names",Mandatory=$true,Position=2)]
        [object]$Account
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:A2aId = (Resolve-SafeguardA2aId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $ParentA2a)

    if ($PsCmdlet.ParameterSetName -eq "None")
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
            Core GET "A2ARegistrations/$($local:A2aId)/Accounts"
    }
    else
    {
        if ($PsCmdlet.ParameterSetName -eq "Object")
        {
            if (not $AccountObj)
            {
                throw "AccountObj must not be null"
            }
            if ($AccountObj.AccountId) { $local:AccountId = $AccountObj.AccountId }
            else { $local:AccountId = $AccountObj.Id }
        }
        else
        {
            $local:AccountId = (Resolve-SafeguardA2aAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                $ParentA2a $Account -System $System)
        }

        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                Core GET "A2ARegistrations/$($local:A2aId)/Accounts/$($local:AccountId)"
    }
}

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
        [Parameter(ParameterSetName="Object",Mandatory=$true,Position=1)]
        [object]$AccountObj,
        [Parameter(ParameterSetName="Names",Mandatory=$false,Position=1)]
        [object]$System,
        [Parameter(ParameterSetName="Names",Mandatory=$true,Position=2)]
        [object]$Account,
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
        Core POST "A2ARegistrations/$($local:A2aId)/Accounts" -Body @($local:Body)
}

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
        [Parameter(ParameterSetName="Object",Mandatory=$true,Position=1)]
        [object]$AccountObj,
        [Parameter(ParameterSetName="Names",Mandatory=$false,Position=1)]
        [object]$System,
        [Parameter(ParameterSetName="Names",Mandatory=$true,Position=2)]
        [object]$Account
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
            $ParentA2a $Account -System $System)
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
            Core DELETE "A2ARegistrations/$($local:A2aId)/Accounts/$($local:AccountId)"
}

function Get-SafeguardA2aCredentialRetrievalIpRestrictions
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
        [Parameter(ParameterSetName="Object",Mandatory=$true,Position=1)]
        [object]$AccountObj,
        [Parameter(ParameterSetName="Names",Mandatory=$false,Position=1)]
        [object]$System,
        [Parameter(ParameterSetName="Names",Mandatory=$true,Position=2)]
        [object]$Account
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:A2aId = (Resolve-SafeguardA2aId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $ParentA2a)
    if ($PsCmdlet.ParameterSetName -eq "Object")
    {
        if (not $AccountObj)
        {
            throw "AccountObj must not be null"
        }
        (Get-SafeguardA2aCredentialRetrieval -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
            $local:A2aId -AccountObj $AccountObj).IpRestrictions
    }
    else
    {
        (Get-SafeguardA2aCredentialRetrieval -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
            $local:A2aId -AccountObj $AccountObj).IpRestrictions
    }
}

function Set-SafeguardA2aCredentialRetrievalIpRestrictions
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
        [Parameter(ParameterSetName="Object",Mandatory=$true,Position=1)]
        [object]$AccountObj,
        [Parameter(ParameterSetName="Names",Mandatory=$false,Position=1)]
        [object]$System,
        [Parameter(ParameterSetName="Names",Mandatory=$true,Position=2)]
        [object]$Account,
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

    if ($PsCmdlet.ParameterSetName -eq "Object")
    {
        if (not $AccountObj)
        {
            throw "AccountObj must not be null"
        }
        $local:A2aCr = (Get-SafeguardA2aCredentialRetrieval -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                            $local:A2aId -AccountObj $AccountObj)
    }
    else
    {
        $local:A2aCr = (Get-SafeguardA2aCredentialRetrieval -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                            $local:A2aId -AccountObj $AccountObj).IpRestrictions
    }

    $local:A2aCr.IpRestrictions = $IpRestrictions

    (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
        Core PUT "A2ARegistrations/$($local:A2aId)/Accounts/$($local:AccountId)" -Body $local:A2aCr).IpRestrictions
}

function Reset-SafeguardA2aCredentialRetrievalApiKey
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
        [Parameter(ParameterSetName="Object",Mandatory=$true,Position=1)]
        [object]$AccountObj,
        [Parameter(ParameterSetName="Names",Mandatory=$false,Position=1)]
        [object]$System,
        [Parameter(ParameterSetName="Names",Mandatory=$true,Position=2)]
        [object]$Account
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
            $ParentA2a $Account -System $System)
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
            Core POST "A2ARegistrations/$($local:A2aId)/Accounts/$($local:AccountId)/ApiKey"
}

function Get-SafeguardA2aCredentialRetrievalApiKey
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
        [Parameter(ParameterSetName="Object",Mandatory=$true,Position=1)]
        [object]$AccountObj,
        [Parameter(ParameterSetName="Names",Mandatory=$false,Position=1)]
        [object]$System,
        [Parameter(ParameterSetName="Names",Mandatory=$true,Position=2)]
        [object]$Account
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
            $ParentA2a $Account -System $System)
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
            Core GET "A2ARegistrations/$($local:A2aId)/Accounts/$($local:AccountId)/ApiKey"
}
