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

function Remove-SafeguardA2a
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

    
}

function Edit-SafeguardA2a
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

    
}

function Add-SafeguardA2aCredentialReleaseAccount
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

    
}

function Remove-SafeguardA2aCredentialReleaseAccount
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

    
}
