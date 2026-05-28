<# Copyright (c) 2026 One Identity LLC. All rights reserved. #>
# Helpers
function Resolve-SafeguardReasonCodeId
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
        [object]$ReasonCode
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($ReasonCode.Id -as [int])
    {
        $ReasonCode = $ReasonCode.Id
    }

    if (-not ($ReasonCode -as [int]))
    {
        try
        {
            $local:ReasonCodes = @(Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "ReasonCodes" `
                                 -Parameters @{ filter = "Name ieq '$ReasonCode'" })
        }
        catch
        {
            Write-Verbose $_
            Write-Verbose "Caught exception with ieq filter, trying with q parameter"
            $local:ReasonCodes = @(Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "ReasonCodes" `
                                 -Parameters @{ q = $ReasonCode })
        }
        if (-not $local:ReasonCodes)
        {
            throw "Unable to find reason code matching '$ReasonCode'"
        }
        if ($local:ReasonCodes.Count -ne 1)
        {
            throw "Found $($local:ReasonCodes.Count) reason codes matching '$ReasonCode'"
        }
        $local:ReasonCodes[0].Id
    }
    else
    {
        $ReasonCode
    }
}

<#
.SYNOPSIS
Get reason codes from Safeguard via the Web API.

.DESCRIPTION
Reason codes are used in access request workflows to require users to select
a reason when requesting privileged access. This cmdlet returns all reason
codes or a specific reason code by ID or name.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER ReasonCodeToGet
An integer containing the ID of the reason code to get or a string containing the name.

.PARAMETER Fields
An array of the property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardReasonCode -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardReasonCode "Maintenance Window"
#>
function Get-SafeguardReasonCode
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
        [object]$ReasonCodeToGet,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Parameters = $null
    if ($Fields)
    {
        $local:Parameters = @{ fields = ($Fields -join ",") }
    }

    if ($PSBoundParameters.ContainsKey("ReasonCodeToGet"))
    {
        $local:Id = (Resolve-SafeguardReasonCodeId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -ReasonCode $ReasonCodeToGet)
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "ReasonCodes/$($local:Id)" -Parameters $local:Parameters
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "ReasonCodes" -Parameters $local:Parameters
    }
}

<#
.SYNOPSIS
Search for a reason code in Safeguard via the Web API.

.DESCRIPTION
Search for reason codes by string query or by a filter. The search is
performed across name and description fields when using SearchString. Use
QueryFilter for SCIM-style server-side filtering.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER SearchString
A string to search for in the reason code name or description.

.PARAMETER QueryFilter
A string to pass to the -filter query parameter in the Safeguard Web API.

.PARAMETER Fields
An array of the property names to return.

.PARAMETER OrderBy
An array of the property names to order by.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Find-SafeguardReasonCode "maintenance"

.EXAMPLE
Find-SafeguardReasonCode -QueryFilter "Name contains 'emergency'"
#>
function Find-SafeguardReasonCode
{
    [CmdletBinding(DefaultParameterSetName="Search")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(ParameterSetName="Search",Mandatory=$true,Position=0)]
        [string]$SearchString,
        [Parameter(ParameterSetName="Filter",Mandatory=$true)]
        [string]$QueryFilter,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields,
        [Parameter(Mandatory=$false)]
        [string[]]$OrderBy
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Parameters = @{}
    if ($SearchString)
    {
        $local:Parameters["q"] = $SearchString
    }
    if ($QueryFilter)
    {
        $local:Parameters["filter"] = $QueryFilter
    }
    if ($Fields)
    {
        $local:Parameters["fields"] = ($Fields -join ",")
    }
    if ($OrderBy)
    {
        $local:Parameters["orderby"] = ($OrderBy -join ",")
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "ReasonCodes" -Parameters $local:Parameters
}

<#
.SYNOPSIS
Create a new reason code in Safeguard via the Web API.

.DESCRIPTION
Create a new reason code that can be assigned to access request policies.
Users will be required to select a reason code when requesting access via
those policies.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Name
A string containing the name of the reason code.

.PARAMETER Description
A string containing the description of the reason code.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
New-SafeguardReasonCode "Emergency Access" -Description "Unplanned emergency requiring immediate access"

.EXAMPLE
New-SafeguardReasonCode -Name "Maintenance Window" -Description "Scheduled maintenance window"
#>
function New-SafeguardReasonCode
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
        [Parameter(Mandatory=$false)]
        [string]$Description
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Body = @{
        Name = $Name
    }
    if ($PSBoundParameters.ContainsKey("Description"))
    {
        $local:Body.Description = $Description
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "ReasonCodes" -Body $local:Body
}

<#
.SYNOPSIS
Edit an existing reason code in Safeguard via the Web API.

.DESCRIPTION
Edit an existing reason code. Use Get-SafeguardReasonCode to retrieve the
object, modify its properties, and pass it to this cmdlet.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER ReasonCodeObject
An object containing the reason code with updated properties.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
$rc = Get-SafeguardReasonCode "Maintenance Window"
$rc.Description = "Updated description"
Edit-SafeguardReasonCode $rc

.EXAMPLE
Get-SafeguardReasonCode 5 | Edit-SafeguardReasonCode
#>
function Edit-SafeguardReasonCode
{
    [CmdletBinding(DefaultParameterSetName="Object")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(ParameterSetName="Object",Mandatory=$true,Position=0,ValueFromPipeline=$true)]
        [object]$ReasonCodeObject
    )

    begin
    {
        if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
        if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    }

    process
    {
        if (-not $ReasonCodeObject)
        {
            throw "ReasonCodeObject must not be null"
        }
        $local:Id = (Resolve-SafeguardReasonCodeId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -ReasonCode $ReasonCodeObject)
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "ReasonCodes/$($local:Id)" -Body $ReasonCodeObject
    }
}

<#
.SYNOPSIS
Remove a reason code from Safeguard via the Web API.

.DESCRIPTION
Remove a reason code from Safeguard. The reason code must not be assigned
to any access policies.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER ReasonCodeToDelete
An integer containing the ID of the reason code to remove or a string containing
the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardReasonCode "Maintenance Window"

.EXAMPLE
Remove-SafeguardReasonCode 5
#>
function Remove-SafeguardReasonCode
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
        [object]$ReasonCodeToDelete
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Id = (Resolve-SafeguardReasonCodeId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -ReasonCode $ReasonCodeToDelete)
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "ReasonCodes/$($local:Id)"
}

<#
.SYNOPSIS
Get the available reason code scopes from Safeguard via the Web API.

.DESCRIPTION
Reason code scopes define the contexts in which reason codes can be applied.
This cmdlet returns the list of available scopes that can be assigned to
reason codes (e.g., access requests, password releases, session requests).

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
Get-SafeguardReasonCodeScope -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardReasonCodeScope
#>
function Get-SafeguardReasonCodeScope
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

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "ReasonCodes/Scopes"
}
