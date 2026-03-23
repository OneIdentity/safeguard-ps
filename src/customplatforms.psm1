<# Copyright (c) 2026 One Identity LLC. All rights reserved. #>

<#
.SYNOPSIS
Get custom platform definitions from Safeguard via the Web API.

.DESCRIPTION
Get the custom platform definitions that have been created in Safeguard.
Custom platforms have PlatformFamily=Custom and are user-defined rather than
built-in. This cmdlet can return all custom platforms or a specific one by
ID or name.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER PlatformToGet
An integer containing the platform ID or a string containing the platform
display name of the custom platform to return.

.PARAMETER Fields
An array of the platform property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardCustomPlatform -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardCustomPlatform

.EXAMPLE
Get-SafeguardCustomPlatform "My Custom Platform"

.EXAMPLE
Get-SafeguardCustomPlatform 65536
#>
function Get-SafeguardCustomPlatform
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
        [object]$PlatformToGet,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Parameters = @{ filter = "PlatformFamily eq 'Custom'"; orderby = "Id" }
    if ($Fields)
    {
        $local:Parameters["fields"] = ($Fields -join ",")
    }

    if ($PSBoundParameters.ContainsKey("PlatformToGet"))
    {
        if ($PlatformToGet -as [int])
        {
            $local:Result = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                GET "Platforms/$($PlatformToGet -as [int])")
            if ($local:Result.PlatformFamily -ne "Custom")
            {
                throw "Platform '$PlatformToGet' is not a custom platform (PlatformFamily=$($local:Result.PlatformFamily))"
            }
            $local:Result
        }
        else
        {
            $local:Parameters["filter"] = "PlatformFamily eq 'Custom' and DisplayName icontains '$PlatformToGet'"
            $local:Results = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                GET Platforms -Parameters $local:Parameters)
            if (-not $local:Results)
            {
                throw "Unable to find custom platform matching '$PlatformToGet'"
            }
            if ($local:Results -is [array] -and $local:Results.Count -ne 1)
            {
                throw "Found $($local:Results.Count) custom platforms matching '$PlatformToGet'"
            }
            $local:Results
        }
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            GET Platforms -Parameters $local:Parameters
    }
}
