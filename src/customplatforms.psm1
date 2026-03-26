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

<#
.SYNOPSIS
Create a new custom platform in Safeguard via the Web API.

.DESCRIPTION
Create a new custom platform definition in Safeguard. Custom platforms have
PlatformFamily=Custom and PlatformType=Custom. Optionally upload a platform
script file at creation time.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Name
A string containing the name for the new custom platform.

.PARAMETER DisplayName
A string containing the display name for the new custom platform.
If not specified, defaults to the Name value.

.PARAMETER Description
A string containing the description for the new custom platform.

.PARAMETER ScriptFile
A string containing the path to a JSON platform script file to upload
after creating the platform. The script will be uploaded via the
Platforms/{id}/Script/Raw endpoint.

.PARAMETER AllowSessionRequests
When specified, enables session management (SupportsSessionManagement) on the
custom platform, allowing session access requests for assets using this platform.

.PARAMETER SshSessionPort
An integer containing the default SSH session port for the custom platform.
This is typically 22. Only meaningful when -AllowSessionRequests is also specified.

.PARAMETER RdpSessionPort
An integer containing the default Remote Desktop session port for the custom platform.
This is typically 3389.

.PARAMETER TelnetSessionPort
An integer containing the default Telnet session port for the custom platform.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
New-SafeguardCustomPlatform "My Custom Linux"

.EXAMPLE
New-SafeguardCustomPlatform -Name "My Custom Linux" -Description "Custom SSH platform" -ScriptFile "C:\scripts\MyScript.json"

.EXAMPLE
New-SafeguardCustomPlatform -Name "My Custom Linux" -AllowSessionRequests -SshSessionPort 22
#>
function New-SafeguardCustomPlatform
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
        [string]$DisplayName,
        [Parameter(Mandatory=$false)]
        [string]$Description,
        [Parameter(Mandatory=$false)]
        [string]$ScriptFile,
        [Parameter(Mandatory=$false)]
        [switch]$AllowSessionRequests,
        [Parameter(Mandatory=$false)]
        [int]$SshSessionPort,
        [Parameter(Mandatory=$false)]
        [int]$RdpSessionPort,
        [Parameter(Mandatory=$false)]
        [int]$TelnetSessionPort
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:DisplayNameValue = $Name
    if ($PSBoundParameters.ContainsKey("DisplayName")) { $local:DisplayNameValue = $DisplayName }
    $local:Body = @{
        Name = $Name;
        DisplayName = $local:DisplayNameValue;
        PlatformType = "Custom";
        PlatformFamily = "Custom"
    }
    if ($PSBoundParameters.ContainsKey("Description")) { $local:Body.Description = $Description }

    $local:Result = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                         POST Platforms -Body $local:Body)

    # Session and script settings require a PUT after creation
    $local:NeedsUpdate = $false
    if ($AllowSessionRequests)
    {
        $local:Result.SessionFeatureProperties.SupportsSessionManagement = $true
        $local:NeedsUpdate = $true
    }
    if ($PSBoundParameters.ContainsKey("SshSessionPort"))
    {
        $local:Result.SessionFeatureProperties.DefaultSshSessionPort = $SshSessionPort
        $local:NeedsUpdate = $true
    }
    if ($PSBoundParameters.ContainsKey("RdpSessionPort"))
    {
        $local:Result.SessionFeatureProperties.DefaultRemoteDesktopSessionPort = $RdpSessionPort
        $local:NeedsUpdate = $true
    }
    if ($PSBoundParameters.ContainsKey("TelnetSessionPort"))
    {
        $local:Result.SessionFeatureProperties.DefaultTelnetSessionPort = $TelnetSessionPort
        $local:NeedsUpdate = $true
    }
    if ($local:NeedsUpdate)
    {
        $local:Result = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                             PUT "Platforms/$($local:Result.Id)" -Body $local:Result)
    }

    if ($PSBoundParameters.ContainsKey("ScriptFile"))
    {
        if (-not (Test-Path $ScriptFile))
        {
            throw "Script file not found: $ScriptFile"
        }
        $local:ScriptContent = (Get-Content -Path $ScriptFile -Raw)
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            PUT "Platforms/$($local:Result.Id)/Script/Raw" -ContentType "application/octet-stream" -JsonBody $local:ScriptContent | Out-Null
        # Re-fetch to return updated platform with script info
        $local:Result = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                             GET "Platforms/$($local:Result.Id)")
    }

    $local:Result
}

<#
.SYNOPSIS
Edit an existing custom platform in Safeguard via the Web API.

.DESCRIPTION
Edit an existing custom platform definition in Safeguard. You can modify
individual properties or pipe a full platform object with modifications.
Optionally upload or replace the platform script file.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER PlatformToEdit
An integer containing the platform ID or a string containing the platform
display name of the custom platform to edit.

.PARAMETER Name
A string containing the new name for the custom platform.

.PARAMETER DisplayName
A string containing the new display name for the custom platform.

.PARAMETER Description
A string containing the new description for the custom platform.

.PARAMETER ScriptFile
A string containing the path to a JSON platform script file to upload,
replacing any existing script on the platform.

.PARAMETER AllowSessionRequests
When specified, enables session management (SupportsSessionManagement) on the
custom platform, allowing session access requests for assets using this platform.

.PARAMETER DenySessionRequests
When specified, disables session management (SupportsSessionManagement) on the
custom platform.

.PARAMETER SshSessionPort
An integer containing the default SSH session port for the custom platform.

.PARAMETER RdpSessionPort
An integer containing the default Remote Desktop session port for the custom platform.

.PARAMETER TelnetSessionPort
An integer containing the default Telnet session port for the custom platform.

.PARAMETER PlatformObject
An object containing the full custom platform object to PUT to the server.
This is typically obtained by piping Get-SafeguardCustomPlatform output.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Edit-SafeguardCustomPlatform 10001 -Description "Updated description"

.EXAMPLE
Edit-SafeguardCustomPlatform "My Custom Linux" -Name "Renamed Platform"

.EXAMPLE
Edit-SafeguardCustomPlatform 10001 -AllowSessionRequests -SshSessionPort 22

.EXAMPLE
Get-SafeguardCustomPlatform "My Custom Linux" | Edit-SafeguardCustomPlatform

.EXAMPLE
Edit-SafeguardCustomPlatform 10001 -ScriptFile "C:\scripts\UpdatedScript.json"
#>
function Edit-SafeguardCustomPlatform
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
        [object]$PlatformToEdit,
        [Parameter(Mandatory=$false)]
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [string]$DisplayName,
        [Parameter(Mandatory=$false)]
        [string]$Description,
        [Parameter(Mandatory=$false)]
        [string]$ScriptFile,
        [Parameter(Mandatory=$false)]
        [switch]$AllowSessionRequests,
        [Parameter(Mandatory=$false)]
        [switch]$DenySessionRequests,
        [Parameter(Mandatory=$false)]
        [int]$SshSessionPort,
        [Parameter(Mandatory=$false)]
        [int]$RdpSessionPort,
        [Parameter(Mandatory=$false)]
        [int]$TelnetSessionPort,
        [Parameter(Mandatory=$false,ValueFromPipeline=$true)]
        [object]$PlatformObject
    )

    begin
    {
        if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
        if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    }

    process
    {
        if ($PlatformObject)
        {
            if ($PlatformObject.PlatformFamily -ne "Custom")
            {
                throw "Platform '$($PlatformObject.DisplayName)' is not a custom platform (PlatformFamily=$($PlatformObject.PlatformFamily))"
            }
            $local:PlatformObj = $PlatformObject
        }
        else
        {
            if (-not $PSBoundParameters.ContainsKey("PlatformToEdit"))
            {
                $PlatformToEdit = (Read-Host "PlatformToEdit")
            }
            $local:PlatformObj = (Get-SafeguardCustomPlatform -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $PlatformToEdit)
        }

        if ($PSBoundParameters.ContainsKey("Name")) { $local:PlatformObj.Name = $Name }
        if ($PSBoundParameters.ContainsKey("DisplayName")) { $local:PlatformObj.DisplayName = $DisplayName }
        if ($PSBoundParameters.ContainsKey("Description")) { $local:PlatformObj.Description = $Description }
        if ($AllowSessionRequests) { $local:PlatformObj.SessionFeatureProperties.SupportsSessionManagement = $true }
        if ($DenySessionRequests) { $local:PlatformObj.SessionFeatureProperties.SupportsSessionManagement = $false }
        if ($PSBoundParameters.ContainsKey("SshSessionPort")) { $local:PlatformObj.SessionFeatureProperties.DefaultSshSessionPort = $SshSessionPort }
        if ($PSBoundParameters.ContainsKey("RdpSessionPort")) { $local:PlatformObj.SessionFeatureProperties.DefaultRemoteDesktopSessionPort = $RdpSessionPort }
        if ($PSBoundParameters.ContainsKey("TelnetSessionPort")) { $local:PlatformObj.SessionFeatureProperties.DefaultTelnetSessionPort = $TelnetSessionPort }

        $local:Result = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                             PUT "Platforms/$($local:PlatformObj.Id)" -Body $local:PlatformObj)

        if ($PSBoundParameters.ContainsKey("ScriptFile"))
        {
            if (-not (Test-Path $ScriptFile))
            {
                throw "Script file not found: $ScriptFile"
            }
            $local:ScriptContent = (Get-Content -Path $ScriptFile -Raw)
            Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                PUT "Platforms/$($local:Result.Id)/Script/Raw" -ContentType "application/octet-stream" -JsonBody $local:ScriptContent | Out-Null
            # Re-fetch to return updated platform with script info
            $local:Result = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                                 GET "Platforms/$($local:Result.Id)")
        }

        $local:Result
    }
}

<#
.SYNOPSIS
Remove a custom platform from Safeguard via the Web API.

.DESCRIPTION
Remove a custom platform definition from Safeguard. This is a permanent
deletion. Use -ForceDelete to remove the platform even if it has associated
assets or other dependencies.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER PlatformToDelete
An integer containing the platform ID or a string containing the platform
display name of the custom platform to remove.

.PARAMETER ForceDelete
Remove the custom platform even if it has dependencies (e.g., associated assets).

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardCustomPlatform 10001

.EXAMPLE
Remove-SafeguardCustomPlatform "My Custom Linux"

.EXAMPLE
Remove-SafeguardCustomPlatform "My Custom Linux" -ForceDelete
#>
function Remove-SafeguardCustomPlatform
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
        [object]$PlatformToDelete,
        [Parameter(Mandatory=$false)]
        [switch]$ForceDelete
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $PSBoundParameters.ContainsKey("PlatformToDelete"))
    {
        $PlatformToDelete = (Read-Host "PlatformToDelete")
    }
    $local:Platform = (Get-SafeguardCustomPlatform -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $PlatformToDelete)

    $local:Parameters = $null
    if ($ForceDelete)
    {
        $local:Parameters = @{ forceDelete = $true }
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
        DELETE "Platforms/$($local:Platform.Id)" -Parameters $local:Parameters
}

<#
.SYNOPSIS
Export a custom platform script from Safeguard via the Web API.

.DESCRIPTION
Retrieve the raw JSON script content from a custom platform. The script can
be returned as a string or written directly to a file using -OutFile.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER PlatformToGet
An integer containing the platform ID or a string containing the platform
display name of the custom platform whose script to export.

.PARAMETER OutFile
A string containing the file path to write the script content to. If not
specified, the raw script JSON string is returned.

.INPUTS
None.

.OUTPUTS
PSCustomObject representing the script content, or nothing if -OutFile is used.
When -OutFile is specified, the JSON is written to the file.

.EXAMPLE
Export-SafeguardCustomPlatformScript -Insecure "My Custom Linux"

.EXAMPLE
Export-SafeguardCustomPlatformScript -Insecure 10001 -OutFile "C:\scripts\MyScript.json"
#>
function Export-SafeguardCustomPlatformScript
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
        [object]$PlatformToGet,
        [Parameter(Mandatory=$false)]
        [string]$OutFile
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Platform = (Get-SafeguardCustomPlatform -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $PlatformToGet)

    if (-not $local:Platform.CustomScriptProperties.HasScript)
    {
        throw "Custom platform '$($local:Platform.Name)' (Id=$($local:Platform.Id)) does not have a script"
    }

    $local:ScriptContent = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                                GET "Platforms/$($local:Platform.Id)/Script/Raw")

    if ($PSBoundParameters.ContainsKey("OutFile"))
    {
        ($local:ScriptContent | ConvertTo-Json -Depth 100) | Out-File -FilePath $OutFile -Encoding utf8 -NoNewline
    }
    else
    {
        $local:ScriptContent
    }
}

<#
.SYNOPSIS
Import a platform script into a custom platform in Safeguard via the Web API.

.DESCRIPTION
Upload a JSON platform script file to a custom platform, replacing any
existing script. The script defines the operations the platform supports
(e.g., CheckPassword, ChangePassword, DiscoverAccounts).

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER PlatformToEdit
An integer containing the platform ID or a string containing the platform
display name of the custom platform to import the script into.

.PARAMETER ScriptFile
A string containing the path to the JSON platform script file to upload.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API (the updated platform object).

.EXAMPLE
Import-SafeguardCustomPlatformScript -Insecure "My Custom Linux" -ScriptFile "C:\scripts\MyScript.json"

.EXAMPLE
Import-SafeguardCustomPlatformScript -Insecure 10001 -ScriptFile "C:\scripts\MyScript.json"
#>
function Import-SafeguardCustomPlatformScript
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
        [object]$PlatformToEdit,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$ScriptFile
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Platform = (Get-SafeguardCustomPlatform -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $PlatformToEdit)

    if (-not (Test-Path $ScriptFile))
    {
        throw "Script file not found: $ScriptFile"
    }
    $local:ScriptContent = (Get-Content -Path $ScriptFile -Raw)

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
        PUT "Platforms/$($local:Platform.Id)/Script/Raw" -ContentType "application/octet-stream" -JsonBody $local:ScriptContent | Out-Null

    # Return the updated platform object
    Get-SafeguardCustomPlatform -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $local:Platform.Id
}

<#
.SYNOPSIS
Validate a custom platform script file via the Safeguard Web API without creating a platform.

.DESCRIPTION
Submit a JSON platform script file to the Safeguard appliance for validation.
The appliance parses the script and checks for structural correctness, required
fields, and valid operation definitions. If the script is valid, a platform
object preview is returned showing the operations and properties the script
would produce. If the script is invalid, an error is thrown with details about
the problem.

This cmdlet does not create or modify any platform -- it is a dry-run validation.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER ScriptFile
A string containing the path to a JSON platform script file to validate.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API representing the platform that would be
created from this script, including SupportedOperations and ConnectionProperties.

.EXAMPLE
Test-SafeguardCustomPlatformScript "C:\scripts\MyScript.json"

.EXAMPLE
Test-SafeguardCustomPlatformScript -ScriptFile "C:\scripts\MyScript.json" -Insecure
#>
function Test-SafeguardCustomPlatformScript
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
        [string]$ScriptFile
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not (Test-Path $ScriptFile))
    {
        throw "Script file not found: $ScriptFile"
    }
    $local:ScriptContent = (Get-Content -Path $ScriptFile -Raw)

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
        POST "Platforms/ValidateScript/Raw" -ContentType "application/octet-stream" -JsonBody $local:ScriptContent
}

<#
.SYNOPSIS
Get the custom script parameter definitions from a custom platform or script file
in Safeguard via the Web API.

.DESCRIPTION
Retrieve the custom script parameter schema defined by a custom platform's script.
These are the custom (non-well-known) parameters that can be configured per-asset
when using this custom platform. Each parameter has a Name, Type, DefaultValue,
and TaskName (the operation it applies to).

When -ScriptFile is specified, the script is validated without creating a platform,
allowing you to discover parameters before platform creation.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Platform
An integer containing the platform ID or a string containing the platform
display name of the custom platform to query.

.PARAMETER ScriptFile
Path to a custom platform script JSON file. The script is validated via the
API and its parameters are returned without creating a platform.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API -- array of parameter definitions with
Name, Description, DefaultValue, Type, and TaskName properties.

.EXAMPLE
Get-SafeguardCustomPlatformScriptParameter "My Custom Linux"

.EXAMPLE
Get-SafeguardCustomPlatformScriptParameter 10022

.EXAMPLE
Get-SafeguardCustomPlatformScriptParameter -ScriptFile ".\MyScript.json"
#>
function Get-SafeguardCustomPlatformScriptParameter
{
    [CmdletBinding(DefaultParameterSetName="ByPlatform")]
    [OutputType([object[]])]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(ParameterSetName="ByPlatform",Mandatory=$true,Position=0)]
        [object]$Platform,
        [Parameter(ParameterSetName="ByScriptFile",Mandatory=$true)]
        [string]$ScriptFile
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSCmdlet.ParameterSetName -eq "ByScriptFile")
    {
        if (-not (Test-Path $ScriptFile))
        {
            throw "Script file not found: $ScriptFile"
        }
        $local:ScriptContent = (Get-Content -Path $ScriptFile -Raw)
        $local:Result = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            POST "Platforms/ValidateScript/Raw" -ContentType "application/octet-stream" -JsonBody $local:ScriptContent)
        if (-not $local:Result.CustomScriptProperties -or -not $local:Result.CustomScriptProperties.Parameters -or
            $local:Result.CustomScriptProperties.Parameters.Count -eq 0)
        {
            Write-Verbose "Script file '$ScriptFile' has no custom parameters"
            return @()
        }
        $local:Result.CustomScriptProperties.Parameters
    }
    else
    {
        $local:PlatformObj = (Get-SafeguardCustomPlatform -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Platform)
        if (-not $local:PlatformObj.CustomScriptProperties -or -not $local:PlatformObj.CustomScriptProperties.HasScript)
        {
            throw "Custom platform '$Platform' does not have a script uploaded"
        }
        if (-not $local:PlatformObj.CustomScriptProperties.Parameters -or $local:PlatformObj.CustomScriptProperties.Parameters.Count -eq 0)
        {
            Write-Verbose "Custom platform '$Platform' has a script but no custom parameters"
            return @()
        }
        $local:PlatformObj.CustomScriptProperties.Parameters
    }
}

<#
.SYNOPSIS
Create a new asset using a custom platform in Safeguard via the Web API.

.DESCRIPTION
Create an asset that uses a custom platform definition. This cmdlet handles the
standard asset creation properties (network address, service account, etc.) and
also supports setting custom script parameters defined by the platform's script.

In interactive mode (when -CustomScriptParameters is not provided), the cmdlet
will discover the platform's custom parameters and prompt for values. In automated
mode, pass an array of parameter override hashtables.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Platform
An integer containing the platform ID or a string containing the platform
display name of the custom platform to use. Must be a custom platform.

.PARAMETER NetworkAddress
A string containing the network address (IP or hostname) of the asset.

.PARAMETER DisplayName
A string containing the display name for the asset. Defaults to NetworkAddress.

.PARAMETER Description
A string containing the description for the asset.

.PARAMETER AssetPartition
An integer or string identifying the asset partition to use.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID. Use -1 for the default partition.

.PARAMETER Port
An integer containing the port for connecting to the asset.

.PARAMETER ServiceAccountCredentialType
A string containing the credential type for the service account.

.PARAMETER ServiceAccountName
A string containing the service account name.

.PARAMETER ServiceAccountPassword
A SecureString containing the service account password.

.PARAMETER NoSshHostKeyDiscovery
Do not attempt SSH host key discovery after asset creation.

.PARAMETER AcceptSshHostKey
Automatically accept the discovered SSH host key.

.PARAMETER CustomScriptParameters
An array of hashtables specifying custom script parameter overrides. Each hashtable
should contain Name and Value keys. Optionally include TaskName to target a specific
operation. If TaskName is omitted, the value is applied to all operations that use
that parameter name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
New-SafeguardCustomPlatformAsset "My Custom Linux" "10.0.0.1"

.EXAMPLE
New-SafeguardCustomPlatformAsset "My Custom Linux" "10.0.0.1" -CustomScriptParameters @(@{Name="RequestTerminal";Value="False"})

.EXAMPLE
New-SafeguardCustomPlatformAsset -Platform 10022 -NetworkAddress "10.0.0.1" -Port 2222 -ServiceAccountCredentialType Password -ServiceAccountName "root"
#>
function New-SafeguardCustomPlatformAsset
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
        [object]$Platform,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$NetworkAddress,
        [Parameter(Mandatory=$false)]
        [string]$DisplayName,
        [Parameter(Mandatory=$false)]
        [string]$Description,
        [Parameter(Mandatory=$false)]
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$false)]
        [int]$Port,
        [Parameter(Mandatory=$false)]
        [ValidateSet("None","Password","SshKey","DirectoryPassword","LocalHostPassword","AccessKey","AccountPassword","Custom",IgnoreCase=$true)]
        [string]$ServiceAccountCredentialType,
        [Parameter(Mandatory=$false)]
        [string]$ServiceAccountName,
        [Parameter(Mandatory=$false)]
        [SecureString]$ServiceAccountPassword,
        [Parameter(Mandatory=$false)]
        [switch]$NoSshHostKeyDiscovery,
        [Parameter(Mandatory=$false)]
        [switch]$AcceptSshHostKey,
        [Parameter(Mandatory=$false)]
        [hashtable[]]$CustomScriptParameters
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local
    Import-Module -Name "$PSScriptRoot\datatypes.psm1" -Scope Local

    # Resolve the custom platform
    $local:PlatformObj = (Get-SafeguardCustomPlatform -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Platform)

    if (-not $PSBoundParameters.ContainsKey("DisplayName") -or [string]::IsNullOrEmpty($DisplayName))
    {
        if ([string]::IsNullOrEmpty($NetworkAddress) -or (Test-IpAddress $NetworkAddress))
        {
            $DisplayName = (Read-Host "DisplayName")
        }
        else
        {
            $DisplayName = $NetworkAddress
        }
    }

    # Build connection properties
    $local:ConnectionProperties = @{}
    if ($PSBoundParameters.ContainsKey("Port")) { $local:ConnectionProperties.Port = $Port }

    if (-not $PSBoundParameters.ContainsKey("ServiceAccountCredentialType"))
    {
        $ServiceAccountCredentialType = "None"
    }
    $local:ConnectionProperties.ServiceAccountCredentialType = $ServiceAccountCredentialType

    if ($ServiceAccountCredentialType -ne "None")
    {
        switch ($ServiceAccountCredentialType.ToLower())
        {
            "password" {
                if (-not $PSBoundParameters.ContainsKey("ServiceAccountName") -or -not $ServiceAccountName)
                {
                    $ServiceAccountName = (Read-Host "ServiceAccountName")
                }
                $local:ConnectionProperties.ServiceAccountName = $ServiceAccountName
                if (-not $PSBoundParameters.ContainsKey("ServiceAccountPassword"))
                {
                    $ServiceAccountPassword = (Read-Host -AsSecureString "ServiceAccountPassword")
                }
                $local:ConnectionProperties.ServiceAccountPassword = `
                    [System.Net.NetworkCredential]::new("", $ServiceAccountPassword).Password
            }
            default {
                if (-not $PSBoundParameters.ContainsKey("ServiceAccountName") -or -not $ServiceAccountName)
                {
                    $ServiceAccountName = (Read-Host "ServiceAccountName")
                }
                $local:ConnectionProperties.ServiceAccountName = $ServiceAccountName
            }
        }
    }

    # Resolve asset partition
    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                            -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -UseDefault)

    # Create the asset
    $local:Body = @{
        Name = "$DisplayName";
        Description = "$Description";
        NetworkAddress = "$NetworkAddress";
        PlatformId = $local:PlatformObj.Id;
        AssetPartitionId = $AssetPartitionId;
        ConnectionProperties = $local:ConnectionProperties;
    }

    $local:NewAsset = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                           POST Assets -Body $local:Body)

    # Handle custom script parameter overrides (POST-then-PUT pattern)
    $local:HasCustomParamOverrides = $false
    $local:ScriptParams = $local:PlatformObj.CustomScriptProperties.Parameters

    if ($PSBoundParameters.ContainsKey("CustomScriptParameters") -and $CustomScriptParameters)
    {
        # Automated mode: apply overrides from the parameter
        $local:HasCustomParamOverrides = $true
    }
    elseif ($local:ScriptParams -and $local:ScriptParams.Count -gt 0 -and -not $PSBoundParameters.ContainsKey("CustomScriptParameters"))
    {
        # Interactive mode: prompt for each unique parameter
        $local:UniqueParams = @{}
        foreach ($local:Param in $local:ScriptParams)
        {
            if (-not $local:UniqueParams.ContainsKey($local:Param.Name))
            {
                $local:UniqueParams[$local:Param.Name] = $local:Param
            }
        }
        $local:InteractiveOverrides = @()
        foreach ($local:ParamName in $local:UniqueParams.Keys)
        {
            $local:ParamDef = $local:UniqueParams[$local:ParamName]
            $local:Prompt = "$local:ParamName [$($local:ParamDef.Type)] (default: $($local:ParamDef.DefaultValue))"
            $local:UserValue = (Read-Host $local:Prompt)
            if (-not [string]::IsNullOrEmpty($local:UserValue))
            {
                $local:InteractiveOverrides += @{ Name = $local:ParamName; Value = $local:UserValue }
            }
        }
        if ($local:InteractiveOverrides.Count -gt 0)
        {
            $CustomScriptParameters = $local:InteractiveOverrides
            $local:HasCustomParamOverrides = $true
        }
    }

    if ($local:HasCustomParamOverrides)
    {
        try
        {
            # GET-then-PUT to apply custom parameter overrides
            $local:AssetObj = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                                   GET "Assets/$($local:NewAsset.Id)")
            if ($local:AssetObj.CustomScriptParameters)
            {
                foreach ($local:Override in $CustomScriptParameters)
                {
                    $local:OverrideName = $local:Override.Name
                    $local:OverrideValue = $local:Override.Value
                    $local:OverrideTaskName = $null
                    if ($local:Override.ContainsKey("TaskName"))
                    {
                        $local:OverrideTaskName = $local:Override.TaskName
                    }
                    foreach ($local:AssetParam in $local:AssetObj.CustomScriptParameters)
                    {
                        if ($local:AssetParam.Name -eq $local:OverrideName)
                        {
                            if ($local:OverrideTaskName -and $local:AssetParam.TaskName -ne $local:OverrideTaskName)
                            {
                                continue
                            }
                            $local:AssetParam.Value = "$local:OverrideValue"
                        }
                    }
                }
                $local:NewAsset = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                                       PUT "Assets/$($local:NewAsset.Id)" -Body $local:AssetObj)
            }
        }
        catch
        {
            Write-Host -ForegroundColor Yellow "Error setting custom script parameters, removing asset..."
            Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                DELETE "Assets/$($local:NewAsset.Id)" | Out-Null
            throw
        }
    }

    # Handle SSH host key discovery
    try
    {
        if ($local:NewAsset.Platform.ConnectionProperties.SupportsSshTransport -and -not $NoSshHostKeyDiscovery)
        {
            Import-Module -Name "$PSScriptRoot\assets.psm1" -Scope Local
            Invoke-SafeguardAssetSshHostKeyDiscovery -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $local:NewAsset -AcceptSshHostKey:$AcceptSshHostKey
        }
        else
        {
            $local:NewAsset
        }
    }
    catch
    {
        Write-Host -ForegroundColor Yellow "Error setting up SSH host key, removing asset..."
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            DELETE "Assets/$($local:NewAsset.Id)" | Out-Null
        throw
    }
}

<#
.SYNOPSIS
Set a custom script parameter value on a Safeguard asset via the Web API.

.DESCRIPTION
Modify one or more custom script parameter values on an existing asset that uses
a custom platform. Uses the GET-then-PUT pattern to update the asset's
CustomScriptParameters array.

When TaskName is specified, only the parameter for that specific operation is
updated. When TaskName is omitted, all operations that use the specified parameter
name are updated to the new value.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetToSet
An integer containing an asset ID or a string containing the asset name.

.PARAMETER ParameterName
A string containing the name of the custom script parameter to set.

.PARAMETER ParameterValue
A string containing the new value for the custom script parameter.

.PARAMETER TaskName
An optional string specifying the operation to target (e.g., TestConnection,
CheckPassword, ChangePassword). If omitted, the value is applied to all
operations that use the specified parameter name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API -- the updated asset object.

.EXAMPLE
Set-SafeguardCustomPlatformAssetParameter 263 "RequestTerminal" "False"

.EXAMPLE
Set-SafeguardCustomPlatformAssetParameter "MyLinuxAsset" "RequestTerminal" "False" -TaskName "CheckPassword"
#>
function Set-SafeguardCustomPlatformAssetParameter
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
        [object]$AssetToSet,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$ParameterName,
        [Parameter(Mandatory=$true,Position=2)]
        [string]$ParameterValue,
        [Parameter(Mandatory=$false)]
        [string]$TaskName
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    # Resolve asset
    Import-Module -Name "$PSScriptRoot\assets.psm1" -Scope Local
    $local:AssetId = (Resolve-SafeguardAssetId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AssetToSet)

    # GET the full asset
    $local:AssetObj = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                           GET "Assets/$local:AssetId")

    if (-not $local:AssetObj.CustomScriptParameters -or $local:AssetObj.CustomScriptParameters.Count -eq 0)
    {
        throw "Asset '$AssetToSet' does not have any custom script parameters. " + `
              "Ensure the asset uses a custom platform with a script that defines custom parameters."
    }

    # Find and update matching parameters
    $local:Updated = $false
    foreach ($local:Param in $local:AssetObj.CustomScriptParameters)
    {
        if ($local:Param.Name -eq $ParameterName)
        {
            if ($PSBoundParameters.ContainsKey("TaskName") -and $local:Param.TaskName -ne $TaskName)
            {
                continue
            }
            $local:Param.Value = $ParameterValue
            $local:Updated = $true
        }
    }

    if (-not $local:Updated)
    {
        if ($PSBoundParameters.ContainsKey("TaskName"))
        {
            throw "Unable to find custom script parameter '$ParameterName' for task '$TaskName' on asset '$AssetToSet'"
        }
        else
        {
            throw "Unable to find custom script parameter '$ParameterName' on asset '$AssetToSet'"
        }
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
        PUT "Assets/$local:AssetId" -Body $local:AssetObj
}
