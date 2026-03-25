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
