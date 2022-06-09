# Helpers (also imported locally and used in other modules)
function Resolve-SafeguardPlatform
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
        [object]$Platform
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($Platform.Id -as [int])
    {
        $Platform = $Platform.Id
    }

    while (-not $($Platform -as [int]))
    {
        Write-Host "Searching for platforms with '$Platform'"
        try
        {
            $local:Platforms = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Platforms `
                                    -Parameters @{ Filter = "DisplayName icontains '$Platform' and Id ge 500" })
        }
        catch
        {
            Write-Verbose $_
            Write-Verbose "Caught exception with icontains filter, trying with contains filter"
            $local:Platforms = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Platforms `
                                    -Parameters @{ Filter = "DisplayName contains '$Platform' and Id ge 500" })
        }
        if (-not $local:Platforms)
        {
            $local:Platforms = (Find-SafeguardPlatform -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure "$Platform")
        }
        if (-not $local:Platforms)
        {
            throw "Unable to find platform matching '$Platform'..."
        }
        if ($local:Platforms -is [array] -and $local:Platforms.Count -ne 1)
        {
            Write-Host "Found $($local:Platforms.Count) platforms matching '$Platform':"
            Write-Host "["
            $local:Platforms | ForEach-Object {
                Write-Host ("    {0,3} - {1}" -f $_.Id,$_.DisplayName)
            }
            Write-Host "]"
            $Platform = (Read-Host "Enter platform ID or search string")
        }
        else
        {
            $Platform = $local:Platforms[0].Id
        }
    }
    $Platform
}
function Resolve-SafeguardLdapDirectoryPlatform
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
        [object]$Platform
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($Platform.Id -as [int])
    {
        $Platform = $Platform.Id
    }

    while (-not $($Platform -as [int]))
    {
        Write-Host "Searching for LDAP platforms with '$Platform'"
        try
        {
            $local:Platforms = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Platforms `
                                    -Parameters @{ filter = "DisplayName icontains '$Platform' and DeviceClass eq 'Directory' and Id ne 522 and Id ge 500"; `
                                                   fields = "Id,DisplayName"; orderby = "Id" })
        }
        catch
        {
            Write-Verbose $_
            Write-Verbose "Caught exception with icontains filter, trying with contains filter"
            $local:Platforms = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Platforms `
                                    -Parameters @{ filter = "DisplayName contains '$Platform' and DeviceClass eq 'Directory' and Id ne 522 and Id ge 500"; `
                                                   fields = "Id,DisplayName"; orderby = "Id" })
        }
        if (-not $local:Platforms)
        {
            $local:Platforms = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Platforms `
                                    -Parameters @{ q = "$Platform"; filter = "Id ge 500 and Id ne 522 and DeviceClass eq 'Directory'"; `
                                                   fields = "Id,DisplayName"; orderby = "Id" })
        }
        if (-not $local:Platforms)
        {
            throw "Unable to find platform matching '$Platform'..."
        }
        if ($local:Platforms.Count -ne 1)
        {
            Write-Host "Found $($local:Platforms.Count) platforms matching '$Platform':"
            Write-Host "["
            $local:Platforms | ForEach-Object {
                Write-Host ("    {0,3} - {1}" -f $_.Id,$_.DisplayName)
            }
            Write-Host "]"
            $Platform = (Read-Host "Enter platform ID or search string")
        }
        else
        {
            $Platform = $local:Platforms[0].Id
        }
    }
    $Platform
}
function Resolve-SafeguardServiceAccountCredentialType
{
    [CmdletBinding()]
    Param(
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    Write-Host $PSBoundParameters
    Write-Host $PSCmdlet
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:CredentialTypes = @(
        @{ Name = "None"; Description = "No service account" },
        @{ Name = "Password"; Description = "User name and password--either new or existing user" },
        @{ Name = "SshKey"; Description = "SSH public key authentication" },
        @{ Name = "DirectoryPassword"; Description = "Existing directory account under management" },
        @{ Name = "LocalHostPassword"; Description = "Existing asset account from asset where application is hosted" },
        @{ Name = "AccessKey"; Description = "User name and API access key (for AWS, etc.)" },
        @{ Name = "AccountPassword"; Description = "Use target account password (for web accounts--Twitter,Facebook,etc.)" }
        @{ Name = "Custom"; Description = "Use custom credential from custom script"}
    )
    do
    {
        Write-Host "Service account credential types:"
        Write-Host "["
        $local:i = 0
        $local:CredentialTypes | ForEach-Object {
            Write-Host ("    ({0}) - {1}" -f $local:i,$_.Description)
            $local:i += 1
        }
        Write-Host "]"
        $local:i = (Read-Host "Select option (0-$($local:CredentialTypes.Count - 1))")
        if (($local:i -as [int]) -ge 0 -and ($local:i -as [int]) -lt $local:CredentialTypes.Count)
        {
            $local:Selection = $local:CredentialTypes[$local:i]
        }
    } until ($local:Selection)
    $local:Selection.Name
}

<#
.SYNOPSIS
Get the identity provider types defined in Safeguard via the Web API.

.DESCRIPTION
Get the identity provider types defined in Safeguard that can be used
for creating users and assigning authentication methods.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Id
A integer containing the identity provider ID.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardIdentityProviderType -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardIdentityProviderType
#>
function Get-SafeguardIdentityProviderType
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
        [int]$Id
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSBoundParameters.ContainsKey("Id"))
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "IdentityProviderTypes/$Id"
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET IdentityProviderTypes
    }
}

<#
.SYNOPSIS
Get the platform types defined in Safeguard via the Web API.

.DESCRIPTION
Get the platform types defined in Safeguard can be used for creating
assets and directories.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Platform
A string with the platform name or an integer containing the platform ID.

.PARAMETER Fields
An array of the platform property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardPlatform -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardPlatform
#>
function Get-SafeguardPlatform
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
        [object]$Platform,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Parameters = @{ orderby = "Id" }
    if ($Fields)
    {
        $local:Parameters.fields = ($Fields -join ",")
    }

    if ($PSBoundParameters.ContainsKey("Platform"))
    {
        $local:PlatformId = (Resolve-SafeguardPlatform -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Platform)
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            GET "Platforms/$($local:PlatformId)" -Parameters $local:Parameters
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            GET Platforms -Parameters $local:Parameters
    }
}

<#
.SYNOPSIS
Search the platform types defined in Safeguard via the Web API.

.DESCRIPTION
Search the platform types defined in Safeguard for string fields containing
the SearchString.  This cmdlet will still find the legacy platform definitions
differentiated only by version and architecture (Id < 500).

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER SearchString
A string to search for in the platform definitions.

.PARAMETER QueryFilter
A string to pass to the -filter query parameter in the Safeguard Web API.

.PARAMETER Fields
An array of the platform property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Find-SafeguardPlatform -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Find-SafeguardPlatform linux

.EXAMPLE
Find-SafeguardPlatform -QueryFilter "PlatformType eq 'Ubuntu'"

.EXAMPLE
Find-SafeguardPlatform -QueryFilter "PasswordFeatureProperties.SupportsSuspendRestoreAccount eq True" | ft Id,PlatformFamily,PlatformType,DisplayName
#>
function Find-SafeguardPlatform
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
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSCmdlet.ParameterSetName -eq "Search")
    {
        $local:Parameters = @{ filter = "DisplayName icontains '$SearchString' or Name icontains '$SearchString'"; orderby = "Id" }
        if ($Fields)
        {
            $local:Parameters["fields"] = ($Fields -join ",")
        }
        try
        {
            $local:Platforms = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Platforms `
                                    -Parameters $local:Parameters)
        }
        catch
        {
            Write-Verbose $_
            Write-Verbose "Caught exception with ieq filter"
        }
        if (-not $local:Platforms)
        {
            $local:Parameters = @{ q = $SearchString; orderby = "Id" }
            if ($Fields)
            {
                $local:Parameters["fields"] = ($Fields -join ",")
            }
            Write-Verbose "No results yet, trying with q parameter"
            $local:Platforms = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Platforms `
                                    -Parameters $local:Parameters)
        }
        $local:Platforms
    }
    else
    {
        $local:Parameters = @{ filter = $QueryFilter; orderby = "Id" }
        if ($Fields)
        {
            $local:Parameters["fields"] = ($Fields -join ",")
        }
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Platforms `
            -Parameters $local:Parameters
    }
}

<#
.SYNOPSIS
Get the time zones defined in Safeguard via the Web API.

.DESCRIPTION
Get the time zones defined in Safeguard that can be assigned to individual users.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Id
A string containing the transfer protocol ID.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardTimeZone -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardTimeZone
#>
function Get-SafeguardTimeZone
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
        [string]$Id
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSBoundParameters.ContainsKey("Id"))
    {
        $Encoded = ($Id -replace " ","%20")
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "TimeZones/$Encoded"
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET TimeZones
    }
}

<#
.SYNOPSIS
Get the transfer protocols defined in Safeguard via the Web API.

.DESCRIPTION
Get the transfer protocols defined in Safeguard that can be assigned to archive servers.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Id
A string containing the transfer protocol ID.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardTransferProtocol -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardTransferProtocol Smb
#>
function Get-SafeguardTransferProtocol
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
        [string]$Id
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSBoundParameters.ContainsKey("Id"))
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "TransferProtocols/$Id"
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET TransferProtocols
    }
}
