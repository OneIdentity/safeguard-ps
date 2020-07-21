
<#
.SYNOPSIS
Get Safeguard appliance settings via the Web API.

.DESCRIPTION
Get the settings managed by the appliance service of a Safeguard appliance.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER SettingName
A string containing the name of the appliance setting.

.PARAMETER Fields
An array of the setting property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardApplianceSetting -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardApplianceSetting -SettingName "Backup Retention Number" -Fields Name,Category,DefaultValue
#>
function Get-SafeguardApplianceSetting
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false, Position=0)]
        [string]$SettingName,
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

    if ($PSBoundParameters.ContainsKey("SettingName"))
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance GET "Settings/$SettingName" -Parameters $local:Parameters
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance GET "Settings" -Parameters $local:Parameters
    }
}


<#
.SYNOPSIS
Set a Safeguard appliance setting via the Web API.

.DESCRIPTION
Set the value of a setting managed by the appliance service of a Safeguard appliance.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER SettingName
A string containing the name of the appliance setting.

.PARAMETER Value
A string containing the new value for the setting.

.PARAMETER SettingObject
An object containing an existing appliance setting object with the new value set.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Set-SafeguardApplianceSetting -AccessToken $token -Appliance 10.5.32.54 -SettingObject $obj -Insecure

.EXAMPLE
Set-SafeguardApplianceSetting -SettingName "Minimum Process Log Level" -Value "Debug"
#>
function Set-SafeguardApplianceSetting
{
    [CmdletBinding(DefaultParameterSetName="Attributes")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(ParameterSetName="Attributes", Mandatory=$true, Position=0)]
        [string]$SettingName,
		[Parameter(ParameterSetName="Attributes", Mandatory=$true, Position=1)]
		[AllowEmptyString()]
        [string]$Value,
		[Parameter(ParameterSetName="Object",Mandatory=$true, Position=0)]
        [object]$SettingObject
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

	if (-not ($PsCmdlet.ParameterSetName -eq "Object"))
    {
        $SettingObject = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance GET "Settings/$SettingName")
        if ($PSBoundParameters.ContainsKey("Value")) { $SettingObject.Value = $Value }
    }
	
	$SettingName = $SettingObject.Name
	Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Appliance PUT "Settings/$SettingName" -Body $SettingObject
}


<#
.SYNOPSIS
Get the Safeguard core settings via the Web API.

.DESCRIPTION
Get the settings managed by the core service of a Safeguard appliance.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER SettingName
A string containing the name of the core setting.

.PARAMETER Fields
An array of the setting property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardCoreSetting -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardCoreSetting -SettingName "Inform User of Bad Password" -Fields Name,Category,DefaultValue
#>
function Get-SafeguardCoreSetting
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false, Position=0)]
        [string]$SettingName,
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

    if ($PSBoundParameters.ContainsKey("SettingName"))
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Settings/$SettingName" -Parameters $local:Parameters
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Settings" -Parameters $local:Parameters
    }
}


<#
.SYNOPSIS
Set a Safeguard core setting via the Web API.

.DESCRIPTION
Set the value of a setting managed by the core service of a Safeguard appliance.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER SettingName
A string containing the name of the core setting.

.PARAMETER Value
A string containing the new value for the setting.

.PARAMETER SettingObject
An object containing an existing core setting object with the new value set.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Set-SafeguardCoreSetting -AccessToken $token -Appliance 10.5.32.54 -SettingObject $obj -Insecure

.EXAMPLE
Set-SafeguardCoreSetting -SettingName "Trusted Servers" -Value "10.5.32.55,test.server"
#>
function Set-SafeguardCoreSetting
{
    [CmdletBinding(DefaultParameterSetName="Attributes")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(ParameterSetName="Attributes", Mandatory=$true, Position=0)]
        [string]$SettingName,
		[Parameter(ParameterSetName="Attributes", Mandatory=$true, Position=1)]
		[AllowEmptyString()]
        [string]$Value,
		[Parameter(ParameterSetName="Object",Mandatory=$true, Position=0)]
        [object]$SettingObject
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

	if (-not ($PsCmdlet.ParameterSetName -eq "Object"))
    {
        $SettingObject = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Settings/$SettingName")
        if ($PSBoundParameters.ContainsKey("Value")) { $SettingObject.Value = $Value }
    }
	
	$SettingName = $SettingObject.Name
	Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "Settings/$SettingName" -Body $SettingObject
}