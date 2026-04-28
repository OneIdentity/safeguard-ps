<# Copyright (c) 2026 One Identity LLC. All rights reserved. #>

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


<#
.SYNOPSIS
Get the Message of the Day from Safeguard via the Web API.

.DESCRIPTION
Get the daily message (Message of the Day) configured on the Safeguard
appliance. This message is displayed to users after login.

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
Get-SafeguardDailyMessage -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardDailyMessage
#>
function Get-SafeguardDailyMessage
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

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "DailyMessage"
}


<#
.SYNOPSIS
Set the Message of the Day in Safeguard via the Web API.

.DESCRIPTION
Update the daily message (Message of the Day) on the Safeguard appliance.
You can pass individual attributes or a full message object retrieved from
Get-SafeguardDailyMessage.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Message
A string containing the message text.

.PARAMETER Subject
A string containing the message subject line.

.PARAMETER UseRss
Whether to use an RSS feed for the daily message.

.PARAMETER Address
The RSS feed URL when UseRss is enabled.

.PARAMETER MessageObject
An object containing the full daily message configuration. Use
Get-SafeguardDailyMessage to retrieve the current object, modify it, and
pass it to this parameter.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Set-SafeguardDailyMessage -Message "System maintenance tonight at 10 PM"

.EXAMPLE
Set-SafeguardDailyMessage -Message "Check the feed" -UseRss $true -Address "https://rss.example.com/feed"

.EXAMPLE
$msg = Get-SafeguardDailyMessage
$msg.Message = "Updated message"
Set-SafeguardDailyMessage -MessageObject $msg
#>
function Set-SafeguardDailyMessage
{
    [CmdletBinding(DefaultParameterSetName="Attributes")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false,Position=0)]
        [string]$Message,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$Subject,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [bool]$UseRss,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$Address,
        [Parameter(ParameterSetName="Object",Mandatory=$true,Position=0)]
        [object]$MessageObject
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PsCmdlet.ParameterSetName -eq "Object")
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "DailyMessage" -Body $MessageObject
    }
    else
    {
        $local:Body = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "DailyMessage")
        if ($PSBoundParameters.ContainsKey("Message")) { $local:Body.Message = $Message }
        if ($PSBoundParameters.ContainsKey("Subject")) { $local:Body.Subject = $Subject }
        if ($PSBoundParameters.ContainsKey("UseRss")) { $local:Body.UseRss = $UseRss }
        if ($PSBoundParameters.ContainsKey("Address")) { $local:Body.Address = $Address }
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "DailyMessage" -Body $local:Body
    }
}


<#
.SYNOPSIS
Get the login message from Safeguard via the Web API.

.DESCRIPTION
Get the login message (login banner) configured on the Safeguard appliance.
This message is displayed on the login page before authentication.

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
Get-SafeguardLoginMessage -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardLoginMessage
#>
function Get-SafeguardLoginMessage
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

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "LoginMessage"
}


<#
.SYNOPSIS
Set the login message in Safeguard via the Web API.

.DESCRIPTION
Update the login message (login banner) on the Safeguard appliance. You can
pass a simple message string or a full message object retrieved from
Get-SafeguardLoginMessage.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Message
A string containing the login message text.

.PARAMETER MessageObject
An object containing the full login message configuration. Use
Get-SafeguardLoginMessage to retrieve the current object, modify it, and
pass it to this parameter.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Set-SafeguardLoginMessage -Message "Authorized users only. All access is monitored."

.EXAMPLE
$msg = Get-SafeguardLoginMessage
$msg.Message = "Updated banner"
Set-SafeguardLoginMessage -MessageObject $msg
#>
function Set-SafeguardLoginMessage
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
        [string]$Message,
        [Parameter(ParameterSetName="Object",Mandatory=$true,Position=0)]
        [object]$MessageObject
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PsCmdlet.ParameterSetName -eq "Object")
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "LoginMessage" -Body $MessageObject
    }
    else
    {
        $local:Body = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "LoginMessage")
        $local:Body.Message = $Message
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "LoginMessage" -Body $local:Body
    }
}