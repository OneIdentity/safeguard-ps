# Helpers
function Show-JoinWindow
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$JoinUrl
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not ([System.Management.Automation.PSTypeName]"JoinWindow").Type)
    {
        Write-Verbose "Adding the PSType for rSTS Web form interaction"
        Add-Type -TypeDefinition  @"
using System;
using System.Text.RegularExpressions;
using System.Windows.Forms;
public class JoinWindow {
    private readonly Uri _joinurl;
    public JoinWindow(string joinurl) { _joinurl = new Uri(joinurl); }
    public string ClientCredentials { get; set; }
    public string TokenEndpoint { get; set; }
    public bool Show() {
        try {
            using (var form = new System.Windows.Forms.Form() { Text = "One Identity Starling Login - " + _joinurl.Host,
                                                                Width = 640, Height = 720, StartPosition = FormStartPosition.CenterParent }) {
                using (var browser = new WebBrowser() { Dock = DockStyle.Fill, Url = _joinurl }) {
                    form.Controls.Add(browser);
                    browser.ScriptErrorsSuppressed = true;
                    browser.DocumentTitleChanged += (sender, args) => {
                        var b = (WebBrowser)sender;
                        var matches = Regex.Match(b.DocumentTitle, "Join - (.+):(.+) \\| (.+)$", RegexOptions.IgnoreCase);
                        if (matches.Groups[0].Success) {
                            ClientCredentials = matches.Groups[1].Value + ":" + matches.Groups[2].Value;
                            TokenEndpoint = matches.Groups[3].Value;
                            form.DialogResult = DialogResult.OK;
                            form.Close(); } };
                    if (form.ShowDialog() == DialogResult.OK) { return true; }
                }
                return false;
            }
        }
        catch (Exception e) {
            var color = Console.ForegroundColor; Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(e); Console.ForegroundColor = color;
            return false;
        }
    }
}
"@ -ReferencedAssemblies System.Windows.Forms
    }

    $local:Browser = New-Object -TypeName JoinWindow -ArgumentList $JoinUrl
    if (!$local:Browser.Show())
    {
        throw "Unable to correctly manipulate browser"
    }
    $global:CredsFromJoin = $local:Browser.ClientCredentials
    $global:EndpointFromJoin = $local:Browser.TokenEndpoint
    $local:Browser = $null
}


<#
.SYNOPSIS
Get any One Identity Starling subscriptions that are being used by this
Safeguard instance.

.DESCRIPTION
Retrieve One Identity Starling subscriptions from the Safeguard Web API
that might be used for two-factor authentication or ApprovalAnywhere.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Name
A string containing the name of the Starling subscription.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardStarlingSubscription

.EXAMPLE
Get-SafeguardStarlingSubscription -Name Default
#>
function Get-SafeguardStarlingSubscription
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [string]$Name
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($Name)
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "StarlingSubscriptions" `
            -Parameters @{ filter = "Name ieq '$Name'" }
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "StarlingSubscriptions"
    }
}

<#
.SYNOPSIS
Create a new One Identity Starling subscription using the Safeguard
Web API.

.DESCRIPTION
This cmdlet will create a Starling subscription.  It requires information
that must be obtained interactively using a web browser to talk to Starling.
The web browser must contact the URL returned from Get-SafeguardStarlingJoinUrl.
This cmdlet will also automatically create a Starling 2FA identity provider.
You can call Invoke-SafeguardStarlingJoin to open the browser for you and
automatically call this cmdlet with the result.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Name
A string containing the name of the Starling subscription.

.PARAMETER ClientCredentials
A string containing the client credentials obtained from Starling.

.PARAMETER TokenEndpoint
A string containing the token endpoint obtained from Starling.

.PARAMETER JoinUrl
A string containing the join URL used to contact Starling for join.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
New-SafeguardStarlingSubscription

.EXAMPLE
New-SafeguardStarlingSubscription -ClientCredentials $creds -TokenEndpoint $url -JoinUrl $joinurl
#>
function New-SafeguardStarlingSubscription
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [string]$Name = "Default",
        [Parameter(Mandatory=$true,Position=0)]
        [string]$ClientCredentials,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$TokenEndpoint,
        [Parameter(Mandatory=$true,Position=2)]
        [string]$JoinUrl
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "StarlingSubscriptions" `
        -Body @{
            Name = $Name;
            ClientCredentials = $ClientCredentials;
            TokenEndpoint = $TokenEndpoint;
            JoinUrl = $JoinUrl
        }
}

<#
.SYNOPSIS
Remove a One Identity Starling subscription using the Safeguard
Web API.

.DESCRIPTION
This cmdlet will remove a Starling subscription, but it requires the
name of the existing subscription.  By default, the Safeguard GUI creates
a single Starling subscription called "Default".

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Name
A string containing the name of the Starling subscription.

.PARAMETER Force
Force Safeguard to remove the subscription

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardStarlingSubscription default

.EXAMPLE
Remove-SafeguardStarlingSubscription -Name Default
#>
function Remove-SafeguardStarlingSubscription
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [switch]$Force,
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Name
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($Name -as [int])
    {
        $local:Id = $Name
    }
    else
    {
        $local:Id = (Get-SafeguardStarlingSubscription -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -Name $Name).Id
    }

    if ($Force)
    {
        $local:ExtraHeaders = @{
            "X-Force-Delete" = "true";
        }

        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
            -ExtraHeaders $local:ExtraHeaders Core DELETE "StarlingSubscriptions/$($local:Id)"
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "StarlingSubscriptions/$($local:Id)"
    }
}

<#
.SYNOPSIS
Remove Safeguard Starling from user's secondary authentication provider from safeguard users.

.DESCRIPTION
This cmdlet will remove the Starling Authentication Profider from safeguard users.

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
Remove-SafeguardStarling2FA default

#>
function Remove-SafeguardStarling2FA
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

	try 
	{
		$local:UserIds = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Users `
										 -Parameters @{ filter = "SecondaryAuthenticationProviderTypeReferenceName in ['StarlingSubscription', 'StarlingTwoFactor']"; fields = "Id" })   
		$local:FailedIds =@()
		$local:SucceededIds = @()

		Foreach ($Id in $local:UserIds)
		{
			$UserObject = (Get-SafeguardUser -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $Id)
			
			if($UserObject -ne $null)
			{				
				$UserObject.SecondaryAuthenticationProviderId = $null
				$UserObject.SecondaryAuthenticationProviderName = $null
				$UserObject.SecondaryAuthenticationProviderTypeReferenceName = "Unknown"
				$UserObject.SecondaryAuthenticationIdentity = $null
				try
				{
					Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "Users/$($UserObject.Id)" -Body $UserObject
					$local:SucceededIds += $UserObject.Id
				}
				catch
				{
					$local:FailedIds += $UserObject.Id
				}
			}
			else
			{
				$local:FailedIds += $UserObject.Id
			}
		}
		
		if ($local:FailedIds -ne $null)
		{
			$FIds = ($local:FailedIds -join ",")
			Write-Host "Failed for users: $FIds"
		}
		if ($local:SucceededIds -ne $null)
		{
			$SIds = $local:SucceededIds -join ","           
			Write-Host "Succeeded for users: $SIds"
		}
	}
	catch
	{
		Write-Host "Error occured while removing Starling Two Factor authentication from user(s)."
	}
}

<#
.SYNOPSIS
Get a join URL for subscribing this Safeguard instance to One Identity Starling.

.DESCRIPTION
This cmdlet will return a join URL which must be accessed via an interactive
browser session.  The result of authenticating with the information in the join
URL will be a new Starling subscription on the Starling side; however, you need to call
New-SafeguardStarlingSubscription to configure the subscription information in
Safeguard as well.  Or, you may call Invoke-SafeguardStarlingJoin which will do all
of these steps for you, including opening the browser.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Name
A string containing the name of the Starling subscription.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardStarlingJoinUrl
#>
function Get-SafeguardStarlingJoinUrl
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

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "StarlingSubscriptions/JoinUrl"
}

<#
.SYNOPSIS
Open an external browser to join One Identity Starling and gather the resulting
subscription information to join Safegaurd to Starling via the Web API.

.DESCRIPTION
This is cmdlet uses an external browser and requires that you copy and paste the
credentials and token endpoint for finalizing the Starling join.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Name
A string containing the name of the Starling subscription. (default: "Default")

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Invoke-SafeguardStarlingJoinBrowser

.EXAMPLE
Invoke-SafeguardStarlingJoin -Name Default
#>
function Invoke-SafeguardStarlingJoinBrowser
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [string]$Name = "Default"
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local

    Write-Host -ForegroundColor Yellow "This command will use an external browser to join Safeguard to Starling."
    Write-host "You will be required to copy and paste interactively from the browser to answer prompts for join information."
    $local:Confirmed = (Get-Confirmation "Join to Starling" "Are you sure you want to use an external browser to join to Starling?" `
                                         "Show the browser." "Cancels this operation.")

    if ($local:Confirmed)
    {
        $local:JoinUrl = (Get-SafeguardStarlingJoinUrl -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure)
        Start-Process $local:JoinUrl

        Write-Host "Following the successful join in the browser, provide the following:"
        $local:Creds = (Read-Host "Credential String")
        $local:Endpoint = (Read-Host "Token Endpoint")

        New-SafeguardStarlingSubscription -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
            -Name $Name -ClientCredentials $local:Creds -TokenEndpoint $local:Endpoint -JoinUrl $local:JoinUrl

        Write-Host -ForegroundColor Yellow "You may close the external browser."
    }
}

<#
.SYNOPSIS
Open an embedded browser to join One Identity Starling and record the resulting
subscription information in Safeguard via the Web API.
DEPRECATED -- use Invoke-SafeguardStarlingJoinBrowser instead

.DESCRIPTION
This is cmdlet uses an embedded browser that is not supported in all versions of
PowerShell and because it is IE based, it will not work with Starling in the future.
If you use this cmdlet:
It will 1) open an embedded browser to join Starling, 2) pull the resulting subscription
information from the web page, and 3) call Safeguard Web API to create the
subscription inside Safeguard, which will also create the Starling 2FA identity
provider.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Name
A string containing the name of the Starling subscription. (default: "Default")

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Invoke-SafeguardStarlingJoin

.EXAMPLE
Invoke-SafeguardStarlingJoin -Name Default
#>
function Invoke-SafeguardStarlingJoin
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [string]$Name = "Default"
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:JoinUrl = (Get-SafeguardStarlingJoinUrl -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure)
    if ($PSVersionTable.PSEdition -eq "Core")
    {
        Write-Warning "This cmdlet cannot open a browser under PowerShell Core, use the following Starling join URL and call New-SafeguardStarlingSubscription"
        Write-Output $local:JoinUrl
    }
    else
    {
        Show-JoinWindow $local:JoinUrl
        $local:Creds = $global:CredsFromJoin
        $local:Endpoint = $global:EndpointFromJoin
        New-SafeguardStarlingSubscription -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
            -Name $Name -ClientCredentials $local:Creds -TokenEndpoint $local:Endpoint -JoinUrl $local:JoinUrl
    }
}

<#
.SYNOPSIS
Get Starling setting by name from Safeguard Web API

.DESCRIPTION
Retrieve One Identity Starling setting from the Safeguard Web API.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER SettingKey
A string containing the name of the Starling setting.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardStarlingSetting Environment

.EXAMPLE
Get-SafeguardStarlingSetting -SettingKey Hostname
#>
function Get-SafeguardStarlingSetting
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
        [string]$SettingKey
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Settings/Starling $SettingKey"
}

<#
.SYNOPSIS
Set a Starling setting by name from Safeguard Web API

.DESCRIPTION
Set a One Identity Starling setting from the Safeguard Web API.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER SettingKey
A string containing the name of the Starling setting.

.PARAMETER SettingValue
A string containing the value of the Starling setting.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Set-SafeguardStarlingSetting

.EXAMPLE
Set-SafeguardStarlingSetting -SettingKey Hostname -SettingValue "www.cloud.oneidentity.com"
#>
function Set-SafeguardStarlingSetting
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
        [string]$SettingKey,
        [Parameter(Mandatory=$false,Position=1)]
        [string]$SettingValue
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $PSBoundParameters.ContainsKey("SettingValue"))
    {
        $SettingValue = (Read-Host "SettingValue")
    }

    if (-not $SettingValue)
    {
        $SettingValue = $null
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "Settings/Starling $SettingKey" `
        -Body @{
            Name = "Starling $SettingKey";
            Value = $SettingValue
        }
}
