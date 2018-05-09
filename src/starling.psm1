# Helpers
function Show-JoinWindow
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$JoinUrl
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not ([System.Management.Automation.PSTypeName]"JoinWindow").Type)
    {
        Write-Verbose "Adding the PSType for rSTS Web form interaction"
        Add-Type -TypeDefinition  @"
using System;
using System.Text.RegularExpressions;
using System.Windows.Forms;
public class JoinWindow {
    private const string ClientId = "00000000-0000-0000-0000-000000000000";
    private const string RedirectUri = "urn%3AInstalledApplication";
    private readonly string _joinurl;
    public JoinWindow(string joinurl) { _joinurl = joinurl; }
    public string ClientCredentials { get; set; }
    public string TokenEndpoint { get; set; }
    public bool Show() {
        try {
            using (var form = new System.Windows.Forms.Form() { Text = string.Format("{0} - Safeguard Login", _appliance),
                                                                Width = 640, Height = 720, StartPosition = FormStartPosition.CenterParent }) {
                using (var browser = new WebBrowser() { Dock = DockStyle.Fill, Url = new Uri(_url) }) {
                    form.Controls.Add(browser);
                    browser.ScriptErrorsSuppressed = true;
                    browser.DocumentTitleChanged += (sender, args) => {
                        var b = (WebBrowser)sender;
                        // TODO: Change code below to extract client credentials and token endpoint
                        //       Need to get a real test instance from Starling folks
                        if (Regex.IsMatch(b.DocumentTitle, "error=[^&]*|code=[^&]*")) {
                            AuthorizationCode = b.DocumentTitle.Substring(5);
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

    $local:Browser = New-Object -TypeName JoinWindow -ArgumentList $Appliance
    if (!$local:Browser.Show())
    {
        throw "Unable to correctly manipulate browser"
    }
    $global:CredsFromJoin = $local:Browser.ClientCredentials
    $global:EndpointFromJoin = $local:Browser.TokenEndpoint
    $local:Browser = $null
}


function Get-SafeguardStarlingSubscription
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

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "StarlingSubscriptions"
}

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
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Name,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$ClientCredentials,
        [Parameter(Mandatory=$true,Position=2)]
        [string]$TokenEndpoint,
        [Parameter(Mandatory=$true,Position=3)]
        [string]$JoinUrl
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "StarlingSubscriptions" `
        -Body @{
            Name = $Name;
            ClientCredentials = $ClientCredentials;
            TokenEndpoint = $TokenEndpoint;
            JoinUrl = $JoinUrl
        }
}

function Remove-SafeguardStarlingSubscription
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

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "StarlingSubscriptions/JoinUrl"
}

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
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Name
    )

    $ErrorActionPreference = "Stop"
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

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Settings/Starling $SettingKey"
}

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
        [Parameter(Mandatory=$true,Position=1)]
        [string]$SettingValue
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "Settings/Starling $SettingKey" `
        -Body @{
            Name = "Starling $SettingKey";
            Value = $SettingValue
        }
}