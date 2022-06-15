# Helpers
function Connect-Sps
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$SessionMaster,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$SessionUsername,
        [Parameter(Mandatory=$true,Position=2)]
        [SecureString]$SessionPassword,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Import-Module -Name "$PSScriptRoot\sslhandling.psm1" -Scope Local
    Edit-SslVersionSupport
    if ($Insecure)
    {
        Disable-SslVerification
        if ($global:PSDefaultParameterValues) { $PSDefaultParameterValues = $global:PSDefaultParameterValues.Clone() }
    }

    $local:PasswordPlainText = [System.Net.NetworkCredential]::new("", $SessionPassword).Password

    $local:BasicAuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $SessionUsername, $local:PasswordPlainText)))
    Remove-Variable -Scope local PasswordPlainText

    Invoke-RestMethod -Uri "https://$SessionMaster/api/authentication" -SessionVariable HttpSession `
        -Headers @{ Authorization = ("Basic {0}" -f $local:BasicAuthInfo) } | Write-Verbose
    Remove-Variable -Scope local BasicAuthInfo

    $HttpSession
}
function New-SpsUrl
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$RelativeUrl,
        [Parameter(Mandatory=$false)]
        [object]$Parameters
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Url = "https://$($SafeguardSpsSession.Appliance)/api/$RelativeUrl"
    if ($Parameters -and $Parameters.Length -gt 0)
    {
        $local:Url += "?"
        $Parameters.Keys | ForEach-Object {
            $local:Url += ($_ + "=" + [uri]::EscapeDataString($Parameters.Item($_)) + "&")
        }
        $local:Url = $local:Url -replace ".$"
    }
    $local:Url
}
function Invoke-SpsWithBody
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Method,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$RelativeUrl,
        [Parameter(Mandatory=$true,Position=2)]
        [object]$Headers,
        [Parameter(Mandatory=$false)]
        [object]$Body,
        [Parameter(Mandatory=$false)]
        [object]$JsonBody,
        [Parameter(Mandatory=$false)]
        [object]$Parameters
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:BodyInternal = $JsonBody
    if ($Body)
    {
        $local:BodyInternal = (ConvertTo-Json -Depth 100 -InputObject $Body)
    }
    $local:Url = (New-SpsUrl $RelativeUrl -Parameters $Parameters)
    Write-Verbose "Url=$($local:Url)"
    Write-Verbose "Parameters=$(ConvertTo-Json -InputObject $Parameters)"
    Write-Verbose "---Request Body---"
    Write-Verbose "$($local:BodyInternal)"
    Invoke-RestMethod -WebSession $SafeguardSpsSession.Session -Method $Method -Headers $Headers -Uri $local:Url `
                      -Body ([System.Text.Encoding]::UTF8.GetBytes($local:BodyInternal)) `
}
function Invoke-SpsWithoutBody
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Method,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$RelativeUrl,
        [Parameter(Mandatory=$true,Position=2)]
        [object]$Headers,
        [Parameter(Mandatory=$false)]
        [object]$Parameters
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Url = (New-SpsUrl $RelativeUrl -Parameters $Parameters)
    Write-Verbose "Url=$($local:Url)"
    Write-Verbose "Parameters=$(ConvertTo-Json -InputObject $Parameters)"
    Invoke-RestMethod -WebSession $SafeguardSpsSession.Session -Method $Method -Headers $Headers -Uri $local:Url
}
function Invoke-SpsInternal
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Method,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$RelativeUrl,
        [Parameter(Mandatory=$true,Position=2)]
        [object]$Headers,
        [Parameter(Mandatory=$false)]
        [object]$Body,
        [Parameter(Mandatory=$false)]
        [string]$JsonBody,
        [Parameter(Mandatory=$false)]
        [HashTable]$Parameters
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    try
    {
        switch ($Method.ToLower())
        {
            {$_ -in "get","delete"} {
                Invoke-SpsWithoutBody $Method $RelativeUrl $Headers -Parameters $Parameters
                break
            }
            {$_ -in "put","post"} {
                Invoke-SpsWithBody $Method $RelativeUrl $Headers `
                    -Body $Body -JsonBody $JsonBody -Parameters $Parameters
                break
            }
        }
    }
    catch
    {
        Import-Module -Name "$PSScriptRoot\sg-utilities.psm1" -Scope Local
        Out-SafeguardExceptionIfPossible $_
    }
}


<#
.SYNOPSIS
Log into a Safeguard SPS appliance in this Powershell session for the purposes
of using the SPS Web API.

.DESCRIPTION
This utility can help you securely create a login session with a Safeguard SPS
appliance and save it as a global variable.

The password may be passed in as a SecureString.  By default, this
script will securely prompt for the password.

.PARAMETER Appliance
IP address or hostname of a Safeguard SPS appliance.

.PARAMETER Insecure
Ignore verification of Safeguard SPS appliance SSL certificate--will be ignored for entire session.

.PARAMETER Username
The username to authenticate as.

.PARAMETER Password
SecureString containing the password.

.INPUTS
None.

.OUTPUTS
None (with session variable filled out for calling Sps Web API).


.EXAMPLE
Connect-SafeguardSps 10.5.32.54 admin -Insecure

Login Successful.

.EXAMPLE
Connect-SafeguardSps sps1.mycompany.corp admin

Login Successful.
#>
function Connect-SafeguardSps
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Appliance,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$Username,
        [Parameter(Mandatory=$false)]
        [SecureString]$Password,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $Password)
    {
        $Password = (Read-Host "Password" -AsSecureString)
    }

    $local:HttpSession = (Connect-Sps -SessionMaster $Appliance -SessionUsername $Username -SessionPassword $Password -Insecure:$Insecure)
    Set-Variable -Name "SafeguardSpsSession" -Scope Global -Value @{
        "Appliance" = $Appliance;
        "Insecure" = $Insecure;
        "Session" = $local:HttpSession
    }
    Write-Host "Login Successful."
}

<#
.SYNOPSIS
Log out of a Safeguard SPS appliance when finished using the SPS Web API.

.DESCRIPTION
This utility will remove the session variable
that was created by the Connect-SafeguardSps cmdlet.

.INPUTS
None.

.OUTPUTS
None.

.EXAMPLE
Disconnect-SafeguardSps

Log out Successful.

#>
function Disconnect-SafeguardSps
{
    [CmdletBinding()]
    Param(
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $SafeguardSpsSession)
    {
        Write-Host "Not logged in."
    }
    else
    {
        Write-Host "Session variable removed."
        Set-Variable -Name "SafeguardSpsSession" -Scope Global -Value $null
    }
}

<#
.SYNOPSIS
Call a method in the Safeguard SPS Web API.

.DESCRIPTION
This utility is useful for calling the Safeguard SPS Web API for testing or
scripting purposes. It provides a couple benefits over using curl.exe or
Invoke-RestMethod by generating or reusing a secure session and composing
the Url, headers, parameters, and body for the request.

This script is meant to be used with the Connect-SafeguardSps cmdlet which
will generate and store a variable in the session so that it doesn't need
to be passed to each call to the API.  Call Disconnect-SafeguardSps when
finished.

Safeguard SPS Web API is implemented as HATEOAS. To get started crawling
through the API, call Invoke-SafeguardSpsMethod GET / -JsonOutput.  Then,
you can follow to the different API areas, such as configuration or
health-status.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER Method
HTTP method verb you would like to use: GET, PUT, POST, DELETE.

.PARAMETER RelativeUrl
Relative portion of the Url you would like to call starting after the version.

.PARAMETER Accept
Specify the Accept header (default: application/json), Use text/csv to request CSV output.

.PARAMETER ContentType
Specify the Content-type header (default: application/json).

.PARAMETER Body
A hash table containing an object to PUT or POST to the Url.

.PARAMETER JsonBody
A pre-formatted JSON string to PUT or Post to the URl.  If -Body is also specified, this is ignored.
It can sometimes be difficult to get arrays of objects to behave properly with hashtables in Powershell.

.PARAMETER Parameters
A hash table containing the HTTP query parameters to add to the Url.

.PARAMETER JsonOutput
A switch to return data as pretty JSON string.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Invoke-SafeguardSpsMethod GET starling/join

.EXAMPLE
Invoke-SafeguardSpsMethod GET / -JsonOutput
#>
function Invoke-SafeguardSpsMethod
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Method,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$RelativeUrl,
        [Parameter(Mandatory=$false)]
        [string]$Accept = "application/json",
        [Parameter(Mandatory=$false)]
        [string]$ContentType = "application/json",
        [Parameter(Mandatory=$false)]
        [object]$Body,
        [Parameter(Mandatory=$false)]
        [string]$JsonBody,
        [Parameter(Mandatory=$false)]
        [HashTable]$Parameters,
        [Parameter(Mandatory=$false)]
        [HashTable]$ExtraHeaders,
        [Parameter(Mandatory=$false)]
        [switch]$JsonOutput
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $SafeguardSpsSession)
    {
        throw "This cmdlet requires that you log in with the Connect-SafeguardSps cmdlet"
    }

    $local:Insecure = $SafeguardSpsSession.Insecure
    Write-Verbose "Insecure=$($local:Insecure)"
    Import-Module -Name "$PSScriptRoot\sslhandling.psm1" -Scope Local
    Edit-SslVersionSupport
    if ($local:Insecure)
    {
        Disable-SslVerification
        if ($global:PSDefaultParameterValues) { $PSDefaultParameterValues = $global:PSDefaultParameterValues.Clone() }
    }

    $local:Headers = @{
        "Accept" = $Accept;
        "Content-type" = $ContentType;
    }

    foreach ($key in $ExtraHeaders.Keys)
    {
        $local:Headers[$key] = $ExtraHeaders[$key]
    }

    Write-Verbose "---Request---"
    Write-Verbose "Headers=$(ConvertTo-Json -InputObject $local:Headers)"

    try
    {
        if ($JsonOutput)
        {
            (Invoke-SpsInternal $Method $RelativeUrl $local:Headers `
                                -Body $Body -JsonBody $JsonBody -Parameters $Parameters) | ConvertTo-Json -Depth 100
        }
        else
        {
            Invoke-SpsInternal $Method $RelativeUrl $local:Headers -Body $Body -JsonBody $JsonBody -Parameters $Parameters
        }
    }
    finally
    {
        if ($local:Insecure)
        {
            Enable-SslVerification
            if ($global:PSDefaultParameterValues) { $PSDefaultParameterValues = $global:PSDefaultParameterValues.Clone() }
        }
    }
}

function Open-SafeguardSpsTransaction
{
    [CmdletBinding()]
    Param(
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardSpsMethod POST transaction
}

function Close-SafeguardSpsTransaction
{
    [CmdletBinding()]
    Param(
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardSpsMethod PUT transaction -Body @{ status = "commit" }
}


function Get-SafeguardSpsTransaction
{
    [CmdletBinding()]
    Param(
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
}


function Clear-SafeguardSpsTransaction
{
    [CmdletBinding()]
    Param(
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardSpsMethod DELETE transaction
}