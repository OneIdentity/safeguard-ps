# Helpers
function Connect-Sps
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$SessionMaster,
        [Parameter(Mandatory=$false)]
        [string]$SessionUsername,
        [Parameter(Mandatory=$false)]
        [SecureString]$SessionPassword,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [switch]$LocalLogin,
        [Parameter(Mandatory=$false)]
        [string]$CertificateFile,
        [Parameter(Mandatory=$false)]
        [string]$Thumbprint

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
        
    try
    {

        if($Thumbprint){Invoke-RestMethod -Uri "https://$SessionMaster/api/authentication?type=x509" -SessionVariable HttpSession -CertificateThumbprint $Thumbprint | Write-Verbose }
        elseif($CertificateFile){  Invoke-RestMethod -Uri "https://$SessionMaster/api/authentication?type=x509" -SessionVariable HttpSession -Certificate $CertificateFile | Write-Verbose }
        else
        {
        $sps_auth_uri = "https://$SessionMaster/api/authentication"
        if($LocalLogin){ $sps_auth_uri = "https://$SessionMaster/api/authentication?login_method=local"}

        $local:PasswordPlainText = [System.Net.NetworkCredential]::new("", $SessionPassword).Password
        $local:BasicAuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $SessionUsername, $local:PasswordPlainText)))
        Remove-Variable -Scope local PasswordPlainText
       
        Invoke-RestMethod -Uri $sps_auth_uri -SessionVariable HttpSession -Headers @{ Authorization = ("Basic {0}" -f $local:BasicAuthInfo) } | Write-Verbose
        }
    }
    catch
    {
        Import-Module -Name "$PSScriptRoot\sg-utilities.psm1" -Scope Local
        Out-SafeguardExceptionIfPossible $_
    }
    finally
    {
     if($local:BasicAuthInfo){
        Remove-Variable -Scope local BasicAuthInfo
        }
    }

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
        [object]$Parameters,
        [Parameter(Mandatory=$false)]
        [string]$InFile
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Url = (New-SpsUrl $RelativeUrl -Parameters $Parameters)
    Write-Verbose "Url=$($local:Url)"
    Write-Verbose "Parameters=$(ConvertTo-Json -InputObject $Parameters)"
    $arguments = @{
        WebSession = $SafeguardSpsSession.Session;
        Method = $Method;
        Headers = $Headers;
        Uri = $local:Url;
    }
    if ($InFile)
    {
        $arguments = $arguments + @{ InFile = $InFile }
    }
    if ($OutFile)
    {
        Write-Verbose "OutFile=$OutFile"
        $arguments = $arguments + @{ OutFile = $OutFile }
    }

    Invoke-RestMethod @arguments
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
        [HashTable]$Parameters,
        [Parameter(Mandatory=$false)]
        [string]$InFile
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
                if($InFile)
                {
                    Invoke-SpsWithoutBody $Method $RelativeUrl $Headers -Parameters $Parameters -InFile $InFile
                }
                else
                {
                    Invoke-SpsWithBody $Method $RelativeUrl $Headers `
                        -Body $Body -JsonBody $JsonBody -Parameters $Parameters
                }
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
Get the welcome wizard status for a newly deployed SPS.

.DESCRIPTION
When SPS first deploys it boots with a DHCP address and needs to be initialized for
secure use.  In the UI, an administrator can go through the welcome wizard experience
to provide the necessary information.  This cmdlet provides a method to determine
whether the welcome wizard has been completed or not.

.PARAMETER Appliance
DHCP address of newly deployed Safeguard SPS appliance.

.INPUTS
None.

.OUTPUTS
None

.EXAMPLE
Get-SafeguardSpsWelcomeWizardStatus -Appliance 10.5.37.96

#>
function Get-SafeguardSpsWelcomeWizardStatus
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Appliance
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    (Invoke-RestMethod -Method GET -Headers @{'Accept' = 'application/json'} -Uri "https://$($Appliance)/api/setup" -SkipCertificateCheck).status
}

<#
.SYNOPSIS
Complete the welcome wizard on a newly deployed SPS so that you can begin using it
via the UI or API.

.DESCRIPTION
When SPS first deploys it boots with a DHCP address and needs to be initialized for
secure use.  In the UI, an administrator can go through the welcome wizard experience
to provide the necessary information.  This cmdlet provides a programmatic interface
to complete the same task.

.PARAMETER Appliance
DHCP address of newly deployed Safeguard SPS appliance.

.PARAMETER LicenseFile
A string containing the path to a Safeguard license file.

.PARAMETER RootPassword
A secure string containing the desired root password.  Default: <will prompt>.

.PARAMETER AdminPassword
A secure string containing the desired admin password.  Default: <will prompt>.

.PARAMETER CaCertificateFile
A string containing the path to a CA certificate file in PEM format.

.PARAMETER WebServerCertificateFile
A string containing the path to a web server certificate file in PEM format.

.PARAMETER WebServerPrivateKeyFile
A string containing the path to a web server private key file in PEM format.

.PARAMETER TimeStampingCertificateFile
A string containing the path to a timestamp authority certificate file in PEM format.

.PARAMETER TimeStampingPrivateKeyFile
A string containing the path to a timestamp authority private key file in PEM format.

.PARAMETER HostName
A string containing the desired hostname for SPS.

.PARAMETER DomainName
A string containing the desired DNS suffix for SPS.

.PARAMETER IpAddressWithNetMask
A string containing the desired IP address for SPS with netmask in CIDR format.

.PARAMETER Gateway
A string containing the desired gateway IP address for SPS.

.PARAMETER PrimaryDns
A string containing the desired primary DNS server IP address for SPS.

.PARAMETER SmtpServer
A string containing the desired SMTP server.

.PARAMETER AdminEmail
A string containing the administrator's email.

.PARAMETER TimeZone
A string containing the IANA time zone for SPS.

.PARAMETER PrimaryNtpServer
A string containing the desired primary NTP server.

.PARAMETER Timeout
A timeout value in seconds to wait for SPS to complete (default: 600 seconds or 10 minutes).

.INPUTS
None.

.OUTPUTS
None

.EXAMPLE
Complete-SafeguardSpsWelcomeWizard -Appliance 10.5.37.96 -LicenseFile License.txt -CaCertificateFile CA.cert.pem -WebServerCertificateFile server.cert.pem -WebServerPrivateKeyFile server.key.pem -TimeStampingCertificateFile TSA.cert.pem -TimeStampingPrivateKeyFile TSA.key.pem -HostName sps -DomainName example.corp -IpAddressWithNetMask 10.5.32.205/24 -Gateway 10.5.32.1 -PrimaryDns 10.5.32.37 -SmtpServer mail.example.corp -AdminEmail admin@example.corp -TimeZone "America/Denver" -PrimaryNtpServer time.windows.com

#>
function Complete-SafeguardSpsWelcomeWizard
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Appliance,
        [Parameter(Mandatory=$true)]
        [string]$LicenseFile,
        [Parameter(Mandatory=$false)]
        [SecureString]$RootPassword,
        [Parameter(Mandatory=$false)]
        [SecureString]$AdminPassword,
        [Parameter(Mandatory=$true)]
        [string]$CaCertificateFile,
        [Parameter(Mandatory=$true)]
        [string]$WebServerCertificateFile,
        [Parameter(Mandatory=$true)]
        [string]$WebServerPrivateKeyFile,
        [Parameter(Mandatory=$true)]
        [string]$TimeStampingCertificateFile,
        [Parameter(Mandatory=$true)]
        [string]$TimeStampingPrivateKeyFile,
        [Parameter(Mandatory=$true)]
        [string]$HostName,
        [Parameter(Mandatory=$true)]
        [string]$DomainName,
        [Parameter(Mandatory=$true)]
        [string]$IpAddressWithNetMask,
        [Parameter(Mandatory=$true)]
        [string]$Gateway,
        [Parameter(Mandatory=$true)]
        [string]$PrimaryDns,
        [Parameter(Mandatory=$true)]
        [string]$SmtpServer,
        [Parameter(Mandatory=$true)]
        [string]$AdminEmail,
        [Parameter(Mandatory=$true)]
        [string]$TimeZone,
        [Parameter(Mandatory=$true)]
        [string]$PrimaryNtpServer,
        [Parameter(Mandatory=$false)]
        [int]$Timeout = 600,
        [Parameter(Mandatory=$false)]
        [switch]$PollOriginalIp
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Response = (Invoke-RestMethod -Method GET -Headers @{'Accept' = 'application/json'} -Uri "https://$($Appliance)/api/setup" -SkipCertificateCheck)
    if ($local:Response.status -ine "uninitialized")
    {
        Write-Host -ForegroundColor "Configuration Status: $($local:Response.status)"
        throw "Configuration is not uninitialized"
    }

    # Validate files and convert to strings ready for JSON
    $local:LicenseContents = ((Get-Content $LicenseFile -Raw) -replace "`r","") -replace "`n","\n"
    $local:Ca = ((Get-Content $CaCertificateFile -Raw) -replace "`r","") -replace "`n","\n"
    $local:WebServer = ((Get-Content $WebServerCertificateFile -Raw) -replace "`r","") -replace "`n","\n"
    $local:WebServerKey = ((Get-Content $WebServerPrivateKeyFile -Raw) -replace "`r","") -replace "`n","\n"
    $local:TimeStamping = ((Get-Content $TimeStampingCertificateFile -Raw) -replace "`r","") -replace "`n","\n"
    $local:TimeStampingKey = ((Get-Content $TimeStampingPrivateKeyFile -Raw) -replace "`r","") -replace "`n","\n"

    # Prompt for / convert passwords
    if (-not $RootPassword)
    {
        $RootPassword = (Read-Host "SPS Root Password" -AsSecureString)
    }
    if (-not $AdminPassword)
    {
        $AdminPassword = (Read-Host "SPS Admin Password" -AsSecureString)
    }
    $local:RootPasswordPlainText = [System.Net.NetworkCredential]::new("", $RootPassword).Password
    $local:AdminPasswordPlainText = [System.Net.NetworkCredential]::new("", $AdminPassword).Password

    # Validate other inputs
    Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local
    if (-not (Test-IpAddress $Gateway))
    {
        throw "Gateway `"$Gateway`" is not an IP address"
    }
    $local:Parts = ($IpAddressWithNetMask -split '/')
    if ($local:Parts.Count -ne 2 -or -not (Test-IpAddress $local:Parts[0]) -or $local:Parts[1] -lt 0 -or $local:Parts[1] -gt 31)
    {
        throw "IpAddressWithNetMask `"$IpAddressWithNetMask`" must be CIDR format"
    }
    if (-not (Test-IpAddress $PrimaryDns))
    {
        throw "PrimaryDns `"$PrimaryDns` is not an IP address"
    }

    $local:JsonBody = @"
{
    "accept_eula": true,
    "license": "$local:LicenseContents",
    "administration": {
        "root_password": "$local:RootPasswordPlainText",
        "admin_password": "$local:AdminPasswordPlainText"
    },
    "certificates": {
        "ca": {
            "certificate": "$local:Ca"
        },
        "webserver": {
            "certificate": "$local:WebServer",
            "private_key": "$local:WebServerKey"
        },
        "tsa": {
            "certificate": "$local:TimeStamping",
            "private_key": "$local:TimeStampingKey"
        }
    },
    "network": {
        "hostname": "$HostName",
        "domainname": "$DomainName",
        "initial_address": "$IpAddressWithNetMask",
        "gateway": "$Gateway",
        "vlantag": null,
        "primary_dns": "$PrimaryDns"
    },
    "email": {
        "smtp_server": "$SmtpServer",
        "admin_email": "$AdminEmail"
    },
    "datetime": {
        "timezone": "$TimeZone",
        "primary_ntp_server": "$PrimaryNtpServer"
    }
}
"@
    Write-Host "Posting configuration data..."
    if ($PollOriginalIp)
    {
        $local:PollAddress = $Appliance
    }
    else
    {
        $local:PollAddress = $local:Parts[0]
    }
    # On an address change SPS does not return a response, and Invoke-RestMethod errors out
    try { $local:Status = (Invoke-RestMethod -Method POST -Headers @{'Content-type' = 'application/json'} -Timeout $Timeout `
                            -Uri "https://$($Appliance)/api/setup" -Body $local:JsonBody -SkipCertificateCheck).status }
    catch { $local:Status = "unknown" }

    Start-Sleep 5 # up front wait to solve new transition timing issues

    $local:StartTime = (Get-Date)
    $local:TimeElapsed = 10
    if ($Timeout -lt 10) { $Timeout = 10 }
    do {
        Write-Progress -Activity "Waiting for completed status" -Status "Current: $($local:Status)" -PercentComplete (($local:TimeElapsed / $Timeout) * 100)
        try { $local:Status = (Invoke-RestMethod -Method Get -Headers @{'Accept'='application/json'} -Uri "https://$($local:PollAddress)/api/setup" `
                                -SkipCertificateCheck -timeout $Timeout).status }
        catch { $local:Status = "unknown" }
        Start-Sleep 2
        $local:TimeElapsed = (((Get-Date) - $local:StartTime).TotalSeconds)
        if ($local:TimeElapsed -gt $Timeout)
        {
            throw "Timed out waiting for completed status, timeout was $Timeout seconds"
        }
    } until ($local:Status -ieq "completed" -or $local:Status -ieq "booting")
    Write-Progress -Activity "Waiting for completed status" -Status "Current: $($local:Status)" -PercentComplete 100
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

.PARAMETER LocalLogin
Enable authentication from the local database.

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
        [Parameter(Mandatory=$false)]
        [string]$Username,
        [Parameter(Mandatory=$false)]
        [SecureString]$Password,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [switch]$LocalLogin,
        [Parameter(Mandatory=$false)]
        [string]$CertificateFile,
        [Parameter(Mandatory=$false)]
        [string]$Thumbprint
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    
    if($CertificateFile){ $local:HttpSession = (Connect-Sps -SessionMaster $Appliance -CertificateFile $CertificateFile -Insecure:$Insecure)}
    elseif($Thumbprint){ $local:HttpSession = (Connect-Sps -SessionMaster $Appliance -Thumbprint $Thumbprint -Insecure:$Insecure)}
    else
    {
        if (-not $Password) {$Password = (Read-Host "Password" -AsSecureString) }
        $local:HttpSession = (Connect-Sps -SessionMaster $Appliance -SessionUsername $Username -SessionPassword $Password -Insecure:$Insecure -LocalLogin:$LocalLogin)
    }


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
through the API, call Show-SafeguardSpsEndpoint.  Then, you can follow to
the different API areas, such as configuration or health-status.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER Method
HTTP method verb you would like to use: GET, PUT, POST, DELETE.

.PARAMETER RelativeUrl
Relative portion of the Url you would like to call starting after /api.

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

.PARAMETER BodyOutput
A switch to just return the body as a PowerShell object.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Invoke-SafeguardSpsMethod GET starling/join

.EXAMPLE
Invoke-SafeguardSpsMethod GET / -JsonOutput

.EXAMPLE
Open-SafeguardSpsTransaction
$body = (Invoke-SafeguardSpsMethod GET configuration/management/email -BodyOutput)
$body.admin_address = "admin@mycompany.corp"
Invoke-SafeguardSpsMethod PUT configuration/management/email -Body $body
Close-SafeguardSpsTransaction
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
        [switch]$JsonOutput,
        [Parameter(Mandatory=$false)]
        [switch]$BodyOutput,
        [Parameter(Mandatory=$false)]
        [string]$InFile
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
        $arguments = @{
            Method = $Method;
            RelativeUrl = $RelativeUrl;
            Headers = $local:Headers;
            Body = $Body;
            JsonBody = $JsonBody;
            Parameters = $Parameters;
            InFile = $InFile;
        }
        if ($JsonOutput)
        {
            (Invoke-SpsInternal @arguments) | ConvertTo-Json -Depth 100
        }
        elseif ($BodyOutput)
        {
            $local:Response = (Invoke-SpsInternal @arguments)
            if ($local:Response.body)
            {
                $local:Response.body
            }
            else
            {
                Write-Verbose "No body returned in response"
            }
        }
        else
        {
            Invoke-SpsInternal @arguments
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

<#
.SYNOPSIS
Open a transaction for making changes via the Safeguard SPS Web API.

.DESCRIPTION
This cmdlet is used to create a transaction necessary to make changes via
the Safeguard SPS API.  Recent versions of SPS will open a transaction
automatically, but this cmdlet may be used to open a transaction explicitly.

In order to permanently save changes made via the Safeguard SPS API, you
must also call Close-SafeguardSpsTransaction or its alias
Save-SafeguardSpsTransaction.  Clear-SafeguardSpsTransaction can be used to
cancel changes.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Open-SafeguardSpsTransaction
$body = (Invoke-SafeguardSpsMethod GET configuration/management/email -BodyOutput)
$body.admin_address = "admin@mycompany.corp"
Invoke-SafeguardSpsMethod PUT configuration/management/email -Body $body
Close-SafeguardSpsTransaction
#>
function Open-SafeguardSpsTransaction
{
    [CmdletBinding()]
    Param(
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardSpsMethod POST transaction
}

<#
.SYNOPSIS
Close a transaction and save changes made via the Safeguard SPS Web API.

.DESCRIPTION
This cmdlet is used to end a transaction and permanently save the changes
made via the Safeguard SPS API.  This cmdlet is meant to be used with
Open-SafeguardSpsTransaction.  Save-SafeguardSpsTransaction is an alias
for this cmdlet.  Clear-SafeguardSpsTransaction can be used to cancel changes.

To see the status of a transaction, use Get-SafeguardSpsTransaction.  To
see only the changes that are about to be made via a transaction, use
Show-SafeguardSpsTransactionChange.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Open-SafeguardSpsTransaction
$body = (Invoke-SafeguardSpsMethod GET configuration/management/email -BodyOutput)
$body.admin_address = "admin@mycompany.corp"
Invoke-SafeguardSpsMethod PUT configuration/management/email -Body $body
Close-SafeguardSpsTransaction
#>
function Close-SafeguardSpsTransaction
{
    [CmdletBinding()]
    Param(
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardSpsMethod PUT transaction -Body @{ status = "commit" }
}
New-Alias -Name Save-SafeguardSpsTransaction -Value Close-SafeguardSpsTransaction

<#
.SYNOPSIS
Get the status of a transaction using the Safeguard SPS Web API.

.DESCRIPTION
This cmdlet will report the status of an SPS transaction.  The status 'closed'
means no transaction is pending.  The status 'open' means the transaction is
pending.  Close-SafeguardSpsTransaction can be used to permanently save changes.
Clear-SafeguardSpsTransaction can be used to cancel changes.  The remaining
seconds is the time before the transaction will cancel automatically and the
login session will be terminated.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Open-SafeguardSpsTransaction
$body = (Invoke-SafeguardSpsMethod GET configuration/management/email -BodyOutput)
$body.admin_address = "admin@mycompany.corp"
Invoke-SafeguardSpsMethod PUT configuration/management/email -Body $body
Get-SafeguardSpsTransaction
Clear-SafeguardSpsTransaction
#>
function Get-SafeguardSpsTransaction
{
    [CmdletBinding()]
    Param(
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:response = (Invoke-SafeguardSpsMethod GET transaction)
    $local:TransactionInfo = [ordered]@{
        Status = $local:response.body.status;
        CommitMessage = $local:response.body.commit_message;
        RemainingSeconds = $local:response.meta.remaining_seconds;
        Changes = @()
    }
    if ($local:response.meta.changes)
    {
        $local:Changes = (Invoke-SafeguardSpsMethod GET transaction/changes).changes
        if ($local:Changes) { $local:TransactionInfo.Changes = $local:Changes }
    }
    New-Object PSObject -Property $local:TransactionInfo
}

<#
.SYNOPSIS
Show the pending changes in a transaction using the Safeguard SPS Web API.

.DESCRIPTION
Transactions are required to make changes via the Safeguard SPS Web API.  The
transaction must be closed or saved before changes become permanent.  This cmdlet
will show what values will be permanently changed if the transaction is closed.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Open-SafeguardSpsTransaction
$body = (Invoke-SafeguardSpsMethod GET configuration/management/email -BodyOutput)
$body.admin_address = "admin@mycompany.corp"
Invoke-SafeguardSpsMethod PUT configuration/management/email -Body $body
Show-SafeguardSpsTransactionChange
#>
function Show-SafeguardSpsTransactionChange
{
    [CmdletBinding()]
    Param(
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    (Get-SafeguardSpsTransaction).Changes | ConvertTo-Json -Depth 100
}

<#
.SYNOPSIS
Cancel a transaction using the Safeguard SPS Web API.

.DESCRIPTION
Transactions are required to make changes via the Safeguard SPS Web API.  The
transaction must be closed or saved before changes become permanent.  This cmdlet
may be used to cancel pending changes.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Open-SafeguardSpsTransaction
$body = (Invoke-SafeguardSpsMethod GET configuration/management/email -BodyOutput)
$body.admin_address = "admin@mycompany.corp"
Invoke-SafeguardSpsMethod PUT configuration/management/email -Body $body
Get-SafeguardSpsTransaction
Clear-SafeguardSpsTransaction
#>
function Clear-SafeguardSpsTransaction
{
    [CmdletBinding()]
    Param(
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardSpsMethod DELETE transaction
}

<#
.SYNOPSIS
Call a method in the Safeguard SPS Web API.

.DESCRIPTION
Safeguard SPS Web API is implemented as HATEOAS. This cmdlet is helpful for
crawling through the API.  You can explore the different API areas, such as
configuration or health-status.

.PARAMETER RelativeUrl
Relative portion of the Url you would like to call starting after /api.

.EXAMPLE
Show-SafeguardSpsEndpoint configuration

.EXAMPLE
Show-SafeguardSpsEndpoint configuration/ssh/connections
#>
function Show-SafeguardSpsEndpoint
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,Position=0)]
        [string]$RelativeUrl
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $RelativeUrl) { $RelativeUrl = "/" }

    $local:Response = (Invoke-SafeguardSpsMethod GET $RelativeUrl)
    if ($local:Response.items)
    {
        $local:Response.items | Select-Object key,meta
    }
    else
    {
        $local:Response.meta.href
    }
}

<#
.SYNOPSIS
Gather join information from Safeguard SPS and open a browser to Starling to
complete the join via the Safeguard SPS Web API.

.DESCRIPTION
This cmdlet with call the Safeguard SPS API to determine the join status, and
if not joined, it will gather the information necessary to start the join
process using the system browser. The join process requires copying and pasting
credentials and token endpoint back from the browser to complete the join.
Credentials will not be echoed to the screen.

.PARAMETER Environment
Which Starling environment to join (default: prod)

.EXAMPLE
Invoke-SafeguardSpsStarlingJoinBrowser
#>
function Invoke-SafeguardSpsStarlingJoinBrowser
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,Position=0)]
        [ValidateSet("dev", "devtest", "stage", "prod", IgnoreCase=$true)]
        [string]$Environment = "prod"
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Info = (Invoke-SafeguardSpsMethod GET configuration/starling).body
    if ($local:Info.join_info)
    {
        Write-Host -ForegroundColor Yellow "Safeguard SPS is already joined to Starling"
        $local:Info.join_info
        Write-Host -ForegroundColor Yellow "You must unjoin before you can rejoin Starling"
    }
    else
    {
        $local:JoinBody = (Invoke-SafeguardSpsMethod GET starling/join).body
        $local:InstanceName = $local:JoinBody.product_instance
        $local:TimsLicense = $local:JoinBody.product_tims
        switch ($Environment)
        {
            "dev" { $local:Suffix = "-dev"; $Environment = "dev"; break }
            "devtest" { $local:Suffix = "-devtest"; $Environment = "devtest"; break }
            "stage" { $local:Suffix = "-stage"; $Environment = "stage"; break }
            "prod" { $local:Suffix = ""; $Environment = "prod"; break }
        }
        $local:JoinUrl = "https://account$($local:Suffix).cloud.oneidentity.com/join/Safeguard/$($local:InstanceName)/$($local:TimsLicense)"

        Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local

        Write-Host -ForegroundColor Yellow "This command will use an external browser to join Safeguard SPS ($($local:InstanceName)) to Starling ($Environment)."
        Write-host "You will be required to copy and paste interactively from the browser to answer prompts for join information."
        $local:Confirmed = (Get-Confirmation "Join to Starling" "Are you sure you want to use an external browser to join to Starling?" `
                                            "Show the browser." "Cancels this operation.")

        if ($local:Confirmed)
        {
            Start-Process $local:JoinUrl

            Write-Host "Following the successful join in the browser, provide the following:"
            $local:Creds = (Read-Host "Credential String" -MaskInput)
            $local:Endpoint = (Read-Host "Token Endpoint")
            $local:Body = [ordered]@{
                environment = $Environment;
                token_endpoint = $local:Endpoint;
                credential_string = $local:Creds;
            }
            $local:JoinBody | Add-Member -NotePropertyMembers $local:Body -TypeName PSCustomObject

            Invoke-SafeguardSpsMethod POST "starling/join" -Body $local:JoinBody

            Write-Host -ForegroundColor Yellow "You may close the external browser."
        }
    }
}

<#
.SYNOPSIS
Remove the Starling join via the Safeguard SPS Web API.

.DESCRIPTION
This cmdlet with call the Safeguard SPS API to remove a Starling join. You
cannot unjoin if SRA is enabled.

.EXAMPLE
Remove-SafeguardSpsStarlingJoin
#>
function Remove-SafeguardSpsStarlingJoin
{
    [CmdletBinding()]
    Param(
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardSpsMethod DELETE starling/join
}

<#
.SYNOPSIS
Enable Safeguard Remote Access in Starling via the Safeguard SPS Web API.

.DESCRIPTION
This cmdlet will enable Safeguard Remote Access in Starling if this Safeguard SPS
is joined to Starling.

.EXAMPLE
Enable-SafeguardSpsStarlingJoin
#>
function Enable-SafeguardSpsRemoteAccess
{
    [CmdletBinding()]
    Param(
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Info = (Invoke-SafeguardSpsMethod GET configuration/starling).Body
    if ($local:Info.remote_access.enabled)
    {
        Write-Warning "Safeguard Remote Access is already enabled"
    }
    else
    {
        $local:Info.remote_access.enabled = $true
        Open-SafeguardSpsTransaction
        Invoke-SafeguardSpsMethod PUT configuration/starling -Body $local:Info
        Save-SafeguardSpsTransaction
    }
}
New-Alias -Name Enable-SafeguardSpsSra -Value Enable-SafeguardSpsRemoteAccess

<#
.SYNOPSIS
Disable Safeguard Remote Access in Starling via the Safeguard SPS Web API.

.DESCRIPTION
This cmdlet will disable Safeguard Remote Access in Starling if this Safeguard SPS
is joined to Starling.

.EXAMPLE
Disable-SafeguardSpsRemoteAccess
#>
function Disable-SafeguardSpsRemoteAccess
{
    [CmdletBinding()]
    Param(
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Info = (Invoke-SafeguardSpsMethod GET configuration/starling).Body
    if ($local:Info.remote_access.enabled)
    {
        $local:Info.remote_access.enabled = $false
        Open-SafeguardSpsTransaction
        Invoke-SafeguardSpsMethod PUT configuration/starling -Body $local:Info
        Save-SafeguardSpsTransaction
    }
    else
    {
        Write-Warning "Safeguard Remote Access is already disabled"
    }
}
New-Alias -Name Disable-SafeguardSpsSra -Value Disable-SafeguardSpsRemoteAccess

<#
Get Safeguard SPS appliance information via the Web API.

.DESCRIPTION
This cmdlet will display basic information about Safeguard SPS.

.EXAMPLE
Get-SafeguardSpsInfo
#>
function Get-SafeguardSpsInfo
{
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0)]
        [string]
        $FilePath
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    (Invoke-SafeguardSpsMethod GET info).body
}

<#
.SYNOPSIS
Uploads a new firmware to SPS.

.DESCRIPTION
This command takes a path to an SPS firmware and uploads it to an open firmware slot.

.EXAMPLE
Import-SafeguardSpsFirmware -FilePath <path to sps .iso>
#>
function Import-SafeguardSpsFirmware
{
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0)]
        [string]
        $FilePath
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardSpsMethod POST upload/firmware -InFile $FilePath -ContentType 'application/x-iso9660-image'

}

<#
.SYNOPSIS
Get Safeguard SPS appliance version via the Web API.

.DESCRIPTION
This cmdlet will display the version of Safeguard SPS.

.EXAMPLE
Get-SafeguardSpsVersion

.EXAMPLE
Get-SafeguardSpsVersion -AltSyntax
#>
function Get-SafeguardSpsVersion
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [switch]$AltSyntax
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($AltSyntax)
    {
        (Get-SafeguardSpsInfo).version
    }
    else
    {
        (Get-SafeguardSpsInfo).firmware_version
    }
}

<#
.SYNOPSIS
Returns the SPS firmware slot information.

.DESCRIPTION
Returns the SPS firmware slot information.

.EXAMPLE
Get-SafeguardSpsFirmwareSlot
#>
function Get-SafeguardSpsFirmwareSlot
{
    [CmdletBinding()]
    Param(
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardSpsMethod GET firmware/slots
}

<#
.SYNOPSIS
Tests a firmware slot.

.DESCRIPTION
This command tests that the firmware slot contains valid firmware that can be installed and returns a boolean result.

.EXAMPLE
Test-SafeguardSpsFirmware -Slot 3
#>
function Test-SafeguardSpsFirmware
{
    [CmdletBinding()]
    Param(
        [parameter(Mandatory)]
        [int]$Slot
    )

    $Body = @{
        slot_id = $Slot
    }

    $summary = (Invoke-SafeguardSpsMethod POST firmware/test -Body $Body).body.test_summary
    Write-Verbose $summary
    return $summary.StartsWith("Upgrade is allowed;")
}

<#
.SYNOPSIS
Starts a firmware upgrade.

.DESCRIPTION
This command upgrades SPS with the firmware installed into the indicated slot.

.EXAMPLE
Install-SafeguardSpsFirmware -Slot 3 -Message "Upgrading SPS firmware..."
#>
function Install-SafeguardSpsFirmware
{
    [CmdletBinding()]
    Param(
        [parameter(Mandatory)]
        [int]$Slot,
        [parameter(Mandatory)]
        [string]$Message
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if(-not $Message)
    {
        $Message = "Upgrading SPS firmware..."
    }
    $Body = @{
        slot_id = $Slot
        message = $Message
    }

    Invoke-SafeguardSpsMethod POST firmware/upgrade -Body $Body
}

<#
.SYNOPSIS
Install-SafeguardSpsUpgrade

.DESCRIPTION
This command automates the steps for uploading and installing an SPS firmware upgrade.

.EXAMPLE
Install-SafeguardSpsPatch -FilePath <path to SPS .iso>
#>
function Install-SafeguardSpsUpgrade
{
    [CmdletBinding()]
    Param(
        [parameter(Mandatory, Position = 0)]
        [string]
        $FilePath,
        [parameter(Mandatory, Position = 1)]
        [string]
        $TargetVersion
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $activity = "Installing SPS upgrade"
    Write-Progress -Activity $activity -Status 'Importing firmware' -PercentComplete 15
    Import-SafeguardSpsFirmware $FilePath
    $slots = (Get-SafeguardSpsFirmwareSlot).items.body
    for($i = 0; $i -lt $slots.count; $i++)
    {
        if($slots[$i].version -ieq $TargetVersion)
        {
            Write-Progress -Activity $activity -Status "Testing firmware in slot $i" -PercentComplete 65
            if( Test-SafeguardSpsFirmware -Slot $i )
            {
                Write-Progress -Activity $activity -Status "Installing $TargetVersion from slot $i" -PercentComplete 75
                Install-SafeguardSpsFirmware -Slot $i -Message "Upgrading SPS firmware to $TargetVersion"
                Write-Progress -Activity $activity -Status "Finished" -PercentComplete 100
                Start-Sleep 60
                Write-Verbose "Waiting for SPS to restart..."
                for($i = 0; $i -lt 20; $i++)
                {
                    try
                    {
                        $currentVersion = Get-SafeguardSpsVersion
                        if($currentVersion -eq $TargetVersion)
                        {
                            Write-Host "Upgrade complete: SPS is at version $currentVersion"
                            return
                        }
                    }
                    catch {
                    }
                    Start-Sleep 15
                }
                throw "Timed out waiting for SPS to reach version $TargetVersion"
            }
            else
            {
                throw "Firmware at slot $i failed upgrade test. For details run: Test-SafeguardSpsFirmware -Slot $i"
            }
        }
    }
    throw "Firmware with version $TargetVersion could not be found in any firmware slot."
}

<#
.SYNOPSIS
Get-SafeguardSpsSupportBundle

.DESCRIPTION
This command downloads an SPS support bundle.

.PARAMETER OutFile
The output file name. If this is omitted, a unique name will be generated.

.EXAMPLE
Get-SafeguardSpsSupportBundle
#>
function Get-SafeguardSpsSupportBundle
{
    [CmdletBinding()]
    Param(
        [parameter(Mandatory = $false, Position = 0)]
        [string] $OutFile
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $pct = 5
    $activity = 'Get SPS Support Bundle'
    Write-Progress -Activity $activity -Status 'Generating support bundle' -PercentComplete $pct
    $response = Invoke-SafeguardSpsMethod POST troubleshooting/support-bundle
    $jobId = $response.key

    $maxTime = (Get-Date).AddMinutes(10)
    $pct += 15
    while((Get-Date) -lt $maxTime) {
        $status = Invoke-SafeguardSpsMethod GET "troubleshooting/support-bundle/$($jobId)"
        if($status.body.status -ieq "finished") {
            break;
        }
        start-sleep -Seconds 10
        $pct += 1
        Write-Progress -Activity $activity -Status 'Waiting for support bundle generation to complete' -PercentComplete $pct
    }

    if ((Get-Date) -gt $maxTime) {
        throw "Timed out waiting for support bundle generation."
    }

    $pct = 80
    Write-Progress -Activity $activity -Status 'Downloading support bundle' -PercentComplete $pct
    if(-not $OutFile) {
        $OutFile = "sps-$($safeguardspssession.Appliance)-$(get-date -f yyyy-MM-dd-HH-mm-ss).tar.gz"
    }

    Invoke-SafeguardSpsMethod GET "troubleshooting/support-bundle/$($jobId)/download" -OutFile $OutFile
    Write-Progress -Activity $activity -Status 'Deleting support bundle from SPS' -PercentComplete 90

    $null = Invoke-SafeguardSpsMethod DELETE "troubleshooting/support-bundle/$($jobId)"
    Write-Progress -Activity $activity -Status 'Complete' -PercentComplete 100

    Write-Host -ForegroundColor Green "Saved SPS support bundle to: $OutFile"
}
