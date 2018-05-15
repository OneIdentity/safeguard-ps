# Helper
function Invoke-SafeguardA2aMethodWithCertificate
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(ParameterSetName="File",Mandatory=$true)]
        [string]$CertificateFile,
        [Parameter(ParameterSetName="File",Mandatory=$false)]
        [SecureString]$Password,
        [Parameter(ParameterSetName="CertStore",Mandatory=$true)]
        [string]$Thumbprint,
        [Parameter(Mandatory=$false)]
        [string]$Authorization,
        [Parameter(Mandatory=$true)]
        [string]$Method,
        [Parameter(Mandatory=$true)]
        [string]$RelativeUrl,
        [Parameter(Mandatory=$false)]
        [int]$Version = 2,
        [Parameter(Mandatory=$false)]
        [object]$Body
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Import-Module -Name "$PSScriptRoot\sslhandling.psm1" -Scope Local
    try
    {
        if ($Insecure)
        {
            Disable-SslVerification
            if ($global:PSDefaultParameterValues) { $PSDefaultParameterValues = $global:PSDefaultParameterValues.Clone() }
        }

        $local:Headers = @{
                "Accept" = "application/json";
                "Content-type" = "application/json"
            }

        if ($Authorization)
        {
            $local:Headers["Authorization"] = $Authorization
        }

        Write-Verbose "---Request---"
        Write-Verbose "Headers=$(ConvertTo-Json -InputObject $Headers)"

        $local:BodyInternal = $null
        if ($Body) 
        {
            $local:BodyInternal = (ConvertTo-Json -InputObject $Body)
            Write-Verbose "---Request Body---"
            Write-Verbose "$($local:BodyInternal)"
        }

        if (-not $Thumbprint)
        {
            Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local
            $local:Cert = (Use-CertificateFile $CertificateFile $Password)      
            Invoke-RestMethod -Certificate $local:Cert -Method $Method -Headers $local:Headers `
                -Uri "https://$Appliance/service/a2a/v$Version/$RelativeUrl" -Body $local:BodyInternal
        }
        else
        {
            Invoke-RestMethod -CertificateThumbprint $Thumbprint -Method $Method -Headers $local:Headers `
                -Uri "https://$Appliance/service/a2a/v$Version/$RelativeUrl" -Body $local:BodyInternal
        }
    }
    catch
    {
        if ($_.Exception.Response)
        {
            Write-Verbose "---Response Status---"
            Write-Verbose "$([int]$_.Exception.Response.StatusCode) $($_.Exception.Response.StatusDescription)"
            Write-Verbose "---Response Body---"
            $local:Stream = $_.Exception.Response.GetResponseStream()
            $local:Reader = New-Object System.IO.StreamReader($local:Stream)
            $local:Reader.BaseStream.Position = 0
            $local:Reader.DiscardBufferedData()
            Write-Verbose $local:Reader.ReadToEnd()
            $local:Reader.Dispose()
        }
        Write-Verbose "---Exception---"
        $_.Exception | Format-List * -Force | Out-String | Write-Verbose
        if ($_.Exception.InnerException)
        {
            Write-Verbose "---Inner Exception---"
            $_.Exception.InnerException | Format-List * -Force | Out-String | Write-Verbose
        }
        throw $_.Exception
    }
    finally
    {
        if ($Insecure)
        {
            Enable-SslVerification
            if ($global:PSDefaultParameterValues) { $PSDefaultParameterValues = $global:PSDefaultParameterValues.Clone() }
        }
    }
}
function Invoke-SafeguardA2aCredentialRetrieval
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [string]$CertificateFile,
        [Parameter(Mandatory=$false)]
        [SecureString]$Password,
        [Parameter(Mandatory=$false)]
        [string]$Thumbprint,
        [Parameter(Mandatory=$false)]
        [string]$Authorization,
        [Parameter(Mandatory=$false)]
        [ValidateSet("Password","Key",IgnoreCase=$true)]
        [string]$CredentialType
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    switch ($CredentialType)
    {
        "password" { $CredentialType = "Password"; break }
        "key" { $CredentialType = "Key"; break }
    }

    if (-not $Thumbprint)
    {
        Invoke-SafeguardA2aMethodWithCertificate -Insecure:$Insecure -Appliance $Appliance -Authorization $Authorization `
            -CertificateFile $CertificateFile -Password $Password -Method GET -RelativeUrl "Credentials?type=$CredentialType"
    }
    else
    {
        Invoke-SafeguardA2aMethodWithCertificate -Insecure:$Insecure -Appliance $Appliance -Authorization $Authorization `
            -Thumbprint $Thumbprint -Method GET -RelativeUrl "Credentials?type=$CredentialType"
    }
}

<#
.SYNOPSIS
Get an account password from Safeguard via the A2A service of the Web API.

.DESCRIPTION
The purpose of this cmdlet is to retrieve a single password without having to
go through access request workflow.  Passwords retrieve using this cmdlet must
be configured as part of an A2A registration.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER CertificateFile
A string containing the path to a certificate file to use for authentication.

.PARAMETER Password
A secure string containing the password for decrypting the certificate file.

.PARAMETER Thumbprint
A string containing the thumbprint of a certificate the system certificate store.

.PARAMETER ApiKey
A string containing the API key that identifies the account being requested.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardA2aPassword -Appliance 10.5.32.54 -CertificateFile C:\certs\file.pfx -Password $pass -ApiKey 6A4psUnrLv1hvoWSB3jsm2V50eFT62vwAI9Zlj/dDWw=

.EXAMPLE
Get-SafeguardA2aPassword 10.5.32.54 6A4psUnrLv1hvoWSB3jsm2V50eFT62vwAI9Zlj/dDWw= -Thumbprint 756766BB590D7FA9CA9E1971A4AE41BB9CEC82F1
#>
function Get-SafeguardA2aPassword
{
    [CmdletBinding(DefaultParameterSetName="CertStore")]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(ParameterSetName="File",Mandatory=$true)]
        [string]$CertificateFile,
        [Parameter(ParameterSetName="File",Mandatory=$false)]
        [SecureString]$Password,
        [Parameter(ParameterSetName="CertStore",Mandatory=$true)]
        [string]$Thumbprint,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$ApiKey
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PsCmdlet.ParameterSetName -eq "CertStore")
    {
        Invoke-SafeguardA2aCredentialRetrieval -Insecure:$Insecure -Appliance $Appliance -Authorization "A2A $ApiKey" `
            -Thumbprint $Thumbprint -CredentialType Password
    }
    else
    {
        Invoke-SafeguardA2aCredentialRetrieval -Insecure:$Insecure -Appliance $Appliance -Authorization "A2A $ApiKey" `
            -CertificateFile $CertificateFile -Password $Password -CredentialType Password
    }
}

<#
.SYNOPSIS
Get an account private key from Safeguard via the A2A service of the Web API.

.DESCRIPTION
The purpose of this cmdlet is to retrieve a single password without having to
go through access request workflow.  Passwords retrieve using this cmdlet must
be configured as part of an A2A registration.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER CertificateFile
A string containing the path to a certificate file to use for authentication.

.PARAMETER Password
A secure string containing the password for decrypting the certificate file.

.PARAMETER Thumbprint
A string containing the thumbprint of a certificate the system certificate store.

.PARAMETER ApiKey
A string containing the API key that identifies the account being requested.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardA2aPrivateKey -Appliance 10.5.32.54 -CertificateFile C:\certs\file.pfx -Password $pass -ApiKey 6A4psUnrLv1hvoWSB3jsm2V50eFT62vwAI9Zlj/dDWw=

.EXAMPLE
Get-SafeguardA2aPrivateKey 10.5.32.54 6A4psUnrLv1hvoWSB3jsm2V50eFT62vwAI9Zlj/dDWw= -Thumbprint 756766BB590D7FA9CA9E1971A4AE41BB9CEC82F1
#>
function Get-SafeguardA2aPrivateKey
{
    [CmdletBinding(DefaultParameterSetName="CertStore")]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(ParameterSetName="File",Mandatory=$true)]
        [string]$CertificateFile,
        [Parameter(ParameterSetName="File",Mandatory=$false)]
        [SecureString]$Password,
        [Parameter(ParameterSetName="CertStore",Mandatory=$true)]
        [string]$Thumbprint,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$ApiKey
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PsCmdlet.ParameterSetName -eq "CertStore")
    {
        Invoke-SafeguardA2aCredentialRetrieval -Insecure:$Insecure -Appliance $Appliance -Authorization "A2A $ApiKey" `
            -Thumbprint $Thumbprint -CredentialType Key
    }
    else
    {
        Invoke-SafeguardA2aCredentialRetrieval -Insecure:$Insecure -Appliance $Appliance -Authorization "A2A $ApiKey" `
            -CertificateFile $CertificateFile -Password $Password -CredentialType Key
    }
}

<#
.SYNOPSIS
Create a new access request on behalf of another Safeguard user using the A2A
service and a configure access request broker.

.DESCRIPTION
This cmdlet will create an access request on behalf of a Safeguard user.  The
A2A certificate user cannot actually access the password or the session.  It just
creates the access request, and the target user will be notified via SignalR.  The
target user can then enter the session or view the password.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER CertificateFile
A string containing the path to a certificate file to use for authentication.

.PARAMETER Password
A secure string containing the password for decrypting the certificate file.

.PARAMETER Thumbprint
A string containing the thumbprint of a certificate the system certificate store.

.PARAMETER ApiKey
A string containing the API key that identifies the account being requested.

.PARAMETER ForProviderName
A string containing the name of the identity provider of the user to create the request for.

.PARAMETER ForUserName
A string containing the name of the user to create the request for.

.PARAMETER AssetToUse
A string containing the name of the asset to request.

.PARAMETER AccountToUse
A string containing the name of the account to request.

.PARAMETER AccessRequestType
A string containing the type of access request to make.

.PARAMETER Emergency
Whether the access request is an emergency.

.PARAMETER ReasonCode
An integer containing the reason code ID or a string containing the name.

.PARAMETER ReasonComment
A string containing the reason comment for the access request.

.PARAMETER TicketNumber
A string containing the ticket number for the access request.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
New-SafeguardA2aAccessRequest

.EXAMPLE
New-SafeguardA2aAccessRequest 10.5.32.23 -CertificateFile .\CERT.pfx UK1Pf45hvWa7OVBu4l87U3dvgydWXMElRZhQ3DDYVwo= TestUser linux.sample.com root SSH
#>
function New-SafeguardA2aAccessRequest
{
    [CmdletBinding(DefaultParameterSetName="CertStore")]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(ParameterSetName="File",Mandatory=$true)]
        [string]$CertificateFile,
        [Parameter(ParameterSetName="File",Mandatory=$false)]
        [SecureString]$Password,
        [Parameter(ParameterSetName="CertStore",Mandatory=$true)]
        [string]$Thumbprint,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$ApiKey,
        [Parameter(Mandatory=$false)]
        [string]$ForProviderName,
        [Parameter(Mandatory=$true,Position=2)]
        [string]$ForUserName,
        [Parameter(Mandatory=$true,Position=3)]
        [string]$AssetToUse,
        [Parameter(Mandatory=$true,Position=4)]
        [string]$AccountToUse,
        [Parameter(Mandatory=$true,Position=5)]
        [ValidateSet("Password", "SSH", "RemoteDesktop", "RDP", IgnoreCase=$true)]
        [string]$AccessRequestType,
        [Parameter(Mandatory=$false)]
        [switch]$Emergency = $false,
        [Parameter(Mandatory=$false)]
        [object]$ReasonCode,
        [Parameter(Mandatory=$false)]
        [string]$ReasonComment,
        [Parameter(Mandatory=$false)]
        [string]$TicketNumber
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($AccessRequestType -ieq "RDP")
    {
        $AccessRequestType = "RemoteDesktop"
    }

    ### We need to figure out how we are going to resolve Asset and Account IDs

    $local:Body = @{
        ForUser = $ForUserName;
        SystemName = $AssetToUse;
        AccountName = $AccountToUse;
        AccessRequestType = "$AccessRequestType"
    }

    if ($ForProviderName) {$local:Body["ForProvider"] = $ForProviderName }

    if ($Emergency) { $local:Body["IsEmergency"] = $true }
    if ($ReasonCode)
    {
        Import-Module -Name "$PSScriptRoot\sg-utilities.psm1" -Scope Local
        $local:ReasonCodeId = (Resolve-ReasonCodeId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $ReasonCode)
        $local:Body["ReasonCode"] = $local:ReasonCodeId
    }
    if ($ReasonComment) { $local:Body["ReasonComment"] = $ReasonComment }
    if ($TicketNumber) { $local:Body["TicketNumber"] = $TicketNumber }

    if ($PsCmdlet.ParameterSetName -eq "CertStore")
    {
        Invoke-SafeguardA2aMethodWithCertificate -Insecure:$Insecure -Appliance $Appliance -Authorization "A2A $ApiKey" `
            -Thumbprint $Thumbprint -Method POST -RelativeUrl AccessRequests -Body $local:Body
    }
    else
    {
        Invoke-SafeguardA2aMethodWithCertificate -Insecure:$Insecure -Appliance $Appliance -Authorization "A2A $ApiKey" `
            -CertificateFile $CertificateFile -Password $Password -Method POST -RelativeUrl AccessRequests -Body $local:Body
    }
}
