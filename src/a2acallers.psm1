<# Copyright (c) 2026 One Identity LLC. All rights reserved. #>
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
        [ValidateSet("a2a", "core", IgnoreCase=$true)]
        [string]$Service,
        [Parameter(Mandatory=$true)]
        [string]$Method,
        [Parameter(Mandatory=$true)]
        [string]$RelativeUrl,
        [Parameter(Mandatory=$false)]
        [int]$Version = 4,
        [Parameter(Mandatory=$false)]
        [object]$Body
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Import-Module -Name "$PSScriptRoot\sslhandling.psm1" -Scope Local

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

    $Service = $Service.ToLower()

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
    }

    try
    {
        if (-not $Thumbprint)
        {
            if (-not $local:BodyInternal)
            {
                Invoke-RestMethod -Certificate $local:Cert -Method $Method -Headers $local:Headers `
                    -Uri "https://$Appliance/service/$Service/v$Version/$RelativeUrl"
            }
            else
            {
                Invoke-RestMethod -Certificate $local:Cert -Method $Method -Headers $local:Headers `
                    -Uri "https://$Appliance/service/$Service/v$Version/$RelativeUrl" -Body ([System.Text.Encoding]::UTF8.GetBytes($local:BodyInternal))
            }
        }
        else
        {
            if (-not $local:BodyInternal)
            {
                Invoke-RestMethod -CertificateThumbprint $Thumbprint -Method $Method -Headers $local:Headers `
                    -Uri "https://$Appliance/service/$Service/v$Version/$RelativeUrl"
            }
            else
            {
                Invoke-RestMethod -CertificateThumbprint $Thumbprint -Method $Method -Headers $local:Headers `
                    -Uri "https://$Appliance/service/$Service/v$Version/$RelativeUrl" -Body ([System.Text.Encoding]::UTF8.GetBytes($local:BodyInternal))
            }
        }
    }
    catch
    {
        Write-Warning "An exception was caught trying to call A2A using a certificate."
        Write-Warning "If you are experiencing a certificate connection failure, your problem may be a quirk on Windows where"
        Write-Warning "the low-level HTTPS client requires that the Issuing CA be in your 'Intermediate Certificate Authorities'"
        Write-Warning "store, otherwise Windows doesn't think you have a matching certificate to send in the initial client"
        Write-Warning "connection. This occurs even if you pass in a PFX file specifying exactly which certificate to use."
        Import-Module -Name "$PSScriptRoot\sg-utilities.psm1" -Scope Local
        Out-SafeguardExceptionIfPossible $_
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
        [ValidateSet("Password","PrivateKey","ApiKey",IgnoreCase=$true)]
        [string]$CredentialType,
        [Parameter(Mandatory=$false)]
        [ValidateSet("OpenSsh","Ssh2","Putty",IgnoreCase=$true)]
        [string]$KeyFormat = $null,
        [Parameter(Mandatory=$false)]
        [int]$Version = 4
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    switch ($CredentialType)
    {
        "password" { $CredentialType = "Password"; break }
        "privatekey" { $CredentialType = "PrivateKey"; break }
        "apikey" { $CredentialType = "ApiKey"; break }
    }

    $local:RelativeUrl = "Credentials?type=$CredentialType"
    if ($KeyFormat)
    {
        switch ($KeyFormat)
        {
            "openssh" { $KeyFormat = "OpenSsh"; break }
            "ssh2" { $KeyFormat = "Ssh2"; break }
            "putty" { $KeyFormat = "Putty"; break }
        }
        $local:RelativeUrl = "Credentials?type=$CredentialType&keyFormat=$KeyFormat"
    }

    if (-not $Thumbprint)
    {
        Invoke-SafeguardA2aMethodWithCertificate -Insecure:$Insecure -Appliance $Appliance -Authorization $Authorization `
            -CertificateFile $CertificateFile -Password $Password -Service a2a -Method GET -RelativeUrl $local:RelativeUrl -Version $Version
    }
    else
    {
        Invoke-SafeguardA2aMethodWithCertificate -Insecure:$Insecure -Appliance $Appliance -Authorization $Authorization `
            -Thumbprint $Thumbprint -Service a2a -Method GET -RelativeUrl $local:RelativeUrl -Version $Version
    }
}

<#
.SYNOPSIS
Get a list of all the accounts retrievable from the A2A service using this
certificate user.

.DESCRIPTION
The purpose of this cmdlet is to know which accounts can be retrieved using A2A
without having to go through access request workflow.  This cmdlet will also
give the API Key to use to request the account.

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

.PARAMETER Version
Version of the Web API you are using (default: 4).

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardA2aRetrievableAccount -Appliance 10.5.32.54 -CertificateFile C:\certs\file.pfx -Password $pass

.EXAMPLE
Get-SafeguardA2aRetrievableAccount 10.5.32.54 -Thumbprint 756766BB590D7FA9CA9E1971A4AE41BB9CEC82F1
#>
function Get-SafeguardA2aRetrievableAccount
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
        [Parameter(Mandatory=$false)]
        [int]$Version = 4
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $Thumbprint)
    {
        if (-not $Password)
        {
            $Password = (Read-Host "Password" -AsSecureString)
        }
        $local:Registrations = (Invoke-SafeguardA2aMethodWithCertificate -Insecure:$Insecure -Appliance $Appliance -Version $Version `
            -CertificateFile $CertificateFile -Password $Password -Service core -Method GET -RelativeUrl "A2ARegistrations")
    }
    else
    {
        $local:Registrations = (Invoke-SafeguardA2aMethodWithCertificate -Insecure:$Insecure -Appliance $Appliance -Version $Version `
            -Thumbprint $Thumbprint -Service core -Method GET -RelativeUrl "A2ARegistrations")
    }
    $local:Registrations | ForEach-Object {
        $local:Reg = $_
        if (-not $Thumbprint)
        {
            $local:Accounts = (Invoke-SafeguardA2aMethodWithCertificate -Insecure:$Insecure -Appliance $Appliance -Version $Version `
                -CertificateFile $CertificateFile -Password $Password -Service core -Method GET -RelativeUrl "A2ARegistrations/$($local:Reg.Id)/RetrievableAccounts")
        }
        else
        {
            $local:Accounts = (Invoke-SafeguardA2aMethodWithCertificate -Insecure:$Insecure -Appliance $Appliance -Version $Version `
                -Thumbprint $Thumbprint -Service core -Method GET -RelativeUrl "A2ARegistrations/$($local:Reg.Id)/RetrievableAccounts")
        }
        $local:Accounts | ForEach-Object {
            $local:Disabled = $local:Reg.Disabled
            if (-not $local:Disabled -and $_.AccountDisabled)
            {
                $local:Disabled = $true
            }
            New-Object PSObject -Property ([ordered]@{
                AppName = $local:Reg.AppName;
                Description = $local:Reg.Description;
                Disabled = $local:Disabled;
                CertificateUserId = $local:Reg.CertificateUserId;
                CertificateUser = $local:Reg.CertificateUser;
                CertificateUserThumbprint = $local:Reg.CertificateUserThumbprint;
                ApiKey = $_.ApiKey;
                AssetId = $_.AssetId;
                AssetName = $_.AssetName;
                NetworkAddress = $_.NetworkAddress;
                AccountId = $_.AccountId;
                AccountName = $_.AccountName;
                DomainName = $_.DomainName;
                AccountType = $_.AccountType;
            })
        }
    }
}

<#
.SYNOPSIS
Get an account password from Safeguard via the A2A service of the Web API.

.DESCRIPTION
The purpose of this cmdlet is to retrieve a single password without having to
go through access request workflow.  Passwords retrieved using this cmdlet must
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

.PARAMETER Version
Version of the Web API you are using (default: 4).

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
        [string]$ApiKey,
        [Parameter(Mandatory=$false)]
        [int]$Version = 4
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PsCmdlet.ParameterSetName -eq "CertStore")
    {
        Invoke-SafeguardA2aCredentialRetrieval -Insecure:$Insecure -Appliance $Appliance -Authorization "A2A $ApiKey" `
            -Thumbprint $Thumbprint -CredentialType Password -Version $Version
    }
    else
    {
        Invoke-SafeguardA2aCredentialRetrieval -Insecure:$Insecure -Appliance $Appliance -Authorization "A2A $ApiKey" `
            -CertificateFile $CertificateFile -Password $Password -CredentialType Password -Version $Version
    }
}

<#
.SYNOPSIS
Set an account password to Safeguard via the A2A service of the Web API.

.DESCRIPTION
The purpose of this cmdlet is to allow A2A users to set a single password.
Passwords set using this cmdlet must be configured as part of an A2A registration.

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

.PARAMETER NewPassword
A SecureString containing the new password to set. If not provided, you will be prompted to enter it.

.PARAMETER Version
Version of the Web API you are using (default: 4).

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Set-SafeguardA2aPassword -Appliance 10.5.32.54 -CertificateFile C:\certs\file.pfx -Password $pass -ApiKey 6A4psUnrLv1hvoWSB3jsm2V50eFT62vwAI9Zlj/dDWw=

.EXAMPLE
Set-SafeguardA2aPassword 10.5.32.54 6A4psUnrLv1hvoWSB3jsm2V50eFT62vwAI9Zlj/dDWw= -Thumbprint 756766BB590D7FA9CA9E1971A4AE41BB9CEC82F1
#>
function Set-SafeguardA2aPassword
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
        [Parameter(Mandatory=$false,Position=2)]
        [SecureString]$NewPassword,
        [Parameter(Mandatory=$false)]
        [int]$Version = 4
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $NewPassword)
    {
        $NewPassword = (Read-Host -AsSecureString "NewPassword")
    }
    $local:PasswordPlainText = [System.Net.NetworkCredential]::new("", $NewPassword).Password

    if ($PsCmdlet.ParameterSetName -eq "CertStore")
    {
        Invoke-SafeguardA2aMethodWithCertificate -Insecure:$Insecure -Appliance $Appliance -Authorization "A2A $ApiKey" `
            -Thumbprint $Thumbprint -Service a2a -Method PUT -RelativeUrl Credentials/Password -Body $local:PasswordPlainText -Version $Version
    }
    else
    {
        Invoke-SafeguardA2aMethodWithCertificate -Insecure:$Insecure -Appliance $Appliance -Authorization "A2A $ApiKey"  -Version $Version `
            -CertificateFile $CertificateFile -Password $Password -Service a2a -Method PUT -RelativeUrl Credentials/Password -Body $local:PasswordPlainText
    }

}

<#
.SYNOPSIS
Get an account private key from Safeguard via the A2A service of the Web API.

.DESCRIPTION
The purpose of this cmdlet is to retrieve a single private key without having to
go through access request workflow.  Private keys retrieved using this cmdlet must
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

.PARAMETER KeyFormat
A string containing which format to use for the private key.  The options are:
  - OpenSsh: OpenSSH legacy PEM format (default)
  - Ssh2: Tectia format for use with tools from SSH.com
  - Putty: Putty format for use with PuTTY tools

.PARAMETER Version
Version of the Web API you are using (default: 4).

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
        [string]$ApiKey,
        [Parameter(Mandatory=$false)]
        [ValidateSet("OpenSsh","Ssh2","Putty",IgnoreCase=$true)]
        [string]$KeyFormat = $null,
        [Parameter(Mandatory=$false)]
        [int]$Version = 4
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PsCmdlet.ParameterSetName -eq "CertStore")
    {
        if ($KeyFormat)
        {
            Invoke-SafeguardA2aCredentialRetrieval -Insecure:$Insecure -Appliance $Appliance -Authorization "A2A $ApiKey" `
                -Thumbprint $Thumbprint -CredentialType PrivateKey -KeyFormat $KeyFormat -Version $Version
        }
        else
        {
            Invoke-SafeguardA2aCredentialRetrieval -Insecure:$Insecure -Appliance $Appliance -Authorization "A2A $ApiKey" `
                -Thumbprint $Thumbprint -CredentialType PrivateKey -Version $Version
        }
    }
    else
    {
        if ($KeyFormat)
        {
            Invoke-SafeguardA2aCredentialRetrieval -Insecure:$Insecure -Appliance $Appliance -Authorization "A2A $ApiKey" `
                -CertificateFile $CertificateFile -Password $Password -CredentialType PrivateKey -KeyFormat $KeyFormat -Version $Version
        }
        else
        {
            Invoke-SafeguardA2aCredentialRetrieval -Insecure:$Insecure -Appliance $Appliance -Authorization "A2A $ApiKey" `
                -CertificateFile $CertificateFile -Password $Password -CredentialType PrivateKey -Version $Version
        }
    }
}

<#
.SYNOPSIS
Set an account private key to Safeguard via the A2A service of the Web API.

.DESCRIPTION
The purpose of this cmdlet is to allow A2A users to set a single private key.
Private keys set using this cmdlet must be configured as part of an A2A registration.

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

.PARAMETER KeyFormat
A string containing which format to use for the private key.  The options are:
  - OpenSsh: OpenSSH legacy PEM format (default)
  - Ssh2: Tectia format for use with tools from SSH.com
  - Putty: Putty format for use with PuTTY tools

.PARAMETER PrivateKey
A string containing the private key to set.

.PARAMETER PrivateKeyPassphrase
A SecureString containing the passphrase for the private key (optional).

.PARAMETER Version
Version of the Web API you are using (default: 4).

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Set-SafeguardA2aPrivateKey -Appliance 10.5.32.54 -CertificateFile C:\certs\file.pfx -Password $pass -ApiKey 6A4psUnrLv1hvoWSB3jsm2V50eFT62vwAI9Zlj/dDWw=

.EXAMPLE
Set-SafeguardA2aPrivateKey 10.5.32.54 6A4psUnrLv1hvoWSB3jsm2V50eFT62vwAI9Zlj/dDWw= -Thumbprint 756766BB590D7FA9CA9E1971A4AE41BB9CEC82F1
#>
function Set-SafeguardA2aPrivateKey
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
        [ValidateSet("OpenSsh","Ssh2","Putty",IgnoreCase=$true)]
        [string]$KeyFormat = $null,
        [Parameter(Mandatory=$false)]
        [SecureString]$PrivateKeyPassphrase,
        [Parameter(Mandatory=$true)]
        [string]$PrivateKey,
        [Parameter(Mandatory=$false)]
        [int]$Version = 4
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $PrivateKeyPassphrase)
    {
        $PrivateKeyPassphrase = (Read-Host -AsSecureString "PrivateKeyPassphrase")
    }
    $local:PasswordPlainText = [System.Net.NetworkCredential]::new("", $PrivateKeyPassphrase).Password

    #$local:PrivateKeyPlainText = (Get-Content $PrivateKeyFile) -join ""

    $local:Body = @{
        "Passphrase" = $local:PasswordPlainText
        "PrivateKey" = $local:PrivateKey
    }

    $local:RelativeUrl = "Credentials/SshKey"
    if ($KeyFormat)
    {
        switch ($KeyFormat)
        {
            "openssh" { $KeyFormat = "OpenSsh"; break }
            "ssh2" { $KeyFormat = "Ssh2"; break }
            "putty" { $KeyFormat = "Putty"; break }
        }
        $local:RelativeUrl = "Credentials/SshKey?keyFormat=$KeyFormat"
    }

    if ($PsCmdlet.ParameterSetName -eq "CertStore")
    {
        Invoke-SafeguardA2aMethodWithCertificate -Insecure:$Insecure -Appliance $Appliance -Authorization "A2A $ApiKey" `
            -Thumbprint $Thumbprint -Service a2a -Method PUT -RelativeUrl $local:RelativeUrl -Body $local:Body -Version $Version
    }
    else
    {
        Invoke-SafeguardA2aMethodWithCertificate -Insecure:$Insecure -Appliance $Appliance -Authorization "A2A $ApiKey" `
            -CertificateFile $CertificateFile -Password $Password -Service a2a -Method PUT -RelativeUrl $local:RelativeUrl -Body $local:Body -Version $Version
    }
}

<#
.SYNOPSIS
Get an account API key secret from Safeguard via the A2A service of the Web API.

.DESCRIPTION
The purpose of this cmdlet is to retrieve an API key secret without having to
go through access request workflow.  Accounts may have more than one API key
secret associated, so this cmdlet returns an array of objects, each representing
an API key secret.  API key secrets retrieved using this cmdlet must be configured
as part of an A2A registration.

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

.PARAMETER Version
Version of the Web API you are using (default: 4).

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardA2aApiKeySecret -Appliance 10.5.32.54 -CertificateFile C:\certs\file.pfx -Password $pass -ApiKey 6A4psUnrLv1hvoWSB3jsm2V50eFT62vwAI9Zlj/dDWw=

.EXAMPLE
Get-SafeguardA2aApiKeySecret 10.5.32.54 6A4psUnrLv1hvoWSB3jsm2V50eFT62vwAI9Zlj/dDWw= -Thumbprint 756766BB590D7FA9CA9E1971A4AE41BB9CEC82F1
#>
function Get-SafeguardA2aApiKeySecret
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
        [int]$Version = 4
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PsCmdlet.ParameterSetName -eq "CertStore")
    {
        Invoke-SafeguardA2aCredentialRetrieval -Insecure:$Insecure -Appliance $Appliance -Authorization "A2A $ApiKey" `
            -Thumbprint $Thumbprint -CredentialType ApiKey -Version $Version
    }
    else
    {
        Invoke-SafeguardA2aCredentialRetrieval -Insecure:$Insecure -Appliance $Appliance -Authorization "A2A $ApiKey" `
            -CertificateFile $CertificateFile -Password $Password -CredentialType ApiKey -Version $Version
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

.PARAMETER ForUserId
An integer containing the ID of the user to create the request for.

.PARAMETER AssetToUse
A string containing the name of the asset to request.

.PARAMETER AssetIdToUse
An integer containing the ID of the asset to request.

.PARAMETER AccountToUse
A string containing the name of the account to request.

.PARAMETER AccountIdToUse
An integer containing the ID of the account to request

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

.PARAMETER RequestedFor
A string containing the UTC date/time the request becomes active.  For example: "2018-10-17T12:11:12Z".

.PARAMETER RequestedDurationDays
An integer containing the number of days for the request duration (0-31).

.PARAMETER RequestedDurationHours
An integer containing the number of hours for the request duration (0-23).

.PARAMETER RequestedDurationMinutes
An integer containing the number of minutes for the request duration (0-59).

.PARAMETER Version
Version of the Web API you are using (default: 4).

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
    [CmdletBinding(DefaultParameterSetName="CertStoreAndNames")]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(ParameterSetName="FileAndNames",Mandatory=$true)]
        [Parameter(ParameterSetName="FileAndIds",Mandatory=$true)]
        [string]$CertificateFile,
        [Parameter(ParameterSetName="FileAndNames",Mandatory=$false)]
        [Parameter(ParameterSetName="FileAndIds",Mandatory=$false)]
        [SecureString]$Password,
        [Parameter(ParameterSetName="CertStoreAndNames",Mandatory=$true)]
        [Parameter(ParameterSetName="CertStoreAndIds",Mandatory=$true)]
        [string]$Thumbprint,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$ApiKey,
        [Parameter(Mandatory=$false)]
        [string]$ForProviderName,
        [Parameter(ParameterSetName="FileAndNames",Mandatory=$true,Position=2)]
        [Parameter(ParameterSetName="CertStoreAndNames",Mandatory=$true,Position=2)]
        [string]$ForUserName,
        [Parameter(ParameterSetName="FileAndIds",Mandatory=$true,Position=2)]
        [Parameter(ParameterSetName="CertStoreAndIds",Mandatory=$true,Position=2)]
        [int]$ForUserId,
        [Parameter(ParameterSetName="FileAndNames",Mandatory=$true,Position=3)]
        [Parameter(ParameterSetName="CertStoreAndNames",Mandatory=$true,Position=3)]
        [string]$AssetToUse,
        [Parameter(ParameterSetName="FileAndIds",Mandatory=$true,Position=3)]
        [Parameter(ParameterSetName="CertStoreAndIds",Mandatory=$true,Position=3)]
        [int]$AssetIdToUse,
        [Parameter(ParameterSetName="FileAndNames",Mandatory=$false,Position=4)]
        [Parameter(ParameterSetName="CertStoreAndNames",Mandatory=$false,Position=4)]
        [string]$AccountToUse,
        [Parameter(ParameterSetName="FileAndIds",Mandatory=$false,Position=4)]
        [Parameter(ParameterSetName="CertStoreAndIds",Mandatory=$false,Position=4)]
        [int]$AccountIdToUse,
        [Parameter(Mandatory=$false,Position=5)]
        [ValidateSet("Password", "SSHKey", "SSH", "RemoteDesktop", "RDP", "RemoteDesktopApplication", "RDPApplication", "RDPApp", "Telnet", "APIKey", "File", IgnoreCase=$true)]
        [string]$AccessRequestType,
        [Parameter(Mandatory=$false)]
        [switch]$Emergency = $false,
        [Parameter(Mandatory=$false)]
        [object]$ReasonCode,
        [Parameter(Mandatory=$false)]
        [string]$ReasonComment,
        [Parameter(Mandatory=$false)]
        [string]$TicketNumber,
        [Parameter(Mandatory=$false)]
        [string]$RequestedFor,
        [Parameter(Mandatory=$false)]
        [ValidateRange(0, 31)]
        [int]$RequestedDurationDays,
        [Parameter(Mandatory=$false)]
        [ValidateRange(0, 23)]
        [int]$RequestedDurationHours,
        [Parameter(Mandatory=$false)]
        [ValidateRange(0, 59)]
        [int]$RequestedDurationMinutes,
        [Parameter(Mandatory=$false)]
        [int]$Version = 4
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($AccessRequestType -ieq "RDP")
    {
        $AccessRequestType = "RemoteDesktop"
    }
    elseif ($AccessRequestType -ieq "RDPApplication" -or $AccessRequestType -ieq "RDPApp")
    {
        $AccessRequestType = "RemoteDesktopApplication"
    }

    if ($PsCmdlet.ParameterSetName -eq "CertStoreAndNames" -or $PsCmdlet.ParameterSetName -eq "FileAndNames")
    {
        $local:Body = @{
            ForUser = $ForUserName;
            AssetName = $AssetToUse;
            AccessRequestType = "$AccessRequestType"
        }
        if ($AccountToUse) { $local:Body["AccountName"] = $AccountToUse }
    }
    else
    {
        $local:Body = @{
            ForUserId = $ForUserId;
            AssetId = $AssetIdToUse;
            AccessRequestType = "$AccessRequestType"
        }
        if ($AccountIdToUse) { $local:Body["AccountId"] = $AccountIdToUse }
    }

    if ($ForProviderName) {$local:Body["ForProvider"] = $ForProviderName }

    if ($Emergency) { $local:Body["IsEmergency"] = $true }
    if ($ReasonCode)
    {
        Import-Module -Name "$PSScriptRoot\sg-utilities.psm1" -Scope Local
        $local:ReasonCodeId = (Resolve-ReasonCodeId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $ReasonCode)
        $local:Body["ReasonCodeId"] = $local:ReasonCodeId
    }
    if ($ReasonComment) { $local:Body["ReasonComment"] = $ReasonComment }
    if ($TicketNumber) { $local:Body["TicketNumber"] = $TicketNumber }

    if ($RequestedFor) { $local:Body["RequestedFor"] = $RequestedFor }

    if ($RequestedDurationDays) { $local:Body["RequestedDurationDays"] = $RequestedDurationDays }
    if ($RequestedDurationHours) { $local:Body["RequestedDurationHours"] = $RequestedDurationHours }
    if ($RequestedDurationMinutes) { $local:Body["RequestedDurationMinutes"] = $RequestedDurationMinutes }

    if ($PsCmdlet.ParameterSetName -eq "CertStoreAndNames" -or $PsCmdlet.ParameterSetName -eq "CertStoreAndIds")
    {
        Invoke-SafeguardA2aMethodWithCertificate -Insecure:$Insecure -Appliance $Appliance -Authorization "A2A $ApiKey" `
            -Thumbprint $Thumbprint -Service a2a -Method POST -RelativeUrl AccessRequests -Body $local:Body -Version $Version
    }
    else
    {
        Invoke-SafeguardA2aMethodWithCertificate -Insecure:$Insecure -Appliance $Appliance -Authorization "A2A $ApiKey"  -Version $Version `
            -CertificateFile $CertificateFile -Password $Password -Service a2a -Method POST -RelativeUrl AccessRequests -Body $local:Body
    }
}

<#
.SYNOPSIS
Listen for real-time Safeguard A2A events over SignalR using Server-Sent Events.

.DESCRIPTION
Wait-SafeguardA2aEvent opens a persistent SignalR connection to the Safeguard A2A
event service (/service/a2a/signalr/) and streams live event notifications using
certificate-based A2A authentication.

The cmdlet blocks until interrupted with Ctrl+C. Events can be processed by a
script block (-Handler), an external script (-HandlerScript), or emitted to the
output pipeline as PSCustomObjects when no handler is specified.

For user-mode event listening with Bearer token authentication, use
Wait-SafeguardEvent instead.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER CertificateFile
A string containing the path to a PFX certificate file for A2A authentication.

.PARAMETER Password
A secure string containing the password for decrypting the certificate file.

.PARAMETER Thumbprint
A string containing the thumbprint of a certificate in the user certificate store
for A2A authentication.

.PARAMETER ApiKey
A string containing the A2A API key for authorization.

.PARAMETER Event
An array of event names to filter for. If omitted, all events are delivered.

.PARAMETER Handler
A script block to invoke for each event. Receives two arguments: $EventName (string)
and $EventBody (PSObject).

.PARAMETER HandlerScript
Path to a .ps1 script to invoke for each event. The script receives two arguments:
$EventName (string) and $EventBody (PSObject).

.INPUTS
None.

.OUTPUTS
When no Handler or HandlerScript is specified, outputs PSCustomObjects with
EventName and EventBody properties.

.EXAMPLE
Wait-SafeguardA2aEvent 10.5.32.54 $apiKey -Thumbprint $tp -Insecure

Listen for all A2A events using certificate store authentication.

.EXAMPLE
Wait-SafeguardA2aEvent 10.5.32.54 $apiKey -CertificateFile C:\cert.pfx -Password $pwd -Insecure -Event "AssetAccountPasswordUpdated"

Listen for specific A2A events using certificate file authentication.

.EXAMPLE
Wait-SafeguardA2aEvent 10.5.32.54 $apiKey -Thumbprint $tp -Insecure -Handler { param($n,$b) Write-Host "Got $n" }

Process A2A events with an inline script block.
#>
function Wait-SafeguardA2aEvent
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
        [string[]]$Event,
        [Parameter(Mandatory=$false)]
        [ScriptBlock]$Handler,
        [Parameter(Mandatory=$false)]
        [string]$HandlerScript
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($Handler -and $HandlerScript)
    {
        throw "You may specify -Handler or -HandlerScript but not both"
    }
    if ($HandlerScript -and -not (Test-Path $HandlerScript))
    {
        throw "Handler script not found: $HandlerScript"
    }

    Import-Module -Name "$PSScriptRoot\sslhandling.psm1" -Scope Local
    Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local
    Import-Module -Name "$PSScriptRoot\signalr-utilities.psm1" -Scope Local

    # Resolve certificate
    $local:Cert = $null
    if ($PSCmdlet.ParameterSetName -eq "File")
    {
        $local:Cert = (Use-CertificateFile $CertificateFile $Password)
    }
    elseif ($PSCmdlet.ParameterSetName -eq "CertStore")
    {
        $local:Store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "CurrentUser")
        $local:Store.Open("ReadOnly")
        $local:Certs = $local:Store.Certificates.Find(
            [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $Thumbprint, $false)
        $local:Store.Close()
        if ($local:Certs.Count -eq 0)
        {
            throw "Certificate with thumbprint '$Thumbprint' not found in CurrentUser\My store"
        }
        $local:Cert = $local:Certs[0]
    }

    # Build event filter lookup for fast matching
    $local:EventFilter = $null
    if ($Event)
    {
        $local:EventFilter = @{}
        foreach ($local:E in $Event)
        {
            $local:EventFilter[$local:E] = $true
        }
    }

    Edit-SslVersionSupport
    if ($Insecure)
    {
        Disable-SslVerification
        if ($global:PSDefaultParameterValues) { $PSDefaultParameterValues = $global:PSDefaultParameterValues.Clone() }
    }

    $local:SseDisposables = @()
    $local:Reader = $null
    $local:BackoffSeconds = 1
    $local:RecordSep = [char]0x1E

    Write-Host "Listening for Safeguard A2A events on $Appliance... (Press Ctrl+C to stop)"

    try
    {
        while ($true)
        {
            try
            {
                # Clean up previous connection if reconnecting
                foreach ($local:D in $local:SseDisposables) { try { $local:D.Dispose() } catch {} }
                $local:SseDisposables = @()
                $local:Reader = $null

                # Step 1: Negotiate -- get a fresh connectionToken
                $local:NegotiateArgs = @{
                    Appliance = $Appliance
                    ServicePath = "a2a"
                    ApiKey = $ApiKey
                    Insecure = $Insecure
                }
                if ($local:Cert) { $local:NegotiateArgs["Certificate"] = $local:Cert }
                elseif ($Thumbprint) { $local:NegotiateArgs["Thumbprint"] = $Thumbprint }

                $local:ConnectionToken = Get-SignalRConnectionToken @local:NegotiateArgs

                # Step 2: Open SSE GET stream
                $local:EncodedToken = [System.Uri]::EscapeDataString($local:ConnectionToken)
                $local:SseUrl = "https://$Appliance/service/a2a/signalr?id=$local:EncodedToken"

                $local:SseArgs = @{
                    Url = $local:SseUrl
                    Headers = @{ "Authorization" = "A2A $ApiKey" }
                    Insecure = $Insecure
                }
                if ($local:Cert) { $local:SseArgs["Certificate"] = $local:Cert }

                $local:Sse = Open-SignalRSseStream @local:SseArgs
                $local:Reader = $local:Sse.Reader
                $local:SseDisposables = $local:Sse.Disposables

                # Step 3: Send handshake via POST (after SSE stream is open)
                $local:HandshakeArgs = @{
                    Appliance = $Appliance
                    ConnectionToken = $local:ConnectionToken
                    ServicePath = "a2a"
                    ApiKey = $ApiKey
                    Insecure = $Insecure
                }
                if ($local:Cert) { $local:HandshakeArgs["Certificate"] = $local:Cert }
                elseif ($Thumbprint) { $local:HandshakeArgs["Thumbprint"] = $Thumbprint }

                Send-SignalRHandshake @local:HandshakeArgs

                # Step 4: Read and verify handshake response from SSE stream
                $local:HandshakeData = ""
                $local:HandshakeComplete = $false
                while (-not $local:HandshakeComplete)
                {
                    $local:Line = $local:Reader.ReadLine()
                    if ($null -eq $local:Line)
                    {
                        throw "SSE stream closed before handshake completed"
                    }
                    if ($local:Line.StartsWith(":"))
                    {
                        continue
                    }
                    elseif ($local:Line.StartsWith("data:"))
                    {
                        $local:Value = $local:Line.Substring(5)
                        if ($local:Value.StartsWith(" "))
                        {
                            $local:Value = $local:Value.Substring(1)
                        }
                        if ($local:HandshakeData.Length -gt 0)
                        {
                            $local:HandshakeData += "`n"
                        }
                        $local:HandshakeData += $local:Value
                    }
                    elseif ($local:Line -eq "" -and $local:HandshakeData.Length -gt 0)
                    {
                        $local:HandshakeComplete = $true
                    }
                }

                # Parse handshake frames
                $local:HsFrames = $local:HandshakeData.Split($local:RecordSep)
                foreach ($local:HsFrame in $local:HsFrames)
                {
                    $local:HsFrame = $local:HsFrame.Trim()
                    if ($local:HsFrame.Length -eq 0) { continue }
                    $local:HsParsed = ConvertFrom-Json $local:HsFrame
                    if ($local:HsParsed.error)
                    {
                        throw "SignalR handshake error: $($local:HsParsed.error)"
                    }
                }

                Write-Verbose "SignalR handshake complete"
                $local:BackoffSeconds = 1

                # Step 5: Event reading loop
                $local:DataBuffer = ""
                $local:CloseReceived = $false

                while (-not $local:CloseReceived)
                {
                    $local:Line = $local:Reader.ReadLine()
                    if ($null -eq $local:Line)
                    {
                        Write-Verbose "SSE stream ended (server closed connection)"
                        break
                    }

                    if ($local:Line.StartsWith(":"))
                    {
                        # SSE comment or heartbeat
                        continue
                    }
                    elseif ($local:Line.StartsWith("data:"))
                    {
                        $local:Value = $local:Line.Substring(5)
                        if ($local:Value.StartsWith(" "))
                        {
                            $local:Value = $local:Value.Substring(1)
                        }
                        if ($local:DataBuffer.Length -gt 0)
                        {
                            $local:DataBuffer += "`n"
                        }
                        $local:DataBuffer += $local:Value
                    }
                    elseif ($local:Line -eq "" -and $local:DataBuffer.Length -gt 0)
                    {
                        # SSE event boundary -- process accumulated data
                        $local:Frames = $local:DataBuffer.Split($local:RecordSep)
                        $local:DataBuffer = ""

                        foreach ($local:Frame in $local:Frames)
                        {
                            $local:Frame = $local:Frame.Trim()
                            if ($local:Frame.Length -eq 0) { continue }

                            try
                            {
                                $local:Msg = ConvertFrom-Json $local:Frame
                            }
                            catch
                            {
                                Write-Verbose "Failed to parse SignalR frame: $local:Frame"
                                continue
                            }

                            # SignalR message types: 1=Invocation, 6=Ping, 7=Close
                            if ($local:Msg.type -eq 6)
                            {
                                Write-Verbose "Received SignalR ping"
                                continue
                            }
                            elseif ($local:Msg.type -eq 7)
                            {
                                Write-Verbose "Received SignalR close frame"
                                $local:CloseReceived = $true
                                break
                            }
                            elseif ($local:Msg.type -eq 1 -and $local:Msg.target -eq "NotifyEventAsync")
                            {
                                $local:EventData = $local:Msg.arguments[0]
                                $local:EvName = $local:EventData.Name
                                $local:EvBody = $local:EventData

                                # Apply event name filter
                                if ($local:EventFilter -and -not $local:EventFilter.ContainsKey($local:EvName))
                                {
                                    Write-Verbose "Skipping filtered event: $local:EvName"
                                    continue
                                }

                                Write-Verbose "A2A event received: $local:EvName"

                                if ($Handler)
                                {
                                    try
                                    {
                                        & $Handler $local:EvName $local:EvBody
                                    }
                                    catch
                                    {
                                        Write-Warning "Event handler error for '$($local:EvName)': $_"
                                    }
                                }
                                elseif ($HandlerScript)
                                {
                                    try
                                    {
                                        & $HandlerScript $local:EvName $local:EvBody
                                    }
                                    catch
                                    {
                                        Write-Warning "Handler script error for '$($local:EvName)': $_"
                                    }
                                }
                                else
                                {
                                    New-Object PSObject -Property @{
                                        EventName = $local:EvName
                                        EventBody = $local:EvBody
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch
            {
                # Determine if this is a fatal (4xx) or transient error
                $local:IsFatal = $false
                if ($_.Exception -is [System.Net.WebException])
                {
                    $local:WebEx = $_.Exception
                    if ($local:WebEx.Response)
                    {
                        $local:StatusCode = [int]$local:WebEx.Response.StatusCode
                        if ($local:StatusCode -ge 400 -and $local:StatusCode -lt 500)
                        {
                            $local:IsFatal = $true
                        }
                    }
                }
                if ($local:IsFatal)
                {
                    throw
                }

                Write-Warning "Connection error: $($_.Exception.Message)"
            }

            # Clean up before reconnect
            foreach ($local:D in $local:SseDisposables) { try { $local:D.Dispose() } catch {} }
            $local:SseDisposables = @()
            $local:Reader = $null

            Write-Verbose "Reconnecting in $local:BackoffSeconds seconds..."
            Start-Sleep -Seconds $local:BackoffSeconds
            $local:BackoffSeconds = [Math]::Min($local:BackoffSeconds * 2, 60)
        }
    }
    finally
    {
        foreach ($local:D in $local:SseDisposables) { try { $local:D.Dispose() } catch {} }
        if ($Insecure)
        {
            Enable-SslVerification
            if ($global:PSDefaultParameterValues) { $PSDefaultParameterValues = $global:PSDefaultParameterValues.Clone() }
        }
        Write-Verbose "A2A event listener stopped."
    }
}

<#
.SYNOPSIS
Listen for A2A password change events and call a handler with the new password.

.DESCRIPTION
Invoke-SafeguardA2aPasswordHandler retrieves the current password for an A2A credential
via the API, passes it to the handler, then opens a persistent SignalR connection to listen
for AssetAccountPasswordUpdated events. Each time the password changes, the new password
is fetched and the handler is called again.

This is the PowerShell equivalent of handle-a2a-password-event.sh from safeguard-bash.

The handler receives the event name (string) and the password (string) as its two arguments.
On initial invocation before any events, the event name is "InitialPassword".

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER CertificateFile
A string containing the path to a PFX certificate file for A2A authentication.

.PARAMETER Password
A secure string containing the password for decrypting the certificate file.

.PARAMETER Thumbprint
A string containing the thumbprint of a certificate in the user certificate store
for A2A authentication.

.PARAMETER ApiKey
A string containing the A2A API key that identifies the account being monitored.

.PARAMETER Handler
A script block to invoke with each password. Receives two arguments: $EventName (string)
and $Password (string).

.PARAMETER HandlerScript
Path to a .ps1 script to invoke with each password. Receives two arguments: $EventName
(string) and $Password (string).

.PARAMETER Version
Version of the Web API you are using (default: 4).

.INPUTS
None.

.OUTPUTS
None.

.EXAMPLE
Invoke-SafeguardA2aPasswordHandler 10.5.32.54 $apiKey -Thumbprint $tp -Insecure -Handler { param($ev,$pw) Write-Host "Password: $pw" }

Listen for password changes and handle with a script block.

.EXAMPLE
Invoke-SafeguardA2aPasswordHandler 10.5.32.54 $apiKey -CertificateFile C:\cert.pfx -Password $pwd -Insecure -HandlerScript C:\scripts\rotate.ps1

Listen for password changes and invoke an external script.
#>
function Invoke-SafeguardA2aPasswordHandler
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
        [ScriptBlock]$Handler,
        [Parameter(Mandatory=$false)]
        [string]$HandlerScript,
        [Parameter(Mandatory=$false)]
        [int]$Version = 4
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $Handler -and -not $HandlerScript)
    {
        throw "You must specify -Handler or -HandlerScript"
    }
    if ($Handler -and $HandlerScript)
    {
        throw "You may specify -Handler or -HandlerScript but not both"
    }
    if ($HandlerScript -and -not (Test-Path $HandlerScript))
    {
        throw "Handler script not found: $HandlerScript"
    }

    # Build common credential args for Get-SafeguardA2aPassword calls
    $local:CredArgs = @{
        Appliance = $Appliance
        ApiKey = $ApiKey
        Version = $Version
    }
    if ($Insecure) { $local:CredArgs["Insecure"] = $true }
    if ($PSCmdlet.ParameterSetName -eq "File")
    {
        $local:CredArgs["CertificateFile"] = $CertificateFile
        if ($Password) { $local:CredArgs["Password"] = $Password }
    }
    else
    {
        $local:CredArgs["Thumbprint"] = $Thumbprint
    }

    # Step 1: Fetch and deliver initial password
    Write-Verbose "Fetching initial password via A2A..."
    $local:InitialPassword = Get-SafeguardA2aPassword @local:CredArgs

    Write-Verbose "Calling handler with initial password"
    $local:HandlerTarget = $Handler
    if (-not $local:HandlerTarget) { $local:HandlerTarget = $HandlerScript }
    try
    {
        & $local:HandlerTarget "InitialPassword" $local:InitialPassword
    }
    catch
    {
        Write-Warning "Handler error for initial password: $_"
    }

    # Step 2: Listen for password change events and fetch new password on each change
    Write-Host "Listening for A2A password changes on $Appliance... (Press Ctrl+C to stop)"

    $local:ListenerArgs = @{
        Appliance = $Appliance
        ApiKey = $ApiKey
        Event = @("AssetAccountPasswordUpdated")
    }
    if ($Insecure) { $local:ListenerArgs["Insecure"] = $true }
    if ($PSCmdlet.ParameterSetName -eq "File")
    {
        $local:ListenerArgs["CertificateFile"] = $CertificateFile
        if ($Password) { $local:ListenerArgs["Password"] = $Password }
    }
    else
    {
        $local:ListenerArgs["Thumbprint"] = $Thumbprint
    }

    # Use a handler that fetches the new password and forwards to the user's handler
    $local:ListenerArgs["Handler"] = {
        param($EvName, $EvBody)
        Write-Verbose "Password change event received, fetching new password..."
        try
        {
            $local:NewPassword = Get-SafeguardA2aPassword @local:CredArgs
            & $local:HandlerTarget $EvName $local:NewPassword
        }
        catch
        {
            Write-Warning "Error handling password change event: $_"
        }
    }.GetNewClosure()

    Wait-SafeguardA2aEvent @local:ListenerArgs
}

<#
.SYNOPSIS
Listen for A2A SSH key change events and call a handler with the new private key.

.DESCRIPTION
Invoke-SafeguardA2aSshKeyHandler retrieves the current SSH private key for an A2A
credential via the API, passes it to the handler, then opens a persistent SignalR
connection to listen for AssetAccountSshKeyUpdated events. Each time the SSH key
changes, the new private key is fetched and the handler is called again.

The handler receives the event name (string) and the private key (string) as its
two arguments. On initial invocation before any events, the event name is
"InitialSshKey".

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER CertificateFile
A string containing the path to a PFX certificate file for A2A authentication.

.PARAMETER Password
A secure string containing the password for decrypting the certificate file.

.PARAMETER Thumbprint
A string containing the thumbprint of a certificate in the user certificate store
for A2A authentication.

.PARAMETER ApiKey
A string containing the A2A API key that identifies the account being monitored.

.PARAMETER KeyFormat
A string containing which format to use for the private key. The options are:
  - OpenSsh: OpenSSH legacy PEM format (default)
  - Ssh2: Tectia format for use with tools from SSH.com
  - Putty: Putty format for use with PuTTY tools

.PARAMETER Handler
A script block to invoke with each SSH key. Receives two arguments: $EventName
(string) and $PrivateKey (string).

.PARAMETER HandlerScript
Path to a .ps1 script to invoke with each SSH key. Receives two arguments:
$EventName (string) and $PrivateKey (string).

.PARAMETER Version
Version of the Web API you are using (default: 4).

.INPUTS
None.

.OUTPUTS
None.

.EXAMPLE
Invoke-SafeguardA2aSshKeyHandler 10.5.32.54 $apiKey -Thumbprint $tp -Insecure -Handler { param($ev,$key) Set-Content -Path ~/.ssh/id_rsa -Value $key }

Listen for SSH key changes and update a local key file.

.EXAMPLE
Invoke-SafeguardA2aSshKeyHandler 10.5.32.54 $apiKey -CertificateFile C:\cert.pfx -Password $pwd -Insecure -KeyFormat Putty -HandlerScript C:\scripts\deploy-key.ps1

Listen for SSH key changes in Putty format and invoke an external script.
#>
function Invoke-SafeguardA2aSshKeyHandler
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
        [ValidateSet("OpenSsh","Ssh2","Putty",IgnoreCase=$true)]
        [string]$KeyFormat = $null,
        [Parameter(Mandatory=$false)]
        [ScriptBlock]$Handler,
        [Parameter(Mandatory=$false)]
        [string]$HandlerScript,
        [Parameter(Mandatory=$false)]
        [int]$Version = 4
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $Handler -and -not $HandlerScript)
    {
        throw "You must specify -Handler or -HandlerScript"
    }
    if ($Handler -and $HandlerScript)
    {
        throw "You may specify -Handler or -HandlerScript but not both"
    }
    if ($HandlerScript -and -not (Test-Path $HandlerScript))
    {
        throw "Handler script not found: $HandlerScript"
    }

    # Build common credential args for Get-SafeguardA2aPrivateKey calls
    $local:CredArgs = @{
        Appliance = $Appliance
        ApiKey = $ApiKey
        Version = $Version
    }
    if ($Insecure) { $local:CredArgs["Insecure"] = $true }
    if ($KeyFormat) { $local:CredArgs["KeyFormat"] = $KeyFormat }
    if ($PSCmdlet.ParameterSetName -eq "File")
    {
        $local:CredArgs["CertificateFile"] = $CertificateFile
        if ($Password) { $local:CredArgs["Password"] = $Password }
    }
    else
    {
        $local:CredArgs["Thumbprint"] = $Thumbprint
    }

    # Step 1: Fetch and deliver initial SSH key
    Write-Verbose "Fetching initial SSH private key via A2A..."
    $local:InitialKey = Get-SafeguardA2aPrivateKey @local:CredArgs

    Write-Verbose "Calling handler with initial SSH key"
    $local:HandlerTarget = $Handler
    if (-not $local:HandlerTarget) { $local:HandlerTarget = $HandlerScript }
    try
    {
        & $local:HandlerTarget "InitialSshKey" $local:InitialKey
    }
    catch
    {
        Write-Warning "Handler error for initial SSH key: $_"
    }

    # Step 2: Listen for SSH key change events and fetch new key on each change
    Write-Host "Listening for A2A SSH key changes on $Appliance... (Press Ctrl+C to stop)"

    $local:ListenerArgs = @{
        Appliance = $Appliance
        ApiKey = $ApiKey
        Event = @("AssetAccountSshKeyUpdated")
    }
    if ($Insecure) { $local:ListenerArgs["Insecure"] = $true }
    if ($PSCmdlet.ParameterSetName -eq "File")
    {
        $local:ListenerArgs["CertificateFile"] = $CertificateFile
        if ($Password) { $local:ListenerArgs["Password"] = $Password }
    }
    else
    {
        $local:ListenerArgs["Thumbprint"] = $Thumbprint
    }

    # Use a handler that fetches the new SSH key and forwards to the user's handler
    $local:ListenerArgs["Handler"] = {
        param($EvName, $EvBody)
        Write-Verbose "SSH key change event received, fetching new key..."
        try
        {
            $local:NewKey = Get-SafeguardA2aPrivateKey @local:CredArgs
            & $local:HandlerTarget $EvName $local:NewKey
        }
        catch
        {
            Write-Warning "Error handling SSH key change event: $_"
        }
    }.GetNewClosure()

    Wait-SafeguardA2aEvent @local:ListenerArgs
}
