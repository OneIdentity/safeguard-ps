$script:SgSpsClusterFields = "Id","NodeId","Description","SpsNetworkAddress","SpsHostName","Trusted","UseHostNameForLaunch"
# Helpers
function Get-SafeguardSessionClusterInternal
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [object]$SessionMaster,
        [Parameter(Mandatory=$false)]
        [switch]$AllFields,
        [Parameter(Mandatory=$false)]
        [switch]$Split
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Parameters = @{}
    $local:RelUri = "Cluster/SessionModules"

    if (-not $AllFields)
    {
        $local:Parameters["fields"] = ($script:SgSpsClusterFields -join ",")
    }

    if ($SessionMaster)
    {
        if ($SessionMaster.Id -as [int])
        {
            $SessionMaster = $SessionMaster.Id
        }

        if (-not ($SessionMaster -as [int]))
        {
            $local:Parameters["filter"] = "(SpsHostName eq '$SessionMaster') or (SpsNetworkAddress eq '$SessionMaster')"
        }
        else
        {
            $local:RelUri = "Cluster/SessionModules/$SessionMaster"
        }
    }

    if ($Split)
    {
        $local:Parameters["includeDisconnected"] = $true
    }

    Invoke-SafeguardMethod -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure Core GET $local:RelUri `
        -Parameters $local:Parameters | Where-Object { ($Split -and $null -eq $_.CertificateUserThumbprint) -or (-not $Split -and $null -ne $_.CertificateUserThumbprint) }
}

<#
.SYNOPSIS
Get currently joined session appliance clusters.

.DESCRIPTION
Get the session appliance clusters that have been previously joined to this
Safeguard cluster.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER SessionMaster
A string containing name or the ID of a specifc session master.

.PARAMETER AllFields
Return all properties that can be displayed.

.INPUTS
None.

.OUTPUTS
None.

.EXAMPLE
Get-SafeguardSessionCluster -AllFields

.EXAMPLE
Get-SafeguardSessionCluster sps1.example.com -AllFields
#>
function Get-SafeguardSessionCluster
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [object]$SessionMaster,
        [Parameter(Mandatory=$false)]
        [switch]$AllFields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Get-SafeguardSessionClusterInternal -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure $SessionMaster -AllFields:$AllFields -Split:$false
}

<#
.SYNOPSIS
Set a few of the properties of a previously joined session appliance cluster.

.DESCRIPTION
Set properties of the session appliance clusters that have been previously joined to this
Safeguard cluster.  This useful for setting the description field and changing the
session cluster to use DNS rather than IP addresses to launch sessions.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER SessionMaster
A string containing name or the ID of a specifc session master.

.PARAMETER Description
A string containing the new description to use for this session cluster.

.PARAMETER UseDns
Configure this session cluster to use DNS instead of IP addresses for
session launch URLs.

.PARAMETER AllFields
Return all properties that can be displayed.

.INPUTS
None.

.OUTPUTS
None.

.EXAMPLE
Set-SafeguardSessionCluster sps1.example.com -UseDns -AllFields

.EXAMPLE
Set-SafeguardSessionCluster sps1.example.com -Description "Secure Env" -AllFields
#>
function Set-SafeguardSessionCluster
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$SessionMaster,
        [Parameter(Mandatory=$false)]
        [string]$Description,
        [Parameter(Mandatory=$false)]
        [switch]$UseDns,
        [Parameter(Mandatory=$false)]
        [switch]$AllFields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:SessionCluster = (Get-SafeguardSessionCluster -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure $SessionMaster -AllFields:$AllFields)[0]
    if (-not $local:SessionCluster)
    {
        throw "Session cluster '$($local:SessionCluster)' not found"
    }

    if ($Description)
    {
        $local:SessionCluster.Description = $Description
    }
    $local:SessionCluster.UseHostNameForLaunch = ([bool]$UseDns)

    Invoke-SafeguardMethod -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure Core `
        PUT "Cluster/SessionModules/$($local:SessionCluster.Id)" -Body $local:SessionCluster | Out-Null

    Get-SafeguardSessionCluster -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure $SessionMaster -AllFields:$AllFields
}

<#
.SYNOPSIS
Join this Safeguard appliance to a session appliance cluster.

.DESCRIPTION
This cmdlet will attempt to log into a session master to initiate a join
with this Safeguard cluster.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER SessionMaster
A string containing the DNS name or IP address of a specifc session master.

.PARAMETER SessionCredential
A PowerShell credential object containing login information for the session master.

.PARAMETER SessionUsername
A string containing the login name for the session master.

.PARAMETER SessionPassword
A secure string containing the password for the session master.

.INPUTS
None.

.OUTPUTS
None.

.EXAMPLE
Join-SafeguardSessionCluster sps1.example.com admin

.EXAMPLE
Join-SafeguardSessionCluster sps1.example.com admin $PassObj

.EXAMPLE
Join-SafeguardSessionCluster sps1.example.com -SessionCredential $cred
#>
function Join-SafeguardSessionCluster
{
    [CmdletBinding(DefaultParameterSetName="Username")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [string]$SessionMaster,
        [Parameter(ParameterSetName="PSCredential")]
        [PSCredential]$SessionCredential,
        [Parameter(ParameterSetName="Username",Mandatory=$true,Position=1)]
        [string]$SessionUsername,
        [Parameter(ParameterSetName="Username",Position=2)]
        [SecureString]$SessionPassword
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    switch ($PsCmdlet.ParameterSetName)
    {
        "Username" {
            if (-not $SessionUsername)
            {
                $SessionUsername = (Read-Host "Username")
            }
            if (-not $SessionPassword)
            {
                $SessionPassword = (Read-Host "SessionPassword" -AsSecureString)
            }
            $local:PasswordPlainText = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SessionPassword))
            break
        }
        "PSCredential" {
            $SessionUsername = $SessionCredential.UserName
            $local:PasswordPlainText = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SessionCredential.Password))
            break
        }
    }

    # Handle SPP session variable stuff
    if (-not $Appliance -and $SafeguardSession)
    {
        $Appliance = $SafeguardSession["Appliance"]
        # if using session variable also inherit trust status
        $Insecure = $SafeguardSession["Insecure"]
    }
    elseif (-not $Appliance)
    {
        $Appliance = (Read-Host "Appliance")
    }
    if (-not $AccessToken -and $SafeguardSession)
    {
        $AccessToken = $SafeguardSession["AccessToken"]
    }
    elseif (-not $AccessToken)
    {
        Write-Verbose "Not using existing session, calling Connect-Safeguard [1]..."
        $AccessToken = (Connect-Safeguard -Appliance $Appliance -Insecure:$Insecure -NoSessionVariable)
    }

    # Get required information from SPP
    $local:SppSsl = (Get-SafeguardSslCertificateForAppliance -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure)
    $local:SppCertData = "$($local:SppSsl.Base64CertificateData)"
    $local:SppSsl.IssuerCertificates | ForEach-Object { $local:SppCertData = $local:SppCertData + "$_" }

    try
    {
        Import-Module -Name "$PSScriptRoot\sslhandling.psm1" -Scope Local
        Edit-SslVersionSupport
        if ($Insecure)
        {
            Disable-SslVerification
            if ($global:PSDefaultParameterValues) { $PSDefaultParameterValues = $global:PSDefaultParameterValues.Clone() }
        }

        $local:BasicAuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $SessionUsername, $local:PasswordPlainText)))
        Remove-Variable -Scope local PasswordPlainText

        Invoke-RestMethod -Uri "https://$SessionMaster/api/authentication" -SessionVariable HttpSession `
            -Headers @{ Authorization = ("Basic {0}" -f $local:BasicAuthInfo) } | Out-Null
        Remove-Variable -Scope local BasicAuthInfo

        Invoke-RestMethod -WebSession $HttpSession -Method Post -Uri "https://$SessionMaster/api/cluster/spp" `
            -Headers @{ "Accept" = "application/json"; "Content-type" = "application/json" } -Body (ConvertTo-Json -InputObject @{
                spp = $Appliance;
                spp_api_token = $AccessToken;
                spp_cert_chain = $local:SppCertData
            }) | Out-Null

        Get-SafeguardSessionCluster -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure $SessionMaster
    }
    finally
    {
        Remove-Variable HttpSession -ErrorAction SilentlyContinue
        if ($Insecure)
        {
            Enable-SslVerification
            if ($global:PSDefaultParameterValues) { $PSDefaultParameterValues = $global:PSDefaultParameterValues.Clone() }
        }
    }
}

<#
.SYNOPSIS
Unjoin from a previously joined session appliance cluster.

.DESCRIPTION
This cmdlet will remove the trust relationship between this Safeguard cluster
and the specified session cluster.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER SessionMaster
A string containing name or the ID of a specifc session master.


.INPUTS
None.

.OUTPUTS
None.

.EXAMPLE
Split-SafeguardSessionCluster sps1.example.com
#>
function Split-SafeguardSessionCluster
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
        [object]$SessionMaster
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:SessionCluster = (Get-SafeguardSessionCluster -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure $SessionMaster -AllFields)[0]
    if (-not $local:SessionCluster)
    {
        throw "Session cluster '$($local:SessionCluster)' not found, maybe previously split? Use Get-SafeguardSessionSplitCluster"
    }

    Invoke-SafeguardMethod -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure Core `
        DELETE "Cluster/SessionModules/$($local:SessionCluster.Id)" | Out-Null
}

<#
.SYNOPSIS
Get session appliance clusters that were split but not yet deleted.

.DESCRIPTION
Get the session appliance clusters that have been previously joined to and
later split from this Safeguard cluster.  These need to be removed using
Remove-SafeguardSessionSplitCluster before they will be deleted completely
from the Safeguard cluster.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER SessionMaster
A string containing name or the ID of a specifc session master.

.PARAMETER AllFields
Return all properties that can be displayed.

.INPUTS
None.

.OUTPUTS
None.

.EXAMPLE
Get-SafeguardSessionSplitCluster -AllFields

.EXAMPLE
Get-SafeguardSessionSplitCluster sps1.example.com -AllFields
#>
function Get-SafeguardSessionSplitCluster
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
        [object]$SessionMaster,
        [Parameter(Mandatory=$false)]
        [switch]$AllFields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Get-SafeguardSessionClusterInternal -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure $SessionMaster -AllFields:$AllFields -Split:$true
}

<#
.SYNOPSIS
Remove a session cluster completely from Safeguard after it has already been split.

.DESCRIPTION
Session clusters that were previously split are remembered by the Safeguard
cluster in case they are re-joined.  This cmdlet can be used to completely
remove them from the Safeguard cluster.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER SessionMaster
A string containing name or the ID of a specifc session master.

.INPUTS
None.

.OUTPUTS
None.

.EXAMPLE
Remove-SafeguardSessionSplitCluster sps1.example.com
#>
function Remove-SafeguardSessionSplitCluster
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
        [object]$SessionMaster
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:SessionCluster = (Get-SafeguardSessionSplitCluster -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure $SessionMaster -AllFields)[0]
    if (-not $local:SessionCluster)
    {
        throw "Session cluster '$($local:SessionCluster)' not found, maybe not split? Use Get-SafeguardSessionSplitCluster"
    }

    Invoke-SafeguardMethod -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure Core `
        DELETE "Cluster/SessionModules/$($local:SessionCluster.Id)" | Out-Null
}
