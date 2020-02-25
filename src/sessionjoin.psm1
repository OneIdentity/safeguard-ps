$script:SgSpsClusterFields = "Id","NodeId","Description","SpsNetworkAddress","SpsHostName","Trusted","UseHostNameForLaunch"
# Helpers
function Get-SafeguardSessionClusterInternal
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
        (Invoke-SafeguardMethod -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure Core GET $local:RelUri `
            -Parameters $local:Parameters) | Where-Object { $null -eq $_.CertificateUserThumbprint }
    }
    else
    {
        Invoke-SafeguardMethod -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure Core GET $local:RelUri `
            -Parameters $local:Parameters
    }
}
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

    $local:PasswordPlainText = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SessionPassword))

    $local:BasicAuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $SessionUsername, $local:PasswordPlainText)))
    Remove-Variable -Scope local PasswordPlainText

    Invoke-RestMethod -Uri "https://$SessionMaster/api/authentication" -SessionVariable HttpSession `
        -Headers @{ Authorization = ("Basic {0}" -f $local:BasicAuthInfo) } | Write-Verbose
    Remove-Variable -Scope local BasicAuthInfo

    $HttpSession
}
function Get-NicRefForIp
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$SessionMaster,
        [Parameter(Mandatory=$true)]
        [object]$HttpSession
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not (Test-IpAddress $SessionMaster))
    {
        $local:ListenAddress = [System.Net.Dns]::GetHostAddresses($SessionMaster)[0].IpAddressToString
    }
    else
    {
        $local:ListenAddress = $SessionMaster
    }

    Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local
    :OUTER foreach ($Name in "nic1","nic2","nic3") {
        $local:Nic = (Invoke-RestMethod -WebSession $HttpSession -Uri "https://$SessionMaster/api/configuration/network/nics/$Name" `
                          -Headers @{ "Accept" = "application/json"; "Content-type" = "application/json" } -Method Get).body
        $local:Nic.interfaces."@order" | ForEach-Object {
            $local:NicId = $_
            ($local:Nic.interfaces."$($local:NicId)".addresses."@order") | ForEach-Object {
                $local:AddressId = $_
                if ($local:Nic.interfaces."$($local:NicId)".addresses."$($local:AddressId)".StartsWith($local:ListenAddress))
                {
                    #"api/configuration/network/nics/$Name#interfaces/$($local:NicId)/addresses/$($local:AddressId)"
                    "$Name.interfaces.$($local:NicId).addresses.$($local:AddressId)"
                    break OUTER
                }
            }
        }
    }
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
    [CmdletBinding()]
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
        PUT "Cluster/SessionModules/$($local:SessionCluster.Id)" -Body $local:SessionCluster | Write-Verbose

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
            break
        }
        "PSCredential" {
            $SessionUsername = $SessionCredential.UserName
            $SessionPassword = $SessionCredential.Password
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

        $HttpSession = (Connect-Sps $SessionMaster $SessionUsername $SessionPassword -Insecure:$Insecure)

        Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local
        # Make sure clustering is turned on
        $local:Clustering = (Invoke-RestMethod -WebSession $HttpSession -Uri "https://$SessionMaster/api/configuration/local_services/cluster" `
            -Headers @{ "Accept" = "application/json"; "Content-type" = "application/json" } -Method Get)
        if (-not $local:Clustering -or -not $local:Clustering.body.enabled)
        {
            $local:Confirmed = (Get-Confirmation "Session Appliance Clustering NOT Enabled" "Do you want to enable clustering on this session appliance?" `
                                    "Enable clustering." "Cancels this operation.")
            if ($local:Confirmed)
            {
                $local:NicRef = (Get-NicRefForIp -SessionMaster $SessionMaster -HttpSession $HttpSession)

                Write-Host "Sending enable clustering command..."
                Write-Host "ListenAddress = $($local:NicRef)"
                try
                {
                    Invoke-RestMethod -WebSession $HttpSession -Method Post -Uri "https://$SessionMaster/api/transaction" `
                        -Headers @{ "Accept" = "application/json"; "Content-type" = "application/json" } | Write-Verbose

                    Invoke-RestMethod -WebSession $HttpSession -Method Put -Uri "https://$SessionMaster/api/configuration/local_services/cluster" `
                        -Headers @{ "Accept" = "application/json"; "Content-type" = "application/json" } -Body (ConvertTo-Json -InputObject @{
                            enabled = $true;
                            listen_address = $local:NicRef
                        }) | Write-Verbose

                    Invoke-RestMethod -WebSession $HttpSession -Method Put -Uri "https://$SessionMaster/api/transaction" `
                        -Headers @{ "Accept" = "application/json"; "Content-type" = "application/json" } -Body (ConvertTo-Json -InputObject @{
                            status = "commit"
                        }) | Write-Verbose

                    Start-Sleep -Seconds 10
                }
                catch
                {
                    try
                    {
                        Invoke-RestMethod -WebSession $HttpSession -Method Delete -Uri "https://$SessionMaster/api/transaction" | Write-Verbose
                    }
                    catch {}
                }
                # reconnect
                $HttpSession = (Connect-Sps $SessionMaster $SessionUsername $SessionPassword -Insecure:$Insecure)
            }
            else
            {
                Write-Host -ForegroundColor Yellow "Operation canceled."
                return
            }
        }

        # Make sure this node is a session master
        try
        {
            Invoke-RestMethod -WebSession $HttpSession -Method Get -Uri "https://$SessionMaster/api/cluster/status" | Write-Verbose
        }
        catch
        {
            $local:Confirmed = (Get-Confirmation "Session Appliance Is NOT Promoted" "Do you want to promote this session appliance to session master?" `
                                    "Promote." "Cancels this operation.")
            if ($local:Confirmed)
            {
                Write-Host "Sending promote command..."
                try
                {
                    Invoke-RestMethod -WebSession $HttpSession -Method Post -Uri "https://$SessionMaster/api/transaction" `
                        -Headers @{ "Accept" = "application/json"; "Content-type" = "application/json" } | Write-Verbose

                    Invoke-RestMethod -WebSession $HttpSession -Method Post -Uri "https://$SessionMaster/api/cluster/promote" `
                        -Headers @{ "Accept" = "application/json"; "Content-type" = "application/json" } | Write-Verbose

                    Invoke-RestMethod -WebSession $HttpSession -Method Put -Uri "https://$SessionMaster/api/transaction" `
                        -Headers @{ "Accept" = "application/json"; "Content-type" = "application/json" } -Body (ConvertTo-Json -InputObject @{
                            status = "commit"
                        }) | Write-Verbose

                    Start-Sleep -Seconds 10
                }
                catch
                {
                    try
                    {
                        Invoke-RestMethod -WebSession $HttpSession -Method Delete -Uri "https://$SessionMaster/api/transaction" | Write-Verbose
                    }
                    catch {}
                }
                # reconnect
                $HttpSession = (Connect-Sps $SessionMaster $SessionUsername $SessionPassword -Insecure:$Insecure)
            }
            else
            {
                Write-Host -ForegroundColor Yellow "Operation canceled."
                return
            }
        }

        # Run the spp join command
        Write-Host "Sending join command..."
        Invoke-RestMethod -WebSession $HttpSession -Method Post -Uri "https://$SessionMaster/api/cluster/spp" `
            -Headers @{ "Accept" = "application/json"; "Content-type" = "application/json" } -Body (ConvertTo-Json -InputObject @{
                spp = $Appliance;
                spp_api_token = $AccessToken;
                spp_cert_chain = $local:SppCertData
            }) | Write-Verbose

        Start-Sleep -Seconds 30

        Get-SafeguardSessionCluster -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure $SessionMaster
    }
    catch
    {
        if (($_.ErrorDetails.Message | ConvertFrom-Json).error.details.response.Code -eq 60657)
        {
            throw "This SPS cluster is already joined, check the output of Get-SafeguardSessionCluster."
        }
        throw
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
        DELETE "Cluster/SessionModules/$($local:SessionCluster.Id)" | Write-Verbose
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
        DELETE "Cluster/SessionModules/$($local:SessionCluster.Id)" | Write-Verbose
}

<#
.SYNOPSIS
Get current status of the Session Access Request Broker setting in Safeguard via the Web API.

.DESCRIPTION
The Session Access Request Broker is used to facilitate SPS initiated sessions.  When enabled, this
setting allows SPS to request access on behalf of a user trying to connect a session through SPS.
Access requests created and used by SPS will still be governed by SPP entitlements.
This cmdlet reports the current status of the setting: true or false.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate

.INPUTS
None.

.OUTPUTS
JSON from the Safeguard Web API.

.EXAMPLE
Get-SafeguardSessionClusterAccessRequestBroker -Appliance 10.5.32.54 -AccessToken $token -Insecure

.EXAMPLE
Get-SafeguardSessionClusterAccessRequestBroker
#>
function Get-SafeguardSessionClusterAccessRequestBroker
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

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Cluster/SessionModules/AccessRequestBroker"
}

<#
.SYNOPSIS
Enable the Session Access Request Broker setting in Safeguard via the Web API.

.DESCRIPTION
The Session Access Request Broker is used to facilitate SPS initiated sessions.  When enabled, this
setting allows SPS to request access on behalf of a user trying to connect a session through SPS.
Access requests created and used by SPS will still be governed by SPP entitlements.
This cmdlet enables the setting.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate

.INPUTS
None.

.OUTPUTS
JSON from the Safeguard Web API.

.EXAMPLE
Enable-SafeguardSessionClusterAccessRequestBroker -Appliance 10.5.32.54 -AccessToken $token -Insecure

.EXAMPLE
Enable-SafeguardSessionClusterAccessRequestBroker
#>
function Enable-SafeguardSessionClusterAccessRequestBroker
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

    $local:Enabled = (Get-SafeguardSessionClusterAccessRequestBroker -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure).Enabled
    if ($local:Enabled)
    {
        Write-Host "Session Access Request Broker is already enabled."
    }
    else
    {
        Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local
        $local:Confirmed = (Get-Confirmation "Enable Session Access Request Broker" `
                                ("You are about to enable SPS to create access requests, monitor workflow, and retrieve credentials on behalf of users to connect sessions.`n" + `
                                 "Access requests created and used by SPS will still be governed by SPP entitlements.`n" + `
                                 "Do you want to enable the Session Access Request Broker?") `
                                "Enable SPS to request access and retrieve credentials on behalf of users." "Cancel this operation.")
        if ($local:Confirmed)
        {
            Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "Cluster/SessionModules/AccessRequestBroker" -Body @{ Enabled = $true }
        }
    }
}

<#
.SYNOPSIS
Disable the Session Access Request Broker setting in Safeguard via the Web API.

.DESCRIPTION
The Session Access Request Broker is used to facilitate SPS initiated sessions.  When enabled, this
setting allows SPS to request access on behalf of a user trying to connect a session through SPS.
Access requests created and used by SPS will still be governed by SPP entitlements.
This cmdlet disables the setting.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate

.INPUTS
None.

.OUTPUTS
JSON from the Safeguard Web API.

.EXAMPLE
Disable-SafeguardSessionClusterAccessRequestBroker -Appliance 10.5.32.54 -AccessToken $token -Insecure

.EXAMPLE
Disable-SafeguardSessionClusterAccessRequestBroker
#>
function Disable-SafeguardSessionClusterAccessRequestBroker
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

    $local:Enabled = (Get-SafeguardSessionClusterAccessRequestBroker -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure).Enabled
    if (-not $local:Enabled)
    {
        Write-Host "Session Access Request Broker is already disabled."
    }
    else
    {
        Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local
        $local:Confirmed = (Get-Confirmation "Enable Session Access Request Broker" `
                                ("You are about to disable SPS from being able to retrieve credentials on behalf of users to connect sessions.`n" + `
                                 "This will prevent SPS initiated sessions from connecting.`n" + `
                                 "Do you want to disable the Session Access Request Broker?") `
                                "Disable to prevent SPS from retrieving credentials on behalf of users." "Cancel this operation.")
        if ($local:Confirmed)
        {
            Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "Cluster/SessionModules/AccessRequestBroker" -Body @{ Enabled = $false }
        }
    }
}

<#
.SYNOPSIS
Get current status of the Session Audit Stream setting in Safeguard via the Web API.

.DESCRIPTION
The Session Audit Stream is used to allow SPS to retrieve SPP audit information.  When enabled, this
setting allows SPS to make SPP audit information avaiable in the SPS audit portal.
This cmdlet reports the current status of the setting: true or false.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate

.INPUTS
None.

.OUTPUTS
JSON from the Safeguard Web API.

.EXAMPLE
Get-SafeguardSessionClusterAuditStream -Appliance 10.5.32.54 -AccessToken $token -Insecure

.EXAMPLE
Get-SafeguardSessionClusterAuditStream
#>
function Get-SafeguardSessionClusterAuditStream
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

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "AuditLog/StreamService"
}

<#
.SYNOPSIS
Enable the Session Audit Stream setting in Safeguard via the Web API.

.DESCRIPTION
The Session Audit Stream is used to allow SPS to retrieve SPP audit information.  When enabled, this
setting allows SPS to make SPP audit information avaiable in the SPS audit portal.
This cmdlet enables the setting.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate

.INPUTS
None.

.OUTPUTS
JSON from the Safeguard Web API.

.EXAMPLE
Enable-SafeguardSessionClusterAuditStream -Appliance 10.5.32.54 -AccessToken $token -Insecure

.EXAMPLE
Enable-SafeguardSessionClusterAuditStream
#>
function Enable-SafeguardSessionClusterAuditStream
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

    $local:Enabled = (Get-SafeguardSessionClusterAuditStream -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure).Enabled
    if ($local:Enabled)
    {
        Write-Host "Session Audit Stream is already enabled."
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "AuditLog/StreamService" -Body @{ Enabled = $true }
    }
}

<#
.SYNOPSIS
Disable the Session Audit Stream setting in Safeguard via the Web API.

.DESCRIPTION
The Session Audit Stream is used to allow SPS to retrieve SPP audit information.  When enabled, this
setting allows SPS to make SPP audit information avaiable in the SPS audit portal.
This cmdlet disables the setting.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate

.INPUTS
None.

.OUTPUTS
JSON from the Safeguard Web API.

.EXAMPLE
Disable-SafeguardSessionClusterAuditStream -Appliance 10.5.32.54 -AccessToken $token -Insecure

.EXAMPLE
Disable-SafeguardSessionClusterAuditStream
#>
function Disable-SafeguardSessionClusterAuditStream
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

    $local:Enabled = (Get-SafeguardSessionClusterAuditStream -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure).Enabled
    if (-not $local:Enabled)
    {
        Write-Host "Session Audit Stream is already disabled."
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "AuditLog/StreamService" -Body @{ Enabled = $false }
    }
}
