$script:SgSpsClusterFields = "Id","NodeId","Description","SpsNetworkAddress","SpsHostName","Trusted","UseHostNameForLaunch"

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

    Invoke-SafeguardMethod -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure Core GET $local:RelUri `
        -Parameters $local:Parameters
}

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
        [Parameter(ParameterSetName="PSCredential",Position=2)]
        [PSCredential]$SessionCredential,
        [Parameter(ParameterSetName="Username",Mandatory=$true,Position=1)]
        [string]$SessionUsername,
        [Parameter(ParameterSetName="Username",Position=3)]
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


    # TODO:
}