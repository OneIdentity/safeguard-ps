<# Copyright (c) 2026 One Identity LLC. All rights reserved. #>
# SignalR SSE helpers for event listening
# Nothing is exported from here -- imported with -Scope Local by consumers

function Get-SignalRConnectionToken
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [string]$ApiKey,
        [Parameter(Mandatory=$false)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory=$false)]
        [string]$Thumbprint
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Url = "https://$Appliance/service/event/signalr/negotiate?negotiateVersion=1"
    $local:Headers = @{
        "Accept" = "application/json";
        "Content-type" = "application/json"
    }

    if ($AccessToken)
    {
        $local:Headers["Authorization"] = "Bearer $AccessToken"
    }
    elseif ($ApiKey)
    {
        $local:Headers["Authorization"] = "A2A $ApiKey"
    }

    Write-Verbose "Negotiating SignalR connection at $local:Url"

    try
    {
        if ($Certificate)
        {
            $local:Response = Invoke-RestMethod -Certificate $Certificate -Method POST `
                -Headers $local:Headers -Uri $local:Url
        }
        elseif ($Thumbprint)
        {
            $local:Response = Invoke-RestMethod -CertificateThumbprint $Thumbprint -Method POST `
                -Headers $local:Headers -Uri $local:Url
        }
        else
        {
            $local:Response = Invoke-RestMethod -Method POST -Headers $local:Headers -Uri $local:Url
        }
    }
    catch
    {
        Import-Module -Name "$PSScriptRoot\sg-utilities.psm1" -Scope Local
        Out-SafeguardExceptionIfPossible $_
    }

    if (-not $local:Response.connectionToken)
    {
        throw "SignalR negotiate failed -- no connectionToken in response"
    }

    # Verify SSE transport is available
    $local:HasSse = $false
    foreach ($local:Transport in $local:Response.availableTransports)
    {
        if ($local:Transport.transport -eq "ServerSentEvents")
        {
            $local:HasSse = $true
            break
        }
    }
    if (-not $local:HasSse)
    {
        throw "SignalR server does not support ServerSentEvents transport"
    }

    $local:TokenPreview = $local:Response.connectionToken
    if ($local:TokenPreview.Length -gt 8)
    {
        $local:TokenPreview = $local:TokenPreview.Substring(0, 8) + "..."
    }
    Write-Verbose "Obtained connectionToken: $local:TokenPreview"

    $local:Response.connectionToken
}

function Send-SignalRHandshake
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Appliance,
        [Parameter(Mandatory=$true)]
        [string]$ConnectionToken,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [string]$ApiKey,
        [Parameter(Mandatory=$false)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory=$false)]
        [string]$Thumbprint
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:EncodedToken = [System.Uri]::EscapeDataString($ConnectionToken)
    $local:Url = "https://$Appliance/service/event/signalr?id=$local:EncodedToken"
    $local:HandshakePayload = '{"protocol":"json","version":1}' + [char]0x1E
    $local:BodyBytes = [System.Text.Encoding]::UTF8.GetBytes($local:HandshakePayload)

    $local:Headers = @{
        "Accept" = "application/json";
        "Content-type" = "application/json"
    }

    if ($AccessToken)
    {
        $local:Headers["Authorization"] = "Bearer $AccessToken"
    }
    elseif ($ApiKey)
    {
        $local:Headers["Authorization"] = "A2A $ApiKey"
    }

    Write-Verbose "Sending SignalR handshake to $local:Url"

    try
    {
        if ($Certificate)
        {
            Invoke-RestMethod -Certificate $Certificate -Method POST `
                -Headers $local:Headers -Uri $local:Url -Body $local:BodyBytes | Out-Null
        }
        elseif ($Thumbprint)
        {
            Invoke-RestMethod -CertificateThumbprint $Thumbprint -Method POST `
                -Headers $local:Headers -Uri $local:Url -Body $local:BodyBytes | Out-Null
        }
        else
        {
            Invoke-RestMethod -Method POST -Headers $local:Headers -Uri $local:Url `
                -Body $local:BodyBytes | Out-Null
        }
    }
    catch
    {
        Import-Module -Name "$PSScriptRoot\sg-utilities.psm1" -Scope Local
        Out-SafeguardExceptionIfPossible $_
    }

    Write-Verbose "SignalR handshake sent successfully"
}
