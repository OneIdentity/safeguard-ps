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
        [string]$ServicePath = "event",
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [string]$ApiKey,
        [Parameter(Mandatory=$false)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory=$false)]
        [string]$Thumbprint,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    # $PSDefaultParameterValues is module-scoped on PS 7 -- the caller's SSL bypass
    # does not propagate into this module. Clone the global values so that
    # Invoke-RestMethod sees -SkipCertificateCheck when -Insecure is set.
    if ($Insecure)
    {
        Import-Module -Name "$PSScriptRoot\sslhandling.psm1" -Scope Local
        Disable-SslVerification
        if ($global:PSDefaultParameterValues) { $PSDefaultParameterValues = $global:PSDefaultParameterValues.Clone() }
    }

    $local:Url = "https://$Appliance/service/$ServicePath/signalr/negotiate?negotiateVersion=1"
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
        [string]$ServicePath = "event",
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [string]$ApiKey,
        [Parameter(Mandatory=$false)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory=$false)]
        [string]$Thumbprint,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    # $PSDefaultParameterValues is module-scoped on PS 7 -- clone from global
    if ($Insecure)
    {
        Import-Module -Name "$PSScriptRoot\sslhandling.psm1" -Scope Local
        Disable-SslVerification
        if ($global:PSDefaultParameterValues) { $PSDefaultParameterValues = $global:PSDefaultParameterValues.Clone() }
    }

    $local:EncodedToken = [System.Uri]::EscapeDataString($ConnectionToken)
    $local:Url = "https://$Appliance/service/$ServicePath/signalr?id=$local:EncodedToken"
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

function Open-SignalRSseStream
{
    [CmdletBinding()]
    [OutputType([hashtable])]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$Url,
        [Parameter(Mandatory=$false)]
        [hashtable]$Headers,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Write-Verbose "Opening SSE stream: $Url"

    if ($PSVersionTable.PSEdition -eq "Core")
    {
        # PS 7+: HttpWebRequest SSL callback is broken on .NET 10+.
        # Use HttpClient with DangerousAcceptAnyServerCertificateValidator.
        $local:Handler = New-Object System.Net.Http.HttpClientHandler
        if ($Insecure)
        {
            $local:Handler.ServerCertificateCustomValidationCallback = `
                [System.Net.Http.HttpClientHandler]::DangerousAcceptAnyServerCertificateValidator
        }
        if ($Certificate)
        {
            $local:Handler.ClientCertificates.Add($Certificate) | Out-Null
        }

        $local:Client = New-Object System.Net.Http.HttpClient($local:Handler)
        $local:Client.Timeout = [System.Threading.Timeout]::InfiniteTimeSpan

        $local:Request = New-Object System.Net.Http.HttpRequestMessage(
            [System.Net.Http.HttpMethod]::Get, $Url)
        $local:Request.Headers.TryAddWithoutValidation("Accept", "text/event-stream") | Out-Null
        if ($Headers)
        {
            foreach ($local:Key in $Headers.Keys)
            {
                $local:Request.Headers.TryAddWithoutValidation($local:Key, $Headers[$local:Key]) | Out-Null
            }
        }

        $local:Response = $local:Client.SendAsync($local:Request,
            [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        $local:Response.EnsureSuccessStatusCode() | Out-Null
        $local:Stream = $local:Response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $local:Reader = New-Object System.IO.StreamReader($local:Stream)

        @{
            Reader = $local:Reader
            Disposables = @($local:Reader, $local:Stream, $local:Response, $local:Request, $local:Client, $local:Handler)
        }
    }
    else
    {
        # PS 5.1: HttpWebRequest with ServicePointManager callback (set by Disable-SslVerification)
        $local:WR = [System.Net.HttpWebRequest]::Create($Url)
        $local:WR.Method = "GET"
        $local:WR.Accept = "text/event-stream"
        $local:WR.KeepAlive = $true
        $local:WR.Timeout = [System.Threading.Timeout]::Infinite
        $local:WR.ReadWriteTimeout = [System.Threading.Timeout]::Infinite
        if ($Headers)
        {
            foreach ($local:Key in $Headers.Keys)
            {
                $local:WR.Headers.Add($local:Key, $Headers[$local:Key])
            }
        }
        if ($Certificate)
        {
            $local:WR.ClientCertificates.Add($Certificate) | Out-Null
        }

        $local:WebResponse = $local:WR.GetResponse()
        $local:Stream = $local:WebResponse.GetResponseStream()
        $local:Reader = New-Object System.IO.StreamReader($local:Stream)

        @{
            Reader = $local:Reader
            Disposables = @($local:Reader, $local:Stream, $local:WebResponse)
        }
    }
}
