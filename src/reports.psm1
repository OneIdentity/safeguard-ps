function Get-SafeguardReportAccountWithoutPassword
{
    [CmdletBinding(DefaultParameterSetName="File")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false, ParameterSetName="File", Position=0)]
        [string]$OutputDirectory = (Get-Location),
        [Parameter(Mandatory=$false, ParameterSetName="File")]
        [switch]$Excel = $false,
        [Parameter(Mandatory=$false, ParameterSetName="StdOut")]
        [switch]$StdOut
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:OutFile = $null
    if ($PSCmdlet.ParameterSetName -eq "File")
    {
        $local:OutFile = (Join-Path $OutputDirectory "sg-accounts-wo-password-$((Get-Date).ToString("yyyyMMddTHHmmssZz")).csv")
    }

    Invoke-SafeguardMethod Core GET PolicyAccounts -Accept "text/csv" -OutFile $local:OutFile -Parameters @{ 
        filter = "HasPassword eq false";
        fields = "SystemId,Id,SystemName,Name,DomainName,SystemNetworkAddress,HasPassword,Disabled,AllowPasswordRequest,AllowSessionRequest,PlatformDisplayName" }

    if ($local:OutFile)
    {
        Write-Host "Data written to $($local:OutFile)"
        if ($Excel)
        {
            Open-CsvInExcel $local:OutFile
        }
    }
}

function Get-SafeguardReportDailyAccessRequest
{
    [CmdletBinding(DefaultParameterSetName="File")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false, ParameterSetName="File", Position=0)]
        [string]$OutputDirectory = (Get-Location),
        [Parameter(Mandatory=$false, ParameterSetName="File")]
        [switch]$Excel = $false,
        [Parameter(Mandatory=$false, ParameterSetName="StdOut")]
        [switch]$StdOut,
        [Parameter(Mandatory=$false)]
        [DateTime]$LocalDate = (Get-Date)
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:DayOnly = (New-Object "System.DateTime" -ArgumentList $LocalDate.Year, $LocalDate.Month, $LocalDate.Day)
    $local:EndDate = ($local:DayOnly.AddDays(1))

    $local:OutFile = $null
    if ($PSCmdlet.ParameterSetName -eq "File")
    {
        $local:OutFile = (Join-Path $OutputDirectory "sg-daily-access-request-$(($local:DayOnly).ToString("yyyy-MM-dd")).csv")
    }

    # Calling AuditLog with just an endDate returns a result using a startDate 24 hours before the specified endDate
    Invoke-SafeguardMethod Core GET AuditLog/AccessRequests/Activities -Accept "text/csv" -OutFile $local:OutFile -Parameters @{
        endDate = "$($local:EndDate.ToString("yyyy-MM-ddTHH:mm:sszzz"))";
        filter = "Action eq 'CheckOutPassword' or Action eq 'InitializeSession'";
        fields = "LogTime,RequestId,RequesterId,RequesterName,SystemId,AccountId,SystemName,AccountName,AccountDomainName,AccessRequestType,Action,SessionId,ApplianceId,ApplianceName" }

    if ($local:OutFile)
    {
        Write-Host "Data written to $($local:OutFile)"
        if ($Excel)
        {
            Open-CsvInExcel $local:OutFile
        }
    }
}