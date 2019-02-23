# Helpers
function Get-OutFileForParam
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$OutputDirectory,
        [Parameter(Mandatory=$false)]
        [string]$FileName,
        [Parameter(Mandatory=$false)]
        [switch]$StdOut
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $StdOut)
    {
        (Join-Path $OutputDirectory $FileName)
    }
    else
    {
        $null
    }
}
function Out-FileAndExcel
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$OutFile,
        [Parameter(Mandatory=$false)]
        [switch]$Excel
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($OutFile)
    {
        Write-Host "Data written to $($OutFile)"
        if ($Excel)
        {
            Open-CsvInExcel $OutFile
        }
    }
}
function Invoke-AuditLogMethod
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [string]$RelativeUrl,
        [Parameter(Mandatory=$true, Position=1)]
        [DateTime]$DayOnly,
        [Parameter(Mandatory=$true, Position=2)]
        [string]$Filter,
        [Parameter(Mandatory=$true, Position=3)]
        [string]$Fields,
        [Parameter(Mandatory=$false)]
        [string]$OutFile,
        [Parameter(Mandatory=$false)]
        [switch]$Excel
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:EndDate = ($DayOnly.AddDays(1))

    # Calling AuditLog with just an endDate returns a result using a startDate 24 hours before the specified endDate
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET $RelativeUrl -Accept "text/csv" -OutFile $local:OutFile -Parameters @{
        endDate = "$($local:EndDate.ToString("yyyy-MM-ddTHH:mm:sszzz"))";
        filter = $Filter; fields = $Fields }

    Out-FileAndExcel -OutFile $local:OutFile -Excel:$Excel
}


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

    $local:OutFile = (Get-OutFileForParam -OutputDirectory $OutputDirectory -FileName "sg-accounts-wo-password-$((Get-Date).ToString("yyyyMMddTHHmmssZz")).csv" -StdOut:$StdOut)

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "PolicyAccounts" -Accept "text/csv" -OutFile $local:OutFile -Parameters @{
        filter = "HasPassword eq false";
        fields = ("SystemId,Id,SystemName,Name,DomainName,SystemNetworkAddress,HasPassword,Disabled,AllowPasswordRequest,AllowSessionRequest," + `
            "PlatformDisplayName") }

    Out-FileAndExcel -OutFile $local:OutFile -Excel:$Excel
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
    $local:OutFile = (Get-OutFileForParam -OutputDirectory $OutputDirectory -FileName "sg-daily-access-request-$(($local:DayOnly).ToString("yyyy-MM-dd")).csv" -StdOut:$StdOut)

    Invoke-AuditLogMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure "AuditLog/AccessRequests/Activities" $local:DayOnly `
        "Action eq 'CheckOutPassword' or Action eq 'InitializeSession'" `
        ("LogTime,RequestId,RequesterId,RequesterName,SystemId,AccountId,SystemName,AccountName,AccountDomainName,AccessRequestType,Action," + `
        "SessionId,ApplianceId,ApplianceName") `
        -OutFile $local:OutFile -Excel:$Excel
}

function Get-SafeguardReportDailyPasswordCheckFail
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
    $local:OutFile = (Get-OutFileForParam -OutputDirectory $OutputDirectory -FileName "sg-daily-pwcheck-fail-$(($local:DayOnly).ToString("yyyy-MM-dd")).csv" -StdOut:$StdOut)

    Invoke-AuditLogMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure "AuditLog/Passwords/CheckPassword" $local:DayOnly `
        "EventName eq 'PasswordCheckFailed'" `
        ("LogTime,SystemId,AccountId,SystemName,AccountName,AccountDomainName,NetworkAddress,PlatformDisplayName,EventName," + `
        "RequestStatus.Message,AssetPartitionId,AssetPartitionName,ProfileId,ProfileName,SyncGroupId,SyncGroupName,ApplianceId,ApplianceName") `
        -OutFile $local:OutFile -Excel:$Excel
}

function Get-SafeguardReportDailyPasswordCheckSuccess
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
    $local:OutFile = (Get-OutFileForParam -OutputDirectory $OutputDirectory -FileName "sg-daily-pwcheck-success-$(($local:DayOnly).ToString("yyyy-MM-dd")).csv" -StdOut:$StdOut)

    Invoke-AuditLogMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure "AuditLog/Passwords/CheckPassword" $local:DayOnly `
        "EventName eq 'PasswordCheckSucceeded'" `
        ("LogTime,SystemId,AccountId,SystemName,AccountName,AccountDomainName,NetworkAddress,PlatformDisplayName,EventName," + `
        "AssetPartitionId,AssetPartitionName,ProfileId,ProfileName,SyncGroupId,SyncGroupName,ApplianceId,ApplianceName") `
        -OutFile $local:OutFile -Excel:$Excel
}

function Get-SafeguardReportDailyPasswordChangeFail
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
    $local:OutFile = (Get-OutFileForParam -OutputDirectory $OutputDirectory -FileName "sg-daily-pwchange-fail-$(($local:DayOnly).ToString("yyyy-MM-dd")).csv" -StdOut:$StdOut)

    Invoke-AuditLogMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure "AuditLog/Passwords/ChangePassword" $local:DayOnly `
        "EventName eq 'PasswordChangeFailed'" `
        ("LogTime,SystemId,AccountId,SystemName,AccountName,AccountDomainName,NetworkAddress,PlatformDisplayName,EventName," + `
        "AssetPartitionId,AssetPartitionName,ProfileId,ProfileName,SyncGroupId,SyncGroupName,ApplianceId,ApplianceName") `
        -OutFile $local:OutFile -Excel:$Excel
}

function Get-SafeguardReportDailyPasswordChangeSuccess
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
    $local:OutFile = (Get-OutFileForParam -OutputDirectory $OutputDirectory -FileName "sg-daily-pwchange-success-$(($local:DayOnly).ToString("yyyy-MM-dd")).csv" -StdOut:$StdOut)

    Invoke-AuditLogMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure "AuditLog/Passwords/ChangePassword" $local:DayOnly `
        "EventName eq 'PasswordChangeSucceeded'" `
        ("LogTime,SystemId,AccountId,SystemName,AccountName,AccountDomainName,NetworkAddress,PlatformDisplayName,EventName," + `
        "AssetPartitionId,AssetPartitionName,ProfileId,ProfileName,SyncGroupId,SyncGroupName,ApplianceId,ApplianceName") `
        -OutFile $local:OutFile -Excel:$Excel
}
