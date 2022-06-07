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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:EndDate = ($DayOnly.AddDays(1))

    # Calling AuditLog with just an endDate returns a result using a startDate 24 hours before the specified endDate
    Import-Module -Name "$PSScriptRoot\sg-utilities.psm1" -Scope Local
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET $RelativeUrl `
        -Accept "text/csv" -OutFile $local:OutFile `
        -Parameters @{
            endDate = (Format-DateTimeAsString $local:EndDate);
            filter = $Filter; fields = $Fields }

    Out-FileAndExcel -OutFile $local:OutFile -Excel:$Excel
}

<#
.SYNOPSIS
Get CSV report of accounts without passwords.

.DESCRIPTION
This cmdlet will generate CSV containing every account that has been added to Safeguard
that does not have a password stored in Safeguard.

This cmdlet will generate and save a CSV file by default.  This file can be opened
in Excel automatically using the -Excel parameter or the Open-CsvInExcel cmdlet.
You may alternatively send the CSV output to standard out.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER OutputDirectory
String containing the directory where to create the CSV file.

.PARAMETER Excel
Automatically open the CSV file into excel after it is generation.

.PARAMETER StdOut
Send CSV to standard out instead of generating a file.

.INPUTS
None.

.OUTPUTS
A CSV file or CSV text.

.EXAMPLE
Get-SafeguardReportAccountWithoutPassword -StdOut

.EXAMPLE
Get-SafeguardReportAccountWithoutPassword -OutputDirectory "C:\reports\" -Excel
#>
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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:OutFile = (Get-OutFileForParam -OutputDirectory $OutputDirectory -FileName "sg-accounts-wo-password-$((Get-Date).ToString("yyyyMMddTHHmmssZz")).csv" -StdOut:$StdOut)

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "PolicyAccounts" -Accept "text/csv" -OutFile $local:OutFile -Parameters @{
        filter = "HasPassword eq false";
        fields = ("Asset.Id,Id,Asset.Name,Name,DomainName,Asset.NetworkAddress,HasPassword,Disabled,RequestProperties.AllowPasswordRequest,RequestProperties.AllowSessionRequest," `
            + "Platform.DisplayName") }

    Out-FileAndExcel -OutFile $local:OutFile -Excel:$Excel
}

<#
.SYNOPSIS
Get CSV report of access requests for a given date (24 hour period).

.DESCRIPTION
This cmdlet will generate CSV containing every instance of access requests that either
released a password or initialized a session during a 24 hour period.  Dates in Safeguard
are UTC, but this cmdlet will use the local time for the 24 hour period.

This cmdlet will generate and save a CSV file by default.  This file can be opened
in Excel automatically using the -Excel parameter or the Open-CsvInExcel cmdlet.
You may alternatively send the CSV output to standard out.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER OutputDirectory
String containing the directory where to create the CSV file.

.PARAMETER Excel
Automatically open the CSV file into excel after it is generation.

.PARAMETER StdOut
Send CSV to standard out instead of generating a file.

.PARAMETER LocalDate
The date for which to run the report (Default is today).  Ex. "2019-02-14".

.INPUTS
None.

.OUTPUTS
A CSV file or CSV text.

.EXAMPLE
Get-SafeguardReportDailyAccessRequest -StdOut

.EXAMPLE
Get-SafeguardReportDailyAccessRequest -OutputDirectory "C:\reports\" -Excel

.EXAMPLE
Get-SafeguardReportDailyAccessRequest -LocalDate "2019-02-22" -Excel
#>
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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:DayOnly = (New-Object "System.DateTime" -ArgumentList $LocalDate.Year, $LocalDate.Month, $LocalDate.Day)
    $local:OutFile = (Get-OutFileForParam -OutputDirectory $OutputDirectory -FileName "sg-daily-access-request-$(($local:DayOnly).ToString("yyyy-MM-dd")).csv" -StdOut:$StdOut)

    Invoke-AuditLogMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure "AuditLog/AccessRequests/Activities" $local:DayOnly `
        "Action eq 'CheckOutPassword' or Action eq 'InitializeSession'" `
        ("LogTime,RequestId,RequesterId,RequesterName,AssetId,AccountId,AssetName,AccountName,AccountDomainName,AccessRequestType,Action," + `
        "SessionId,ApplianceId,ApplianceName") `
        -OutFile $local:OutFile -Excel:$Excel
}

<#
.SYNOPSIS
Get CSV report of password check failures for a given date (24 hour period).

.DESCRIPTION
This cmdlet will generate CSV containing every instance of password check
failures for a 24 hour period.  Dates in Safeguard are UTC, but this cmdlet
will use the local time for the 24 hour period.

This cmdlet will generate and save a CSV file by default.  This file can be opened
in Excel automatically using the -Excel parameter or the Open-CsvInExcel cmdlet.
You may alternatively send the CSV output to standard out.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER OutputDirectory
String containing the directory where to create the CSV file.

.PARAMETER Excel
Automatically open the CSV file into excel after it is generation.

.PARAMETER StdOut
Send CSV to standard out instead of generating a file.

.PARAMETER LocalDate
The date for which to run the report (Default is today).  Ex. "2019-02-14".

.INPUTS
None.

.OUTPUTS
A CSV file or CSV text.

.EXAMPLE
Get-SafeguardReportDailyPasswordCheckFail -StdOut

.EXAMPLE
Get-SafeguardReportDailyPasswordCheckFail -OutputDirectory "C:\reports\" -Excel

.EXAMPLE
Get-SafeguardReportDailyPasswordCheckFail -LocalDate "2019-02-22" -Excel
#>
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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:DayOnly = (New-Object "System.DateTime" -ArgumentList $LocalDate.Year, $LocalDate.Month, $LocalDate.Day)
    $local:OutFile = (Get-OutFileForParam -OutputDirectory $OutputDirectory -FileName "sg-daily-pwcheck-fail-$(($local:DayOnly).ToString("yyyy-MM-dd")).csv" -StdOut:$StdOut)

    Invoke-AuditLogMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure "AuditLog/Passwords/CheckPassword" $local:DayOnly `
        "EventName eq 'PasswordCheckFailed'" `
        ("LogTime,AssetId,AccountId,AssetName,AccountName,AccountDomainName,NetworkAddress,PlatformDisplayName,EventName," + `
        "RequestStatus.Message,AssetPartitionId,AssetPartitionName,ProfileId,ProfileName,SyncGroupId,SyncGroupName,ApplianceId,ApplianceName") `
        -OutFile $local:OutFile -Excel:$Excel
}

<#
.SYNOPSIS
Get CSV report of successful password checks for a given date (24 hour period).

.DESCRIPTION
This cmdlet will generate CSV containing every instance of password checks that
succeeded for a 24 hour period.  Dates in Safeguard are UTC, but this cmdlet
will use the local time for the 24 hour period.

This cmdlet will generate and save a CSV file by default.  This file can be opened
in Excel automatically using the -Excel parameter or the Open-CsvInExcel cmdlet.
You may alternatively send the CSV output to standard out.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER OutputDirectory
String containing the directory where to create the CSV file.

.PARAMETER Excel
Automatically open the CSV file into excel after it is generation.

.PARAMETER StdOut
Send CSV to standard out instead of generating a file.

.PARAMETER LocalDate
The date for which to run the report (Default is today).  Ex. "2019-02-14".

.INPUTS
None.

.OUTPUTS
A CSV file or CSV text.

.EXAMPLE
Get-SafeguardReportDailyPasswordCheckSuccess -StdOut

.EXAMPLE
Get-SafeguardReportDailyPasswordCheckSuccess -OutputDirectory "C:\reports\" -Excel

.EXAMPLE
Get-SafeguardReportDailyPasswordCheckSuccess -LocalDate "2019-02-22" -Excel
#>
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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:DayOnly = (New-Object "System.DateTime" -ArgumentList $LocalDate.Year, $LocalDate.Month, $LocalDate.Day)
    $local:OutFile = (Get-OutFileForParam -OutputDirectory $OutputDirectory -FileName "sg-daily-pwcheck-success-$(($local:DayOnly).ToString("yyyy-MM-dd")).csv" -StdOut:$StdOut)

    Invoke-AuditLogMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure "AuditLog/Passwords/CheckPassword" $local:DayOnly `
        "EventName eq 'PasswordCheckSucceeded'" `
        ("LogTime,AssetId,AccountId,AssetName,AccountName,AccountDomainName,NetworkAddress,PlatformDisplayName,EventName," + `
        "AssetPartitionId,AssetPartitionName,ProfileId,ProfileName,SyncGroupId,SyncGroupName,ApplianceId,ApplianceName") `
        -OutFile $local:OutFile -Excel:$Excel
}

<#
.SYNOPSIS
Get CSV report of password change failures for a given date (24 hour period).

.DESCRIPTION
This cmdlet will generate CSV containing every instance of password changes that
failed for a 24 hour period.  Dates in Safeguard are UTC, but this cmdlet
will use the local time for the 24 hour period.

This cmdlet will generate and save a CSV file by default.  This file can be opened
in Excel automatically using the -Excel parameter or the Open-CsvInExcel cmdlet.
You may alternatively send the CSV output to standard out.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER OutputDirectory
String containing the directory where to create the CSV file.

.PARAMETER Excel
Automatically open the CSV file into excel after it is generation.

.PARAMETER StdOut
Send CSV to standard out instead of generating a file.

.PARAMETER LocalDate
The date for which to run the report (Default is today).  Ex. "2019-02-14".

.INPUTS
None.

.OUTPUTS
A CSV file or CSV text.

.EXAMPLE
Get-SafeguardReportDailyPasswordChangeFail -StdOut

.EXAMPLE
Get-SafeguardReportDailyPasswordChangeFail -OutputDirectory "C:\reports\" -Excel

.EXAMPLE
Get-SafeguardReportDailyPasswordChangeFail -LocalDate "2019-02-22" -Excel
#>
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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:DayOnly = (New-Object "System.DateTime" -ArgumentList $LocalDate.Year, $LocalDate.Month, $LocalDate.Day)
    $local:OutFile = (Get-OutFileForParam -OutputDirectory $OutputDirectory -FileName "sg-daily-pwchange-fail-$(($local:DayOnly).ToString("yyyy-MM-dd")).csv" -StdOut:$StdOut)

    Invoke-AuditLogMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure "AuditLog/Passwords/ChangePassword" $local:DayOnly `
        "EventName eq 'PasswordChangeFailed'" `
        ("LogTime,AssetId,AccountId,AssetName,AccountName,AccountDomainName,NetworkAddress,PlatformDisplayName,EventName," + `
        "RequestStatus.Message,AssetPartitionId,AssetPartitionName,ProfileId,ProfileName,SyncGroupId,SyncGroupName,ApplianceId,ApplianceName") `
        -OutFile $local:OutFile -Excel:$Excel
}

<#
.SYNOPSIS
Get CSV report of successful password changes for a given date (24 hour period).

.DESCRIPTION
This cmdlet will generate CSV containing every instance of successful password changes
for a 24 hour period.  Dates in Safeguard are UTC, but this cmdlet
will use the local time for the 24 hour period.

This cmdlet will generate and save a CSV file by default.  This file can be opened
in Excel automatically using the -Excel parameter or the Open-CsvInExcel cmdlet.
You may alternatively send the CSV output to standard out.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER OutputDirectory
String containing the directory where to create the CSV file.

.PARAMETER Excel
Automatically open the CSV file into excel after it is generation.

.PARAMETER StdOut
Send CSV to standard out instead of generating a file.

.PARAMETER LocalDate
The date for which to run the report (Default is today).  Ex. "2019-02-14".

.INPUTS
None.

.OUTPUTS
A CSV file or CSV text.

.EXAMPLE
Get-SafeguardReportDailyPasswordChangeSuccess -StdOut

.EXAMPLE
Get-SafeguardReportDailyPasswordChangeSuccess -OutputDirectory "C:\reports\" -Excel

.EXAMPLE
Get-SafeguardReportDailyPasswordChangeSuccess -LocalDate "2019-02-22" -Excel
#>
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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:DayOnly = (New-Object "System.DateTime" -ArgumentList $LocalDate.Year, $LocalDate.Month, $LocalDate.Day)
    $local:OutFile = (Get-OutFileForParam -OutputDirectory $OutputDirectory -FileName "sg-daily-pwchange-success-$(($local:DayOnly).ToString("yyyy-MM-dd")).csv" -StdOut:$StdOut)

    Invoke-AuditLogMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure "AuditLog/Passwords/ChangePassword" $local:DayOnly `
        "EventName eq 'PasswordChangeSucceeded'" `
        ("LogTime,AssetId,AccountId,AssetName,AccountName,AccountDomainName,NetworkAddress,PlatformDisplayName,EventName," + `
        "AssetPartitionId,AssetPartitionName,ProfileId,ProfileName,SyncGroupId,SyncGroupName,ApplianceId,ApplianceName") `
        -OutFile $local:OutFile -Excel:$Excel
}

<#
.SYNOPSIS
Generates user entitlement report for a set of users in Safeguard via the Web API.

.DESCRIPTION
User entitlement report is a report of what accounts can be accessed by a set of users.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER UserList
An integer containing the ID of the access policy to get or a string containing the name.

.PARAMETER OutputDirectory
String containing the directory where to create the CSV file.

.PARAMETER Excel
Automatically open the CSV file into excel after it is generation.

.PARAMETER StdOut
Send CSV to standard out instead of generating a file.

.INPUTS
None.

.OUTPUTS
A CSV file or CSV text.

.EXAMPLE
Get-SafeguardReportUserEntitlement -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardReportUserEntitlement testUser1,testUser2

.EXAMPLE
Get-SafeguardReportUserEntitlement 123
#>
function Get-SafeguardReportUserEntitlement
{
    [CmdletBinding(DefaultParameterSetName="File")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [object[]]$UserList,
        [Parameter(Mandatory=$false, ParameterSetName="File")]
        [string]$OutputDirectory = (Get-Location),
        [Parameter(Mandatory=$false, ParameterSetName="File")]
        [switch]$Excel = $false,
        [Parameter(Mandatory=$false, ParameterSetName="StdOut")]
        [switch]$StdOut
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Import-Module -Name "$PSScriptRoot\sg-utilities.psm1" -Scope Local
    if (-not (Test-SafeguardMinVersionInternal -Appliance $Appliance -Insecure:$Insecure -MinVersion "2.7"))
    {
        throw "This cmdlet requires Safeguard version 2.7 or greater"
    }

    $local:OutFile = (Get-OutFileForParam -OutputDirectory $OutputDirectory -FileName "sg-user-entitlements-$((Get-Date).ToString("yyyy-MM-dd")).csv" -StdOut:$StdOut)

    if ($UserList)
    {
        [object[]]$local:Users = $null
        foreach ($local:User in $UserList)
        {
            $local:ResolvedUser = (Get-SafeguardUser -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -UserToGet $User)
            $local:Users += $($local:ResolvedUser).Id
        }
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Reports/Entitlements/UserEntitlements" `
            -Parameters @{ userIds = ($Users -join ",") } -Accept "text/csv" -OutFile $local:OutFile
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Reports/Entitlements/UserEntitlements" `
            -Accept "text/csv" -OutFile $local:OutFile
    }

    Out-FileAndExcel -OutFile $local:OutFile -Excel:$Excel
}

<#
.SYNOPSIS
Generates report of user group memberships for users in Safeguard via the Web API.

.DESCRIPTION
User membership report includes which users are in which groups along with
a few of the attributes of those users.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER OutputDirectory
String containing the directory where to create the CSV file.

.PARAMETER Excel
Automatically open the CSV file into excel after it is generation.

.PARAMETER StdOut
Send CSV to standard out instead of generating a file.

.INPUTS
None.

.OUTPUTS
A CSV file or CSV text.

.EXAMPLE
Get-SafeguardReportUserGroupMembership -Excel

.EXAMPLE
Get-SafeguardReportUserGroupMembership -StdOut
#>
function Get-SafeguardReportUserGroupMembership
{
    [CmdletBinding(DefaultParameterSetName="File")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false, ParameterSetName="File")]
        [string]$OutputDirectory = (Get-Location),
        [Parameter(Mandatory=$false, ParameterSetName="File")]
        [switch]$Excel = $false,
        [Parameter(Mandatory=$false, ParameterSetName="StdOut")]
        [switch]$StdOut
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Memberships = @()
    (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "UserGroups") | ForEach-Object {
        $local:GroupInfo = New-Object PSObject -Property ([ordered]@{
            GroupId = $_.Id;
            GroupName = $_.Name;
            GroupDescription = $_.Description;
            GroupDistinguishedName = $_.DirectoryProperties.DistinguishedName
        })
        $_.Members | ForEach-Object {
            $local:MembershipInfo = New-Object PSObject -Property ([ordered]@{
                GroupName = $local:GroupInfo.GroupName;
                GroupDescription = $local:GroupInfo.GroupDescription;
                GroupDistinguishedName = $local:GroupInfo.GroupDistinguishedName;
                GroupId = $local:GroupInfo.GroupId;
                UserIdentityProvider = $_.PrimaryAuthenticationProviderName;
                UserName = $_.UserName;
                UserDisplayName = $_.DisplayName;
                UserDescription = $_.Description;
                UserDistinguishedName = $_.DirectoryProperties.DistinguishedName;
                UserIdentityProviderId = $_.PrimaryAuthenticationProviderId;
                UserId = $_.Id;
                UserAdminRoles = ($_.AdminRoles -join ", ");
                UserIsPartitionOwner = $_.IsPartitionOwner;
                UserEmailAddress = $_.EmailAddress;
                UserWorkPhone = $_.WorkPhone;
                UserMobilePhone = $_.MobilePhone;
                UserSecondaryMobilePhone = $_.SecondaryMobilePhone
            })
            $local:Memberships += $local:MembershipInfo
        }
    }

    if ($StdOut)
    {
        $local:Memberships | ConvertTo-Csv -NoTypeInformation
    }
    else
    {
        $local:OutFile = (Get-OutFileForParam -OutputDirectory $OutputDirectory -FileName "sg-usergroup-memberships-$((Get-Date).ToString("yyyy-MM-dd")).csv" -StdOut:$StdOut)
        $local:Memberships | ConvertTo-Csv -NoTypeInformation | Out-File $local:OutFile
        Out-FileAndExcel -OutFile $local:OutFile -Excel:$Excel
    }
}

<#
.SYNOPSIS
Generates report of asset group memberships for assets in Safeguard via the Web API.

.DESCRIPTION
Asset membership report includes which assets are in which groups along with
a few of the attributes of those assets.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER OutputDirectory
String containing the directory where to create the CSV file.

.PARAMETER Excel
Automatically open the CSV file into excel after it is generation.

.PARAMETER StdOut
Send CSV to standard out instead of generating a file.

.INPUTS
None.

.OUTPUTS
A CSV file or CSV text.

.EXAMPLE
Get-SafeguardReportAssetGroupMembership -Excel

.EXAMPLE
Get-SafeguardReportAssetGroupMembership -StdOut
#>
function Get-SafeguardReportAssetGroupMembership
{
    [CmdletBinding(DefaultParameterSetName="File")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false, ParameterSetName="File")]
        [string]$OutputDirectory = (Get-Location),
        [Parameter(Mandatory=$false, ParameterSetName="File")]
        [switch]$Excel = $false,
        [Parameter(Mandatory=$false, ParameterSetName="StdOut")]
        [switch]$StdOut
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Memberships = @()
    (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "AssetGroups") | ForEach-Object {
        $local:GroupInfo = New-Object PSObject -Property ([ordered]@{
            GroupId = $_.Id;
            GroupName = $_.Name;
            GroupDescription = $_.Description;
            GroupIsDynamic = $_.IsDynamic
        })
        $_.Assets | ForEach-Object {
            $local:MembershipInfo = New-Object PSObject -Property ([ordered]@{
                GroupName = $local:GroupInfo.GroupName;
                GroupDescription = $local:GroupInfo.GroupDescription;
                GroupIsDynamic = $local:GroupInfo.GroupIsDynamic;
                GroupId = $local:GroupInfo.GroupId;
                AssetName = $_.Name;
                NetworkAddress = $_.NetworkAddress;
                DomainName = $_.DomainName;
                AssetDescription = $_.Description;
                AssetId = $_.Id;
                AssetPartitionName = $_.AssetPartitionName;
                AssetPartitionId = $_.AssetPartitionId;
                PlatformDisplayName = $_.PlatformDisplayName;
                PlatformType = $_.PlatformType;
                PlatformId = $_.PlatformId;
                Disabled = $_.Disabled;
                SupportsSessionManagement = $_.SupportsSessionManagement;
                AllowSessionRequests = $_.AllowSessionRequests;
                SshHostKeyFingerprint = $_.SshHostKeyFingerprint;
                SshHostKeyFingerprintSha256 = $_.SshHostKeyFingerprintSha256;
                SshSessionPort = $_.SessionAccessProperties.SshSessionPort;
                RemoteDesktopSessionPort = $_.SessionAccessProperties.RemoteDesktopSessionPort;
                TelnetSessionPort = $_.SessionAccessProperties.TelnetSessionPort
            })
            $local:Memberships += $local:MembershipInfo
        }
    }

    if ($StdOut)
    {
        $local:Memberships | ConvertTo-Csv -NoTypeInformation
    }
    else
    {
        $local:OutFile = (Get-OutFileForParam -OutputDirectory $OutputDirectory -FileName "sg-assetgroup-memberships-$((Get-Date).ToString("yyyy-MM-dd")).csv" -StdOut:$StdOut)
        $local:Memberships | ConvertTo-Csv -NoTypeInformation | Out-File $local:OutFile
        Out-FileAndExcel -OutFile $local:OutFile -Excel:$Excel
    }
}

<#
.SYNOPSIS
Generates report of account group memberships for accounts in Safeguard via the Web API.

.DESCRIPTION
Account membership report includes which accounts are in which groups along with
a few of the attributes of those accounts.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER OutputDirectory
String containing the directory where to create the CSV file.

.PARAMETER Excel
Automatically open the CSV file into excel after it is generation.

.PARAMETER StdOut
Send CSV to standard out instead of generating a file.

.INPUTS
None.

.OUTPUTS
A CSV file or CSV text.

.EXAMPLE
Get-SafeguardReportAccountGroupMembership -Excel

.EXAMPLE
Get-SafeguardReportAccountGroupMembership -StdOut
#>
function Get-SafeguardReportAccountGroupMembership
{
    [CmdletBinding(DefaultParameterSetName="File")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false, ParameterSetName="File")]
        [string]$OutputDirectory = (Get-Location),
        [Parameter(Mandatory=$false, ParameterSetName="File")]
        [switch]$Excel = $false,
        [Parameter(Mandatory=$false, ParameterSetName="StdOut")]
        [switch]$StdOut
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Memberships = @()
    (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "AccountGroups") | ForEach-Object {
        $local:GroupInfo = New-Object PSObject -Property ([ordered]@{
            GroupId = $_.Id;
            GroupName = $_.Name;
            GroupDescription = $_.Description;
            GroupIsDynamic = $_.IsDynamic
        })
        $_.Accounts | ForEach-Object {
            $local:MembershipInfo = New-Object PSObject -Property ([ordered]@{
                GroupName = $local:GroupInfo.GroupName;
                GroupDescription = $local:GroupInfo.GroupDescription;
                GroupIsDynamic = $local:GroupInfo.GroupIsDynamic;
                GroupId = $local:GroupInfo.GroupId;
                AccountName = $_.Name;
                AccountDescription = $_.Description;
                AccountId = $_.AccountId;
                AssetName = $_.SystemName;
                NetworkAddress = $_.SystemNetworkAddress;
                AssetId = $_.SystemId;
                IsServiceAccount = $_.IsServiceAccount;
                HasPassword = $_.HasPassword;
                HasSshKey = $_.HasSshKey;
                DomainName = $_.DomainName;
                DistinguishedName = $_.DistinguishedName;
                NetBiosName = $_.NetBiosName;
                AltLoginName = $_.AltLoginName;
                PlatformDisplayName = $_.PlatformDisplayName;
                PlatformType = $_.PlatformType;
                PlatformId = $_.PlatformId;
                Disabled = $_.Disabled;
                AllowPasswordRequest = $_.AllowPasswordRequest;
                AllowSessionRequest = $_.AllowSessionRequest;
                AllowSshKeyRequest = $_.AllowSshKeyRequest;
                SuspendAccountWhenCheckedIn = $_.SuspendAccountWhenCheckedIn
            })
            $local:Memberships += $local:MembershipInfo
        }
    }

    if ($StdOut)
    {
        $local:Memberships | ConvertTo-Csv -NoTypeInformation
    }
    else
    {
        $local:OutFile = (Get-OutFileForParam -OutputDirectory $OutputDirectory -FileName "sg-accountgroup-memberships-$((Get-Date).ToString("yyyy-MM-dd")).csv" -StdOut:$StdOut)
        $local:Memberships | ConvertTo-Csv -NoTypeInformation | Out-File $local:OutFile
        Out-FileAndExcel -OutFile $local:OutFile -Excel:$Excel
    }
}

<#
.SYNOPSIS
Generates report of account management configuration in Safeguard via the Web API.

.DESCRIPTION
Account management configuration report includes information for each asset and
account: asset partition, profile, password policy, check schedule, change
schedule, and sync group.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER OutputDirectory
String containing the directory where to create the CSV file.

.PARAMETER Excel
Automatically open the CSV file into excel after it is generation.

.PARAMETER StdOut
Send CSV to standard out instead of generating a file.

.INPUTS
None.

.OUTPUTS
A CSV file or CSV text.

.EXAMPLE
Get-SafeguardReportAssetManagementConfiguration -Excel

.EXAMPLE
Get-SafeguardReportAssetManagementConfiguration -StdOut
#>
function Get-SafeguardReportAssetManagementConfiguration
{
    [CmdletBinding(DefaultParameterSetName="File")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false, ParameterSetName="File")]
        [string]$OutputDirectory = (Get-Location),
        [Parameter(Mandatory=$false, ParameterSetName="File")]
        [switch]$Excel = $false,
        [Parameter(Mandatory=$false, ParameterSetName="StdOut")]
        [switch]$StdOut
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:ProfileLookupTable = @{}
    (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance `
            -Insecure:$Insecure Core GET "AssetPartitions/Profiles") | ForEach-Object {
        $local:ProfileLookupTable["$($_.AssetParitionId)_$($_.Id)"] = $_
    }
    $local:Configurations = @()
    (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance `
            -Insecure:$Insecure Core GET "AssetAccounts") | ForEach-Object {
        $local:Profile = $local:ProfileLookupTable["$($_.AssetParitionId)_$($_.EffectiveProfileId)"]
        $local:Configuration = New-Object PSObject -Property ([ordered]@{
            AssetPartitionName = $_.AssetPartitionName;
            AssetName = $_.AssetName;
            AccountName = $_.Name;
            AccountDescription = $_.Description;
            AccountDistinguishedName = $_.DistinguishedName;
            PlatformDisplayName = $_.PlatformDisplayName;
            AssetPartitionId = $_.AssetParitionId;
            AssetId = $_.AssetId;
            AccountId = $_.Id;
            ProfileName = $_.EffectiveProfileName;
            SyncGroupName = $_.SyncGroupName;
            AccountPasswordRuleName = $local:Profile.AccountPasswordRuleName;
            AccountPasswordRuleDescription = $local:Profile.AccountPasswordRule.Description;
            CheckScheduleName = $local:Profile.CheckScheduleName;
            CheckScheduleDescription = $local:Profile.CheckSchedule.Description;
            ChangeScheduleName = $local:Profile.ChangeScheduleName;
            ChangeScheduleDescription = $local:Profile.ChangeSchedule.Description;
            ProfileId = $_.EffectiveProfileId;
            AccountPasswordRuleId = $local:Profile.AccountPasswordRuleId;
            CheckScheduleId = $local:Profile.CheckScheduleId;
            ChangeScheduleId = $local:Profile.ChangeScheduleId;
            SyncGroupId = $_.SyncGroupId;
            SyncGroupPriority = $_.SyncGroupPriority
        })
        $local:Configurations += $local:Configuration
    }

    if ($StdOut)
    {
        $local:Configurations | ConvertTo-Csv -NoTypeInformation
    }
    else
    {
        $local:OutFile = (Get-OutFileForParam -OutputDirectory $OutputDirectory -FileName "sg-usergroup-memberships-$((Get-Date).ToString("yyyy-MM-dd")).csv" -StdOut:$StdOut)
        $local:Configurations | ConvertTo-Csv -NoTypeInformation | Out-File $local:OutFile
        Out-FileAndExcel -OutFile $local:OutFile -Excel:$Excel
    }
}

<#
.SYNOPSIS
Generates report of a2a entitlements in Safeguard via the Web API.

.DESCRIPTION
A2A entitlement report contains information about every A2A registration,
the certificate user that can call the account retrieval, and which accounts
can be retrieved.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER OutputDirectory
String containing the directory where to create the CSV file.

.PARAMETER Excel
Automatically open the CSV file into excel after it is generation.

.PARAMETER StdOut
Send CSV to standard out instead of generating a file.

.INPUTS
None.

.OUTPUTS
A CSV file or CSV text.

.EXAMPLE
Get-SafeguardReportA2aEntitlement -Excel

.EXAMPLE
Get-SafeguardReportA2aEntitlement -StdOut
#>
function Get-SafeguardReportA2aEntitlement
{
    [CmdletBinding(DefaultParameterSetName="File")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false, ParameterSetName="File")]
        [string]$OutputDirectory = (Get-Location),
        [Parameter(Mandatory=$false, ParameterSetName="File")]
        [switch]$Excel = $false,
        [Parameter(Mandatory=$false, ParameterSetName="StdOut")]
        [switch]$StdOut
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Entitlements = @()

    (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
            Core GET "A2ARegistrations") | ForEach-Object {
        $local:A2a = $_
        (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                Core GET "A2ARegistrations/$($local:A2a.Id)/RetrievableAccounts") | ForEach-Object {
            $local:Entitlement = New-Object PSObject -Property ([ordered]@{
                A2ARegistrationId = $local:A2a.Id;
                AppName = $local:A2a.AppName;
                Description = $local:A2a.Description;
                Disabled = $local:A2a.Disabled;
                CertificateUserId = $local:A2a.CertificateUserId;
                CertificateUser = $local:A2a.CertificateUser;
                CertificateUserThumbprint = $local:A2a.CertificateUserThumbprint;
                AssetId = $_.SystemId;
                AccountId = $_.AccountId;
                AssetName = $_.SystemName;
                AccountName = $_.AccountName;
                DomainName = $_.DomainName;
                AccountType = $_.AccountType;
                IPRestrictions = ($_.IpRestrictions -join ", ");
                AccountDisabled = [bool]($_.AccountDisabled)
            })
            $local:Entitlements += $local:Entitlement
        }
    }

    if ($StdOut)
    {
        $local:Entitlements | ConvertTo-Csv -NoTypeInformation
    }
    else
    {
        $local:OutFile = (Get-OutFileForParam -OutputDirectory $OutputDirectory -FileName "sg-a2a-entitlements-$((Get-Date).ToString("yyyy-MM-dd")).csv" -StdOut:$StdOut)
        $local:Entitlements | ConvertTo-Csv -NoTypeInformation | Out-File $local:OutFile
        Out-FileAndExcel -OutFile $local:OutFile -Excel:$Excel
    }
}

<#
.SYNOPSIS
Generates report of the last time each was password changed by Safeguard via the Web API.

.DESCRIPTION
This report contains information for every asset account that the caller has access to.
An asset admin or an auditor would be able to report on every account in Safeguard.  When
this report is generated, all dates and times are converted from UTC to the local system
time.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER OutputDirectory
String containing the directory where to create the CSV file.

.PARAMETER Excel
Automatically open the CSV file into excel after it is generation.

.PARAMETER StdOut
Send CSV to standard out instead of generating a file.

.INPUTS
None.

.OUTPUTS
A CSV file or CSV text.

.EXAMPLE
Get-SafeguardReportPasswordLastChanged -Excel

.EXAMPLE
Get-SafeguardReportPasswordLastChanged -StdOut
#>
function Get-SafeguardReportPasswordLastChanged
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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Changes = @()
    (Get-SafeguardAssetAccount -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
        -Fields AssetId,Id,AssetName,Name,DomainName,Description,LastSuccessPasswordCheckDate,LastSuccessPasswordChangeDate) | ForEach-Object {
            $local:Change = New-Object PSObject -Property ([ordered]@{
                AssetId = $_.AssetId;
                AccountId = $_.Id;
                AssetName = $_.AssetName;
                AccountName = $_.Name;
                DomainName = $_.DomainName;
                Description = $_.Description;
                LastPasswordChange = "";
                LastPasswordCheck = "";
            })
            if ($_.LastSuccessPasswordChangeDate) {$local:Change.LastPasswordChange = (Get-Date $_.LastSuccessPasswordChangeDate -Format "yyyy-MM-dd HH:mm:ss");}
            if ($_.LastSuccessPasswordCheckDate) {$local:Change.LastPasswordCheck = (Get-Date $_.LastSuccessPasswordCheckDate -Format "yyyy-MM-dd HH:mm:ss");}
            $local:Changes += $local:Change
        }

    if ($StdOut)
    {
        $local:Changes | ConvertTo-Csv -NoTypeInformation
    }
    else
    {
        $local:OutFile = (Get-OutFileForParam -OutputDirectory $OutputDirectory -FileName "sg-password-lastchanged-$((Get-Date).ToString("yyyy-MM-dd")).csv" -StdOut:$StdOut)
        $local:Changes | ConvertTo-Csv -NoTypeInformation | Out-File $local:OutFile
        Out-FileAndExcel -OutFile $local:OutFile -Excel:$Excel
    }
}

<#
.SYNOPSIS
Generates report of the password history for an asset account in Safeguard via the Web API.

.DESCRIPTION
This report contains past passwords for the request asset account.  The output includes a
time started and a time ended when that password was valid.

This cmdlet has a simpler alias: Get-SafeguardPasswordHistory

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER OutputDirectory
String containing the directory where to create the CSV file.

.PARAMETER Excel
Automatically open the CSV file into excel after it is generation.

.PARAMETER StdOut
Send CSV to standard out instead of generating a file.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to get asset account password history from.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to get asset account password history from.
(If specified, this will override the AssetPartition parameter)

.PARAMETER AssetToGet
An integer containing the ID of the asset to get asset account password history from or
a string containing the name.

.PARAMETER AccountToGet
An integer containing the ID of the account to get asset account password history from or
a string containing the name.

.INPUTS
None.

.OUTPUTS
A CSV file or CSV text.

.EXAMPLE
Get-SafeguardReportAssetAccountPasswordHistory example.corp adm-danp -Excel

.EXAMPLE
Get-SafeguardReportAssetAccountPasswordHistory linux.example.corp root -StdOut

.EXAMPLE
Get-SafeguardReportAssetAccountPasswordHistory linux.example.corp root -Days 5 -StdOut
#>
function Get-SafeguardReportAssetAccountPasswordHistory
{
    [CmdletBinding(DefaultParameterSetName="File")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false, ParameterSetName="File")]
        [string]$OutputDirectory = (Get-Location),
        [Parameter(Mandatory=$false, ParameterSetName="File")]
        [switch]$Excel = $false,
        [Parameter(Mandatory=$false, ParameterSetName="StdOut")]
        [switch]$StdOut,
        [Parameter(Mandatory=$false)]
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$false,Position=0)]
        [object]$AssetToGet,
        [Parameter(Mandatory=$true,Position=1)]
        [object]$AccountToGet,
        [Parameter(Mandatory=$false)]
        [int]$Days = 30
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:PastDays = (0 - $Days)
    $LocalDate = (Get-Date).AddDays($local:PastDays)
    $local:DayOnly = (New-Object "System.DateTime" -ArgumentList $LocalDate.Year, $LocalDate.Month, $LocalDate.Day)

    Import-Module -Name "$PSScriptRoot\sg-utilities.psm1" -Scope Local
    Import-Module -Name "$PSScriptRoot\assets.psm1" -Scope Local
    $local:Account = (Get-SafeguardAssetAccount -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                                -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -AssetToGet $AssetToGet -AccountToGet $AccountToGet)
    $local:AccountId = $local:Account.Id

    $local:OutFile = (Get-OutFileForParam -OutputDirectory $OutputDirectory -FileName "sg-pwhistory-$Days-days-$($local:Account.AssetName)-$($local:Account.Name).csv" -StdOut:$StdOut)

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "AssetAccounts/$($local:AccountId)/Passwords" `
        -Accept "text/csv" -OutFile $local:OutFile `
        -Parameters @{ startDate = (Format-DateTimeAsString $local:DayOnly) }

    Out-FileAndExcel -OutFile $local:OutFile -Excel:$Excel
}
New-Alias -Name Get-SafeguardPasswordHistory -Value Get-SafeguardReportAssetAccountPasswordHistory