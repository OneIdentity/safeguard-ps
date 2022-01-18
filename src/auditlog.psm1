<#
.SYNOPSIS
Get audit log data from Safeguard via the web API.

.DESCRIPTION
This cmdlet will query Safeguard audit log endpoints and return audit data as
objects, JSON, or CSV.  This is a generic cmdlet that is meant for search.
More specific audit log cmdlets may be provided in the future for the more
efficiently retrieving data from the individual log endpoints.

This cmdlet only supports querying data in discreet units of time: days,
hours, or minutes.  You can query for 10 days of data or 2 hours of data, but
you can't mix and match to query for 2 days and 5 hours of data.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Log
The name of the Log to search.

.PARAMETER StartDate
An optional start date for the query.

.PARAMETER Days
Number of days of data to retrieve.

.PARAMETER Hours
Number of hours of data to retrieve.

.PARAMETER Minutes
Number of minutes of data to retrieve.

.PARAMETER QueryFilter
A string to pass to the -filter query parameter in the Safeguard Web API.

.PARAMETER Fields
An array of the event property names to return.  You can use "-<FieldName>" to exclude.

.PARAMETER JsonOutput
A switch to return data as pretty JSON string.

.PARAMETER CsvOutput
A switch to return data as CSV.

.INPUTS
None.

.OUTPUTS
JSON, CSV, or Objects

.EXAMPLE
Get-SafeguardAuditLog ObjectChanges -Fields "-UserProperties,-Changes,SessionSpsNodeIpAddress" -Hours 12 -Csv

.EXAMPLE
Get-SafeguardAuditLog AllActivity -Fields "Id,LogTime,UserId,UserProperties,EventName" -Days 2

.EXAMPLE
Get-SafeguardAuditLog CredentialManagement -Fields "-UserProperties,-ConnectionProperties,-RequestStatus" -StartDate "2021-12-14" -Days 2 -JsonOutput -QueryFilter "EventName eq 'SshKeyChangeFailed'"
#>
function Get-SafeguardAuditLog
{
    [CmdletBinding(DefaultParameterSetName="Days")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [ValidateSet("AccessRequests","AccessRequestActivities","AccessRequestSessions","Appliance","Archives","CredentialManagement",
                     "DirectorySync","DiscoveryAccounts","DiscoveryAssets","DiscoveryServices","DiscoverySshKeys","Licenses",
                     "Logins","Maintenance","ObjectChanges","Patches","AllActivity")]
        [string]$Log,
        [Parameter(Mandatory=$false)]
        [DateTime]$StartDate,
        [Parameter(Mandatory=$false,ParameterSetName="Days")]
        [int]$Days = 1,
        [Parameter(Mandatory=$false,ParameterSetName="Hours")]
        [int]$Hours,
        [Parameter(Mandatory=$false,ParameterSetName="Minutes")]
        [int]$Minutes,
        [Parameter(Mandatory=$false)]
        [string]$QueryFilter,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields,
        [Parameter(Mandatory=$false)]
        [switch]$JsonOutput,
        [Parameter(Mandatory=$false)]
        [switch]$CsvOutput
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    switch ($Log)
    {
        "AccessRequests" { $local:RelUrl = "AuditLog/AccessRequests/Requests"; break }
        "AccessRequestActivities" { $local:RelUrl = "AuditLog/AccessRequests/Activities"; break }
        "AccessRequestSessions" { $local:RelUrl = "AuditLog/AccessRequests/Sessions"; break }
        "Appliance" { $local:RelUrl = "AuditLog/Appliances"; break }
        "Archives" { $local:RelUrl = "AuditLog/Archives"; break }
        "CredentialManagement" { $local:RelUrl = "AuditLog/Passwords"; break }
        "DirectorySync" { $local:RelUrl = "AuditLog/DirectorySync"; break }
        "DiscoveryAccounts" { $local:RelUrl = "AuditLog/Discovery/Accounts"; break }
        "DiscoveryAssets" { $local:RelUrl = "AuditLog/Discovery/Assets"; break }
        "DiscoveryServices" { $local:RelUrl = "AuditLog/Services"; break }
        "DiscoverySshKeys" { $local:RelUrl = "AuditLog/SshKeys"; break }
        "Licenses" { $local:RelUrl = "AuditLog/Licenses"; break }
        "Logins" { $local:RelUrl = "AuditLog/Logins"; break }
        "Maintenance" { $local:RelUrl = "AuditLog/Maintenance"; break }
        "ObjectChanges" { $local:RelUrl = "AuditLog/ObjectChanges"; break }
        "Patches" { $local:RelUrl = "AuditLog/Patches"; break }
        "AllActivity"  { $local:RelUrl = "AuditLog/Search"; break }
    }

    if ($StartDate)
    {
        $local:UtcStartDate = $StartDate.ToUniversalTime()
        if ($PSBoundParameters.ContainsKey("Minutes"))
        {
            $local:UtcEndDate = ($local:UtcStartDate.AddMinutes($Minutes))
        }
        elseif ($PSBoundParameters.ContainsKey("Hours"))
        {
            $local:UtcEndDate = ($local:UtcStartDate.AddHours($Hours))
        }
        else
        {
            $local:UtcEndDate = ($local:UtcStartDate.AddDays($Days))
        }
    }
    else
    {
        if ($PSBoundParameters.ContainsKey("Minutes"))
        {
            $local:UtcStartDate = ([DateTime]::UtcNow.AddMinutes(0 - $Minutes))
        }
        elseif ($PSBoundParameters.ContainsKey("Hours"))
        {
            $local:UtcStartDate = ([DateTime]::UtcNow.AddHours(0 - $Hours))
        }
        else
        {
            $local:UtcStartDate = ([DateTime]::UtcNow.AddDays(0 - $Days))
        }
    }
    Import-Module -Name "$PSScriptRoot\sg-utilities.psm1" -Scope Local
    $local:Parameters = @{ startDate = (Format-UtcDateTimeAsString $local:UtcStartDate) }
    if ($local:UtcEndDate)
    {
        $local:Parameters["endDate"] = (Format-UtcDateTimeAsString $local:UtcEndDate)
    }
    if ($QueryFilter)
    {
        $local:Parameters["filter"] = $QueryFilter
    }
    if ($Fields)
    {
        $local:Parameters["fields"] = ($Fields -join ",")
    }

    if ($CsvOutput)
    {
        $local:Accept = "text/csv"
    }
    else
    {
        $local:Accept = "application/json"
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -Accept $local:Accept `
                           Core GET $local:RelUrl -Parameters $local:Parameters -JsonOutput:$JsonOutput
}