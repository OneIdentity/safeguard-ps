<# Copyright (c) 2026 One Identity LLC. All rights reserved. #>

<#
.SYNOPSIS
Get audit log data from Safeguard via the web API.

.DESCRIPTION
This cmdlet will query Safeguard audit log endpoints and return audit data as
objects, JSON, or CSV.  This is a generic cmdlet that is meant for search.
More specific audit log cmdlets may be provided in the future for the more
efficiently retrieving data from the individual log endpoints.

When querying by time range, this cmdlet supports discreet units of time: days,
hours, or minutes.  You can query for 10 days of data or 2 hours of data, but
you can't mix and match to query for 2 days and 5 hours of data.

When looking up a specific audit log entry by ID, use the -Id parameter to
retrieve a single record without time range filtering.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Log
The name of the Log to search.

.PARAMETER Id
The unique identifier of a specific audit log entry to retrieve.  Supported
for: AccessRequests, Appliance, Archives, DiscoveryAccounts, DiscoveryAssets,
DiscoveryServices, DiscoverySshKeys, Logins, Patches.  For log types with
hierarchical drill-down paths use Invoke-SafeguardMethod directly.

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
Get-SafeguardAuditLog ObjectChanges -Fields "-UserProperties,-Changes,SessionSpsNodeIpAddress" -Hours 12 -CsvOutput

.EXAMPLE
Get-SafeguardAuditLog AllActivity -Fields "Id,LogTime,UserId,UserProperties,EventName" -Days 2

.EXAMPLE
Get-SafeguardAuditLog CredentialManagement -Fields "-UserProperties,-ConnectionProperties,-RequestStatus" -StartDate "2021-12-14" -Days 2 -JsonOutput -QueryFilter "EventName eq 'SshKeyChangeFailed'"

.EXAMPLE
Get-SafeguardAuditLog Logins -Id "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
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
                     "Logins","Maintenance","ObjectChanges","Patches","PlatformScripts","AllActivity")]
        [string]$Log,
        [Parameter(Mandatory=$true,ParameterSetName="Id",Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]$Id,
        [Parameter(Mandatory=$false,ParameterSetName="Days")]
        [Parameter(Mandatory=$false,ParameterSetName="Hours")]
        [Parameter(Mandatory=$false,ParameterSetName="Minutes")]
        [DateTime]$StartDate,
        [Parameter(Mandatory=$false,ParameterSetName="Days")]
        [int]$Days = 1,
        [Parameter(Mandatory=$false,ParameterSetName="Hours")]
        [int]$Hours,
        [Parameter(Mandatory=$false,ParameterSetName="Minutes")]
        [int]$Minutes,
        [Parameter(Mandatory=$false,ParameterSetName="Days")]
        [Parameter(Mandatory=$false,ParameterSetName="Hours")]
        [Parameter(Mandatory=$false,ParameterSetName="Minutes")]
        [string]$QueryFilter,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields,
        [Parameter(Mandatory=$false)]
        [switch]$JsonOutput,
        [Parameter(Mandatory=$false,ParameterSetName="Days")]
        [Parameter(Mandatory=$false,ParameterSetName="Hours")]
        [Parameter(Mandatory=$false,ParameterSetName="Minutes")]
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
        "DiscoveryServices" { $local:RelUrl = "AuditLog/Discovery/Services"; break }
        "DiscoverySshKeys" { $local:RelUrl = "AuditLog/Discovery/SshKeys"; break }
        "Licenses" { $local:RelUrl = "AuditLog/Licenses"; break }
        "Logins" { $local:RelUrl = "AuditLog/Logins"; break }
        "Maintenance" { $local:RelUrl = "AuditLog/Maintenance"; break }
        "ObjectChanges" { $local:RelUrl = "AuditLog/ObjectChanges"; break }
        "Patches" { $local:RelUrl = "AuditLog/Patches"; break }
        "PlatformScripts" { $local:RelUrl = "AuditLog/PlatformScripts"; break }
        "AllActivity"  { $local:RelUrl = "AuditLog/Search"; break }
    }

    if ($PSCmdlet.ParameterSetName -eq "Id")
    {
        # Detail lookup -- validate that this log type supports simple /{id} paths
        $local:DetailTypes = @("AccessRequests","Appliance","Archives","DiscoveryAccounts","DiscoveryAssets",
                               "DiscoveryServices","DiscoverySshKeys","Logins","Patches")
        if ($local:DetailTypes -notcontains $Log)
        {
            throw ("The $Log log type uses hierarchical drill-down paths and does not support -Id. " +
                   "Use Invoke-SafeguardMethod for detail access, e.g. " +
                   "Invoke-SafeguardMethod Core GET '$($local:RelUrl)/<subtype>/<id>'")
        }

        $local:Parameters = @{}
        if ($Fields)
        {
            $local:Parameters["fields"] = ($Fields -join ",")
        }

        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                               Core GET "$($local:RelUrl)/$Id" -Parameters $local:Parameters -JsonOutput:$JsonOutput
    }
    else
    {
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
}

# Helper to build common query parameters for audit log list endpoints
function Get-AuditLogListParameters
{
    [CmdletBinding()]
    [OutputType([hashtable])]
    Param(
        [Parameter(Mandatory=$false)]
        [object]$StartDate,
        [Parameter(Mandatory=$false)]
        [object]$EndDate,
        [Parameter(Mandatory=$false)]
        [string]$QueryFilter,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    Import-Module -Name "$PSScriptRoot\sg-utilities.psm1" -Scope Local
    $local:Parameters = @{}
    if ($null -ne $StartDate)
    {
        $local:Parameters["startDate"] = (Format-UtcDateTimeAsString ([DateTime]$StartDate).ToUniversalTime())
    }
    if ($null -ne $EndDate)
    {
        $local:Parameters["endDate"] = (Format-UtcDateTimeAsString ([DateTime]$EndDate).ToUniversalTime())
    }
    if ($QueryFilter)
    {
        $local:Parameters["filter"] = $QueryFilter
    }
    if ($Fields)
    {
        $local:Parameters["fields"] = ($Fields -join ",")
    }
    $local:Parameters
}

<#
.SYNOPSIS
Get access request activity audit log data from Safeguard via the web API.

.DESCRIPTION
This cmdlet drills into the access request activity audit log, allowing you to list
activities, filter by request, retrieve individual log entries, or get session log
data for a specific activity.

Without parameters, returns all access request activity entries from the last 24 hours
(API default).  Use -StartDate and -EndDate to control the time range.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER RequestId
The unique ID of the access request to filter by.  When provided alone, returns
all activity entries for that request.

.PARAMETER LogId
The database ID of a specific activity log entry.  Requires -RequestId.

.PARAMETER SessionLog
Switch to retrieve session log entries for a specific activity.  Requires both
-RequestId and -LogId.

.PARAMETER StartDate
Get activity that occurred after this date.  Defaults to 1 day before EndDate.

.PARAMETER EndDate
Get activity that occurred before this date.  Defaults to now.

.PARAMETER QueryFilter
A string to pass to the -filter query parameter in the Safeguard Web API.

.PARAMETER UserId
Get activity for a specific user (top-level list only).

.PARAMETER AssetId
Get activity for a specific asset (top-level list only).

.PARAMETER AccountId
Get activity for a specific account (top-level list only).

.PARAMETER Fields
An array of the property names to return.

.PARAMETER JsonOutput
A switch to return data as pretty JSON string.

.INPUTS
None.

.OUTPUTS
JSON or Objects

.EXAMPLE
Get-SafeguardAuditLogAccessRequestActivity -Insecure

.EXAMPLE
Get-SafeguardAuditLogAccessRequestActivity -Insecure -RequestId "abc-123" -LogId "def-456"

.EXAMPLE
Get-SafeguardAuditLogAccessRequestActivity -Insecure -RequestId "abc-123" -LogId "def-456" -SessionLog
#>
function Get-SafeguardAuditLogAccessRequestActivity
{
    [CmdletBinding(DefaultParameterSetName="List")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,ParameterSetName="List",Position=0)]
        [Parameter(Mandatory=$true,ParameterSetName="Detail",Position=0)]
        [Parameter(Mandatory=$true,ParameterSetName="SessionLog",Position=0)]
        [string]$RequestId,
        [Parameter(Mandatory=$true,ParameterSetName="Detail",Position=1)]
        [Parameter(Mandatory=$true,ParameterSetName="SessionLog",Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]$LogId,
        [Parameter(Mandatory=$true,ParameterSetName="SessionLog")]
        [switch]$SessionLog,
        [Parameter(Mandatory=$false,ParameterSetName="List")]
        [Parameter(Mandatory=$false,ParameterSetName="SessionLog")]
        [DateTime]$StartDate,
        [Parameter(Mandatory=$false,ParameterSetName="List")]
        [Parameter(Mandatory=$false,ParameterSetName="SessionLog")]
        [DateTime]$EndDate,
        [Parameter(Mandatory=$false,ParameterSetName="List")]
        [Parameter(Mandatory=$false,ParameterSetName="SessionLog")]
        [string]$QueryFilter,
        [Parameter(Mandatory=$false,ParameterSetName="List")]
        [ValidateRange(1,[int]::MaxValue)]
        [int]$UserId,
        [Parameter(Mandatory=$false,ParameterSetName="List")]
        [ValidateRange(1,[int]::MaxValue)]
        [int]$AssetId,
        [Parameter(Mandatory=$false,ParameterSetName="List")]
        [ValidateRange(1,[int]::MaxValue)]
        [int]$AccountId,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields,
        [Parameter(Mandatory=$false)]
        [switch]$JsonOutput
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSCmdlet.ParameterSetName -eq "Detail")
    {
        $local:RelUrl = "AuditLog/AccessRequests/Activities/$RequestId/$LogId"
        $local:Parameters = @{}
        if ($Fields)
        {
            $local:Parameters["fields"] = ($Fields -join ",")
        }
    }
    elseif ($PSCmdlet.ParameterSetName -eq "SessionLog")
    {
        $local:RelUrl = "AuditLog/AccessRequests/Activities/$RequestId/$LogId/SessionLog"
        $local:Parameters = (Get-AuditLogListParameters -StartDate $StartDate -EndDate $EndDate `
                                -QueryFilter $QueryFilter -Fields $Fields)
    }
    else
    {
        # List mode -- top-level or filtered by RequestId
        if ($RequestId)
        {
            # UserId/AssetId/AccountId are only valid on the top-level list endpoint
            if ($PSBoundParameters.ContainsKey("UserId") -or $PSBoundParameters.ContainsKey("AssetId") -or `
                $PSBoundParameters.ContainsKey("AccountId"))
            {
                throw "-UserId, -AssetId, and -AccountId filters are only supported on the top-level list " +
                      "(without -RequestId). Use -QueryFilter for request-level filtering."
            }
            $local:RelUrl = "AuditLog/AccessRequests/Activities/$RequestId"
        }
        else
        {
            $local:RelUrl = "AuditLog/AccessRequests/Activities"
        }
        $local:Parameters = (Get-AuditLogListParameters -StartDate $StartDate -EndDate $EndDate `
                                -QueryFilter $QueryFilter -Fields $Fields)
        if ($PSBoundParameters.ContainsKey("UserId"))
        {
            $local:Parameters["userId"] = $UserId
        }
        if ($PSBoundParameters.ContainsKey("AssetId"))
        {
            $local:Parameters["assetId"] = $AssetId
        }
        if ($PSBoundParameters.ContainsKey("AccountId"))
        {
            $local:Parameters["accountId"] = $AccountId
        }
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                           Core GET $local:RelUrl -Parameters $local:Parameters -JsonOutput:$JsonOutput
}

<#
.SYNOPSIS
Get access request session audit log data from Safeguard via the web API.

.DESCRIPTION
This cmdlet drills into the access request session audit log, allowing you to list
session activities, filter by request and session, retrieve individual log entries,
get session playback data, or get the SPS audit portal link for a session.

Without parameters, returns all access request session entries from the last 24 hours
(API default).  Use -StartDate and -EndDate to control the time range.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER RequestId
The unique ID of the access request to filter by.

.PARAMETER SessionId
The unique session ID within an access request.  Requires -RequestId.

.PARAMETER LogId
The database ID of a specific session log entry.  Requires -RequestId and -SessionId.

.PARAMETER Playback
Switch to retrieve session playback data.  Requires -RequestId and -SessionId.

.PARAMETER AuditPortalLink
Switch to retrieve the SPS audit portal permalink.  Requires -RequestId and -SessionId.

.PARAMETER StartDate
Get activity that occurred after this date.  Defaults to 1 day before EndDate.

.PARAMETER EndDate
Get activity that occurred before this date.  Defaults to now.

.PARAMETER QueryFilter
A string to pass to the -filter query parameter in the Safeguard Web API.

.PARAMETER UserId
Get activity for a specific user (top-level list only).

.PARAMETER AssetId
Get activity for a specific asset (top-level list only).

.PARAMETER AccountId
Get activity for a specific account (top-level list only).

.PARAMETER Fields
An array of the property names to return.

.PARAMETER JsonOutput
A switch to return data as pretty JSON string.

.INPUTS
None.

.OUTPUTS
JSON, Objects, or String (for AuditPortalLink)

.EXAMPLE
Get-SafeguardAuditLogAccessRequestSession -Insecure

.EXAMPLE
Get-SafeguardAuditLogAccessRequestSession -Insecure -RequestId "abc-123" -SessionId 1

.EXAMPLE
Get-SafeguardAuditLogAccessRequestSession -Insecure -RequestId "abc-123" -SessionId 1 -Playback

.EXAMPLE
Get-SafeguardAuditLogAccessRequestSession -Insecure -RequestId "abc-123" -SessionId 1 -AuditPortalLink
#>
function Get-SafeguardAuditLogAccessRequestSession
{
    [CmdletBinding(DefaultParameterSetName="List")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,ParameterSetName="List",Position=0)]
        [Parameter(Mandatory=$true,ParameterSetName="Detail",Position=0)]
        [Parameter(Mandatory=$true,ParameterSetName="Playback",Position=0)]
        [Parameter(Mandatory=$true,ParameterSetName="AuditPortalLink",Position=0)]
        [string]$RequestId,
        [Parameter(Mandatory=$false,ParameterSetName="List",Position=1)]
        [Parameter(Mandatory=$true,ParameterSetName="Detail",Position=1)]
        [Parameter(Mandatory=$true,ParameterSetName="Playback",Position=1)]
        [Parameter(Mandatory=$true,ParameterSetName="AuditPortalLink",Position=1)]
        [ValidateRange(1,[int]::MaxValue)]
        [int]$SessionId,
        [Parameter(Mandatory=$true,ParameterSetName="Detail",Position=2)]
        [ValidateNotNullOrEmpty()]
        [string]$LogId,
        [Parameter(Mandatory=$true,ParameterSetName="Playback")]
        [switch]$Playback,
        [Parameter(Mandatory=$true,ParameterSetName="AuditPortalLink")]
        [switch]$AuditPortalLink,
        [Parameter(Mandatory=$false,ParameterSetName="List")]
        [DateTime]$StartDate,
        [Parameter(Mandatory=$false,ParameterSetName="List")]
        [DateTime]$EndDate,
        [Parameter(Mandatory=$false,ParameterSetName="List")]
        [string]$QueryFilter,
        [Parameter(Mandatory=$false,ParameterSetName="List")]
        [ValidateRange(1,[int]::MaxValue)]
        [int]$UserId,
        [Parameter(Mandatory=$false,ParameterSetName="List")]
        [ValidateRange(1,[int]::MaxValue)]
        [int]$AssetId,
        [Parameter(Mandatory=$false,ParameterSetName="List")]
        [ValidateRange(1,[int]::MaxValue)]
        [int]$AccountId,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields,
        [Parameter(Mandatory=$false)]
        [switch]$JsonOutput
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSCmdlet.ParameterSetName -eq "Detail")
    {
        $local:RelUrl = "AuditLog/AccessRequests/Sessions/$RequestId/$SessionId/$LogId"
        $local:Parameters = @{}
        if ($Fields)
        {
            $local:Parameters["fields"] = ($Fields -join ",")
        }
    }
    elseif ($PSCmdlet.ParameterSetName -eq "Playback")
    {
        $local:RelUrl = "AuditLog/AccessRequests/Sessions/$RequestId/$SessionId/Playback"
        $local:Parameters = @{}
    }
    elseif ($PSCmdlet.ParameterSetName -eq "AuditPortalLink")
    {
        $local:RelUrl = "AuditLog/AccessRequests/Sessions/$RequestId/$SessionId/AuditPortalLink"
        $local:Parameters = @{}
    }
    else
    {
        # List mode -- validate parameter combinations
        if ($PSBoundParameters.ContainsKey("SessionId") -and -not $RequestId)
        {
            throw "-SessionId requires -RequestId. Provide a RequestId to filter sessions within a request."
        }
        if ($RequestId -and ($PSBoundParameters.ContainsKey("UserId") -or $PSBoundParameters.ContainsKey("AssetId") -or `
            $PSBoundParameters.ContainsKey("AccountId")))
        {
            throw "-UserId, -AssetId, and -AccountId filters are only supported on the top-level list " +
                  "(without -RequestId). Use -QueryFilter for request-level filtering."
        }

        $local:RelUrl = "AuditLog/AccessRequests/Sessions"
        if ($RequestId)
        {
            $local:RelUrl += "/$RequestId"
            if ($PSBoundParameters.ContainsKey("SessionId"))
            {
                $local:RelUrl += "/$SessionId"
            }
        }
        $local:Parameters = (Get-AuditLogListParameters -StartDate $StartDate -EndDate $EndDate `
                                -QueryFilter $QueryFilter -Fields $Fields)
        if ($PSBoundParameters.ContainsKey("UserId"))
        {
            $local:Parameters["userId"] = $UserId
        }
        if ($PSBoundParameters.ContainsKey("AssetId"))
        {
            $local:Parameters["assetId"] = $AssetId
        }
        if ($PSBoundParameters.ContainsKey("AccountId"))
        {
            $local:Parameters["accountId"] = $AccountId
        }
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                           Core GET $local:RelUrl -Parameters $local:Parameters -JsonOutput:$JsonOutput
}

<#
.SYNOPSIS
Get object change audit log data from Safeguard via the web API.

.DESCRIPTION
This cmdlet drills into the object change audit log, allowing you to list changes
by object type, filter to a specific object, or retrieve the detail of a single
change entry.

At minimum, -ObjectType is required.  Provide -ObjectId to narrow to a single
object, and -LogId to retrieve a specific change entry.

The API accepts many object types including User, Asset, AssetAccount, Policy,
Role, Directory, IdentityProvider, UserGroup, AssetGroup, AccountGroup, and more.
Use the Swagger documentation for a complete list.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER ObjectType
The type of object to retrieve changes for (e.g., User, Asset, AssetAccount,
Policy, Role).  Required for all modes.

.PARAMETER ObjectId
The ID of the specific object to retrieve changes for.  Requires -ObjectType.

.PARAMETER LogId
The unique ID of a specific change log entry.  Requires -ObjectType and -ObjectId.
Use the Id field from the list output.

.PARAMETER StartDate
Get changes that occurred after this date.  Only used for list queries (not with -LogId).

.PARAMETER EndDate
Get changes that occurred before this date.  Only used for list queries (not with -LogId).

.PARAMETER QueryFilter
A string to pass to the -filter query parameter in the Safeguard Web API.

.PARAMETER Fields
An array of the property names to return.

.PARAMETER JsonOutput
A switch to return data as pretty JSON string.

.INPUTS
None.

.OUTPUTS
JSON or Objects

.EXAMPLE
Get-SafeguardAuditLogObjectChange -Insecure User

.EXAMPLE
Get-SafeguardAuditLogObjectChange -Insecure User -ObjectId 123

.EXAMPLE
Get-SafeguardAuditLogObjectChange -Insecure User -ObjectId 123 -LogId "abc-def-123"

.EXAMPLE
Get-SafeguardAuditLogObjectChange -Insecure Asset -StartDate (Get-Date).AddDays(-7) -QueryFilter "EventName eq 'AssetCreated'"
#>
function Get-SafeguardAuditLogObjectChange
{
    [CmdletBinding(DefaultParameterSetName="ByType")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$ObjectType,
        [Parameter(ParameterSetName="ByObject",Mandatory=$true,Position=1)]
        [Parameter(ParameterSetName="Detail",Mandatory=$true,Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]$ObjectId,
        [Parameter(ParameterSetName="Detail",Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$LogId,
        [Parameter(ParameterSetName="ByType",Mandatory=$false)]
        [Parameter(ParameterSetName="ByObject",Mandatory=$false)]
        [DateTime]$StartDate,
        [Parameter(ParameterSetName="ByType",Mandatory=$false)]
        [Parameter(ParameterSetName="ByObject",Mandatory=$false)]
        [DateTime]$EndDate,
        [Parameter(ParameterSetName="ByType",Mandatory=$false)]
        [Parameter(ParameterSetName="ByObject",Mandatory=$false)]
        [string]$QueryFilter,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields,
        [Parameter(Mandatory=$false)]
        [switch]$JsonOutput
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSBoundParameters.ContainsKey("StartDate") -and $PSBoundParameters.ContainsKey("EndDate"))
    {
        if ($StartDate -gt $EndDate)
        {
            throw "-StartDate must not be later than -EndDate."
        }
    }

    if ($PSCmdlet.ParameterSetName -eq "Detail")
    {
        $local:RelUrl = "AuditLog/ObjectChanges/$ObjectType/$ObjectId/$LogId"
        $local:Parameters = @{}
        if ($Fields)
        {
            $local:Parameters["fields"] = ($Fields -join ",")
        }
    }
    else
    {
        $local:RelUrl = "AuditLog/ObjectChanges/$ObjectType"
        if ($PSCmdlet.ParameterSetName -eq "ByObject")
        {
            $local:RelUrl += "/$ObjectId"
        }
        $local:Parameters = (Get-AuditLogListParameters -StartDate $StartDate -EndDate $EndDate `
                                -QueryFilter $QueryFilter -Fields $Fields)
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                           Core GET $local:RelUrl -Parameters $local:Parameters -JsonOutput:$JsonOutput
}

<#
.SYNOPSIS
Get items discovered during a specific discovery job from the Safeguard audit log.

.DESCRIPTION
This cmdlet retrieves the actual accounts, assets, or services that were discovered
during a specific discovery job run.  The discovery job is identified by its audit
log entry ID, which can be obtained from Get-SafeguardAuditLog (e.g.,
Get-SafeguardAuditLog DiscoveryAccounts -Id <logEntryId>).

This endpoint requires AssetAdmin or Auditor roles.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER DiscoveryType
The type of discovery results to retrieve: Accounts, Assets, or Services.

.PARAMETER DiscoveryLogId
The ID of the discovery audit log entry.  Obtain this from the Id field of
Get-SafeguardAuditLog DiscoveryAccounts (or DiscoveryAssets, DiscoveryServices).

.PARAMETER QueryFilter
A string to pass to the -filter query parameter in the Safeguard Web API.

.PARAMETER Fields
An array of the property names to return.

.PARAMETER JsonOutput
A switch to return data as pretty JSON string.

.INPUTS
None.

.OUTPUTS
JSON or Objects

.EXAMPLE
Get-SafeguardAuditLogDiscoveredItem -Insecure Accounts -DiscoveryLogId "abc-123"

.EXAMPLE
Get-SafeguardAuditLogDiscoveredItem -Insecure Assets -DiscoveryLogId "abc-123" -Fields "Name","IpAddress"
#>
function Get-SafeguardAuditLogDiscoveredItem
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
        [ValidateSet("Accounts","Assets","Services")]
        [string]$DiscoveryType,
        [Parameter(Mandatory=$true,Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]$DiscoveryLogId,
        [Parameter(Mandatory=$false)]
        [string]$QueryFilter,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields,
        [Parameter(Mandatory=$false)]
        [switch]$JsonOutput
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:RelUrl = "AuditLog/Discovery/$DiscoveryType/$DiscoveryLogId/Discovered$DiscoveryType"

    $local:Parameters = @{}
    if ($QueryFilter)
    {
        $local:Parameters["filter"] = $QueryFilter
    }
    if ($Fields)
    {
        $local:Parameters["fields"] = ($Fields -join ",")
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                           Core GET $local:RelUrl -Parameters $local:Parameters -JsonOutput:$JsonOutput
}
<#
.SYNOPSIS
Get platform script change audit log data from Safeguard via the web API.

.DESCRIPTION
This cmdlet drills into the platform script audit log, allowing you to list all
script changes, filter by platform, retrieve a specific script version, or download
the raw script content as it existed at that point in time.

The list endpoints return metadata (Id, PlatformId, PlatformDisplayName, LogTime).
The detail endpoint (-PlatformId -LogId) returns the actual script content at that
version.  The -Raw switch returns the script as raw bytes.

This endpoint requires AssetAdmin or Auditor roles.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER PlatformId
The ID of the platform to filter script changes for.  Required for detail and
raw lookups.

.PARAMETER LogId
The unique ID of a specific script change log entry.  Requires -PlatformId.
Use the Id field from the list output.

.PARAMETER Raw
Switch to retrieve the raw script content at the time of this change entry.
Requires both -PlatformId and -LogId.

.PARAMETER QueryFilter
A string to pass to the -filter query parameter in the Safeguard Web API.

.PARAMETER Fields
An array of the property names to return.

.PARAMETER JsonOutput
A switch to return data as pretty JSON string.

.INPUTS
None.

.OUTPUTS
JSON, Objects, or String (for -Raw)

.EXAMPLE
Get-SafeguardAuditLogPlatformScript -Insecure

.EXAMPLE
Get-SafeguardAuditLogPlatformScript -Insecure -PlatformId 12345

.EXAMPLE
Get-SafeguardAuditLogPlatformScript -Insecure -PlatformId 12345 -LogId "abc-123"

.EXAMPLE
Get-SafeguardAuditLogPlatformScript -Insecure -PlatformId 12345 -LogId "abc-123" -Raw
#>
function Get-SafeguardAuditLogPlatformScript
{
    [CmdletBinding(DefaultParameterSetName="List")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(ParameterSetName="ByPlatform",Mandatory=$true,Position=0)]
        [Parameter(ParameterSetName="Detail",Mandatory=$true,Position=0)]
        [Parameter(ParameterSetName="Raw",Mandatory=$true,Position=0)]
        [ValidateRange(1,[int]::MaxValue)]
        [int]$PlatformId,
        [Parameter(ParameterSetName="Detail",Mandatory=$true,Position=1)]
        [Parameter(ParameterSetName="Raw",Mandatory=$true,Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]$LogId,
        [Parameter(ParameterSetName="Raw",Mandatory=$true)]
        [switch]$Raw,
        [Parameter(ParameterSetName="List",Mandatory=$false)]
        [Parameter(ParameterSetName="ByPlatform",Mandatory=$false)]
        [string]$QueryFilter,
        [Parameter(ParameterSetName="List",Mandatory=$false)]
        [Parameter(ParameterSetName="ByPlatform",Mandatory=$false)]
        [string[]]$Fields,
        [Parameter(Mandatory=$false)]
        [switch]$JsonOutput
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSCmdlet.ParameterSetName -eq "Raw")
    {
        $local:RelUrl = "AuditLog/PlatformScripts/$PlatformId/$LogId/Raw"
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                               Core GET $local:RelUrl
    }
    elseif ($PSCmdlet.ParameterSetName -eq "Detail")
    {
        $local:RelUrl = "AuditLog/PlatformScripts/$PlatformId/$LogId"
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                               Core GET $local:RelUrl -JsonOutput:$JsonOutput
    }
    else
    {
        $local:RelUrl = "AuditLog/PlatformScripts"
        if ($PSCmdlet.ParameterSetName -eq "ByPlatform")
        {
            $local:RelUrl += "/$PlatformId"
        }
        $local:Parameters = @{}
        if ($QueryFilter)
        {
            $local:Parameters["filter"] = $QueryFilter
        }
        if ($Fields)
        {
            $local:Parameters["fields"] = ($Fields -join ",")
        }
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                               Core GET $local:RelUrl -Parameters $local:Parameters -JsonOutput:$JsonOutput
    }
}
