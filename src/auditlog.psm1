

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
        [switch]$JsonOutput
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

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                           Core GET $local:RelUrl -Parameters $local:Parameters -JsonOutput:$JsonOutput
}