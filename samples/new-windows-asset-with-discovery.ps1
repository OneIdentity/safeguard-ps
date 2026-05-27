# Copyright (c) 2026 One Identity LLC. All rights reserved.

<#
.SYNOPSIS
Add a Windows asset with WinRM connection and configure account discovery.

.DESCRIPTION
Create a new Windows asset in Safeguard, configure the connection using either a
directory account already under management (preferred) or an explicit username and
password, verify the connection, and set up an account discovery schedule that finds
members of a specified local group (default: Administrators).

The script works interactively (prompting for any missing parameters) or fully
non-interactively when all required parameters are supplied on the command line.

Connection credential types are inferred from the parameters you provide:
  - If -DirectoryAccountName is specified, directory account connection is used.
  - If -ServiceAccountName is specified, explicit password connection is used.
  - If neither is specified, you are prompted to choose interactively.

.PARAMETER Appliance
IP address or hostname of the Safeguard appliance. If omitted and an existing
session ($SafeguardSession) is active, the session is reused. If no session exists,
you are prompted for the appliance address.

.PARAMETER Insecure
Ignore verification of the Safeguard appliance SSL certificate. Use this
switch only with self-signed development / lab appliances. For production
deployments, install a trusted certificate on the appliance and OMIT this
switch so the connection is validated against the trust store.

.PARAMETER NetworkAddress
IP address or hostname of the Windows machine to add as an asset. Prompted
interactively if not supplied.

.PARAMETER DisplayName
Friendly display name for the asset in Safeguard. Defaults to the NetworkAddress
if not specified.

.PARAMETER Platform
Platform name to resolve for the asset. Defaults to "Windows Server (WinRM)". You can
also pass a platform ID or another name (e.g., "Windows Desktop (WinRM)").

.PARAMETER DirectoryAccountName
A directory account already under management in Safeguard to use for WinRM
connection. This is the preferred connection method. Accepts multiple formats:
  - Integer ID (e.g., 42)
  - UPN format (e.g., svc_winrm@corp.local)
  - Down-level format (e.g., CORP\svc_winrm)
  - Plain account name (you will be prompted for the domain)
Mutually exclusive with -ServiceAccountName and -ServiceAccountPassword.

.PARAMETER ServiceAccountName
Username for explicit password connection. Providing this parameter automatically
selects explicit password as the connection method.
Mutually exclusive with -DirectoryAccountName.

.PARAMETER ServiceAccountPassword
SecureString password for explicit password connection. Prompted securely if
-ServiceAccountName is specified without a password.
Mutually exclusive with -DirectoryAccountName.

.PARAMETER AssetPartition
Name or ID of the asset partition to create the asset and discovery schedule in.
If omitted, the session default partition is used.

.PARAMETER DiscoveryScheduleName
Name for the account discovery schedule. Defaults to "WinRM Discovery - <DisplayName>"
if not specified. If a schedule with this name already exists, it is reused rather than
creating a new one.

.PARAMETER GroupFilter
Windows local group whose members will be discovered. Defaults to "Administrators".

.PARAMETER AutoManage
Automatically bring discovered accounts under Safeguard management.

.PARAMETER UseSslEncryption
Use HTTPS (port 5986) for the WinRM connection instead of the default HTTP
(port 5985). Requires a WinRM HTTPS listener configured on the target machine.

.PARAMETER VerifySslCertificate
Verify the target machine's SSL certificate when using HTTPS. Only meaningful
when -UseSslEncryption is also specified.

.PARAMETER SkipConnectionTest
Skip the connection test after creating the asset.

.PARAMETER SkipDiscovery
Skip invoking account discovery after configuring the schedule. The schedule is
still created and can be run later.

.EXAMPLE
.\new-windows-asset-with-discovery.ps1

Runs interactively, prompting for all required values.

.EXAMPLE
.\new-windows-asset-with-discovery.ps1 -Appliance 10.0.0.1 -Insecure `
    -NetworkAddress win-server1.corp.local `
    -DirectoryAccountName "svc_winrm@corp.local" -AutoManage

Non-interactive with a directory account connection (preferred).

.EXAMPLE
.\new-windows-asset-with-discovery.ps1 -Appliance 10.0.0.1 -Insecure `
    -NetworkAddress win-server1.corp.local `
    -DirectoryAccountName 42

Non-interactive using a directory account ID.

.EXAMPLE
.\new-windows-asset-with-discovery.ps1 -Appliance 10.0.0.1 -Insecure `
    -NetworkAddress win-server1.corp.local `
    -ServiceAccountName svc_winrm `
    -ServiceAccountPassword (ConvertTo-SecureString "P@ss" -AsPlainText -Force) `
    -GroupFilter "Administrators" -AutoManage

Non-interactive with explicit username and password.
#>
[CmdletBinding(DefaultParameterSetName="Interactive")]
Param(
    [Parameter(Mandatory=$false)]
    [string]$Appliance,
    [Parameter(Mandatory=$false)]
    [switch]$Insecure,
    [Parameter(Mandatory=$false)]
    [string]$NetworkAddress,
    [Parameter(Mandatory=$false)]
    [string]$DisplayName,
    [Parameter(Mandatory=$false)]
    [string]$Platform = "Windows Server (WinRM)",
    [Parameter(ParameterSetName="DirectoryAccount",Mandatory=$false)]
    [object]$DirectoryAccountName,
    [Parameter(ParameterSetName="ExplicitPassword",Mandatory=$false)]
    [string]$ServiceAccountName,
    [Parameter(ParameterSetName="ExplicitPassword",Mandatory=$false)]
    [SecureString]$ServiceAccountPassword,
    [Parameter(Mandatory=$false)]
    [string]$AssetPartition,
    [Parameter(Mandatory=$false)]
    [string]$DiscoveryScheduleName,
    [Parameter(Mandatory=$false)]
    [string]$GroupFilter = "Administrators",
    [Parameter(Mandatory=$false)]
    [switch]$AutoManage,
    [Parameter(Mandatory=$false)]
    [switch]$UseSslEncryption,
    [Parameter(Mandatory=$false)]
    [switch]$VerifySslCertificate,
    [Parameter(Mandatory=$false)]
    [switch]$SkipConnectionTest,
    [Parameter(Mandatory=$false)]
    [switch]$SkipDiscovery
)

if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }

# ============================================================
# Helper: Parse a directory account string into domain + name
# ============================================================
function Resolve-DirectoryAccountInput
{
    Param(
        [Parameter(Mandatory=$true)]
        [string]$InputValue
    )

    # Integer ID
    if ($InputValue -as [int])
    {
        return @{ Id = [int]$InputValue; Domain = $null; Name = $null }
    }
    # UPN format: name@domain.suffix
    if ($InputValue -match '^([^@]+)@(.+)$')
    {
        return @{ Id = $null; Domain = $Matches[2]; Name = $Matches[1] }
    }
    # Down-level format: domain\name
    if ($InputValue -match '^([^\\]+)\\(.+)$')
    {
        return @{ Id = $null; Domain = $Matches[1]; Name = $Matches[2] }
    }
    # Plain name -- domain must be supplied separately
    return @{ Id = $null; Domain = $null; Name = $InputValue }
}


# ============================================================
# 1. Import module and establish session
# ============================================================
if (-not (Get-Module safeguard-ps)) { Import-Module safeguard-ps }

if ($SafeguardSession -and (-not $PSBoundParameters.ContainsKey("Appliance") -or $SafeguardSession.Appliance -eq $Appliance))
{
    Write-Host -ForegroundColor Green "Using existing session for $($SafeguardSession.Appliance)"
}
else
{
    if (-not $PSBoundParameters.ContainsKey("Appliance") -or [string]::IsNullOrEmpty($Appliance))
    {
        $Appliance = Read-Host "Appliance address"
        if ([string]::IsNullOrWhiteSpace($Appliance))
        {
            throw "Appliance address is required"
        }
    }
    Connect-Safeguard -Appliance $Appliance -Insecure:$Insecure -Browser
    Write-Host -ForegroundColor Green "Connected to Safeguard -- $Appliance"
}


# ============================================================
# 2. Validate and prompt for missing parameters
# ============================================================
Write-Host ""
Write-Host -ForegroundColor Cyan "--- Parameter Validation ---"

# NetworkAddress
if (-not $PSBoundParameters.ContainsKey("NetworkAddress") -or [string]::IsNullOrWhiteSpace($NetworkAddress))
{
    $NetworkAddress = Read-Host "Network address of the Windows machine (IP or hostname)"
    if ([string]::IsNullOrWhiteSpace($NetworkAddress))
    {
        throw "NetworkAddress is required"
    }
}

# DisplayName defaults to NetworkAddress
if (-not $PSBoundParameters.ContainsKey("DisplayName") -or [string]::IsNullOrWhiteSpace($DisplayName))
{
    $DisplayName = $NetworkAddress
}

# Connection method -- infer from supplied parameters or prompt
$local:CredentialType = "None"
if ($PSBoundParameters.ContainsKey("DirectoryAccountName"))
{
    $local:CredentialType = "DirectoryPassword"
}
elseif ($PSBoundParameters.ContainsKey("ServiceAccountName"))
{
    $local:CredentialType = "Password"
}
else
{
    Write-Host ""
    Write-Host "How should Safeguard connect to this asset?"
    Write-Host "  [1] Directory account (recommended -- uses an account already under management)"
    Write-Host "  [2] Username and password"
    Write-Host "  [3] None (configure credentials later)"
    $local:Choice = Read-Host "Choice [1]"
    if ([string]::IsNullOrWhiteSpace($local:Choice) -or $local:Choice -eq "1")
    {
        $local:CredentialType = "DirectoryPassword"
    }
    elseif ($local:Choice -eq "2")
    {
        $local:CredentialType = "Password"
    }
    elseif ($local:Choice -eq "3")
    {
        $local:CredentialType = "None"
    }
    else
    {
        throw "Invalid choice: $($local:Choice)"
    }
}

# Resolve credential-type-specific parameters
$local:ServiceAccountDomainName = $null
if ($local:CredentialType -eq "DirectoryPassword")
{
    # Get directory account input if not supplied
    if (-not $PSBoundParameters.ContainsKey("DirectoryAccountName"))
    {
        $DirectoryAccountName = Read-Host "Directory account (ID, name@domain, domain\name, or name)"
        if ([string]::IsNullOrWhiteSpace("$DirectoryAccountName"))
        {
            throw "A directory account is required when using directory account connection"
        }
    }

    $local:Parsed = Resolve-DirectoryAccountInput -InputValue "$DirectoryAccountName"

    if ($local:Parsed.Id)
    {
        # Validate the account exists by ID
        Write-Host "Resolving directory account by ID: $($local:Parsed.Id)..."
        $local:DirAcct = Invoke-SafeguardMethod -Insecure:$Insecure Core GET "AssetAccounts/$($local:Parsed.Id)"
        if (-not $local:DirAcct)
        {
            throw "Directory account with ID $($local:Parsed.Id) not found"
        }
        $local:ServiceAccountDomainName = $local:DirAcct.Asset.Name
        $ServiceAccountName = $local:DirAcct.Name
        Write-Host -ForegroundColor Green "Resolved directory account: $ServiceAccountName on $($local:ServiceAccountDomainName) (ID=$($local:DirAcct.Id))"
    }
    else
    {
        # Determine domain from parsed input or prompt
        if ($local:Parsed.Domain)
        {
            $local:ServiceAccountDomainName = $local:Parsed.Domain
        }
        else
        {
            $local:ServiceAccountDomainName = Read-Host "Directory domain name"
            if ([string]::IsNullOrWhiteSpace($local:ServiceAccountDomainName))
            {
                throw "Domain name is required when specifying a directory account by name"
            }
        }
        $ServiceAccountName = $local:Parsed.Name

        # Validate the directory account exists
        Write-Host "Resolving directory account '$ServiceAccountName' in domain '$($local:ServiceAccountDomainName)'..."
        $local:DirAcct = Get-SafeguardDirectoryAccount -Insecure:$Insecure `
            -DirectoryToGet $local:ServiceAccountDomainName -AccountToGet $ServiceAccountName
        if (-not $local:DirAcct)
        {
            throw "Directory account '$($local:ServiceAccountDomainName)\$ServiceAccountName' not found in Safeguard"
        }
        Write-Host -ForegroundColor Green "Resolved directory account: $ServiceAccountName (ID=$($local:DirAcct.Id))"
    }
}
elseif ($local:CredentialType -eq "Password")
{
    if (-not $PSBoundParameters.ContainsKey("ServiceAccountName") -or [string]::IsNullOrWhiteSpace($ServiceAccountName))
    {
        $ServiceAccountName = Read-Host "Service account username"
        if ([string]::IsNullOrWhiteSpace($ServiceAccountName))
        {
            throw "Service account name is required when using username and password"
        }
    }
    if (-not $PSBoundParameters.ContainsKey("ServiceAccountPassword"))
    {
        $ServiceAccountPassword = Read-Host -AsSecureString "Service account password"
    }
    $local:DomainInput = Read-Host "Service account domain (leave blank if local)"
    if (-not [string]::IsNullOrWhiteSpace($local:DomainInput))
    {
        $local:ServiceAccountDomainName = $local:DomainInput
    }
}

# Resolve and validate platform -- must be a WinRM platform
if ($Platform -as [int])
{
    $local:PlatformObj = Get-SafeguardPlatform -Insecure:$Insecure -Platform ([int]$Platform)
    if ($local:PlatformObj.PlatformType -ne "WindowsRm")
    {
        throw "Platform ID $Platform ($($local:PlatformObj.DisplayName)) is not a WinRM platform. Use a WindowsRm platform such as 'Windows Server (WinRM)' or 'Windows Desktop (WinRM)'."
    }
    $local:ResolvedPlatformId = $local:PlatformObj.Id
    $local:ResolvedPlatformName = $local:PlatformObj.DisplayName
}
else
{
    $local:AllWinRm = @(Find-SafeguardPlatform -Insecure:$Insecure -QueryFilter "PlatformType eq 'WindowsRm' and Id ge 500")
    $local:Matches = @($local:AllWinRm | Where-Object { $_.DisplayName -ilike "*$Platform*" })
    if ($local:Matches.Count -eq 0)
    {
        Write-Host -ForegroundColor Red "No WinRM platform found matching '$Platform'."
        Write-Host "Available WinRM platforms:"
        foreach ($local:P in $local:AllWinRm)
        {
            Write-Host "  [$($local:P.Id)] $($local:P.DisplayName)"
        }
        throw "No WinRM platform matches '$Platform'. Specify a valid platform name or ID."
    }
    elseif ($local:Matches.Count -eq 1)
    {
        $local:ResolvedPlatformId = $local:Matches[0].Id
        $local:ResolvedPlatformName = $local:Matches[0].DisplayName
    }
    else
    {
        # Multiple matches -- pick exact match if available, otherwise show choices
        $local:Exact = @($local:Matches | Where-Object { $_.DisplayName -ieq $Platform })
        if ($local:Exact.Count -eq 1)
        {
            $local:ResolvedPlatformId = $local:Exact[0].Id
            $local:ResolvedPlatformName = $local:Exact[0].DisplayName
        }
        else
        {
            Write-Host "Multiple WinRM platforms match '$Platform':"
            for ($local:i = 0; $local:i -lt $local:Matches.Count; $local:i++)
            {
                Write-Host "  [$($local:i + 1)] $($local:Matches[$local:i].DisplayName) (ID=$($local:Matches[$local:i].Id))"
            }
            $local:PlatChoice = Read-Host "Select platform [1]"
            if ([string]::IsNullOrWhiteSpace($local:PlatChoice)) { $local:PlatChoice = "1" }
            $local:PlatIdx = ([int]$local:PlatChoice) - 1
            if ($local:PlatIdx -lt 0 -or $local:PlatIdx -ge $local:Matches.Count)
            {
                throw "Invalid platform selection: $local:PlatChoice"
            }
            $local:ResolvedPlatformId = $local:Matches[$local:PlatIdx].Id
            $local:ResolvedPlatformName = $local:Matches[$local:PlatIdx].DisplayName
        }
    }
}
Write-Host -ForegroundColor Green "Platform: $local:ResolvedPlatformName (ID=$local:ResolvedPlatformId)"

Write-Host -ForegroundColor Green "All parameters validated."
Write-Host ""


# ============================================================
# 3. Create the Windows asset
# ============================================================
Write-Host -ForegroundColor Cyan "--- Creating Asset ---"
Write-Host "  Display Name:    $DisplayName"
Write-Host "  Network Address: $NetworkAddress"
Write-Host "  Platform:        $local:ResolvedPlatformName (ID=$local:ResolvedPlatformId)"
Write-Host "  Credential Type: $($local:CredentialType)"
if ($local:CredentialType -ne "None")
{
    Write-Host "  Account:         $ServiceAccountName"
    if (-not [string]::IsNullOrEmpty($local:ServiceAccountDomainName))
    {
        Write-Host "  Domain:          $($local:ServiceAccountDomainName)"
    }
}

$local:AssetParams = @{
    Insecure = $Insecure
    DisplayName = $DisplayName
    NetworkAddress = $NetworkAddress
    Platform = $local:ResolvedPlatformId
    ServiceAccountCredentialType = $local:CredentialType
}
if (-not $UseSslEncryption)
{
    $local:AssetParams.NoSslEncryption = $true
}
elseif (-not $VerifySslCertificate)
{
    $local:AssetParams.DoNotVerifyServerSslCertificate = $true
}
if (-not [string]::IsNullOrEmpty($local:ServiceAccountDomainName))
{
    $local:AssetParams.ServiceAccountDomainName = $local:ServiceAccountDomainName
}
if (-not [string]::IsNullOrEmpty($ServiceAccountName))
{
    $local:AssetParams.ServiceAccountName = $ServiceAccountName
}
if ($null -ne $ServiceAccountPassword)
{
    $local:AssetParams.ServiceAccountPassword = $ServiceAccountPassword
}
if ($PSBoundParameters.ContainsKey("AssetPartition"))
{
    $local:AssetParams.AssetPartition = $AssetPartition
}

try
{
    $local:Asset = New-SafeguardAsset @local:AssetParams
}
catch
{
    Write-Host -ForegroundColor Red "Asset creation failed: $_"
    throw
}
$local:AssetId = $local:Asset.Id
Write-Host -ForegroundColor Green "Asset created: '$DisplayName' (ID=$($local:AssetId))"
Write-Host ""


# ============================================================
# 4. Test connection
# ============================================================
$local:ConnectionTestResult = "Skipped"
if (-not $SkipConnectionTest -and $local:CredentialType -ne "None")
{
    Write-Host -ForegroundColor Cyan "--- Testing Connection ---"
    try
    {
        $null = Test-SafeguardAsset -Insecure:$Insecure -AssetToTest $local:AssetId
        Write-Host -ForegroundColor Green "Connection test succeeded."
        $local:ConnectionTestResult = "Success"
    }
    catch
    {
        Write-Host -ForegroundColor Yellow "Connection test failed: $_"
        Write-Host -ForegroundColor Yellow "Continuing with discovery schedule setup. Discovery invocation will be skipped."
        $local:ConnectionTestResult = "Failed"
    }
    Write-Host ""
}
elseif ($local:CredentialType -eq "None")
{
    Write-Host -ForegroundColor Yellow "Skipping connection test -- no credentials configured."
    $local:ConnectionTestResult = "Skipped (no credentials)"
    Write-Host ""
}


# ============================================================
# 5. Create or reuse account discovery schedule
# ============================================================
Write-Host -ForegroundColor Cyan "--- Setting Up Account Discovery ---"

if (-not $PSBoundParameters.ContainsKey("DiscoveryScheduleName") -or [string]::IsNullOrWhiteSpace($DiscoveryScheduleName))
{
    $DiscoveryScheduleName = "WinRM Discovery - $DisplayName"
}

# Check if a schedule with this name already exists
$local:ExistingSchedules = Get-SafeguardAccountDiscoverySchedule -Insecure:$Insecure
$local:Schedule = $local:ExistingSchedules | Where-Object { $_.Name -eq $DiscoveryScheduleName } | Select-Object -First 1

if ($local:Schedule)
{
    Write-Host -ForegroundColor Yellow "Discovery schedule '$DiscoveryScheduleName' already exists (ID=$($local:Schedule.Id)) -- reusing it."
}
else
{
    $local:ScheduleParams = @{
        Insecure = $Insecure
        Name = $DiscoveryScheduleName
        DiscoveryType = "Windows"
        Schedule = (New-SafeguardSchedule -Days -StartHour 2 -StartMinute 0)
    }
    if ($PSBoundParameters.ContainsKey("AssetPartition"))
    {
        $local:ScheduleParams.AssetPartition = $AssetPartition
    }

    $local:Schedule = New-SafeguardAccountDiscoverySchedule @local:ScheduleParams
    Write-Host -ForegroundColor Green "Discovery schedule created: '$DiscoveryScheduleName' (ID=$($local:Schedule.Id))"
}


# ============================================================
# 6. Add asset to discovery schedule
# ============================================================
$local:AddAssetParams = @{
    Insecure = $Insecure
    Schedule = $local:Schedule.Id
    AssetsToAdd = @($local:AssetId)
}
if ($PSBoundParameters.ContainsKey("AssetPartition"))
{
    $local:AddAssetParams.AssetPartition = $AssetPartition
}

Add-SafeguardAccountDiscoveryScheduleAsset @local:AddAssetParams | Out-Null
Write-Host -ForegroundColor Green "Asset '$DisplayName' added to discovery schedule."


# ============================================================
# 7. Add Windows discovery rule (Administrators group)
# ============================================================
$local:Rule = New-SafeguardAccountDiscoveryRuleWindows `
    -Name "Discover $GroupFilter" `
    -GroupFilter $GroupFilter `
    -AutoManageDiscoveredAccounts:$AutoManage

$local:AddRuleParams = @{
    Insecure = $Insecure
    Schedule = $local:Schedule.Id
    RuleObject = $local:Rule
}
if ($PSBoundParameters.ContainsKey("AssetPartition"))
{
    $local:AddRuleParams.AssetPartition = $AssetPartition
}

Add-SafeguardAccountDiscoveryRule @local:AddRuleParams | Out-Null
Write-Host -ForegroundColor Green "Discovery rule added: find members of '$GroupFilter' group."
if ($AutoManage)
{
    Write-Host -ForegroundColor Green "  Auto-manage: ON -- discovered accounts will be brought under management."
}
else
{
    Write-Host "  Auto-manage: OFF -- discovered accounts will need to be imported manually."
}
Write-Host ""


# ============================================================
# 8. Invoke discovery (optional)
# ============================================================
$local:DiscoveredAccounts = @()
if (-not $SkipDiscovery -and $local:CredentialType -ne "None" -and $local:ConnectionTestResult -ne "Failed")
{
    Write-Host -ForegroundColor Cyan "--- Running Account Discovery ---"
    try
    {
        Invoke-SafeguardAssetAccountDiscovery -Insecure:$Insecure -Asset $local:AssetId
        Write-Host "Waiting for discovery to complete..."
        Start-Sleep -Seconds 15

        $local:DiscoveredAccounts = @(Get-SafeguardDiscoveredAccount -Insecure:$Insecure -Asset $local:AssetId)
        if ($local:DiscoveredAccounts.Count -gt 0)
        {
            Write-Host -ForegroundColor Green "Discovered $($local:DiscoveredAccounts.Count) account(s):"
            foreach ($local:Acct in $local:DiscoveredAccounts)
            {
                $local:Status = $local:Acct.Status
                if (-not $local:Status) { $local:Status = "New" }
                $local:AcctName = $local:Acct.Name
                if (-not $local:AcctName) { $local:AcctName = $local:Acct.AccountName }
                Write-Host "  - $local:AcctName ($local:Status)"
            }
        }
        else
        {
            Write-Host -ForegroundColor Yellow "No accounts discovered yet. Discovery may still be running."
            Write-Host -ForegroundColor Yellow "Check later with: Get-SafeguardDiscoveredAccount -Insecure -Asset $($local:AssetId)"
        }
    }
    catch
    {
        Write-Host -ForegroundColor Yellow "Discovery invocation failed: $_"
        Write-Host -ForegroundColor Yellow "You can run it manually: Invoke-SafeguardAssetAccountDiscovery -Insecure -Asset $($local:AssetId)"
    }
    Write-Host ""
}
elseif ($local:ConnectionTestResult -eq "Failed")
{
    Write-Host -ForegroundColor Yellow "Skipping discovery -- connection test failed. Fix connection settings and run manually:"
    Write-Host -ForegroundColor Yellow "  Invoke-SafeguardAssetAccountDiscovery -Insecure -Asset $($local:AssetId)"
    Write-Host ""
}
elseif ($local:CredentialType -eq "None")
{
    Write-Host -ForegroundColor Yellow "Skipping discovery -- no credentials configured on the asset."
    Write-Host ""
}
else
{
    Write-Host "Discovery skipped (use -SkipDiscovery:`$false to run)."
    Write-Host ""
}


# ============================================================
# 9. Summary
# ============================================================
Write-Host -ForegroundColor Cyan "============================================================"
Write-Host -ForegroundColor Cyan "  Summary"
Write-Host -ForegroundColor Cyan "============================================================"
Write-Host "  Asset:              $DisplayName (ID=$($local:AssetId))"
Write-Host "  Network Address:    $NetworkAddress"
Write-Host "  Credential Type:    $($local:CredentialType)"
Write-Host "  Connection Test:    $($local:ConnectionTestResult)"
Write-Host "  Discovery Schedule: $DiscoveryScheduleName (ID=$($local:Schedule.Id))"
Write-Host "  Group Filter:       $GroupFilter"
Write-Host "  Auto-Manage:        $AutoManage"
if ($local:DiscoveredAccounts.Count -gt 0)
{
    Write-Host "  Accounts Found:     $($local:DiscoveredAccounts.Count)"
}
Write-Host -ForegroundColor Cyan "============================================================"
Write-Host ""
Write-Host "Next steps:"
Write-Host "  - Review discovered accounts:  Get-SafeguardDiscoveredAccount -Insecure -Asset $($local:AssetId)"
Write-Host "  - Import an account:           Import-SafeguardDiscoveredAccount -Insecure -Asset $($local:AssetId) -AccountName <name>"
Write-Host "  - Edit the schedule:           Edit-SafeguardAccountDiscoverySchedule -Insecure $($local:Schedule.Id)"
Write-Host "  - Re-run discovery:            Invoke-SafeguardAssetAccountDiscovery -Insecure -Asset $($local:AssetId)"
