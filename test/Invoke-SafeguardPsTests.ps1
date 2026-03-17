#Requires -Version 7.0
<#
.SYNOPSIS
    safeguard-ps Integration Test Runner

.DESCRIPTION
    Discovers and runs test suites from the Suites/ directory against a live
    Safeguard appliance. Each suite follows Setup → Execute → Cleanup lifecycle
    with continue-on-failure semantics and structured reporting.

.PARAMETER Appliance
    Safeguard appliance network address (required).

.PARAMETER AdminUserName
    Bootstrap admin username. Default: "Admin".

.PARAMETER AdminPassword
    Bootstrap admin password. Default: "Admin123".

.PARAMETER SpsAppliance
    Optional Safeguard for Privileged Sessions appliance address.

.PARAMETER SpsUser
    SPS admin username. Default: "admin".

.PARAMETER SpsPassword
    SPS admin password. Required if SpsAppliance is specified.

.PARAMETER Suite
    Run only the specified suite(s) by name. Accepts wildcards.
    Example: -Suite "Connect","Users"

.PARAMETER ExcludeSuite
    Skip the specified suite(s) by name. Accepts wildcards.

.PARAMETER ListSuites
    List available test suites without running them.

.PARAMETER ReportPath
    Optional path to export JSON test report.

.PARAMETER TestPrefix
    Prefix for test objects created on the appliance. Default: "SgPsTest".

.EXAMPLE
    # Run all suites
    ./Invoke-SafeguardPsTests.ps1 -Appliance 192.168.117.15 -AdminPassword root4EDMZ

.EXAMPLE
    # Run specific suites
    ./Invoke-SafeguardPsTests.ps1 -Appliance 192.168.117.15 -AdminPassword root4EDMZ -Suite Connect,Users

.EXAMPLE
    # List available suites
    ./Invoke-SafeguardPsTests.ps1 -ListSuites
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, Position = 0)]
    [string]$Appliance,

    [Parameter()]
    [string]$AdminUserName = "Admin",

    [Parameter()]
    [string]$AdminPassword = "Admin123",

    [Parameter()]
    [string]$SpsAppliance,

    [Parameter()]
    [string]$SpsUser = "admin",

    [Parameter()]
    [string]$SpsPassword,

    [Parameter()]
    [string[]]$Suite,

    [Parameter()]
    [string[]]$ExcludeSuite,

    [Parameter()]
    [switch]$ListSuites,

    [Parameter()]
    [string]$ReportPath,

    [Parameter()]
    [string]$TestPrefix = "SgPsTest"
)

$ErrorActionPreference = "Continue"

# Import the framework module
$frameworkModule = Join-Path $PSScriptRoot "SafeguardPsTestFramework.psm1"
if (-not (Test-Path $frameworkModule)) {
    Write-Error "Framework module not found: $frameworkModule"
    exit 1
}
Import-Module $frameworkModule -Force

# Discover suite files
$suitesDir = Join-Path $PSScriptRoot "Suites"
if (-not (Test-Path $suitesDir)) {
    Write-Error "Suites directory not found: $suitesDir"
    exit 1
}

$suiteFiles = Get-ChildItem -Path $suitesDir -Filter "Suite-*.ps1" | Sort-Object Name

if ($suiteFiles.Count -eq 0) {
    Write-Warning "No suite files found in $suitesDir"
    if ($ListSuites) { exit 0 }
}

# --- List mode ---
if ($ListSuites) {
    Write-Host ""
    Write-Host "Available Test Suites:" -ForegroundColor Cyan
    Write-Host ("-" * 60) -ForegroundColor DarkGray
    foreach ($file in $suiteFiles) {
        $def = & $file.FullName
        $shortName = $file.BaseName -replace '^Suite-', ''
        $tags = if ($def.Tags) { "[$($def.Tags -join ', ')]" } else { "" }
        Write-Host "  $($shortName.PadRight(30)) $($def.Name)" -ForegroundColor White
        if ($def.Description) {
            Write-Host "    $($def.Description)" -ForegroundColor DarkGray
        }
        if ($tags) {
            Write-Host "    Tags: $tags" -ForegroundColor DarkGray
        }
    }
    Write-Host ""
    exit 0
}

# --- Run mode: Appliance is required ---
if (-not $Appliance) {
    Write-Error "The -Appliance parameter is required when running tests. Use -ListSuites to see available suites."
    exit 1
}

# Filter suites
$selectedSuites = $suiteFiles
if ($Suite) {
    # Explicit selection — include exactly what was requested (even optional suites)
    $selectedSuites = $selectedSuites | Where-Object {
        $shortName = $_.BaseName -replace '^Suite-', ''
        $matched = $false
        foreach ($pattern in $Suite) {
            if ($shortName -like $pattern) { $matched = $true; break }
        }
        $matched
    }
} else {
    # Default run — auto-exclude suites tagged "optional"
    $selectedSuites = $selectedSuites | Where-Object {
        $def = & $_.FullName
        if ($def.Tags -and ($def.Tags -contains "optional")) {
            Write-Host "  Skipping optional suite: $($_.BaseName -replace '^Suite-', '') (use -Suite to include)" -ForegroundColor DarkYellow
            $false
        } else {
            $true
        }
    }
}
if ($ExcludeSuite) {
    $selectedSuites = $selectedSuites | Where-Object {
        $shortName = $_.BaseName -replace '^Suite-', ''
        $excluded = $false
        foreach ($pattern in $ExcludeSuite) {
            if ($shortName -like $pattern) { $excluded = $true; break }
        }
        -not $excluded
    }
}

if (-not $selectedSuites -or @($selectedSuites).Count -eq 0) {
    Write-Warning "No suites matched the specified filters."
    exit 0
}

# --- Initialize ---
Write-Host ""
Write-Host ("=" * 66) -ForegroundColor Cyan
Write-Host "  safeguard-ps Integration Tests" -ForegroundColor Cyan
Write-Host ("=" * 66) -ForegroundColor Cyan
Write-Host "  Appliance:  $Appliance" -ForegroundColor White
Write-Host "  Suites:     $(@($selectedSuites).Count) selected" -ForegroundColor White
Write-Host ("=" * 66) -ForegroundColor Cyan

$context = New-SgPsTestContext `
    -Appliance $Appliance `
    -AdminUserName $AdminUserName `
    -AdminPassword $AdminPassword `
    -SpsAppliance $SpsAppliance `
    -SpsUser $SpsUser `
    -SpsPassword $SpsPassword `
    -TestPrefix $TestPrefix

# --- Import safeguard-ps module ---
Write-Host ""
Write-Host "Importing safeguard-ps module..." -ForegroundColor Yellow
try {
    Import-SgPsModule -Context $context
    Write-Host "  Module imported from: $($context.ModuleRoot)" -ForegroundColor Green
}
catch {
    Write-Host "  Failed to import module: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# --- Connect to appliance ---
Write-Host ""
Write-Host "Connecting to appliance..." -ForegroundColor Yellow
try {
    Connect-SgPsTestSession -Context $context
    Write-Host "  Connected as: $($context.AdminUserName)" -ForegroundColor Green
}
catch {
    Write-Host "  Failed to connect: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# --- Global pre-cleanup (runs BEFORE RunAdmin creation to avoid deleting it) ---
Write-Host ""
Write-Host "Pre-cleanup: removing stale objects from previous runs..." -ForegroundColor Yellow
Clear-SgPsStaleTestEnvironment -Context $context

# --- Ensure full admin privileges ---
# The bootstrap admin may not have all roles (e.g., AssetAdmin, PolicyAdmin).
# Create a temporary full-admin user and reconnect as that user for the test run.
Write-Host ""
Write-Host "Ensuring full admin privileges..." -ForegroundColor Yellow
$testAdminName = "$($context.TestPrefix)_RunAdmin"
$testAdminPassword = "RunAdmin9876!xyzQWE"
$testAdminCreated = $false
try {
    # Check if current user has AssetAdmin role
    $me = Get-SafeguardLoggedInUser -Insecure
    $hasAllRoles = ($me.AdminRoles -contains "AssetAdmin") -and ($me.AdminRoles -contains "PolicyAdmin")
    if (-not $hasAllRoles) {
        Write-Host "  Bootstrap admin missing roles — creating full-admin user..." -ForegroundColor Yellow
        $secPwd = ConvertTo-SecureString $testAdminPassword -AsPlainText -Force
        $runAdmin = New-SafeguardUser -Insecure -Provider -1 -NewUserName $testAdminName `
            -AdminRoles @('GlobalAdmin','Auditor','AssetAdmin','ApplianceAdmin','PolicyAdmin','UserAdmin','HelpdeskAdmin','OperationsAdmin') `
            -Password $secPwd
        $context | Add-Member -NotePropertyName RunAdminId -NotePropertyValue $runAdmin.Id -Force
        $context | Add-Member -NotePropertyName RunAdminName -NotePropertyValue $testAdminName -Force
        $context | Add-Member -NotePropertyName RunAdminPassword -NotePropertyValue $testAdminPassword -Force
        $testAdminCreated = $true

        # Reconnect as the full-admin user
        Disconnect-Safeguard
        $secPwd = ConvertTo-SecureString $testAdminPassword -AsPlainText -Force
        Connect-Safeguard -Appliance $context.Appliance -IdentityProvider "Local" `
            -Username $testAdminName -Password $secPwd -Insecure
        Write-Host "  Connected as full-admin: $testAdminName" -ForegroundColor Green
    } else {
        Write-Host "  Admin has full roles." -ForegroundColor Green
    }
}
catch {
    Write-Host "  Warning: could not create full-admin user: $($_.Exception.Message)" -ForegroundColor DarkYellow
    Write-Host "  Continuing with bootstrap admin — some tests may fail." -ForegroundColor DarkYellow
}

# --- Run suites ---
foreach ($suiteFile in $selectedSuites) {
    Invoke-SgPsTestSuite -SuiteFile $suiteFile.FullName -Context $context
}

# --- Report ---
$failCount = Write-SgPsTestReport -Context $context

if ($ReportPath) {
    Export-SgPsTestReport -OutputPath $ReportPath -Context $context
}

# --- Cleanup run admin and disconnect ---
if ($testAdminCreated) {
    try {
        # Reconnect as original admin to delete the run admin
        Disconnect-Safeguard
        $secPwd = ConvertTo-SecureString $context.AdminPassword -AsPlainText -Force
        Connect-Safeguard -Appliance $context.Appliance -IdentityProvider "Local" `
            -Username $context.AdminUserName -Password $secPwd -Insecure
        Remove-SafeguardUser -Insecure $context.RunAdminId
        Write-Host "Cleaned up run admin user." -ForegroundColor DarkGray
    }
    catch {
        Write-Host "Warning: could not delete run admin: $($_.Exception.Message)" -ForegroundColor DarkYellow
    }
}

try {
    Disconnect-Safeguard
}
catch {
    # Silently ignore disconnect errors
}

# Exit with appropriate code for CI
if ($failCount -gt 0) {
    exit 1
}
exit 0
