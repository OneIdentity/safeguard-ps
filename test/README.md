# safeguard-ps Integration Test Framework

Automated integration tests for the safeguard-ps PowerShell module running against a live
Safeguard appliance. Tests exercise the exported cmdlets through Setup → Execute → Cleanup
lifecycle with structured reporting.

## Prerequisites

- **PowerShell 7.x** or later
- A running **Safeguard appliance** accessible on the network
- An **admin account** with sufficient privileges (default: `Admin`)
- Resource owner password grant must be enabled on the appliance

## Quick Start

```powershell
# Run all suites
./test/Invoke-SafeguardPsTests.ps1 -Appliance 192.168.117.15 -AdminPassword root4EDMZ

# Run specific suites
./test/Invoke-SafeguardPsTests.ps1 -Appliance 192.168.117.15 -AdminPassword root4EDMZ `
    -Suite Connect,Users

# Run with SPS appliance
./test/Invoke-SafeguardPsTests.ps1 -Appliance 192.168.117.15 -AdminPassword root4EDMZ `
    -SpsAppliance 192.168.117.16 -SpsUser admin -SpsPassword secret

# Include optional suites (e.g., BackupRestore)
./test/Invoke-SafeguardPsTests.ps1 -Appliance 192.168.117.15 -AdminPassword root4EDMZ `
    -Suite BackupRestore

# List available suites
./test/Invoke-SafeguardPsTests.ps1 -ListSuites

# Exclude specific suites
./test/Invoke-SafeguardPsTests.ps1 -Appliance 192.168.117.15 -AdminPassword root4EDMZ `
    -ExcludeSuite BackupRestore

# Export JSON report for CI
./test/Invoke-SafeguardPsTests.ps1 -Appliance 192.168.117.15 -AdminPassword root4EDMZ `
    -ReportPath results.json
```

## Directory Structure

```
test/
├── Invoke-SafeguardPsTests.ps1       # Test runner entry point
├── SafeguardPsTestFramework.psm1     # Core framework module
├── README.md                         # This file
└── Suites/                           # Test suite files
    ├── Suite-Connect.ps1             # Connection and auth cmdlets
    ├── Suite-Users.ps1               # User management cmdlets
    └── ...
```

## Architecture

### Test Runner (`Invoke-SafeguardPsTests.ps1`)

The runner handles:
1. Importing the framework module and safeguard-ps from `src/`
2. Connecting to the appliance with admin credentials
3. Discovering `Suite-*.ps1` files from the `Suites/` directory
4. Filtering suites by `-Suite` / `-ExcludeSuite` parameters
5. Running global pre-cleanup to remove stale objects from previous runs
6. Executing each suite through the framework
7. Printing a formatted test report with pass/fail/skip statistics

### Framework Module (`SafeguardPsTestFramework.psm1`)

The framework provides:

| Category | Functions |
|----------|-----------|
| **Context** | `New-SgPsTestContext`, `Get-SgPsTestContext` |
| **Module** | `Import-SgPsModule` |
| **Connection** | `Connect-SgPsTestAppliance`, `Connect-SgPsTestSession`, `Connect-SgPsTestUser` |
| **API** | `Invoke-SgPsApi` |
| **Cleanup** | `Register-SgPsTestCleanup`, `Invoke-SgPsTestCleanup` |
| **Assertions** | `Test-SgPsAssert`, `Test-SgPsAssertEqual`, `Test-SgPsAssertNotNull`, `Test-SgPsAssertContains`, `Test-SgPsAssertThrows`, `Test-SgPsSkip` |
| **Suite** | `Invoke-SgPsTestSuite` |
| **Reporting** | `Write-SgPsTestReport`, `Export-SgPsTestReport` |
| **Helpers** | `Remove-SgPsTestObject`, `Remove-SgPsStaleTestObject`, `Clear-SgPsStaleTestEnvironment` |

### Suite Lifecycle

Each suite file returns a hashtable with `Setup`, `Execute`, and `Cleanup` scriptblocks:

```powershell
@{
    Name        = "User Management"
    Description = "Tests user CRUD operations"
    Tags        = @("users", "core")

    Setup = {
        param($Context)
        # Create test objects, register cleanup actions
    }

    Execute = {
        param($Context)
        # Run test assertions
        Test-SgPsAssert "Can get users" {
            $users = Get-SafeguardUser
            $null -ne $users
        }
    }

    Cleanup = {
        param($Context)
        # Additional cleanup (registered cleanups run automatically)
    }
}
```

**Lifecycle rules:**
- Setup failure → Execute is skipped, Cleanup still runs
- Each test assertion is recorded individually (pass/fail/skip)
- Registered cleanup actions execute in LIFO order after Cleanup
- All cleanup errors are caught and logged, never propagated

## Writing a New Suite

1. Create `test/Suites/Suite-YourFeature.ps1`
2. Return a hashtable with `Name`, `Description`, `Tags`, `Setup`, `Execute`, `Cleanup`
3. Use `$Context.TestPrefix` when naming test objects (e.g., `"${prefix}_MyTestAsset"`)
4. Register cleanup actions immediately after creating objects
5. Use `Test-SgPsAssert` and friends for assertions in Execute

### Naming Convention

All test objects should use the `$Context.TestPrefix` (default: `SgPsTest`) so the
pre-cleanup can find and remove stale objects from failed runs:

```powershell
$prefix = $Context.TestPrefix
$testUser = "${prefix}_MyUser"
```

### Cleanup Registration

Register cleanup immediately after creating each object:

```powershell
$user = New-SafeguardUser -NewUserName $testUser ...
$Context.SuiteData["UserId"] = $user.Id

Register-SgPsTestCleanup -Description "Delete test user" -Action {
    param($Ctx)
    try { Remove-SafeguardUser $Ctx.SuiteData['UserId'] } catch {}
}
```

## Differences from SafeguardDotNet Framework

| Aspect | SafeguardDotNet | safeguard-ps |
|--------|----------------|--------------|
| API calls | Via dotnet tool processes | Via safeguard-ps cmdlets (in-process) |
| Build step | `dotnet build` required | None — module imported directly |
| Auth | Process args + stdin | `Connect-Safeguard` + `$SafeguardSession` |
| Function prefix | `SgDn` | `SgPs` |
| Object prefix | `SgDnTest` | `SgPsTest` |
| PKCE preflight | Yes (resource owner grant check) | No |

## Test Suite Inventory

29 suites, 306 tests (298 default + 8 SPS-conditional), plus 6 optional (BackupRestore).

| Suite | Tests | Module | Description |
|-------|-------|--------|-------------|
| **Framework Smoke Test** | 4 | — | Verifies test framework itself works |
| **Connect & Core** | 14 | safeguard-ps.psm1 | Connect/Disconnect, tokens, Invoke-SafeguardMethod |
| **User Management** | 14 | users.psm1 | User CRUD, enable/disable, password, search |
| **Data Types** | 8 | safeguard-ps.psm1 | Platforms, timezones, transfer protocols, providers |
| **Management Shell** | 4 | safeguard-ps.psm1 | Get-SafeguardCommand, Get-SafeguardBanner |
| **Asset Management** | 11 | assets.psm1 | Asset CRUD, search, edit |
| **Asset Accounts** | 14 | assets.psm1 | Account CRUD, password, enable/disable, search |
| **Asset Partitions** | 13 | assetpartitions.psm1 | Partition CRUD, owners, enter/exit context |
| **Tags** | 14 | tags.psm1 | Tag CRUD, asset/account tagging |
| **User Groups** | 11 | usergroups.psm1 | Group CRUD, membership |
| **Asset Groups** | 10 | assetgroups.psm1 | Group CRUD, membership |
| **Account Groups** | 10 | accountgroups.psm1 | Group CRUD, membership |
| **Entitlements** | 14 | entitlements.psm1 | Entitlement CRUD, user/group membership |
| **Access Policies** | 14 | accesspolicies.psm1 | Policy CRUD, scope, properties |
| **Access Requests** | 11 | accessrequests.psm1 | Request lifecycle: create, approve, checkout, close, deny |
| **Certificates** | 14 | certificates.psm1 | Trusted/SSL certs, CSR lifecycle, audit log signing |
| **A2A Registrations** | 15 | a2a.psm1 | A2A CRUD, credential retrieval config, API keys |
| **A2A Credentials** | 5 | a2a.psm1 | PFX cert auth, password retrieval/set, API key secrets |
| **Settings** | 7 | settings.psm1 | Appliance/core settings read/write/restore |
| **Events** | 12 | events.psm1 | Event names/categories/properties, subscriptions |
| **Appliance Status** | 13 | safeguard-ps.psm1 | Status, version, health, time, state, TLS |
| **Password Profiles** | 22 | assetpartitions.psm1 | Profiles, rules, check/change schedules |
| **Diagnostics** | 10 | diagnostics.psm1 | Ping, nslookup, traceroute, netstat, ARP, telnet |
| **Deleted Objects** | 13 | deleted.psm1 | Delete/restore/purge assets, accounts, users; purge settings |
| **Reports** | 13 | reports.psm1 | All report cmdlets (daily, membership, entitlement, A2A) |
| **Networking** | 5 | networking.psm1 | Network interfaces, DNS suffix (read-only) |
| **Licensing** | 3 | licensing.psm1 | License listing (read-only) |
| **SPS Integration** | 8 | sessionapi.psm1 | SPS connect/disconnect, version, info, firmware (conditional) |
| **Backup & Restore** | 6 | maintenance.psm1 | Backup CRUD, export/import (optional, tagged) |

### Optional / Conditional Suites

- **BackupRestore** — Tagged `optional`, auto-skipped unless explicitly requested via `-Suite BackupRestore`. Puts appliance in maintenance mode.
- **SPS Integration** — Requires `-SpsAppliance`, `-SpsUser`, `-SpsPassword` parameters. Gracefully skips all tests when SPS is not configured.

### Test Data

Test certificates are stored in `test/TestData/CERTS/`:
- `RootCA.pem/.pfx/.cer` — Self-signed root CA
- `IntermediateCA.pem/.pfx/.cer` — Intermediate CA signed by RootCA
- `UserCert.pem/.pfx/.cer/.pvk` — End-entity cert signed by IntermediateCA
- All PFX files use password: `a`
