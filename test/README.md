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
