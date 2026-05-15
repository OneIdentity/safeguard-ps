---
name: testing-guide
description: >-
  Use when running tests, writing tests, investigating test failures,
  or setting up a test environment against a live Safeguard appliance.
  Covers the integration test framework, test runner commands, suite
  structure, assertion patterns, and module-to-suite mapping.
---

# Testing Guide

Use this skill when working on safeguard-ps test tasks. The repo has no mock test layer -- meaningful test work requires a live Safeguard appliance, and some session-related coverage also requires an SPS appliance.

## Appliance access

Always ask the user for the live environment details before starting test work:

1. Appliance address -- IP or hostname
2. Admin password -- bootstrap default is `Admin123`
3. Optional SPS appliance address and SPS credentials -- needed for session/SPS suites

Why this matters:

- A live appliance is required to browse Swagger docs and run the integration suite.
- SPS-specific suites skip or cannot run without SPS connectivity.
- The built-in bootstrap environment is often enough to start, but not enough to validate every role-sensitive path.

Useful Swagger endpoints once connected:

- `https://<appliance>/service/core/swagger`
- `https://<appliance>/service/appliance/swagger`
- `https://<appliance>/service/notification/swagger`
- `https://<appliance>/service/event/swagger`

## Connecting to the appliance

Resource Owner Grant (ROG) is disabled by default. For ad-hoc manual connections, use `-Pkce`:

```powershell
$secPwd = ConvertTo-SecureString "<password>" -AsPlainText -Force
Connect-Safeguard -Appliance <address> -IdentityProvider Local -Username Admin `
    -Password $secPwd -Insecure -Pkce
```

Notes:

- Use this pattern for manual exploration and quick verification.
- The test runner handles ROG automatically for the test session and restores the prior state afterward.
- `-Insecure` is acceptable for local test environments, not production guidance.

## Running the test suite

The repo is a pure PowerShell module, but you must reinstall it from source before testing so stale installed copies do not mask changes.

```powershell
# Reinstall first, then run
Remove-Module safeguard-ps -ErrorAction SilentlyContinue
./cleanup-local.ps1
./install-local.ps1

# Run all suites (AdminPassword defaults to Admin123)
pwsh -File ./test/Invoke-SafeguardPsTests.ps1 -Appliance <address>

# Run specific suites
pwsh -File ./test/Invoke-SafeguardPsTests.ps1 -Appliance <address> -Suite Connect,Users,Assets

# List available suites
pwsh -File ./test/Invoke-SafeguardPsTests.ps1 -ListSuites
```

From a Windows PowerShell 5.1 host, invoke `pwsh` with `-Command` and an explicit array:

```powershell
pwsh -NoProfile -Command "& .\test\Invoke-SafeguardPsTests.ps1 -Appliance '10.0.0.1' -Suite @('Connect','Users')"
```

Important runtime facts:

- The runner requires PowerShell 7 (`pwsh`).
- It automatically creates a temporary admin user, enables ROG, performs pre-cleanup, and emits structured results.
- A healthy baseline is `370+ passed, 0 failed, ~8 skipped`.
- SPS-related skips are expected when SPS details are not supplied.

Recommended workflow:

1. Reinstall the module.
2. Run the narrowest relevant suite set first.
3. Expand to broader coverage only after the targeted suites pass.
4. Re-run after each code change that could affect exported behavior.

## Fixing test failures

Default rule: fix the product code first.

- Do not change a test merely to make it pass.
- Only modify a test when the test itself is wrong, the user approves the change, or a deliberate feature change has changed expected behavior.
- Always ask before weakening an assertion.
- When debugging, prefer reproducing the failure in the smallest relevant suite instead of editing assertions prematurely.

## Module-to-suite mapping

Use this table to choose the smallest suite set that covers the module you are changing.

| Module | Relevant suites |
|--------|----------------|
| `safeguard-ps.psm1` | Connect, CertificateAuthentication, ApplianceStatus, DataTypes, ManagementShell |
| `users.psm1` | Users |
| `assets.psm1` | Assets, AssetAccounts |
| `assetpartitions.psm1` | AssetPartitions, PasswordProfiles |
| `a2a.psm1` | A2ARegistrations, A2ACredentials |
| `policies.psm1` | AccessPolicies |
| `entitlements.psm1` | Entitlements |
| `groups.psm1` | UserGroups, AssetGroups, AccountGroups |
| `tags.psm1` | Tags |
| `events.psm1` | Events, EventListener |
| `a2acallers.psm1` | A2ARegistrations, A2ACredentials, A2AEventListener |
| `certificates.psm1` | Certificates |
| `reports.psm1` | Reports |
| `deleted.psm1` | DeletedObjects |
| `requests.psm1` | AccessRequests |
| `settings.psm1` | Settings |
| `networking.psm1` | Networking |
| `licensing.psm1` | Licensing |
| `diagnostics.psm1` | Diagnostics |
| `sessionapi.psm1` | SpsIntegration (requires SPS) |
| `maintenance.psm1` | BackupRestore (must be explicitly requested) |
| `customplatforms.psm1` | CustomPlatforms |
| `discovery.psm1` | AccountDiscovery |
| `auditlog.psm1` | AuditLog, AuditLogAccessRequests, AuditLogMaintenance, AuditLogObjectChanges, AuditLogPlatformScripts, AuditLogScheduledReports |
| `reasoncodes.psm1` | ReasonCodes |
| `runningtasks.psm1` | RunningTasks |
| `profiles.psm1` | PasswordProfiles |
| `managementShell.psm1` | ManagementShell |
| `datatypes.psm1` | DataTypes |
| `directories.psm1`, `clustering.psm1`, `archives.psm1`, `syslog.psm1`, `starling.psm1`, `service.psm1`, `schedules.psm1` | No dedicated suite -- test manually |
| `sessionjoin.psm1` | SpsApi (requires SPS) |

## Built-in Admin role limitations

This matters for test setup and for interpreting authorization failures.

- The built-in `Admin` account includes Authorizer and UserAdmin.
- It does not include AssetAdmin or PolicyAdmin.
- Those missing roles cannot be added to built-in `Admin` -- the appliance returns error `50100`.
- The test runner creates `SgPsTest_RunAdmin` with all needed roles so role-sensitive suites can execute cleanly.

Practical implication: if manual validation as built-in `Admin` fails but the suite passes under `SgPsTest_RunAdmin`, check role coverage before assuming the module is broken.

## Writing a new test suite

Create a new suite file at `test/Suites/Suite-YourFeature.ps1`.

Each suite returns a hashtable with these keys:

- `Name`
- `Description`
- `Tags`
- `Setup`
- `Execute`
- `Cleanup`

Authoring rules:

- Use `$Context.TestPrefix` when naming test objects.
- Use `$Context.SuiteData` to carry state between phases.
- Register cleanup immediately after creating each object.
- Pre-clean stale objects in `Setup` with `Remove-SgPsStaleTestObject`.
- Prefer existing Safeguard cmdlets over raw `Invoke-SafeguardMethod` in tests.
- See `test/README.md` for the full framework API.

Template:

```powershell
@{
    Name = "My Feature"; Description = "Tests for my feature"; Tags = @("myfeature")
    Setup = {
        param($Context)
        $prefix = $Context.TestPrefix
        Remove-SgPsStaleTestObject -Collection "Assets" -Name "${prefix}_TestAsset"
        $obj = New-SafeguardAsset -DisplayName "${prefix}_TestAsset" ...
        $Context.SuiteData["AssetId"] = $obj.Id
        Register-SgPsTestCleanup -Description "Remove test asset" -Action {
            param($Ctx)
            try { Remove-SafeguardAsset $Ctx.SuiteData["AssetId"] } catch {}
        }
    }
    Execute = {
        param($Context)
        Test-SgPsAssert "Can retrieve asset" {
            $asset = Get-SafeguardAsset $Context.SuiteData["AssetId"]
            $null -ne $asset
        }
    }
    Cleanup = { param($Context) }
}
```

Suggested suite-writing flow:

1. Pick the module and corresponding suite coverage area.
2. Create unique objects using `$Context.TestPrefix`.
3. Register cleanup immediately.
4. Add independent readback assertions.
5. Run the narrow suite until stable.
6. Re-run adjacent suites if the module has shared behavior.

## Key framework functions

Core helpers you will use repeatedly:

- `Test-SgPsAssert`
- `Register-SgPsTestCleanup`
- `Remove-SgPsStaleTestObject`
- `Connect-SgPsTestAppliance`
- `Connect-SgPsTestSession`
- `Connect-SgPsTestUser`

What they are for:

- `Test-SgPsAssert` wraps individual assertions with structured reporting.
- `Register-SgPsTestCleanup` records cleanup actions so the suite can unwind reliably.
- `Remove-SgPsStaleTestObject` clears leftovers from prior failed runs.
- `Connect-SgPsTestAppliance`, `Connect-SgPsTestSession`, and `Connect-SgPsTestUser` establish the test identities used by the framework.

## Test data

Static test assets live in `test/TestData/`.

Important details:

- A2A suites use a 3-level certificate chain.
- CertificateAuthentication uses a simpler CA chain.
- All PFX files in test data use password `"a"`.

Treat this data as test-only fixtures. Do not reuse the password or handling patterns as production guidance.

## Unique name constraints

Some APIs enforce uniqueness more strictly than normal object names.

- Platform script IDs must be globally unique and alphanumeric only. Failure mode: error `60031`.
- User names must be unique within the identity provider.
- Use `$Context.TestPrefix` to namespace test-created objects.
- Strip non-alphanumeric characters for strict ID fields such as platform script IDs.

Practical rule: if a create call fails unexpectedly, inspect whether the field is a display name or a globally unique identifier with tighter syntax rules.

## Writing strong assertions

Weak assertions create flaky suites and false confidence. Prefer explicit, independent validation.

- Always read back after create, edit, or delete using an independent GET.
- Assert specific values, not just existence.
- Treat `$null -ne $result` as insufficient unless the command truly only returns presence/absence.
- Test the immediate return value and the follow-up readback as separate assertions.
- Test error paths with `try/catch` and assert that the expected failure actually occurred.
- Use two different values when testing edits so you prove the update path works.
- For negative tests, create fresh temporary objects instead of relying on state left by earlier assertions.

Good mindset:

1. Verify the action returned the right shape or fields.
2. Verify persisted state with a separate read.
3. Verify cleanup removes the object or resets the condition.
4. Verify failure paths intentionally, not accidentally.

## Quick test-task checklist

Use this short checklist before finishing test work:

- Confirm appliance details are available.
- Reinstall the module before running suites.
- Run the smallest relevant suite set first.
- Keep test object names isolated with `$Context.TestPrefix`.
- Register cleanup immediately after each create.
- Fix source code before touching tests.
- Re-run affected suites after changes.
- Expect SPS-related skips when SPS is not configured.
