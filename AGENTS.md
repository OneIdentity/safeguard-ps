# AGENTS.md -- safeguard-ps

PowerShell module for interacting with the One Identity Safeguard Web API.
Published on [PowerShell Gallery](https://www.powershellgallery.com/packages/safeguard-ps)
and [Docker Hub](https://hub.docker.com/r/oneidentity/safeguard-ps).

Targets Windows PowerShell 5.1 with PowerShell Core (7.x) support.

## Project structure

```
safeguard-ps/
|-- src/                          # Module source (all .psm1 feature modules)
|   |-- safeguard-ps.psd1        # Module manifest -- source of truth for exports
|   |-- safeguard-ps.psm1        # Root module (Connect-Safeguard, Invoke-SafeguardMethod, auth flows)
|   |-- sslhandling.psm1         # SSL/TLS helper (not exported)
|   |-- ps-utilities.psm1        # Shared PowerShell utilities (not exported)
|   |-- sg-utilities.psm1        # Shared Safeguard utilities (not exported)
|   `-- <feature>.psm1           # Feature modules (assets, users, a2a, policies, customplatforms, etc.)
|-- test/                         # Integration test framework and suites (requires PS 7)
|   |-- Invoke-SafeguardPsTests.ps1       # Test runner
|   |-- SafeguardPsTestFramework.psm1     # Framework module
|   `-- Suites/Suite-*.ps1                # 32 test suite files (~355 tests)
|-- samples/                      # Example scripts
|-- docker/                       # Dockerfiles (Ubuntu, Alpine, Mariner, Windows)
|-- pipeline-templates/           # Azure Pipelines CI/CD templates
|-- Invoke-PsLint.ps1            # PSScriptAnalyzer lint script
|-- install-local.ps1            # Local development install
|-- install-forpipeline.ps1      # CI pipeline install (with mandatory lint)
|-- cleanup-local.ps1            # Remove local module installation
`-- build.yml                    # Azure Pipelines build definition
```

## Setup and build commands

There is no build step. The module is pure PowerShell loaded directly from source.

```powershell
# Full local install cycle (run after every code change)
Remove-Module safeguard-ps -ErrorAction SilentlyContinue
./cleanup-local.ps1
./install-local.ps1

# Verify the module loads
Import-Module safeguard-ps
Get-SafeguardCommand Get Asset

# Install and lint
./install-local.ps1 -WithLinting
```

You must re-run the full `Remove-Module` -> `cleanup-local.ps1` -> `install-local.ps1` cycle
after every code change. The module is installed to the user's PowerShell module path, and
stale versions will mask your changes.

## Linting

PSScriptAnalyzer is the linter. The lint script is `Invoke-PsLint.ps1`.

```powershell
# Run the linter (both src/ and test/)
./Invoke-PsLint.ps1

# Strict mode -- fail on any finding (used by CI)
./Invoke-PsLint.ps1 -Strict

# Auto-fix what PSScriptAnalyzer can
./Invoke-PsLint.ps1 -Fix

# Lint a specific directory
./Invoke-PsLint.ps1 -Path src
```

The CI pipeline (`install-forpipeline.ps1`) runs `Invoke-PsLint.ps1 -Strict` and fails
the build on any finding. **All code must pass lint before merging.**

11 rules are excluded with documented rationale in the script. Do not add new exclusions
without a clear justification.

## Testing against a live appliance

This module interacts with a live Safeguard appliance API. There are no mock tests.
The integration test suite is the primary way to validate changes.

### Asking the user for appliance access

**If you are making non-trivial code changes, ask the user whether they have access to a
live Safeguard appliance for testing.** If they do, ask for:

1. **Appliance address** (IP or hostname of a Safeguard for Privileged Passwords appliance)
2. **Admin password** (password for the built-in `Admin` account)
3. *(Optional)* **SPS appliance address** (for Safeguard for Privileged Sessions tests)
4. *(Optional)* **SPS credentials** (username and password)

This is not required for documentation or minor fixes, but it is **strongly encouraged**
for any change that touches cmdlet logic, API calls, parameters, or module structure.
Running the test suite against a live appliance is the only way to catch regressions.

### Connecting to the appliance (PKCE vs Resource Owner Grant)

**Resource Owner Grant (ROG) is disabled by default** on recent Safeguard appliances.
When connecting to a user's test appliance for the first time, always use the `-Pkce` flag:

```powershell
$secPwd = ConvertTo-SecureString "<password>" -AsPlainText -Force
Connect-Safeguard -Appliance <address> -IdentityProvider Local -Username Admin `
    -Password $secPwd -Insecure -Pkce
```

If you attempt a direct `Connect-Safeguard` without `-Pkce` and receive a 400 error like
`"OAuth2 resource owner password credentials grant type is not allowed"`, switch to PKCE
immediately. Do not try to enable ROG on the appliance -- use PKCE as the default connection
method.

The test runner (`Invoke-SafeguardPsTests.ps1`) handles this automatically by connecting
with PKCE first, enabling ROG for the test session, and restoring the original setting
afterward. You do not need to worry about ROG when running the test suite -- just when
making ad-hoc `Connect-Safeguard` calls.

### Running the test suite

```powershell
# Reinstall the module first
Remove-Module safeguard-ps -ErrorAction SilentlyContinue
./cleanup-local.ps1
./install-local.ps1

# Run all suites
pwsh -File ./test/Invoke-SafeguardPsTests.ps1 `
    -Appliance <address> -AdminPassword <password>

# Run specific suites
pwsh -File ./test/Invoke-SafeguardPsTests.ps1 `
    -Appliance <address> -AdminPassword <password> `
    -Suite Connect,Users,Assets

# Include SPS suites
pwsh -File ./test/Invoke-SafeguardPsTests.ps1 `
    -Appliance <address> -AdminPassword <password> `
    -SpsAppliance <sps-address> -SpsUser admin -SpsPassword <sps-password>

# List available suites
pwsh -File ./test/Invoke-SafeguardPsTests.ps1 -ListSuites
```

The test runner requires **PowerShell 7** (`pwsh`). It automatically:
- Creates a temporary admin user for isolation
- Enables Resource Owner grant if disabled (and restores the original setting afterward)
- Runs pre-cleanup to remove stale objects from prior failed runs
- Reports pass/fail/skip with structured output

A healthy baseline is **344 passed, 0 failed, 8 skipped** (SPS tests skip when no SPS
appliance is provided).

### Fixing test failures

When a test fails, **investigate and fix the source code first** -- do not change the test
to make it pass without asking the user. The test suite exists to catch regressions and
verify correctness. A failing test usually means the code is wrong, not the test.

Only modify a test if:
- The test itself has a genuine bug (wrong assertion logic, stale assumptions)
- The user explicitly approves changing the test
- A new feature intentionally changes behavior and the test needs updating

Always ask the user before weakening or removing an assertion. The goal is solid,
regression-free code -- not a green test report.

### Running a subset of suites

When you change a specific feature module, run the relevant suites rather than the full set.
Map feature modules to suites:

| Module | Relevant suites |
|--------|----------------|
| `safeguard-ps.psm1` | Connect, ApplianceStatus, DataTypes, ManagementShell |
| `users.psm1` | Users |
| `assets.psm1` | Assets, AssetAccounts |
| `assetpartitions.psm1` | AssetPartitions, PasswordProfiles |
| `a2a.psm1` | A2ARegistrations, A2ACredentials |
| `policies.psm1` | AccessPolicies |
| `entitlements.psm1` | Entitlements |
| `groups.psm1` | UserGroups, AssetGroups, AccountGroups |
| `tags.psm1` | Tags |
| `directories.psm1` | (no dedicated suite -- test manually) |
| `events.psm1` | Events |
| `certificates.psm1` | Certificates |
| `reports.psm1` | Reports |
| `deleted.psm1` | DeletedObjects |
| `requests.psm1` | AccessRequests |
| `settings.psm1` | Settings |
| `networking.psm1` | Networking |
| `licensing.psm1` | Licensing |
| `diagnostics.psm1` | Diagnostics |
| `sessionapi.psm1` | SpsIntegration (requires SPS appliance) |
| `maintenance.psm1` | BackupRestore (optional, must be explicitly requested) |
| `customplatforms.psm1` | CustomPlatforms |

## Exploring the Safeguard API

The appliance exposes Swagger UI for each service at:
- `https://<appliance>/service/core/swagger` -- Core service (assets, users, platforms, policies)
- `https://<appliance>/service/appliance/swagger` -- Appliance service (networking, diagnostics, backups)
- `https://<appliance>/service/notification/swagger` -- Notification service (events, subscriptions)
- `https://<appliance>/service/event/swagger` -- Event service (signalR streaming)

Use Swagger to discover endpoints, required fields, supported query parameters, and response
schemas before implementing new cmdlets. The Swagger docs are the authoritative API reference.

## Architecture

### Module manifest (`src/safeguard-ps.psd1`)

This is the **source of truth** for what the module exposes. It lists:
- `NestedModules` -- all feature modules loaded with the root module
- `FunctionsToExport` -- all public cmdlets

When adding a new feature module:
1. Create `src/<feature>.psm1`
2. Add it to `NestedModules` in the manifest (append at the end)
3. Add exported function names to `FunctionsToExport` in the manifest

### Root module (`src/safeguard-ps.psm1`)

Initializes global session variables (`$SafeguardSession`, `$SafeguardSpsSession`),
embeds a C# OAuth helper class, and defines core cmdlets: `Connect-Safeguard`,
`Disconnect-Safeguard`, `Invoke-SafeguardMethod`, etc.

All authentication flows (password, certificate, PKCE, browser) are implemented here.

### Feature modules (`src/<feature>.psm1`)

Each module contains related cmdlets (e.g., `assets.psm1` has `Get-SafeguardAsset`,
`New-SafeguardAsset`, etc.). Feature modules import helpers locally:

```powershell
Import-Module -Name "$PSScriptRoot\sg-utilities.psm1" -Scope Local
```

### Global state

`$SafeguardSession` and `$SafeguardSpsSession` hold connection/token state. Most cmdlets
read these implicitly. Do not refactor global state handling in small edits -- it is a
deliberate architectural choice.

### API versioning

The default API version is **v4** (since module version 7.0). Callers can pass `-Version 3`.
`Invoke-SafeguardMethod` is the generic REST caller that most cmdlets delegate to.

### Invoke-SafeguardMethod: `-Body` vs `-JsonBody`

This is the most common source of bugs when implementing new cmdlets. Understanding the
difference prevents double-serialization issues:

- **`-Body`** accepts a PowerShell object (hashtable or PSCustomObject). It is automatically
  serialized to JSON via `ConvertTo-Json` before sending. Use this for most API calls.
- **`-JsonBody`** accepts a string that is already valid JSON. It is sent **as-is** with no
  additional serialization. Use this when uploading raw content (scripts, files, pre-built JSON).

**The trap:** If you pass a JSON string to `-Body`, `ConvertTo-Json` wraps it in quotes,
producing `"\"{ ... }\""` instead of `{ ... }`. The API receives a JSON string literal
instead of a JSON object, and silently does the wrong thing or returns an obscure error.

```powershell
# WRONG -- double-serializes the string, API gets quoted JSON
$scriptJson = Get-Content -Path $file -Raw
Invoke-SafeguardMethod Core PUT "Platforms/$id/Script/Raw" -Body $scriptJson

# RIGHT -- sends raw JSON as-is
Invoke-SafeguardMethod Core PUT "Platforms/$id/Script/Raw" -JsonBody $scriptJson
```

For raw content uploads (scripts, certificates), also pass `-ContentType "application/octet-stream"`.

### SCIM-style filtering

Many GET endpoints support server-side filtering via a `filter` query parameter using a
syntax inspired by SCIM (System for Cross-domain Identity Management). Pass it through
`-Parameters`:

```powershell
Invoke-SafeguardMethod -Insecure Core GET "Platforms" `
    -Parameters @{ filter = "PlatformFamily eq 'Custom'" }
```

This is more efficient than client-side filtering with `Where-Object` and is required when
building cmdlets that need to return a subset of objects (e.g., only custom platforms).
Refer to the Safeguard API documentation or Swagger for the supported filter operators
and field names for each endpoint.

### Built-in Admin role limitations

The built-in `Admin` account has the Authorizer and UserAdmin roles, but **lacks AssetAdmin
and PolicyAdmin**. These roles cannot be added to the built-in Admin (error 50100). Any
cmdlet that requires AssetAdmin (e.g., creating platforms, modifying asset partitions) will
fail when run as built-in Admin.

The test runner handles this automatically by creating a temporary `SgPsTest_RunAdmin` user
with all roles. For ad-hoc testing, create a temporary user with the needed roles:

```powershell
$user = New-SafeguardUser -Insecure -Provider Local -UserName "TempAdmin" -AdminRoles ...
```

### POST-then-PUT pattern

Some API endpoints do not accept all properties during creation (POST). For example, custom
platform session management properties (`SupportsSessionManagement`, `DefaultSshSessionPort`,
etc.) are ignored by the POST endpoint and can only be set via PUT after the object exists.

When implementing a `New-Safeguard*` cmdlet that needs to set properties not supported by
POST, use the POST-then-PUT pattern:

```powershell
# 1. Create the object with POST (minimal properties)
$local:Result = Invoke-SafeguardMethod Core POST "Platforms" -Body $local:Body

# 2. Conditionally PUT to set additional properties
if ($NeedsExtraProperties)
{
    $local:Result.SomeProperty = $Value
    $local:Result = Invoke-SafeguardMethod Core PUT "Platforms/$($local:Result.Id)" -Body $local:Result
}
```

Always check whether the POST endpoint accepts a property before adding it to the POST body.
If it is silently ignored, move it to a follow-up PUT.

### Custom script parameters on assets

When an asset is created from a custom platform, default parameter values from the platform
script are copied into `Asset.CustomScriptParameters`. The platform schema is at
`Platform.CustomScriptProperties.Parameters`.

**Platform schema** (`CustomScriptProperties.Parameters`):
```json
[
  { "Name": "RequestTerminal", "Description": null, "DefaultValue": "True", "Type": "Boolean", "TaskName": "TestConnection" }
]
```

**Asset values** (`CustomScriptParameters`):
```json
[
  { "Name": "RequestTerminal", "Value": "True", "Type": "Boolean", "TaskName": "TestConnection" }
]
```

Key patterns:
- Parameters are **per-operation** (`TaskName`). The same parameter name may appear multiple
  times, once per operation (TestConnection, CheckPassword, ChangePassword, etc.)
- To modify: GET the full asset, change `CustomScriptParameters[n].Value`, PUT the full asset back
- When applying a value to "all operations", iterate all entries with matching `Name`
- When applying to a specific operation, match both `Name` and `TaskName`
- Cmdlets: `Get-SafeguardCustomPlatformScriptParameters` (read schema), `New-SafeguardCustomPlatformAsset` (create with overrides), `Set-SafeguardCustomPlatformAssetParameter` (modify on existing asset)

## Code conventions

### Cmdlet naming

All exported functions use `Verb-Safeguard*` (e.g., `Get-SafeguardAsset`, `New-SafeguardUser`).
Follow standard PowerShell approved verbs.

### Standard function boilerplate

Every function begins with:

```powershell
if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
```

### Common parameter set

Public cmdlets accept `$Appliance`, `$AccessToken`, and `[switch]$Insecure` to allow
explicit credentials, but fall back to `$SafeguardSession` globals when omitted.

### Resolve helpers

Each feature module has internal `Resolve-Safeguard*` functions that accept either an
integer ID or a name string, look up the object via the API, and return the ID. Follow this
pattern when adding new entity types.

### Pipeline support

Functions with `[Parameter(ValueFromPipeline=$true)]` **must** use `begin {}` and
`process {}` blocks. PSScriptAnalyzer enforces this -- without them, piping multiple objects
silently drops all but the last. All `Edit-Safeguard*` functions follow this pattern:

```powershell
function Edit-SafeguardThing
{
    [CmdletBinding()]
    Param(
        # ... other params ...
        [Parameter(Mandatory=$false,ValueFromPipeline=$true)]
        [object]$ThingObject
    )

    begin
    {
        # Standard boilerplate goes here -- NOT before begin
        if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
        if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    }

    process
    {
        # All cmdlet logic goes here
    }
}
```

**Important:** Any code placed before the `begin` block causes a PSScriptAnalyzer ParseError.
The standard boilerplate lines must be inside `begin`, not at function scope.

### Named parameters

Always use named parameters when calling internal functions. Do not use positional arguments.

### Output types

Functions that return typed output should declare `[OutputType([type])]` before `param()`.

## PowerShell 5.1 compatibility

The `src/` directory **must** remain compatible with Windows PowerShell 5.1. This means:

- No null-coalescing operator (`??`)
- No ternary operator (`$x ? $a : $b`)
- No pipeline chain operators (`&&`, `||`)
- No `$var = if (...) {} else {}` expression assignment
- **No non-ASCII characters** in any `.ps1` or `.psm1` file (including comments). PS 5.1
  reads UTF-8 files without BOM as Windows-1252, where byte `0x94` (from UTF-8 em-dash)
  becomes a smart-quote that breaks parsing. Use `--` instead of `--` (em-dash), `->` instead
  of arrows, and ASCII-only box drawing.

The `test/` directory requires PowerShell 7 and is exempt from these constraints, though
it currently follows them as well for consistency.

## Versioning

`ModuleVersion` in the manifest contains a `99999` placeholder (e.g., `8.2.99999`).
**Do not edit it manually.** The CI pipeline (`install-forpipeline.ps1`) replaces it with
the real build version and toggles `Prerelease = 'pre'`.

## CI/CD pipeline

The project uses Azure Pipelines (not GitHub Actions). Templates are in `pipeline-templates/`.
CI runs `install-forpipeline.ps1` which:

1. Replaces the version placeholder with the build version
2. Toggles prerelease tag if applicable
3. Creates a file catalog for code signing (Windows only)
4. Installs the module to the pipeline module path
5. Runs `Invoke-PsLint.ps1 -Strict` -- **build fails on any lint finding**

CI uses Azure Key Vault secrets and eSignerCKA for code signing. Never add code that
assumes those secrets exist locally.

## Security considerations

- Never commit secrets, tokens, or credentials to source
- The `$SafeguardSession` variable contains access tokens -- do not log or serialize it
- Test credentials should only appear in test runner parameters, never hardcoded in suites
- Certificate PFX files in `test/TestData/CERTS/` use password `a` -- these are test-only
  self-signed certificates, not production material
- The `-Insecure` switch disables SSL verification for development -- never recommend it
  for production use without explanation

## Writing a new test suite

1. Create `test/Suites/Suite-YourFeature.ps1`
2. Return a hashtable with `Name`, `Description`, `Tags`, `Setup`, `Execute`, `Cleanup`
3. Use `$Context.TestPrefix` when naming test objects (e.g., `"${prefix}_MyAsset"`)
4. Register cleanup actions immediately after creating each object
5. Use `Test-SgPsAssert` and related assertion functions in Execute
6. See `test/README.md` for the full framework API and suite lifecycle

```powershell
@{
    Name        = "My Feature"
    Description = "Tests for my feature"
    Tags        = @("myfeature")

    Setup = {
        param($Context)
        $prefix = $Context.TestPrefix
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

    Cleanup = {
        param($Context)
        # Registered cleanups run automatically after this block
    }
}
```

### Test data files

Static test data (scripts, certificates, JSON fixtures) lives in `test/TestData/`. Reference
files relative to `$PSScriptRoot` in test suites:

```powershell
$scriptPath = Join-Path $PSScriptRoot "..\TestData\GenericLinuxWithSSHKeySupport.json"
```

When test data contains identifiers that must be globally unique (e.g., platform script IDs),
replace them with test-prefixed values at runtime to avoid collisions with other tests or
pre-existing data on the appliance.

### Pre-cleanup for test reliability

Test suites run against a shared live appliance. If a previous run failed mid-suite, stale
objects may remain. Always pre-clean in Setup using `Remove-SgPsStaleTestObject`:

```powershell
Setup = {
    param($Context)
    $prefix = $Context.TestPrefix
    $name = "${prefix}_MyPlatform"
    Remove-SgPsStaleTestObject -Collection "Platforms" -Name $name
    # ... create the object ...
}
```

The test runner also runs a global pre-cleanup sweep before any suites execute, but per-suite
pre-cleanup handles objects that the global sweep might miss (e.g., objects with non-standard
naming or in collections not covered by the global sweep).

### Unique name constraints

Some API objects have uniqueness constraints beyond simple name collisions:

- **Platform script IDs** must be globally unique across the appliance and **alphanumeric
  only** (no underscores, hyphens, or special characters). Error 60031 is returned for
  invalid or duplicate script IDs.
- **User names** must be unique within their identity provider.
- **Asset display names** should be unique for clarity but are not strictly enforced.

When generating test identifiers, use `$Context.TestPrefix` (default: `SgPsTest`) to
namespace them. For IDs with strict character rules, strip non-alphanumeric characters.

### Writing strong test assertions

Tests must validate that operations **actually worked** -- not just that they did not throw.
The goal is to catch regressions, confirm the API contract, and prove that data round-trips
correctly. Every state-changing operation (create, edit, delete, associate, disassociate)
should be followed by an independent GET readback that confirms the change persisted.

**Principles:**

1. **Always readback after create.** After `New-Safeguard*`, call the corresponding
   `Get-Safeguard*` and assert that every property you set matches what you requested.
   Do not just check `$null -ne $result.Id` -- verify Name, Description, and any other
   fields you passed in.

2. **Always readback after edit.** After `Edit-Safeguard*`, call `Get-Safeguard*` in a
   separate assertion to confirm the change was persisted server-side. Check both the
   changed field and at least one unchanged field to confirm the edit did not clobber
   other properties.

3. **Always readback after delete.** After `Remove-Safeguard*`, attempt a `Get-Safeguard*`
   and assert that it throws or returns nothing. Wrap in try/catch:
   ```powershell
   Test-SgPsAssert "Object deleted" {
       $found = $false
       try {
           $null = Get-SafeguardAsset -Insecure $id
           $found = $true
       } catch {}
       -not $found
   }
   ```

4. **Always readback after association changes.** When adding or removing linked objects
   (e.g., tag assignment, group membership, A2A credential mappings), call the
   corresponding list/get endpoint to confirm the link was created or removed.

5. **Assert specific values, not just existence.** Do not write `$null -ne $result` or
   `$true` as the assertion. Assert concrete field values:
   ```powershell
   # BAD -- proves nothing about correctness
   Test-SgPsAssert "Created asset" { $null -ne $asset }

   # GOOD -- proves the API accepted and stored our values
   Test-SgPsAssert "Created asset with correct properties" {
       $asset.DisplayName -eq $expectedName -and
           $asset.PlatformId -eq 521 -and
           $asset.NetworkAddress -eq "10.0.1.1"
   }
   ```

6. **Test both the return value and the readback.** The cmdlet's return value confirms the
   immediate response; the readback confirms persistence. Use two separate assertions:
   ```powershell
   Test-SgPsAssert "Edit returns updated description" {
       $edited = Edit-SafeguardAsset -Insecure $id -Description "New desc"
       $edited.Description -eq "New desc"
   }
   Test-SgPsAssert "Edit description persisted" {
       $readback = Get-SafeguardAsset -Insecure $id
       $readback.Description -eq "New desc"
   }
   ```

7. **Test error paths.** When a cmdlet should reject invalid input, wrap it in try/catch
   and assert it threw. Use `-match` on the error message if you want to verify the
   specific error:
   ```powershell
   Test-SgPsAssert "Rejects non-custom platform" {
       $threw = $false
       try { $null = Get-SafeguardCustomPlatform -Insecure 521 }
       catch { $threw = $true }
       $threw
   }
   ```

8. **Verify round-trip fidelity for complex data.** When testing script uploads, file
   exports, or structured data, export/download the data and verify a distinguishing
   field matches what was uploaded. This catches serialization bugs:
   ```powershell
   Test-SgPsAssert "Script change verified via export" {
       $exported = Export-SafeguardCustomPlatformScript -Insecure $id
       $exported.Id -eq $expectedScriptId
   }
   ```

9. **Use two different data values to prove edits work.** When testing edit operations,
   do not just set a value and read it back -- set a *different* value from the original
   and verify the change. If possible, edit twice with different values to confirm both
   transitions.

## Sample scripts

The `samples/` directory contains example scripts demonstrating common workflows:
certificate authentication, bulk asset loading, entitlement setup, event monitoring, etc.
Refer users to these for usage patterns.

## Keeping this file current

After completing a series of tasks, review what you learned and suggest updates to this
file. Things to look for:

- **New API quirks or pitfalls** that caused debugging time (e.g., endpoints that silently
  ignore fields, serialization traps, role requirements)
- **Stale counts** -- suite count, test count, and healthy baseline numbers drift as tests
  are added or removed
- **New patterns** that future work should follow (e.g., a new cmdlet category, a new
  test data convention, a workaround for an appliance limitation)
- **Module-to-suite mapping** updates when new suites or feature modules are added
- **Corrections** to anything that turned out to be wrong or misleading

Propose the updates to the user rather than silently editing -- they may have additional
context or prefer different wording.
