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
|   |-- signalr-utilities.psm1   # SignalR SSE helpers for event listeners (not exported)
|   `-- <feature>.psm1           # Feature modules (assets, users, a2a, policies, customplatforms, etc.)
|-- test/                         # Integration test framework and suites (requires PS 7)
|   |-- Invoke-SafeguardPsTests.ps1       # Test runner
|   |-- SafeguardPsTestFramework.psm1     # Framework module
|   `-- Suites/Suite-*.ps1                # Test suite files
|-- samples/                      # Example scripts (see samples/README.md)
|-- docker/                       # Dockerfiles (Ubuntu, Alpine, Azure Linux)
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
```

You must re-run the full `Remove-Module` -> `cleanup-local.ps1` -> `install-local.ps1` cycle
after every code change. Stale installed versions will mask your changes.

## Linting

PSScriptAnalyzer is the linter. The lint script is `Invoke-PsLint.ps1`.

```powershell
./Invoke-PsLint.ps1           # Run (src/ and test/)
./Invoke-PsLint.ps1 -Strict   # Fail on any finding (CI mode)
./Invoke-PsLint.ps1 -Fix      # Auto-fix what it can
./Invoke-PsLint.ps1 -Path src # Lint specific directory
```

**All code must pass `Invoke-PsLint.ps1 -Strict` before merging.** 11 rules are excluded
with documented rationale in the script. Do not add new exclusions without justification.

## Testing against a live appliance

There are no mock tests. The integration test suite runs against a live Safeguard appliance.

### Appliance access

**Always ask the user for a live appliance address** when starting work on this repo. A live
appliance is needed to browse Swagger API docs and run the integration test suite. Ask for:

1. **Appliance address** (IP or hostname)
2. **Admin password** (default bootstrap password is `Admin123`, defined in
   `test/Invoke-SafeguardPsTests.ps1` and `samples/certificate-user-demo.ps1`)
3. *(Optional)* **SPS appliance address** and **SPS credentials** (for session tests)

### Connecting to the appliance

**Resource Owner Grant (ROG) is disabled by default.** Use `-Pkce` for ad-hoc connections:

```powershell
$secPwd = ConvertTo-SecureString "<password>" -AsPlainText -Force
Connect-Safeguard -Appliance <address> -IdentityProvider Local -Username Admin `
    -Password $secPwd -Insecure -Pkce
```

The test runner handles ROG automatically (enables it for the session, restores afterward).

### Running the test suite

```powershell
# Reinstall first, then run
Remove-Module safeguard-ps -ErrorAction SilentlyContinue
./cleanup-local.ps1 && ./install-local.ps1

# Run all suites (AdminPassword defaults to Admin123)
pwsh -File ./test/Invoke-SafeguardPsTests.ps1 -Appliance <address>

# Run specific suites
pwsh -File ./test/Invoke-SafeguardPsTests.ps1 -Appliance <address> -Suite Connect,Users,Assets

# List available suites
pwsh -File ./test/Invoke-SafeguardPsTests.ps1 -ListSuites
```

**From PS 5.1 host:** use `-Command` with `@()` array instead of `-File` with commas:

```powershell
pwsh -NoProfile -Command "& .\test\Invoke-SafeguardPsTests.ps1 -Appliance '10.0.0.1' -Suite @('Connect','Users')"
```

The test runner requires **PowerShell 7** (`pwsh`). It automatically creates a temporary
admin user, enables ROG, runs pre-cleanup, and reports structured results.

A healthy baseline is **370+ passed, 0 failed, ~8 skipped** (SPS tests skip without SPS).

### Fixing test failures

**Investigate and fix the source code first** -- do not change the test to make it pass.
Only modify a test if it has a genuine bug, the user approves, or a new feature intentionally
changes behavior. Always ask before weakening an assertion.

### Module-to-suite mapping

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

## Exploring the Safeguard API

Swagger UI per service:
- `https://<appliance>/service/core/swagger` -- Core (assets, users, platforms, policies)
- `https://<appliance>/service/appliance/swagger` -- Appliance (networking, diagnostics, backups)
- `https://<appliance>/service/notification/swagger` -- Notification (events, subscriptions)
- `https://<appliance>/service/event/swagger` -- Event (signalR streaming)

## Architecture

### Module manifest (`src/safeguard-ps.psd1`)

**Source of truth** for exports. Lists `NestedModules` and `FunctionsToExport`.

When adding a new feature module:
1. Create `src/<feature>.psm1`
2. Add it to `NestedModules` (append at end)
3. Add exported function names to `FunctionsToExport`

### Root module (`src/safeguard-ps.psm1`)

Initializes `$SafeguardSession`/`$SafeguardSpsSession`, embeds a C# OAuth helper, defines
core cmdlets (`Connect-Safeguard`, `Disconnect-Safeguard`, `Invoke-SafeguardMethod`, etc.).

### Feature modules (`src/<feature>.psm1`)

Each contains related cmdlets. Import helpers locally:
```powershell
Import-Module -Name "$PSScriptRoot\sg-utilities.psm1" -Scope Local
```

### Global state

`$SafeguardSession` and `$SafeguardSpsSession` hold connection/token state. Most cmdlets
read these implicitly. Do not refactor global state in small edits.

### SignalR event listeners

Two SignalR SSE endpoints: user mode (`/service/event/signalr/` with Bearer token) and
A2A mode (`/service/a2a/signalr/` with client cert + API key). Shared helpers in
`signalr-utilities.psm1`. PS 5.1 vs PS 7 have different SSL callback mechanisms --
see per-request `ServerCertificateValidationCallback` usage in the SSE stream code.

### `ConvertTo-Json` depth

Always use `-Depth 100` when calling `ConvertTo-Json`. The default depth 2 silently
truncates nested objects into type-name strings.

### API versioning

Default API version is **v4** (since module version 7.0). `Invoke-SafeguardMethod` is
the generic REST caller that most cmdlets delegate to.

### `-Body` vs `-JsonBody`

- **`-Body`** -- accepts a PowerShell object, auto-serialized to JSON. Use for most calls.
- **`-JsonBody`** -- accepts a JSON string, sent as-is. Use for raw content uploads.

**Trap:** Passing a JSON string to `-Body` double-serializes it (API gets quoted JSON).
```powershell
# WRONG: Invoke-SafeguardMethod Core PUT "..." -Body $jsonString
# RIGHT: Invoke-SafeguardMethod Core PUT "..." -JsonBody $jsonString
```

### Prefer cmdlets over Invoke-SafeguardMethod

Always prefer `Get-Safeguard*`, `Find-Safeguard*`, `New-Safeguard*`, `Edit-Safeguard*`,
`Remove-Safeguard*`, `Close-Safeguard*` over raw `Invoke-SafeguardMethod`. This applies to
test suites too. Use `Get-SafeguardCommand <keyword>` to find existing cmdlets.

### `Get-` vs `Find-` cmdlets

- **`Get-`** -- retrieves by ID or scoped to current user.
- **`Find-`** -- system-wide text search (uses `q` parameter). Use for cross-user lookups.

### `Close-SafeguardAccessRequest` (universal cleanup)

Transitions any access request to its terminal state regardless of current state (cancels,
checks in, closes, or acknowledges as appropriate). Use for bulk cleanup.

### Access request overlap constraint

Error 90001 rejects creating a new request for the same account/asset if one already
overlaps in time. Cancel or close prior requests first.

### Query parameters and filtering

Pass via `-Parameters` on `Invoke-SafeguardMethod`:
```powershell
Invoke-SafeguardMethod -Insecure Core GET "Platforms" `
    -Parameters @{ filter = "PlatformFamily eq 'Custom'" }
```

Supported params: `fields`, `orderby` (`-` prefix = descending), `count`, `page`/`limit`,
`q` (text search), `filter`.

**Filter operators:** `eq`, `ieq`, `ne`, `gt`, `ge`, `lt`, `le`, `sw`, `isw`, `ew`, `iew`,
`contains`, `icontains`, `in`, `and`, `or`, `not`.

**Important:** Use short forms only (`sw`, `ew`, `contains`). Do NOT use `startswith`,
`endswith` -- error 70003. Escape quotes/asterisks/backslashes with `\`.

### Built-in Admin role limitations

Built-in `Admin` has Authorizer and UserAdmin but **lacks AssetAdmin and PolicyAdmin**
(cannot be added -- error 50100). The test runner creates `SgPsTest_RunAdmin` with all roles.

### POST-then-PUT pattern

Some POST endpoints silently ignore certain properties. Set them via a follow-up PUT:
```powershell
$local:Result = Invoke-SafeguardMethod Core POST "Platforms" -Body $local:Body
$local:Result.SomeProperty = $Value
$local:Result = Invoke-SafeguardMethod Core PUT "Platforms/$($local:Result.Id)" -Body $local:Result
```

### Dynamic group gotchas

1. **GET may omit null properties** like `Description`. Use `Add-Member -Force` to set them.
2. **`Convert-RuleToString` requires non-null rule.** Always provide `-GroupingRule` when
   creating dynamic groups.
3. **Rule syntax requires parenthesized condition groups.** `([Name contains 'x'])` not
   `[Name contains 'x']`.
4. **Attribute names differ** between asset and account groups. Check the `ValidateSet` on
   `$ObjectAttribute` in `grouptag-utilities.psm1`.

### Custom script parameters on assets

Platform schema: `Platform.CustomScriptProperties.Parameters` (has `DefaultValue`).
Asset values: `Asset.CustomScriptParameters` (has `Value`). Parameters are **per-operation**
(`TaskName`). To modify: GET full asset, change `CustomScriptParameters[n].Value`, PUT back.

Cmdlets: `Get-SafeguardCustomPlatformScriptParameter`, `New-SafeguardCustomPlatformAsset`,
`Set-SafeguardCustomPlatformAssetParameter`.

## Code conventions

### Cmdlet naming

`Verb-Safeguard*` with standard PowerShell verbs. **Nouns must be singular.**

### Standard function boilerplate

Every function begins with (inside `begin` block if pipeline, else at function scope):
```powershell
if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
```

### Common parameter set

Public cmdlets accept `$Appliance`, `$AccessToken`, `[switch]$Insecure`, falling back to
`$SafeguardSession`. **Exception:** A2A caller cmdlets use `-CertificateFile`/`-Thumbprint`/
`-CertificateObject` instead of `-AccessToken` (mutual TLS authentication).

### Resolve helpers

Each module has internal `Resolve-Safeguard*` functions that accept ID or name and return ID.

### Remove-SafeguardAssetAccount parameter ordering

`AssetToUse` is Position=0 (optional), `AccountToDelete` is Position=1 (mandatory). Always
use `-AccountToDelete $id` explicitly when deleting by account ID alone.

### Pipeline support

Functions with `ValueFromPipeline=$true` **must** use `begin{}`/`process{}` blocks.
Boilerplate goes inside `begin`, not before it (PSScriptAnalyzer ParseError otherwise).

```powershell
function Edit-SafeguardThing
{
    [CmdletBinding(DefaultParameterSetName="Attributes")]
    Param(
        [Parameter(ParameterSetName="Attributes",Mandatory=$false,Position=0)]
        [int]$ThingId,
        [Parameter(ParameterSetName="Object",Mandatory=$false,ValueFromPipeline=$true)]
        [object]$ThingObject
    )

    begin
    {
        if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
        if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    }

    process
    {
        # All cmdlet logic goes here
    }
}
```

### Output types

Functions returning `@()` must declare `[OutputType([object[]])]` -- PSScriptAnalyzer's
`PSUseOutputTypeCorrectly` rule flags this and breaks CI.

### Parameter sets for multi-mode cmdlets

Use parameter sets for mutually exclusive input modes (e.g., `ByPlatform` vs `ByScriptFile`).

## PowerShell 5.1 compatibility

The `src/` directory **must** remain compatible with Windows PowerShell 5.1:

- No `??`, ternary (`? :`), pipeline chain (`&&`/`||`), or expression assignment
- **No non-ASCII characters** in `.ps1`/`.psm1` files -- PS 5.1 reads UTF-8 without BOM
  as Windows-1252, breaking parsing. ASCII only.

The `test/` directory requires PS 7 and is exempt.

## Versioning

`ModuleVersion` has a `99999` placeholder. **Do not edit.** CI replaces it with the build version.

## CI/CD pipeline

Azure Pipelines (not GitHub Actions). CI runs `install-forpipeline.ps1` which replaces
the version placeholder, installs the module, and runs `Invoke-PsLint.ps1 -Strict`.

## Security

- Never commit secrets or credentials
- `$SafeguardSession` contains tokens -- do not log or serialize
- Certificate PFX files in `test/TestData/CERTS/` use password `a` (test-only certs)
- `-Insecure` disables SSL verification -- never recommend for production

## Writing a new test suite

1. Create `test/Suites/Suite-YourFeature.ps1`
2. Return a hashtable with `Name`, `Description`, `Tags`, `Setup`, `Execute`, `Cleanup`
3. Use `$Context.TestPrefix` when naming objects, `$Context.SuiteData` for state
4. Register cleanup actions immediately after creating each object
5. Pre-clean stale objects in Setup with `Remove-SgPsStaleTestObject`
6. See `test/README.md` for the full framework API

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

### Key framework functions

`Test-SgPsAssert`, `Register-SgPsTestCleanup`, `Remove-SgPsStaleTestObject`,
`Connect-SgPsTestAppliance`, `Connect-SgPsTestSession`, `Connect-SgPsTestUser`.

### Test data

Static data in `test/TestData/`. Certificate chains: 3-level chain (A2A suites) and
simple CA (CertificateAuthentication). All PFX password: `"a"`.

### Unique name constraints

- **Platform script IDs** -- globally unique, alphanumeric only (error 60031)
- **User names** -- unique within identity provider

Use `$Context.TestPrefix` to namespace. Strip non-alphanumeric for strict ID fields.

### Writing strong assertions

- Always **readback after create/edit/delete** with an independent GET
- Assert **specific values**, not just existence (`$null -ne $result` proves nothing)
- Test **both return value and readback** as separate assertions
- Test **error paths** with try/catch (assert it threw)
- Use **two different values** to prove edits work (not just one set-and-check)
- For negative tests, **create fresh temporary objects** rather than relying on state
  from earlier tests

## Keeping this file current

After completing tasks, propose updates for new API quirks, stale counts, new patterns,
module-to-suite mapping changes, or corrections.
