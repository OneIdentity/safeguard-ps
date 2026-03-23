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
|   `-- Suites/Suite-*.ps1                # 31 test suite files (~300 tests)
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

A healthy baseline is **304 passed, 0 failed, 8 skipped** (SPS tests skip when no SPS
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
| `customplatforms.psm1` | (no dedicated suite yet -- test manually) |

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

Functions with `[Parameter(ValueFromPipeline=$true)]` must have a `process {}` block.
Without it, piping multiple objects silently drops all but the last. All `Edit-Safeguard*`
functions follow this pattern.

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

## Sample scripts

The `samples/` directory contains example scripts demonstrating common workflows:
certificate authentication, bulk asset loading, entitlement setup, event monitoring, etc.
Refer users to these for usage patterns.
