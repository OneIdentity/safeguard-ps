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
|   |-- SafeguardLogo.ico        # Module icon for PowerShell Gallery
|   `-- <feature>.psm1           # Feature modules (assets, users, a2a, policies, etc.)
|-- test/                         # Integration test framework and suites (requires PS 7)
|-- samples/                      # Example scripts (see samples/README.md)
|-- docker/                       # Dockerfiles and Docker build/run scripts
|   |-- Dockerfile_*             # Container definitions (Ubuntu, Alpine, Azure Linux)
|   |-- build-docker.sh          # Build Docker images (bash)
|   |-- run-docker.sh            # Build and run Docker images (bash)
|   |-- invoke-docker-build.ps1  # Build Docker images (PowerShell)
|   `-- invoke-docker-run.ps1    # Build and run Docker images (PowerShell)
|-- pipeline-templates/           # Azure Pipelines CI/CD templates and scripts
|   |-- versionnumber.ps1        # Version derivation (Windows)
|   |-- versionnumber.sh         # Version derivation (Linux)
|   `-- install-forpipeline.ps1  # CI pipeline install (with mandatory lint)
|-- Invoke-PsLint.ps1            # PSScriptAnalyzer lint script
|-- install-local.ps1            # Local development install
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

## Testing

Integration tests live under `test/`, require PowerShell 7 and a live Safeguard appliance, and run through `test/Invoke-SafeguardPsTests.ps1`. Use the testing skill for suite selection, environment setup, and debugging details.

```powershell
./test/Invoke-SafeguardPsTests.ps1 -ListSuites
./test/Invoke-SafeguardPsTests.ps1 -Appliance <address> -AdminPassword <password>
```

See `.agents/skills/testing-guide/SKILL.md` for the full workflow, optional SPS coverage, and suite-to-module mapping.

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
See the `new-feature-module` skill for full templates.

### Output types

Functions returning `@()` must declare `[OutputType([object[]])]` -- PSScriptAnalyzer's
`PSUseOutputTypeCorrectly` rule flags this and breaks CI.

### Parameter sets

Use parameter sets for mutually exclusive input modes (e.g., `ByPlatform` vs `ByScriptFile`).

### JSON serialization

Always use `ConvertTo-Json -Depth 100`. The default depth 2 silently truncates nested objects.

### `-Body` vs `-JsonBody`

- **`-Body`** -- PowerShell object, auto-serialized. Use for most calls.
- **`-JsonBody`** -- raw JSON string, sent as-is.
- **Trap:** Passing a JSON string to `-Body` double-serializes it.

### PowerShell 5.1 compatibility

The `src/` directory **must** remain compatible with Windows PowerShell 5.1:

- No `??`, ternary (`? :`), pipeline chain (`&&`/`||`), or expression assignment
- **No non-ASCII characters** in `.ps1`/`.psm1` files -- PS 5.1 reads UTF-8 without BOM
  as Windows-1252, breaking parsing. ASCII only.

The `test/` directory requires PS 7 and is exempt.

## CI/CD

See `.agents/skills/build-and-release/SKILL.md` for Azure Pipelines job layout, version stamping, signing, publishing targets, and required service connections.

## Security

- Never commit secrets or credentials
- `$SafeguardSession` contains tokens -- do not log or serialize
- Certificate PFX files in `test/TestData/CERTS/` use password `a` (test-only certs)
- `-Insecure` disables SSL verification -- never recommend for production

## Versioning

`ModuleVersion` has a `99999` placeholder. **Do not edit.** CI replaces it with the build version and prerelease suffixes. See `.agents/skills/build-and-release/SKILL.md` for the exact version derivation rules.

## On-demand skills

The following skills contain deeper reference material loaded only when relevant.
Read the `SKILL.md` when your current task matches the trigger.

| Skill | When to read | File |
|-------|-------------|------|
| Testing Guide | Running, writing, or debugging integration tests; setting up live test environments | `.agents/skills/testing-guide/SKILL.md` |
| API Patterns | Making API calls, using filters/query params, exploring Swagger | `.agents/skills/api-patterns/SKILL.md` |
| Architecture | Working on module internals, SignalR, dynamic groups, custom scripts | `.agents/skills/architecture/SKILL.md` |
| Build and Release | Working on Azure Pipelines, version stamping, signing, PowerShell Gallery publication, Docker publishing, or GitHub releases | `.agents/skills/build-and-release/SKILL.md` |
| A2A Workflow | Working on A2A registrations, certificate auth, credential retrieval, brokering, or A2A event listeners | `.agents/skills/a2a-workflow/SKILL.md` |
| New Feature Module | Creating new .psm1 modules, adding cmdlets, updating manifest | `.agents/skills/new-feature-module/SKILL.md` |

## Keeping this file current

After completing tasks, propose updates for new patterns, corrections, or skill changes. Update the routing table when skills are added, renamed, or retired, and keep CI/testing pointers aligned with the actual pipeline and test runner files.
