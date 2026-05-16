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
|   `-- <feature>.psm1           # Feature modules (assets, users, a2a, policies, etc.)
|-- test/                         # Integration test framework and suites (requires PS 7)
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

## On-demand skills

The following skills contain deeper reference material loaded only when relevant.
Read the `SKILL.md` when your current task matches the trigger.

| Skill | When to read | File |
|-------|-------------|------|
| Testing Guide | Running, writing, or debugging tests; setting up test environments | `.agents/skills/testing-guide/SKILL.md` |
| API Patterns | Making API calls, using filters/query params, exploring Swagger | `.agents/skills/api-patterns/SKILL.md` |
| Architecture Deep Dive | Working on module internals, SignalR, dynamic groups, custom scripts | `.agents/skills/architecture-deep-dive/SKILL.md` |
| New Feature Module | Creating new .psm1 modules, adding cmdlets, updating manifest | `.agents/skills/new-feature-module/SKILL.md` |

## Keeping this file current

After completing tasks, propose updates for new patterns, corrections, or skill changes.
