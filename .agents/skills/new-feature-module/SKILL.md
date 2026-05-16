---
name: new-feature-module
description: >-
  Use when creating a new PowerShell feature module (.psm1), adding new
  exported cmdlets, or extending the module manifest. Includes step-by-step
  checklists, file templates, and manifest update procedures.
---

# New Feature Module

Use this skill when creating a new `src/<feature>.psm1` file, adding exported
cmdlets, or wiring a new module into `src/safeguard-ps.psd1`.

## Quick Rules

- Target Windows PowerShell 5.1 compatibility in `src/` and keep content ASCII only.
- Import helpers locally with `Import-Module -Name "$PSScriptRoot\..." -Scope Local`.
- Use `Invoke-SafeguardMethod` for Web API calls.
- Use `-Body` for PowerShell objects and `-JsonBody` only for raw JSON strings.
- Use `ConvertTo-Json -Depth 100` whenever you serialize nested objects yourself.
- Do not edit `ModuleVersion = '8.3.99999'` except through CI.

## 1. Step-by-Step Checklist for Adding a Feature Module

1. Create `src/<feature>.psm1`.
2. Add `<feature>.psm1` to `NestedModules` in `src/safeguard-ps.psd1` -- append it at the end.
3. Add exported function names to `FunctionsToExport` in `src/safeguard-ps.psd1`.
4. Write functions using the patterns in this skill: common parameter set, standard boilerplate, resolve helper, singular cmdlet nouns, parameter sets, and `begin {}` plus `process {}` for pipeline cmdlets.
5. Run `./Invoke-PsLint.ps1 -Strict`.
6. Reinstall locally: `Remove-Module safeguard-ps -ErrorAction SilentlyContinue; ./cleanup-local.ps1; ./install-local.ps1`
7. Verify: `Import-Module safeguard-ps; Get-SafeguardCommand <keyword>`
8. Create or update a test suite. See the `testing-guide` skill for full test details.
9. Update the module-to-suite mapping if you add a dedicated suite.

## 2. Feature Module File Template

Copy this template into `src/<feature>.psm1` and replace `Thing`, `Things`, and
related placeholders.

```powershell
<# Copyright (c) 2026 One Identity LLC. All rights reserved. #>
# Helpers
Import-Module -Name "$PSScriptRoot\sg-utilities.psm1" -Scope Local

function Resolve-SafeguardThingId
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$Thing
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($Thing.Id -as [int])
    {
        $Thing = $Thing.Id
    }

    if (-not ($Thing -as [int]))
    {
        $local:EscapedThingName = $Thing -replace "'", "\'"
        try
        {
            $local:Things = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Things" `
                             -Parameters @{ filter = "Name ieq '$($local:EscapedThingName)'"; fields = "Id" })
        }
        catch
        {
            Write-Verbose $_
            Write-Verbose "Caught exception with ieq filter, trying with q parameter"
            $local:Things = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Things" `
                             -Parameters @{ q = $Thing; fields = "Id" })
        }
        if (-not $local:Things)
        {
            throw "Unable to find thing matching '$Thing'"
        }
        if ($local:Things.Count -ne 1)
        {
            throw "Found $($local:Things.Count) things matching '$Thing'"
        }
        $local:Things[0].Id
    }
    else
    {
        $Thing
    }
}

function Get-SafeguardThing
{
    [OutputType([object[]])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [object]$ThingToGet,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Parameters = $null
    if ($Fields)
    {
        $local:Parameters = @{ fields = ($Fields -join ",") }
    }

    if ($PSBoundParameters.ContainsKey("ThingToGet"))
    {
        $local:Id = (Resolve-SafeguardThingId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -Thing $ThingToGet)
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Things/$($local:Id)" -Parameters $local:Parameters
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Things" -Parameters $local:Parameters
    }
}

function Find-SafeguardThing
{
    [OutputType([object[]])]
    [CmdletBinding(DefaultParameterSetName="Search")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(ParameterSetName="Search",Mandatory=$true,Position=0)]
        [string]$SearchString,
        [Parameter(ParameterSetName="Filter",Mandatory=$true)]
        [string]$QueryFilter,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields,
        [Parameter(Mandatory=$false)]
        [string[]]$OrderBy
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Parameters = @{}
    if ($SearchString)
    {
        $local:Parameters["q"] = $SearchString
    }
    if ($QueryFilter)
    {
        $local:Parameters["filter"] = $QueryFilter
    }
    if ($Fields)
    {
        $local:Parameters["fields"] = ($Fields -join ",")
    }
    if ($OrderBy)
    {
        $local:Parameters["orderby"] = ($OrderBy -join ",")
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Things" -Parameters $local:Parameters
}

function New-SafeguardThing
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [string]$Description
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Body = @{ Name = $Name }
    if ($PSBoundParameters.ContainsKey("Description"))
    {
        $local:Body.Description = $Description
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "Things" -Body $local:Body
}

function Edit-SafeguardThing
{
    [CmdletBinding(DefaultParameterSetName="Attributes")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false,Position=0)]
        [int]$ThingId,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$Name,
        [Parameter(ParameterSetName="Attributes",Mandatory=$false)]
        [string]$Description,
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
        if ($PSCmdlet.ParameterSetName -eq "Object")
        {
            if (-not $ThingObject)
            {
                throw "ThingObject must not be null"
            }
            $local:EditObject = $ThingObject
            $local:Id = (Resolve-SafeguardThingId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -Thing $ThingObject)
        }
        else
        {
            $local:Id = (Resolve-SafeguardThingId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -Thing $ThingId)
            $local:EditObject = Get-SafeguardThing -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -ThingToGet $local:Id
            if ($PSBoundParameters.ContainsKey("Name"))
            {
                $local:EditObject.Name = $Name
            }
            if ($PSBoundParameters.ContainsKey("Description"))
            {
                if ($null -eq $local:EditObject.Description)
                {
                    $local:EditObject | Add-Member -NotePropertyName Description -NotePropertyValue $Description -Force
                }
                else
                {
                    $local:EditObject.Description = $Description
                }
            }
        }

        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "Things/$($local:Id)" -Body $local:EditObject
    }
}

function Remove-SafeguardThing
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$ThingToDelete
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Id = (Resolve-SafeguardThingId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -Thing $ThingToDelete)
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "Things/$($local:Id)"
}
```

Template notes: replace `Things` with the real REST collection path, import other feature modules only when needed, keep resolve helpers out of `FunctionsToExport`, and use `Add-Member -Force` when a nullable property is missing on GET.

## 3. Common Parameter Set

Most public cmdlets use this parameter block prefix:

```powershell
[Parameter(Mandatory=$false)]
[string]$Appliance,
[Parameter(Mandatory=$false)]
[object]$AccessToken,
[Parameter(Mandatory=$false)]
[switch]$Insecure
```

Use it on public cmdlets that fall back to `$SafeguardSession` when the caller
omits explicit connection details.

A2A caller cmdlets are the main exception. They use mutual TLS input such as:

```powershell
[Parameter(Mandatory=$false)]
[string]$CertificateFile,
[Parameter(Mandatory=$false)]
[string]$Thumbprint,
[Parameter(Mandatory=$false)]
[System.Security.Cryptography.X509Certificates.X509Certificate2]$CertificateObject,
[Parameter(Mandatory=$false)]
[string]$ApiKey,
[Parameter(Mandatory=$false)]
[switch]$Insecure
```

Do not mix the normal `-AccessToken` pattern into A2A caller cmdlets.

## 4. Resolve Helper Pattern

Internal resolve helpers accept an integer ID, a name string, or an object with
an `.Id` property and return a single integer ID.

```powershell
function Resolve-SafeguardThingId
{
    Param([string]$Appliance,[object]$AccessToken,[switch]$Insecure,[object]$Thing)
    if ($Thing.Id -as [int]) { $Thing = $Thing.Id }
    if ($Thing -as [int]) { return $Thing }

    $local:EscapedThingName = $Thing -replace "'", "\'"
    $local:Things = Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Things" `
                   -Parameters @{ filter = "Name ieq '$($local:EscapedThingName)'"; fields = "Id" }
    if (-not $local:Things) { throw "Unable to find thing matching '$Thing'" }
    if ($local:Things.Count -ne 1) { throw "Found $($local:Things.Count) things matching '$Thing'" }
    $local:Things[0].Id
}
```

Use direct ID lookup when possible. When name filters are unreliable, follow
`reasoncodes.psm1` and fall back from `Name ieq` to `q`.

## 5. Pipeline Support Template

Functions with `ValueFromPipeline=$true` must use `begin {}` and `process {}`.
Put the standard boilerplate inside `begin {}` -- not before it.

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

For `Attributes`, resolve the ID, GET the current object, update only supplied
fields, and PUT the full object back. For `Object`, validate the pipeline input,
resolve the ID, and PUT the object directly.

## 6. Output Types

- If a function returns `@()` or otherwise returns a collection, declare
  `[OutputType([object[]])]`.
- `PSUseOutputTypeCorrectly` is enforced by `Invoke-PsLint.ps1 -Strict` and will
  fail CI when collection output types are missing.
- Good default choices:
  - `Get-SafeguardThing` -- `[OutputType([object[]])]` if it can return all items
  - `Find-SafeguardThing` -- `[OutputType([object[]])]`
  - `New-SafeguardThing` -- optional `[OutputType([object])]`
  - `Edit-SafeguardThing` -- optional `[OutputType([object])]`

## 7. Cmdlet Naming Rules

- Use `Verb-Safeguard*` names with approved PowerShell verbs.
- Nouns must be singular.
- Good: `Get-SafeguardAsset`, `Find-SafeguardReasonCode`, `New-SafeguardCustomPlatform`.
- Bad: `Get-SafeguardAssets`.

## 8. Parameter Sets for Multi-Mode Cmdlets

Use parameter sets for mutually exclusive modes such as `Search` vs `Filter`,
`Attributes` vs `Object`, or `ByPlatform` vs `ByScriptFile`.

- Set `DefaultParameterSetName` explicitly.
- Mark mode-specific parameters with `ParameterSetName`.
- Keep shared connection parameters outside specific sets.
- Prefer parameter sets over manual `if ($A -and $B)` validation.

## 9. Manifest Update Details

`src/safeguard-ps.psd1` is the source of truth for module wiring and exports.

### `NestedModules`

Add the new module file at the end of the array:

```powershell
NestedModules = @(
    'sslhandling.psm1',
    'ps-utilities.psm1',
    'sg-utilities.psm1',
    ...
    'discovery.psm1',
    '<feature>.psm1'
)
```

Do not insert the new module in the middle. Append it after the current last
entry.

### `FunctionsToExport`

Add each public cmdlet to `FunctionsToExport` and keep the function names in
alphabetical position within the array section you edit. A typical block looks
like this:

```powershell
FunctionsToExport = @(
    ...
    # <feature>.psm1
    'Edit-SafeguardThing','Find-SafeguardThing','Get-SafeguardThing',
    'New-SafeguardThing','Remove-SafeguardThing',
    ...
)
```

Practical rules:

- Add only public cmdlets.
- Do not export resolve helpers or private utility functions.
- Preserve nearby comments that label module sections.
- Keep the added function names sorted for easy review.

### Version placeholder warning

Do not edit `ModuleVersion = '8.3.99999'`. The `99999` placeholder is replaced
by CI.

## 10. Adding a Corresponding Test Suite

1. Create `test/Suites/Suite-YourFeature.ps1`.
2. Use the standard hashtable shape: `Name`, `Description`, `Tags`, `Setup`, `Execute`, `Cleanup`.
3. Use `$Context.TestPrefix` for unique object names and register cleanup immediately.
4. Update the module-to-suite mapping table.
5. See the `testing-guide` skill for the full test workflow and assertion guidance.

## Final Verification

1. `./Invoke-PsLint.ps1 -Strict`
2. `Remove-Module safeguard-ps -ErrorAction SilentlyContinue; ./cleanup-local.ps1; ./install-local.ps1`
3. `Import-Module safeguard-ps; Get-SafeguardCommand <keyword>`
4. Run the relevant live-appliance suite if one exists and appliance access is available.
