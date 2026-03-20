# Copyright (c) 2026 One Identity LLC. All rights reserved.
<#
.SYNOPSIS
    Run PSScriptAnalyzer on the safeguard-ps source and test code.

.DESCRIPTION
    Installs PSScriptAnalyzer if needed and runs it against src/ and test/ directories.
    Returns a non-zero exit code if any Error-severity findings are reported.

    Rules that are known false positives for this codebase are excluded (see the
    ExcludeRules list below for rationale).

.PARAMETER Path
    Directories to analyze. Defaults to src/ and test/.

.PARAMETER Fix
    Attempt to auto-fix findings where PSScriptAnalyzer supports it.

.PARAMETER IncludeAll
    Include suppressed rules (shows the full unfiltered output).

.PARAMETER Strict
    Fail (exit 1) if any findings exist, not just Error-severity ones.
    Used by CI pipelines to enforce zero-finding policy.

.EXAMPLE
    ./Invoke-PsLint.ps1

.EXAMPLE
    ./Invoke-PsLint.ps1 -Path src

.EXAMPLE
    ./Invoke-PsLint.ps1 -Fix
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string[]]$Path,

    [switch]$Fix,

    [switch]$IncludeAll,

    [switch]$Strict
)

$ErrorActionPreference = "Stop"

# --- Ensure PSScriptAnalyzer is available ---
if (-not (Get-Module PSScriptAnalyzer -ListAvailable)) {
    Write-Host "Installing PSScriptAnalyzer..." -ForegroundColor Yellow
    Install-Module PSScriptAnalyzer -Force -Scope CurrentUser -Repository PSGallery
}
Import-Module PSScriptAnalyzer -ErrorAction Stop

# --- Determine paths ---
$repoRoot = $PSScriptRoot
if (-not $Path) {
    $Path = @(
        (Join-Path $repoRoot "src"),
        (Join-Path $repoRoot "test")
    )
}
else {
    $Path = $Path | ForEach-Object {
        if ([System.IO.Path]::IsPathRooted($_)) { $_ }
        else { Join-Path $repoRoot $_ }
    }
}

# --- Rules to exclude ---
# Each exclusion has a rationale tied to this codebase's conventions.
$excludeRules = @(
    # Module uses Write-Host intentionally for user-facing output and test reporting.
    'PSAvoidUsingWriteHost'

    # API cmdlets (New-/Set-/Remove-Safeguard*) call REST endpoints. Adding
    # SupportsShouldProcess to hundreds of functions would be impractical and
    # is not the module's convention.
    'PSUseShouldProcessForStateChangingFunctions'

    # Tests and some cmdlets legitimately build SecureStrings from plaintext
    # parameters that arrive as strings from callers or config.
    'PSAvoidUsingConvertToSecureStringWithPlainText'

    # Test framework and runner accept -AdminPassword / -Password as plain
    # strings by design (they convert to SecureString internally).
    'PSAvoidUsingPlainTextForPassword'

    # Tests use empty catch blocks for "expect this to throw" assertions.
    # The framework's Assert-SgPsThrows handles the pattern.
    'PSAvoidUsingEmptyCatchBlock'

    # install-local.ps1 uses Invoke-Expression to parse the .psd1 manifest,
    # which is the standard pattern for reading module definitions.
    'PSAvoidUsingInvokeExpression'

    # $SafeguardSession and $SafeguardSpsSession are module-scoped globals
    # by design — they hold connection state across cmdlet calls.
    'PSAvoidGlobalVars'

    # BOM preference is a style choice, not a correctness issue.
    'PSUseBOMForUnicodeEncodedFile'

    # Test framework accepts -Username/-Password params by design.
    'PSAvoidUsingUsernameAndPasswordParams'

    # The test suite convention passes $Context to all Setup/Execute/Cleanup
    # blocks. Many blocks don't reference it directly. The assertion helpers
    # use $PSBoundParameters which also triggers false positives.
    'PSReviewUnusedParameter'

    # Many cmdlets deal with plural entities (Get-SafeguardAssetAccounts,
    # Get-SafeguardUsers, etc.) — singular nouns would be incorrect.
    'PSUseSingularNouns'
)

# --- Run analysis ---
Write-Host ""
Write-Host ("=" * 60) -ForegroundColor Cyan
Write-Host "  PSScriptAnalyzer — safeguard-ps" -ForegroundColor Cyan
Write-Host ("=" * 60) -ForegroundColor Cyan

$allResults = @()

foreach ($dir in $Path) {
    if (-not (Test-Path $dir)) {
        Write-Warning "Path not found: $dir"
        continue
    }
    $label = (Resolve-Path $dir -Relative -ErrorAction SilentlyContinue) ?? $dir
    Write-Host ""
    Write-Host "Analyzing: $label" -ForegroundColor Yellow

    $params = @{
        Path        = $dir
        Recurse     = $true
        Settings    = @{ ExcludeRules = if ($IncludeAll) { @() } else { $excludeRules } }
    }
    if ($Fix) { $params.Fix = $true }

    $results = @(Invoke-ScriptAnalyzer @params)
    $allResults += $results

    if ($results.Count -eq 0) {
        Write-Host "  No findings." -ForegroundColor Green
    }
    else {
        $grouped = $results | Group-Object Severity
        $summary = ($grouped | ForEach-Object { "$($_.Name): $($_.Count)" }) -join ", "
        Write-Host "  $summary" -ForegroundColor White
    }
}

# --- Report ---
Write-Host ""
Write-Host ("-" * 60) -ForegroundColor Cyan

$errors   = @($allResults | Where-Object { $_.Severity -eq 'Error' })
$warnings = @($allResults | Where-Object { $_.Severity -eq 'Warning' })
$infos    = @($allResults | Where-Object { $_.Severity -eq 'Information' })

if ($allResults.Count -eq 0) {
    Write-Host "  All clear — no findings." -ForegroundColor Green
    Write-Host ("=" * 60) -ForegroundColor Cyan
    exit 0
}

# Show errors first, then warnings
foreach ($sev in @('Error', 'Warning', 'Information')) {
    $items = @($allResults | Where-Object { $_.Severity -eq $sev })
    if ($items.Count -eq 0) { continue }

    $color = switch ($sev) {
        'Error'       { 'Red' }
        'Warning'     { 'DarkYellow' }
        'Information' { 'Gray' }
    }

    Write-Host ""
    Write-Host "  $sev ($($items.Count)):" -ForegroundColor $color
    foreach ($item in ($items | Sort-Object ScriptName, Line)) {
        $file = $item.ScriptName
        Write-Host "    $file`:$($item.Line)" -ForegroundColor White -NoNewline
        Write-Host " [$($item.RuleName)]" -ForegroundColor DarkGray -NoNewline
        Write-Host " $($item.Message)" -ForegroundColor $color
    }
}

# Summary
Write-Host ""
Write-Host ("-" * 60) -ForegroundColor Cyan
$summaryParts = @()
if ($errors.Count -gt 0)   { $summaryParts += "$($errors.Count) error(s)" }
if ($warnings.Count -gt 0) { $summaryParts += "$($warnings.Count) warning(s)" }
if ($infos.Count -gt 0)    { $summaryParts += "$($infos.Count) info(s)" }
Write-Host "  Total: $($summaryParts -join ', ')" -ForegroundColor $(if ($errors.Count -gt 0) { 'Red' } else { 'DarkYellow' })
Write-Host ("=" * 60) -ForegroundColor Cyan

# Exit with error if any findings meet the threshold
if ($errors.Count -gt 0) {
    exit 1
}
if ($Strict -and $allResults.Count -gt 0) {
    Write-Host "  Strict mode: failing because $($allResults.Count) finding(s) remain." -ForegroundColor Red
    exit 1
}
exit 0
