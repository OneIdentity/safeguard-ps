#Requires -Version 7.0
<#
.SYNOPSIS
    safeguard-ps Test Framework Module

.DESCRIPTION
    Provides test context management, assertion functions, cleanup registration,
    and structured reporting for safeguard-ps integration tests.

    All tests run against a live Safeguard appliance. Unlike the SafeguardDotNet
    framework, this module calls safeguard-ps cmdlets directly (in-process) rather
    than spawning dotnet tool processes.

    All exported functions use the SgPs noun prefix to avoid conflicts.
#>

# ============================================================================
# Module-scoped state
# ============================================================================

$script:TestContext = $null

# ============================================================================
# Context Management
# ============================================================================

function New-SgPsTestContext {
    <#
    .SYNOPSIS
        Creates a new test context tracking appliance info, credentials, results, and cleanup.

    .PARAMETER Appliance
        Network address of the Safeguard appliance to test against.

    .PARAMETER AdminUserName
        Bootstrap admin username. Default: "Admin".

    .PARAMETER AdminPassword
        Bootstrap admin password. Default: "Admin123".

    .PARAMETER SpsAppliance
        Optional network address of a Safeguard for Privileged Sessions appliance.

    .PARAMETER SpsUser
        SPS admin username. Default: "admin".

    .PARAMETER SpsPassword
        SPS admin password. Required if SpsAppliance is specified.

    .PARAMETER TestPrefix
        Prefix used for naming test objects on the appliance. Default: "SgPsTest".

    .EXAMPLE
        $ctx = New-SgPsTestContext -Appliance "192.168.117.15" -AdminPassword "root4EDMZ"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Appliance,

        [Parameter()]
        [string]$AdminUserName = "Admin",

        [Parameter()]
        [string]$AdminPassword = "Admin123",

        [Parameter()]
        [string]$SpsAppliance,

        [Parameter()]
        [string]$SpsUser = "admin",

        [Parameter()]
        [string]$SpsPassword,

        [Parameter()]
        [string]$TestPrefix = "SgPsTest"
    )

    $context = [PSCustomObject]@{
        # Connection info
        Appliance       = $Appliance
        AdminUserName   = $AdminUserName
        AdminPassword   = $AdminPassword

        # SPS connection info
        SpsAppliance    = $SpsAppliance
        SpsUser         = $SpsUser
        SpsPassword     = $SpsPassword

        # Naming
        TestPrefix      = $TestPrefix

        # Paths
        TestRoot        = $PSScriptRoot
        ModuleRoot      = (Join-Path (Split-Path -Parent $PSScriptRoot) "src")

        # Per-suite transient data (reset each suite)
        SuiteData       = @{}

        # Cleanup stack (LIFO)
        CleanupActions  = [System.Collections.Generic.Stack[PSCustomObject]]::new()

        # Results
        SuiteResults    = [System.Collections.Generic.List[PSCustomObject]]::new()
        StartTime       = [DateTime]::UtcNow
    }

    $script:TestContext = $context
    return $context
}

function Get-SgPsTestContext {
    <#
    .SYNOPSIS
        Returns the current module-scoped test context.
    #>
    if (-not $script:TestContext) {
        throw "No test context. Call New-SgPsTestContext first."
    }
    return $script:TestContext
}

# ============================================================================
# Module Import
# ============================================================================

function Import-SgPsModule {
    <#
    .SYNOPSIS
        Imports the safeguard-ps module from the source tree.

    .DESCRIPTION
        Removes any previously loaded safeguard-ps module, then imports from
        the src/ directory relative to the test root.

    .PARAMETER Context
        Test context. If omitted, uses the module-scoped context.

    .EXAMPLE
        Import-SgPsModule -Context $ctx
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSCustomObject]$Context
    )

    if (-not $Context) { $Context = Get-SgPsTestContext }

    Remove-Module safeguard-ps -ErrorAction SilentlyContinue
    $manifestPath = Join-Path $Context.ModuleRoot "safeguard-ps.psd1"
    if (-not (Test-Path $manifestPath)) {
        throw "Module manifest not found at: $manifestPath"
    }
    Import-Module $manifestPath -Force -Global
}

# ============================================================================
# Connection Helpers
# ============================================================================

function Connect-SgPsTestAppliance {
    <#
    .SYNOPSIS
        Connects to the test appliance using the admin credentials from the context.

    .DESCRIPTION
        Calls Connect-Safeguard with the context's appliance, username, and password.
        Sets the global $SafeguardSession. Returns the connection result.

    .PARAMETER Context
        Test context. If omitted, uses the module-scoped context.

    .EXAMPLE
        Connect-SgPsTestAppliance -Context $ctx
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSCustomObject]$Context
    )

    if (-not $Context) { $Context = Get-SgPsTestContext }

    $secPassword = ConvertTo-SecureString $Context.AdminPassword -AsPlainText -Force
    Connect-Safeguard -Appliance $Context.Appliance -IdentityProvider "Local" `
        -Username $Context.AdminUserName -Password $secPassword -Insecure -NoSessionVariable
}

function Connect-SgPsTestSession {
    <#
    .SYNOPSIS
        Connects to the test appliance and stores the session in $SafeguardSession.

    .DESCRIPTION
        Calls Connect-Safeguard with the context's appliance, username, and password.
        Unlike Connect-SgPsTestAppliance, this stores the result in $SafeguardSession
        for use by cmdlets that read the global session implicitly.

    .PARAMETER Context
        Test context. If omitted, uses the module-scoped context.

    .EXAMPLE
        Connect-SgPsTestSession -Context $ctx
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSCustomObject]$Context
    )

    if (-not $Context) { $Context = Get-SgPsTestContext }

    $secPassword = ConvertTo-SecureString $Context.AdminPassword -AsPlainText -Force
    Connect-Safeguard -Appliance $Context.Appliance -IdentityProvider "Local" `
        -Username $Context.AdminUserName -Password $secPassword -Insecure
}

function Connect-SgPsTestUser {
    <#
    .SYNOPSIS
        Connects to the test appliance as a specific user and returns an access token.

    .PARAMETER Appliance
        The appliance address. If omitted, uses context.

    .PARAMETER Username
        The username to authenticate as.

    .PARAMETER Password
        The password (plain text string).

    .EXAMPLE
        $token = Connect-SgPsTestUser -Username "TestUser" -Password "P@ss123"
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Appliance,

        [Parameter(Mandatory)]
        [string]$Username,

        [Parameter(Mandatory)]
        [string]$Password
    )

    $ctx = Get-SgPsTestContext
    if (-not $Appliance) { $Appliance = $ctx.Appliance }

    $secPassword = ConvertTo-SecureString $Password -AsPlainText -Force
    Connect-Safeguard -Appliance $Appliance -IdentityProvider "Local" `
        -Username $Username -Password $secPassword -Insecure -NoSessionVariable
}

# ============================================================================
# Safeguard API Helpers
# ============================================================================

function Invoke-SgPsApi {
    <#
    .SYNOPSIS
        Convenience wrapper for Invoke-SafeguardMethod with common defaults.

    .DESCRIPTION
        Calls Invoke-SafeguardMethod using either the global session or explicit
        access token. Handles the -Insecure flag automatically.

    .PARAMETER Service
        Safeguard service: Core, Appliance, Notification, A2A.

    .PARAMETER Method
        HTTP method: Get, Post, Put, Delete.

    .PARAMETER RelativeUrl
        API endpoint relative to the service root.

    .PARAMETER Body
        Optional request body (will be serialized to JSON).

    .PARAMETER AccessToken
        Optional explicit access token. If omitted, uses $SafeguardSession.

    .PARAMETER Parameters
        Optional query parameters hashtable.

    .PARAMETER Version
        API version. Default: 4.

    .EXAMPLE
        $users = Invoke-SgPsApi -Service Core -Method Get -RelativeUrl "Users"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Service,

        [Parameter(Mandatory)]
        [string]$Method,

        [Parameter(Mandatory)]
        [string]$RelativeUrl,

        [Parameter()]
        $Body,

        [Parameter()]
        [string]$AccessToken,

        [Parameter()]
        [hashtable]$Parameters,

        [Parameter()]
        [int]$Version = 4
    )

    $ctx = Get-SgPsTestContext
    $params = @{
        Insecure    = $true
        Service     = $Service
        Method      = $Method
        RelativeUrl = $RelativeUrl
        Version     = $Version
    }

    if ($AccessToken) {
        $params.Appliance = $ctx.Appliance
        $params.AccessToken = $AccessToken
    }

    if ($null -ne $Body) {
        $params.Body = $Body
    }

    if ($Parameters) {
        $params.Parameters = $Parameters
    }

    Invoke-SafeguardMethod @params
}

# ============================================================================
# Cleanup Registration
# ============================================================================

function Register-SgPsTestCleanup {
    <#
    .SYNOPSIS
        Registers an idempotent cleanup action that runs during suite cleanup.
        Actions execute in LIFO order. Failures are logged but do not propagate.

    .PARAMETER Description
        Human-readable description of what this cleanup does.

    .PARAMETER Action
        ScriptBlock to execute. Receives $Context as parameter.

    .EXAMPLE
        Register-SgPsTestCleanup -Description "Delete test user" -Action {
            param($Ctx)
            Remove-SafeguardUser $Ctx.SuiteData['UserId']
        }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Description,

        [Parameter(Mandatory)]
        [scriptblock]$Action
    )

    $ctx = Get-SgPsTestContext
    $ctx.CleanupActions.Push([PSCustomObject]@{
        Description = $Description
        Action      = $Action
    })
}

function Invoke-SgPsTestCleanup {
    <#
    .SYNOPSIS
        Executes all registered cleanup actions in LIFO order.
        Each action is wrapped in try/catch — failures are logged but never propagate.

    .PARAMETER Context
        The test context whose cleanup stack should be drained.

    .EXAMPLE
        Invoke-SgPsTestCleanup -Context $ctx
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context
    )

    $count = $Context.CleanupActions.Count
    if ($count -eq 0) {
        Write-Host "  No cleanup actions registered." -ForegroundColor DarkGray
        return
    }

    Write-Host "  Running $count cleanup action(s)..." -ForegroundColor DarkGray
    while ($Context.CleanupActions.Count -gt 0) {
        $item = $Context.CleanupActions.Pop()
        try {
            Write-Host "    Cleanup: $($item.Description)" -ForegroundColor DarkGray
            & $item.Action $Context
        }
        catch {
            Write-Host "    Cleanup ignored failure: $($_.Exception.Message)" -ForegroundColor DarkYellow
        }
    }
}

# ============================================================================
# Assertion Functions
# ============================================================================

function Test-SgPsAssert {
    <#
    .SYNOPSIS
        Records a named test result. Pass a scriptblock that returns $true/$false or throws.

    .PARAMETER Name
        Human-readable name for this test assertion.

    .PARAMETER Test
        ScriptBlock to evaluate. Return $true for pass, $false for fail, or throw for fail.

    .EXAMPLE
        Test-SgPsAssert "User can log in" { (Get-SafeguardLoggedInUser).UserName -eq "Admin" }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Name,

        [Parameter(Mandatory, Position = 1)]
        [scriptblock]$Test
    )

    $ctx = Get-SgPsTestContext
    $result = [PSCustomObject]@{
        Name      = $Name
        Status    = "Unknown"
        Message   = ""
        Duration  = [TimeSpan]::Zero
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $testResult = & $Test
        $sw.Stop()
        $result.Duration = $sw.Elapsed

        if ($testResult -eq $false) {
            $result.Status = "Fail"
            $result.Message = "Assertion returned `$false"
            Write-Host "    FAIL: $Name — Assertion returned `$false" -ForegroundColor Red
        }
        else {
            $result.Status = "Pass"
            Write-Host "    PASS: $Name" -ForegroundColor Green
        }
    }
    catch {
        $sw.Stop()
        $result.Duration = $sw.Elapsed
        $result.Status = "Fail"
        $result.Message = $_.Exception.Message
        Write-Host "    FAIL: $Name — $($_.Exception.Message)" -ForegroundColor Red
    }

    if (-not $ctx.SuiteData.ContainsKey('_TestResults')) {
        $ctx.SuiteData['_TestResults'] = [System.Collections.Generic.List[PSCustomObject]]::new()
    }
    $ctx.SuiteData['_TestResults'].Add($result)
}

function Test-SgPsAssertEqual {
    <#
    .SYNOPSIS
        Asserts two values are equal.

    .EXAMPLE
        Test-SgPsAssertEqual "Status is active" "Active" $user.Status
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Name,

        [Parameter(Mandatory, Position = 1)]
        $Expected,

        [Parameter(Mandatory, Position = 2)]
        $Actual
    )

    Test-SgPsAssert $Name {
        if ($Expected -ne $Actual) {
            throw "Expected '$Expected' but got '$Actual'"
        }
        $true
    }
}

function Test-SgPsAssertNotNull {
    <#
    .SYNOPSIS
        Asserts a value is not null or empty.

    .EXAMPLE
        Test-SgPsAssertNotNull "User ID is set" $user.Id
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Name,

        [Parameter(Position = 1)]
        $Value
    )

    Test-SgPsAssert $Name {
        if ($null -eq $Value -or ($Value -is [string] -and [string]::IsNullOrWhiteSpace($Value))) {
            throw "Value was null or empty"
        }
        $true
    }
}

function Test-SgPsAssertContains {
    <#
    .SYNOPSIS
        Asserts a string contains a substring, or a collection contains an element.

    .EXAMPLE
        Test-SgPsAssertContains "Has admin role" $user.AdminRoles "GlobalAdmin"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Name,

        [Parameter(Mandatory, Position = 1)]
        $Haystack,

        [Parameter(Mandatory, Position = 2)]
        $Needle
    )

    Test-SgPsAssert $Name {
        if ($Haystack -is [string]) {
            if (-not $Haystack.Contains($Needle)) {
                throw "String does not contain '$Needle'"
            }
        }
        elseif ($Haystack -is [System.Collections.IEnumerable]) {
            if ($Needle -notin $Haystack) {
                throw "Collection does not contain '$Needle'"
            }
        }
        else {
            throw "Unsupported haystack type: $($Haystack.GetType().Name)"
        }
        $true
    }
}

function Test-SgPsAssertThrows {
    <#
    .SYNOPSIS
        Asserts that a scriptblock throws an exception.

    .PARAMETER ExpectedMessage
        Optional substring that the exception message must contain.

    .EXAMPLE
        Test-SgPsAssertThrows "Bad endpoint throws" { Invoke-SgPsApi -Service Core -Method Get -RelativeUrl "NonExistent" }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Name,

        [Parameter(Mandatory, Position = 1)]
        [scriptblock]$Action,

        [Parameter()]
        [string]$ExpectedMessage
    )

    Test-SgPsAssert $Name {
        $threw = $false
        try {
            & $Action
        }
        catch {
            $threw = $true
            if ($ExpectedMessage -and $_.Exception.Message -notlike "*$ExpectedMessage*") {
                throw "Expected exception containing '$ExpectedMessage' but got: $($_.Exception.Message)"
            }
        }
        if (-not $threw) {
            throw "Expected an exception but none was thrown"
        }
        $true
    }
}

function Test-SgPsSkip {
    <#
    .SYNOPSIS
        Records a named test as skipped with a reason.

    .EXAMPLE
        Test-SgPsSkip "Requires AD directory" "No Active Directory configured"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Name,

        [Parameter(Mandatory, Position = 1)]
        [string]$Reason
    )

    $ctx = Get-SgPsTestContext
    $result = [PSCustomObject]@{
        Name     = $Name
        Status   = "Skip"
        Message  = $Reason
        Duration = [TimeSpan]::Zero
    }

    Write-Host "    SKIP: $Name — $Reason" -ForegroundColor Yellow

    if (-not $ctx.SuiteData.ContainsKey('_TestResults')) {
        $ctx.SuiteData['_TestResults'] = [System.Collections.Generic.List[PSCustomObject]]::new()
    }
    $ctx.SuiteData['_TestResults'].Add($result)
}

# ============================================================================
# Suite Execution
# ============================================================================

function Invoke-SgPsTestSuite {
    <#
    .SYNOPSIS
        Runs a single test suite through Setup → Execute → Cleanup.

    .DESCRIPTION
        Loads a suite definition file, resets per-suite state, then runs Setup, Execute,
        and Cleanup phases. Setup failures skip Execute but Cleanup always runs.
        Results are appended to the context's SuiteResults collection.

    .PARAMETER SuiteFile
        Full path to the Suite-*.ps1 file to run.

    .PARAMETER Context
        Test context. If omitted, uses the module-scoped context.

    .EXAMPLE
        Invoke-SgPsTestSuite -SuiteFile "C:\Tests\Suites\Suite-Connect.ps1" -Context $ctx
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SuiteFile,

        [Parameter()]
        [PSCustomObject]$Context
    )

    if (-not $Context) { $Context = Get-SgPsTestContext }

    # Load suite definition
    $suite = & $SuiteFile
    if (-not $suite -or -not $suite.Name) {
        Write-Host "  ERROR: Invalid suite file: $SuiteFile" -ForegroundColor Red
        return
    }

    $suiteName = $suite.Name
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Suite: $suiteName" -ForegroundColor Cyan
    if ($suite.Description) {
        Write-Host "  $($suite.Description)" -ForegroundColor DarkCyan
    }
    Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan

    # Reset per-suite state
    $Context.SuiteData = @{}
    $Context.SuiteData['_TestResults'] = [System.Collections.Generic.List[PSCustomObject]]::new()
    $Context.CleanupActions = [System.Collections.Generic.Stack[PSCustomObject]]::new()

    $suiteResult = [PSCustomObject]@{
        Name         = $suiteName
        SetupError   = $null
        ExecuteError = $null
        CleanupError = $null
        Tests        = [System.Collections.Generic.List[PSCustomObject]]::new()
        Duration     = [TimeSpan]::Zero
    }

    $suiteSw = [System.Diagnostics.Stopwatch]::StartNew()

    # --- Setup ---
    if ($suite.Setup) {
        Write-Host "  [Setup]" -ForegroundColor DarkGray
        try {
            & $suite.Setup $Context
        }
        catch {
            $suiteResult.SetupError = $_.Exception.Message
            Write-Host "  SETUP FAILED: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # --- Execute (only if setup succeeded) ---
    if (-not $suiteResult.SetupError -and $suite.Execute) {
        Write-Host "  [Execute]" -ForegroundColor DarkGray
        try {
            & $suite.Execute $Context
        }
        catch {
            $suiteResult.ExecuteError = $_.Exception.Message
            Write-Host "  EXECUTE ERROR: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    elseif ($suiteResult.SetupError) {
        Write-Host "  [Execute] Skipped due to setup failure" -ForegroundColor Yellow
    }

    # --- Cleanup (always runs) ---
    Write-Host "  [Cleanup]" -ForegroundColor DarkGray
    try {
        if ($suite.Cleanup) {
            & $suite.Cleanup $Context
        }
    }
    catch {
        $suiteResult.CleanupError = $_.Exception.Message
        Write-Host "  CLEANUP ERROR: $($_.Exception.Message)" -ForegroundColor DarkYellow
    }
    # Run registered cleanup actions regardless
    Invoke-SgPsTestCleanup -Context $Context

    $suiteSw.Stop()
    $suiteResult.Duration = $suiteSw.Elapsed

    # Collect test results from this suite
    if ($Context.SuiteData.ContainsKey('_TestResults')) {
        foreach ($tr in $Context.SuiteData['_TestResults']) {
            $suiteResult.Tests.Add($tr)
        }
    }

    # If setup failed and no tests were recorded, add a synthetic failure
    if ($suiteResult.SetupError -and $suiteResult.Tests.Count -eq 0) {
        $suiteResult.Tests.Add([PSCustomObject]@{
            Name     = "Suite Setup"
            Status   = "Fail"
            Message  = "Setup failed: $($suiteResult.SetupError)"
            Duration = [TimeSpan]::Zero
        })
    }

    $pass = ($suiteResult.Tests | Where-Object Status -eq "Pass").Count
    $fail = ($suiteResult.Tests | Where-Object Status -eq "Fail").Count
    $skip = ($suiteResult.Tests | Where-Object Status -eq "Skip").Count
    $statusColor = if ($fail -gt 0) { "Red" } elseif ($skip -gt 0) { "Yellow" } else { "Green" }
    Write-Host "  Result: $pass passed, $fail failed, $skip skipped ($([math]::Round($suiteResult.Duration.TotalSeconds, 1))s)" -ForegroundColor $statusColor
    Write-Host ""

    $Context.SuiteResults.Add($suiteResult)
}

# ============================================================================
# Reporting
# ============================================================================

function Write-SgPsTestReport {
    <#
    .SYNOPSIS
        Writes a formatted test report to the console.

    .OUTPUTS
        Returns the total number of failed tests (int) for use as exit code.

    .EXAMPLE
        $failCount = Write-SgPsTestReport -Context $ctx
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [PSCustomObject]$Context
    )

    if (-not $Context) { $Context = Get-SgPsTestContext }

    $totalDuration = [DateTime]::UtcNow - $Context.StartTime

    Write-Host ""
    Write-Host ("=" * 66) -ForegroundColor Cyan
    Write-Host "  safeguard-ps Test Report" -ForegroundColor Cyan
    Write-Host ("=" * 66) -ForegroundColor Cyan
    Write-Host "  Appliance: $($Context.Appliance)" -ForegroundColor White
    Write-Host "  Duration:  $([math]::Floor($totalDuration.TotalMinutes))m $($totalDuration.Seconds)s" -ForegroundColor White
    Write-Host ("-" * 66) -ForegroundColor DarkGray

    $totalPass = 0
    $totalFail = 0
    $totalSkip = 0

    # Suite summary table
    $headerFmt = "  {0,-36} {1,5} {2,5} {3,5} {4,6}"
    Write-Host ($headerFmt -f "Suite", "Pass", "Fail", "Skip", "Total") -ForegroundColor White
    Write-Host ("-" * 66) -ForegroundColor DarkGray

    foreach ($suite in $Context.SuiteResults) {
        $pass = ($suite.Tests | Where-Object Status -eq "Pass").Count
        $fail = ($suite.Tests | Where-Object Status -eq "Fail").Count
        $skip = ($suite.Tests | Where-Object Status -eq "Skip").Count
        $total = $suite.Tests.Count

        $totalPass += $pass
        $totalFail += $fail
        $totalSkip += $skip

        $color = if ($fail -gt 0) { "Red" } elseif ($skip -gt 0) { "Yellow" } else { "Green" }
        Write-Host ($headerFmt -f $suite.Name, $pass, $fail, $skip, $total) -ForegroundColor $color
    }

    $grandTotal = $totalPass + $totalFail + $totalSkip
    Write-Host ("-" * 66) -ForegroundColor DarkGray
    Write-Host ($headerFmt -f "TOTAL", $totalPass, $totalFail, $totalSkip, $grandTotal) -ForegroundColor White

    if ($grandTotal -gt 0) {
        $passRate = [math]::Round(($totalPass / $grandTotal) * 100, 1)
        $execTotal = $totalPass + $totalFail
        $execPassRate = if ($execTotal -gt 0) { [math]::Round(($totalPass / $execTotal) * 100, 1) } else { 0 }
        Write-Host "  Pass Rate: ${passRate}%    (excluding skipped: ${execPassRate}%)" -ForegroundColor White
    }

    # List failures
    $failures = foreach ($suite in $Context.SuiteResults) {
        foreach ($test in $suite.Tests) {
            if ($test.Status -eq "Fail") {
                [PSCustomObject]@{
                    Suite   = $suite.Name
                    Test    = $test.Name
                    Message = $test.Message
                }
            }
        }
    }

    if ($failures) {
        Write-Host ""
        Write-Host ("-" * 66) -ForegroundColor DarkGray
        Write-Host "  FAILURES:" -ForegroundColor Red
        foreach ($f in $failures) {
            Write-Host "    [$($f.Suite)] $($f.Test)" -ForegroundColor Red
            if ($f.Message) {
                Write-Host "      $($f.Message)" -ForegroundColor DarkRed
            }
        }
    }

    Write-Host ("=" * 66) -ForegroundColor Cyan
    Write-Host ""

    return $totalFail
}

function Export-SgPsTestReport {
    <#
    .SYNOPSIS
        Exports test results to a JSON file for CI integration.

    .PARAMETER OutputPath
        File path to write the JSON report to.

    .PARAMETER Context
        Test context. If omitted, uses the module-scoped context.

    .EXAMPLE
        Export-SgPsTestReport -OutputPath "C:\results\test-report.json" -Context $ctx
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$OutputPath,

        [Parameter()]
        [PSCustomObject]$Context
    )

    if (-not $Context) { $Context = Get-SgPsTestContext }

    $report = [PSCustomObject]@{
        Appliance = $Context.Appliance
        StartTime = $Context.StartTime.ToString("o")
        EndTime   = [DateTime]::UtcNow.ToString("o")
        Suites    = foreach ($suite in $Context.SuiteResults) {
            [PSCustomObject]@{
                Name       = $suite.Name
                DurationMs = [math]::Round($suite.Duration.TotalMilliseconds)
                SetupError = $suite.SetupError
                Tests      = foreach ($test in $suite.Tests) {
                    [PSCustomObject]@{
                        Name       = $test.Name
                        Status     = $test.Status
                        Message    = $test.Message
                        DurationMs = [math]::Round($test.Duration.TotalMilliseconds)
                    }
                }
            }
        }
        Summary = [PSCustomObject]@{
            TotalPass = ($Context.SuiteResults | ForEach-Object { ($_.Tests | Where-Object Status -eq "Pass").Count } | Measure-Object -Sum).Sum
            TotalFail = ($Context.SuiteResults | ForEach-Object { ($_.Tests | Where-Object Status -eq "Fail").Count } | Measure-Object -Sum).Sum
            TotalSkip = ($Context.SuiteResults | ForEach-Object { ($_.Tests | Where-Object Status -eq "Skip").Count } | Measure-Object -Sum).Sum
        }
    }

    $report | ConvertTo-Json -Depth 10 | Set-Content -Path $OutputPath -Encoding UTF8
    Write-Host "Test report exported to: $OutputPath" -ForegroundColor DarkCyan
}

# ============================================================================
# Safeguard Object Helpers
# ============================================================================

function Remove-SgPsTestObject {
    <#
    .SYNOPSIS
        Idempotent delete — removes an object via Invoke-SafeguardMethod if it exists.

    .PARAMETER RelativeUrl
        API endpoint for the DELETE call (e.g., "Users/123").

    .PARAMETER AccessToken
        Optional explicit access token.

    .EXAMPLE
        Remove-SgPsTestObject -RelativeUrl "Users/$userId"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RelativeUrl,

        [Parameter()]
        [string]$AccessToken
    )

    try {
        Invoke-SgPsApi -Service Core -Method Delete -RelativeUrl $RelativeUrl `
            -AccessToken:$AccessToken | Out-Null
    }
    catch {
        # Silently ignore — object may not exist
    }
}

function Remove-SgPsStaleTestObject {
    <#
    .SYNOPSIS
        Finds and deletes a Safeguard object by Name filter. Used for pre-cleanup.

    .PARAMETER Collection
        The API collection to search (e.g., "Users", "Assets", "AssetAccounts").

    .PARAMETER Name
        The exact Name value to search for.

    .PARAMETER AccessToken
        Optional explicit access token.

    .EXAMPLE
        Remove-SgPsStaleTestObject -Collection "Users" -Name "SgPsTest_User1"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Collection,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter()]
        [string]$AccessToken
    )

    try {
        $existing = Invoke-SgPsApi -Service Core -Method Get `
            -RelativeUrl "${Collection}?filter=Name eq '${Name}'" `
            -AccessToken:$AccessToken
        if ($existing) {
            $items = @($existing)
            foreach ($item in $items) {
                if ($item.Id) {
                    Write-Verbose "  Pre-cleanup: removing stale $Collection object '$Name' (Id=$($item.Id))"
                    Remove-SgPsTestObject -RelativeUrl "${Collection}/$($item.Id)" `
                        -AccessToken:$AccessToken
                }
            }
        }
    }
    catch {
        # Silently ignore — best-effort pre-cleanup
    }
}

function Clear-SgPsStaleTestEnvironment {
    <#
    .SYNOPSIS
        Removes all stale test objects from the appliance before a test run.

    .DESCRIPTION
        Creates a temporary admin user with full rights, then searches for and deletes
        all objects created by previous test runs (identified by the TestPrefix) in the
        correct dependency order. This function is best-effort.

    .PARAMETER Context
        Test context (required).

    .EXAMPLE
        Clear-SgPsStaleTestEnvironment -Context $ctx
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Context
    )

    $prefix = $Context.TestPrefix
    $cleanupAdmin = "${prefix}_CleanupAdmin"
    $cleanupPassword = "Cleanup8392!xyzABC"
    Write-Host "  Checking for stale test objects (prefix: ${prefix})..." -ForegroundColor DarkGray

    # Create a temporary admin with full rights for cleanup operations
    $adminId = $null
    $cleanupToken = $null
    try {
        # First remove any stale cleanup admin from a previous failed cleanup
        Remove-SgPsStaleTestObject -Collection "Users" -Name $cleanupAdmin

        $admin = Invoke-SgPsApi -Service Core -Method Post `
            -RelativeUrl "Users" -Body @{
                PrimaryAuthenticationProvider = @{ Id = -1 }
                Name = $cleanupAdmin
                AdminRoles = @('GlobalAdmin','Auditor','AssetAdmin','ApplianceAdmin','PolicyAdmin','UserAdmin','HelpdeskAdmin','OperationsAdmin')
            }
        $adminId = $admin.Id
        Invoke-SgPsApi -Service Core -Method Put `
            -RelativeUrl "Users/$adminId/Password" -Body $cleanupPassword

        $cleanupToken = Connect-SgPsTestUser -Username $cleanupAdmin -Password $cleanupPassword
    }
    catch {
        Write-Host "  Could not create cleanup admin — skipping pre-cleanup." -ForegroundColor DarkYellow
        # Still try to remove the admin if it was partially created
        if ($adminId) {
            try { Remove-SgPsTestObject -RelativeUrl "Users/$adminId" } catch {}
        }
        return
    }

    $foundAny = $false

    # Close any stale access requests first (they block user/account deletion)
    try {
        $staleRequests = Invoke-SgPsApi -Service Core -Method Get `
            -RelativeUrl "AccessRequests" `
            -AccessToken $cleanupToken
        foreach ($req in @($staleRequests)) {
            if ($req.Id -and $req.AccountName -and $req.AccountName -match $prefix) {
                if ($req.State -notin @('Closed','Complete','Expired')) {
                    if (-not $foundAny) {
                        $foundAny = $true
                        Write-Host "  Found stale test objects — removing..." -ForegroundColor Yellow
                    }
                    Write-Host "    Closing stale access request: $($req.Id)" -ForegroundColor DarkYellow
                    try {
                        Invoke-SgPsApi -Service Core -Method Post `
                            -RelativeUrl "AccessRequests/$($req.Id)/Close" `
                            -AccessToken $cleanupToken
                    } catch {}
                }
            }
        }
    }
    catch {
        # Silently ignore
    }

    # Delete in dependency order: event subscriptions → policies → entitlements → A2A → accounts → assets → groups → users
    $collections = @(
        @{ Collection = "EventSubscriptions"; NameField = "Name" },
        @{ Collection = "AccessPolicies"; NameField = "Name" },
        @{ Collection = "Roles"; NameField = "Name" },
        @{ Collection = "A2ARegistrations"; NameField = "AppName" },
        @{ Collection = "AssetAccounts"; NameField = "Name" },
        @{ Collection = "Assets"; NameField = "Name" },
        @{ Collection = "UserGroups"; NameField = "Name" },
        @{ Collection = "AssetGroups"; NameField = "Name" },
        @{ Collection = "AccountGroups"; NameField = "Name" },
        @{ Collection = "AssetPartitions"; NameField = "Name" },
        @{ Collection = "Tags"; NameField = "Name" }
    )

    foreach ($col in $collections) {
        try {
            $items = Invoke-SgPsApi -Service Core -Method Get `
                -RelativeUrl "$($col.Collection)?filter=$($col.NameField) contains '${prefix}'" `
                -AccessToken $cleanupToken
            $list = @($items)
            foreach ($item in $list) {
                if ($item.Id) {
                    if (-not $foundAny) {
                        $foundAny = $true
                        Write-Host "  Found stale test objects — removing..." -ForegroundColor Yellow
                    }
                    $displayName = if ($item.Name) { $item.Name } elseif ($item.AppName) { $item.AppName } else { "Id=$($item.Id)" }
                    Write-Host "    Deleting $($col.Collection): $displayName" -ForegroundColor DarkYellow
                    Remove-SgPsTestObject -RelativeUrl "$($col.Collection)/$($item.Id)" `
                        -AccessToken $cleanupToken
                }
            }
        }
        catch {
            # Silently ignore — best-effort
        }
    }

    # Delete stale test users (excluding the cleanup admin itself)
    try {
        $staleUsers = Invoke-SgPsApi -Service Core -Method Get `
            -RelativeUrl "Users?filter=Name contains '${prefix}'" `
            -AccessToken $cleanupToken
        $list = @($staleUsers)
        foreach ($user in $list) {
            if ($user.Id -and $user.Id -ne $adminId) {
                if (-not $foundAny) {
                    $foundAny = $true
                    Write-Host "  Found stale test objects — removing..." -ForegroundColor Yellow
                }
                Write-Host "    Deleting user: $($user.Name) (Id=$($user.Id))" -ForegroundColor DarkYellow
                Remove-SgPsTestObject -RelativeUrl "Users/$($user.Id)" `
                    -AccessToken $cleanupToken
            }
        }
    }
    catch {
        # Silently ignore
    }

    # Purge soft-deleted objects left by DeletedObjects suite
    foreach ($deletedType in @("Assets", "AssetAccounts", "Users")) {
        try {
            $deletedItems = Invoke-SgPsApi -Service Core -Method Get `
                -RelativeUrl "Deleted${deletedType}?filter=Name contains '${prefix}'" `
                -AccessToken $cleanupToken
            foreach ($item in @($deletedItems)) {
                if ($item.Id) {
                    if (-not $foundAny) {
                        $foundAny = $true
                        Write-Host "  Found stale test objects — removing..." -ForegroundColor Yellow
                    }
                    Write-Host "    Purging deleted $deletedType`: $($item.Name) (Id=$($item.Id))" -ForegroundColor DarkYellow
                    try {
                        Invoke-SgPsApi -Service Core -Method Delete `
                            -RelativeUrl "Deleted${deletedType}/$($item.Id)" `
                            -AccessToken $cleanupToken
                    } catch {}
                }
            }
        }
        catch {
            # Silently ignore
        }
    }

    # Delete the cleanup admin
    try {
        Remove-SgPsTestObject -RelativeUrl "Users/$adminId"
    }
    catch {
        # Silently ignore
    }

    if (-not $foundAny) {
        Write-Host "  No stale objects found." -ForegroundColor DarkGray
    }
    Write-Host "  Pre-cleanup complete." -ForegroundColor DarkGray
}

# ============================================================================
# SPS Configuration Check
# ============================================================================

function Test-SgPsSpsConfigured {
    <#
    .SYNOPSIS
        Returns $true if the test context has SPS appliance connection info configured.
    #>
    [CmdletBinding()]
    param()

    $ctx = Get-SgPsTestContext
    return ($ctx.SpsAppliance -and $ctx.SpsUser -and $ctx.SpsPassword)
}

# ============================================================================
# Module Exports
# ============================================================================

Export-ModuleMember -Function @(
    # Context
    'New-SgPsTestContext'
    'Get-SgPsTestContext'

    # Module import
    'Import-SgPsModule'

    # Connection helpers
    'Connect-SgPsTestAppliance'
    'Connect-SgPsTestSession'
    'Connect-SgPsTestUser'

    # API helpers
    'Invoke-SgPsApi'

    # Cleanup
    'Register-SgPsTestCleanup'
    'Invoke-SgPsTestCleanup'

    # Assertions
    'Test-SgPsAssert'
    'Test-SgPsAssertEqual'
    'Test-SgPsAssertNotNull'
    'Test-SgPsAssertContains'
    'Test-SgPsAssertThrows'
    'Test-SgPsSkip'

    # Suite execution
    'Invoke-SgPsTestSuite'

    # Reporting
    'Write-SgPsTestReport'
    'Export-SgPsTestReport'

    # Helpers
    'Remove-SgPsTestObject'
    'Remove-SgPsStaleTestObject'
    'Clear-SgPsStaleTestEnvironment'
    'Test-SgPsSpsConfigured'
)
