#Requires -Version 7.0
<#
.SYNOPSIS
Checks SSL assignment request shapes locally without contacting an appliance.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$source = Get-Content (Join-Path $PSScriptRoot "..\src\certificates.psm1") -Raw
# Isolate the REST stub so it cannot replace a live session's request handler.
$module = New-Module -ScriptBlock {
    param($Source)
    . ([scriptblock]::Create($Source))
    $script:Assignments = @()
    $script:Requests = @()
    $script:StatusReads = 0
    function Invoke-SafeguardMethod {
        param($Service, $Method, $RelativeUrl, $Body, $JsonBody, $AccessToken, $Appliance,
            [switch]$Insecure, [switch]$Anonymous)
        if ($Service -eq "Notification" -and $Method -eq "GET" -and $RelativeUrl -eq "Status") {
            $script:StatusReads++
            return [pscustomobject]@{ ApplianceId = "target" }
        }
        if ($Service -ne "Core" -or $RelativeUrl -ne "SslCertificates/test/Appliances") {
            throw "Unexpected request: $Service $Method $RelativeUrl"
        }
        if ($Method -eq "GET") {
            if ($script:PreserveArray) { Write-Output -NoEnumerate -InputObject $script:Assignments }
            else { $script:Assignments }
            return
        }
        if ($Method -ne "PUT") { throw "Unexpected method: $Method" }
        $json = if ($JsonBody) { $JsonBody } else { ConvertTo-Json -InputObject $Body -Depth 100 -Compress }
        if (-not $json.StartsWith("[")) { throw "PUT body must be a JSON array: $json" }
        $script:Requests += $json
        $script:Assignments = @($json | ConvertFrom-Json)
    }
} -ArgumentList $source

try {
    & $module {
        $cases = @(
            @{ Name = "Set empty"; Initial = @(); Expected = @("target"); Clear = $false },
            @{ Name = "Set singleton"; Initial = @("other"); Expected = @("other", "target"); Clear = $false },
            @{ Name = "Set multiple"; Initial = @("other", "peer"); Expected = @("other", "peer", "target"); Clear = $false },
            @{ Name = "Repeat singleton"; Initial = @("target"); Expected = @("target"); Clear = $false },
            @{ Name = "Repeat multiple"; Initial = @("other", "target"); Expected = @("other", "target"); Clear = $false },
            @{ Name = "Clear empty"; Initial = @(); Expected = @(); Clear = $true },
            @{ Name = "Clear last"; Initial = @("target"); Expected = @(); Clear = $true },
            @{ Name = "Clear to singleton"; Initial = @("other", "target"); Expected = @("other"); Clear = $true },
            @{ Name = "Clear to multiple"; Initial = @("other", "target", "peer"); Expected = @("other", "peer"); Clear = $true },
            @{ Name = "Clear absent singleton"; Initial = @("other"); Expected = @("other"); Clear = $true }
        )
        foreach ($preserveArray in @($false, $true)) {
            $script:PreserveArray = $preserveArray
            foreach ($defaultResolution in @($false, $true)) {
                foreach ($case in $cases) {
                    $script:Assignments = @($case.Initial | ForEach-Object { [pscustomobject]@{ Id = $_; Name = "Preserved $_" } })
                    $script:Requests = @()
                    $script:StatusReads = 0
                    $parameters = @{ Thumbprint = "test"; Appliance = "local-shape-check"; Insecure = $true }
                    if (-not $defaultResolution) { $parameters.ApplianceId = "target" }
                    if ($case.Clear) { Clear-SafeguardSslCertificateForAppliance @parameters }
                    else { Set-SafeguardSslCertificateForAppliance @parameters }
                    $actual = @($script:Assignments | ForEach-Object { $_.Id })
                    if (($actual -join ",") -cne ($case.Expected -join ",") -or $script:Requests.Count -ne 1) {
                        throw "$($case.Name): unexpected assignments or PUT count"
                    }
                    foreach ($id in @($case.Initial | Where-Object { $_ -in $case.Expected })) {
                        if (($script:Assignments | Where-Object { $_.Id -eq $id }).Name -ne "Preserved $id") {
                            throw "$($case.Name): existing assignment properties were lost"
                        }
                    }
                    if ($script:StatusReads -ne [int]$defaultResolution) { throw "Incorrect default appliance resolution" }
                    Write-Host "PASS: $($case.Name), default resolution=$defaultResolution, REST array preserved=$preserveArray"
                }
            }
        }
    }
}
finally {
    Remove-Module $module -ErrorAction Stop
}
