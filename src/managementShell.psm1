<#
.SYNOPSIS
Get the available cmdlets from the safeguard-ps module.

.DESCRIPTION
This cmdlet can be used to determine what cmdlets are available from safeguard-ps.
To make it easier to find cmdlets you may specify up to three strings as matching criteria.

.PARAMETER Criteria1
A string to match against the name of the cmdlet.

.PARAMETER Criteria2
A string to match against the name of the cmdlet.

.PARAMETER Criteria3
A string to match against the name of the cmdlet.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardCommand

.EXAMPLE
Get-SafeguardCommand Get Account

.EXAMPLE
Get-SafeguardCommand cluster
#>
function Get-SafeguardCommand
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,Position=0)]
        [string]$Criteria1,
        [Parameter(Mandatory=$false,Position=1)]
        [string]$Criteria2,
        [Parameter(Mandatory=$false,Position=2)]
        [string]$Criteria3
    )

    $local:Commands = (Get-Command -Module 'safeguard-ps')
    if ($Criteria1) { $local:Commands = ($local:Commands | Where-Object { $_.Name -match $Criteria1 }) }
    if ($Criteria2) { $local:Commands = ($local:Commands | Where-Object { $_.Name -match $Criteria2 }) }
    if ($Criteria3) { $local:Commands = ($local:Commands | Where-Object { $_.Name -match $Criteria3 }) }
    $local:Commands
}

function Get-SafeguardBanner
{
    [CmdletBinding()]
    Param(
    )

    Clear-Host

    Write-Host "`nWelcome to Safeguard PowerShell Management Shell`n"

    Write-Host " Full list of cmdlets:         " -no
    Write-Host -fore Yellow "Get-Command"

    Write-Host " Only Safeguard cmdlets:       " -no
    Write-Host -fore Yellow "Get-SafeguardCommand"

    Write-Host "`n"
}