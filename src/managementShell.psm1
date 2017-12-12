function Get-SafeguardCommand
{
    [CmdletBinding()]
    Param(
    )

    if ($args[0] -eq $null)
    {
        Get-Command -Module 'safeguard-ps'
    }
    else
    {
        Get-Command -Name $args[0] -Module 'safeguard-ps'
    }
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