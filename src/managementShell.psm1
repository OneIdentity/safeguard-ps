function Get-SafeguardCommand
{    
	if ($args[0] -eq $null)
	{
		get-command -Module 'safeguard-ps'
	}
	else
	{
        get-command -Name $args[0] -Module 'safeguard-ps'
	}

}

function Get-SafeguardBanner
{
	clear

	write-host "`nWelcome to Safeguard PowerShell Management Shell`n"

	write-host " Full list of cmdlets:         " -no 
	write-host -fore Yellow "Get-Command"

	write-host " Only Safeguard cmdlets:       " -no
	write-host -fore Yellow "Get-SafeguardCommand"

    write-host "`n"
}