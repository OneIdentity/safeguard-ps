[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false,Position=0)]
    [string]$ImageType = "alpine"
)

if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

Import-Module -Name "$PSScriptRoot\docker-include.psm1" -Scope Local

$ImageType = $ImageType.ToLower()
$SafeguardDockerFile = (Get-SafeguardDockerFile $ImageType)

if (-not (Test-Command "docker"))
{
    throw "Unabled to find docker command. Is docker installed on this machine?"
}

if (Invoke-Expression "docker images -q safeguard-ps:$ImageType")
{
    Write-Host "Cleaning up the old image: safeguard-ps:$ImageType ..."
    & docker rmi --force "safeguard-ps:$ImageType"
}

Write-Host "Building a new image: safeguard-ps:$ImageType ..."
& docker build --no-cache -t "safeguard-ps:$ImageType" -f "$SafeguardDockerFile" "$PSScriptRoot"
