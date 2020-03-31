[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false,Position=0)]
    [string]$ImageType = "alpine",
    [Parameter(Mandatory=$false,Position=1)]
    [string]$Version
)

if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

Import-Module -Name "$PSScriptRoot\docker\docker-include.psm1" -Scope Local -Force

$ImageType = $ImageType.ToLower()
$SafeguardDockerFile = (Get-SafeguardDockerFile $ImageType)

Write-Host $SafeguardDockerFile

if (-not (Get-Command "docker" -EA SilentlyContinue))
{
    throw "Unabled to find docker command. Is docker installed on this machine?"
}

if ($Version)
{
    $Version = "$Version-"
}

if (Invoke-Expression "docker images -q safeguard-ps:$ImageType")
{
    Write-Host "Cleaning up the old image: safeguard-ps:$ImageType ..."
    & docker rmi --force "safeguard-ps:$ImageType"
}

Write-Host "Building a new image: safeguard-ps:$ImageType ..."
& docker build --no-cache -t "safeguard-ps:$Version$ImageType" -f "$SafeguardDockerFile" "$PSScriptRoot"
