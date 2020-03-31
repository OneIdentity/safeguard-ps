[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false,Position=0)]
    [string]$ImageType = "alpine"
)

if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

Import-Module -Name "$PSScriptRoot\docker\docker-include.psm1" -Scope Local

$ImageType = $ImageType.ToLower()
Get-SafeguardDockerFile $ImageType # Make sure the ImageType exists

if (-not (Test-Command "docker"))
{
    throw "Unabled to find docker command. Is docker installed on this machine?"
}

Write-Host "Rebuilding the image: safeguard-ps:$ImageType ..."
& "$PSScriptRoot/invoke-docker-build.ps1" $ImageType

Write-Host "Building a new image: safeguard-ps:$ImageType ..."
& docker run -it "safeguard-ps:$ImageType"
