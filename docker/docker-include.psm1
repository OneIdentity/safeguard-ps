# Copyright (c) 2026 One Identity LLC. All rights reserved.
function Get-SafeguardDockerFileName
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$ImageType
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    switch ($ImageType)
    {
        # Ubuntu
        {$_ -ieq "ubuntu" -or $_ -ieq "ubuntu-24.04"} {"Dockerfile_ubuntu"}
        # Azure Linux (formerly Mariner)
        {$_ -ieq "azurelinux" -or $_ -ieq "azurelinux-3.0" -or $_ -ieq "mariner"} {"Dockerfile_azurelinux"}
        # Alpine
        {$_ -ieq "alpine" -or $_ -ieq "alpine-3.20"} {"Dockerfile_alpine"}
        # Unknown
        default { throw "Invalid ImageType specified."}
    }
}

function Get-SafeguardDockerFile
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,Position=0)]
        [ValidateSet(
            "ubuntu","ubuntu-24.04",
            "azurelinux","azurelinux-3.0","mariner",
            "alpine","alpine-3.20",
            IgnoreCase=$true)]
        [string]$ImageType = "alpine"
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    (Resolve-Path (Join-Path "docker" (Get-SafeguardDockerFileName $ImageType))).Path
}
