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
        # Mariner
        {$_ -ieq "mariner" -or $_ -ieq "mariner-2.0"} {"Dockerfile_mariner"}
        # Alpine
        {$_ -ieq "alpine" -or $_ -ieq "alpine-3.20"} {"Dockerfile_alpine"}
        # Windows Server Core LTSC
        "windowsservercore" {"Dockerfile_windowsservercore"}
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
            "mariner","mariner-2.0",
            "alpine","alpine-3.20",
            "windowsservercore",
            IgnoreCase=$true)]
        [string]$ImageType = "alpine"
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    (Resolve-Path (Join-Path "docker" (Get-SafeguardDockerFileName $ImageType))).Path
}
