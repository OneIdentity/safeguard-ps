function Get-SafeguardDockerFile
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,Position=0)]
        [ValidateSet(
            "ubuntu","ubuntu18.04","ubuntu16.04",
            "centos","centos7",
            "alpine","alpine3.8",
            "opensuse","opensuse42.3",
            "fedora","fedora28",
            IgnoreCase=$true)]
        [string]$ImageType = "alpine"
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    switch ($ImageType)
    {
        # Ubuntu
        {$_ -ieq "ubuntu" -or $_ -ieq "ubuntu18.04"} {"Dockerfile_ubuntu18.04"}
        "ubuntu16.04" {"Dockerfile_ubuntu16.04"}
        # CentOS
        {$_ -ieq "centos" -or $_ -ieq "centos7"} {"Dockerfile_centos7"}
        # Alpine
        {$_ -ieq "alpine" -or $_ -ieq "alpine3.8"} {"Dockerfile_alpine3.8"}
        # OpenSuSE
        {$_ -ieq "opensuse" -or $_ -ieq "opensuse42.3"} {"Dockerfile_opensuse42.3"}
        # Fedora
        {$_ -ieq "fedora" -or $_ -ieq "fedora28"} {"Dockerfile_fedora28"}

        # Unknown
        default { throw "Invalid ImageType specified."}
    }
}
