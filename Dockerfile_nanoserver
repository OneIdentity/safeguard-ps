FROM microsoft/powershell:nanoserver
MAINTAINER support@oneidentity.com

COPY ["install-local.ps1", "C:/safeguard/"]
COPY ["src/", "C:/safeguard/src/"]

RUN pwsh -NoProfile -Command "C:\safeguard\install-local.ps1 'C:\Program Files\PowerShell\Modules'; Remove-Item -Path c:\safeguard -recurse"

ENTRYPOINT [ "pwsh" ]
CMD ["-NoExit", "-Command", "Get-SafeguardBanner"]