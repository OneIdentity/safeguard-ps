FROM mcr.microsoft.com/powershell:ubuntu-18.04
MAINTAINER support@oneidentity.com

RUN groupadd -r safeguard \
    && useradd -r -g safeguard -s /bin/bash safeguard \
    && mkdir -p /home/safeguard \
    && chown -R safeguard:safeguard /home/safeguard

COPY ["install-local.ps1", "/tmp/safeguard/"]
COPY ["src/", "/tmp/safeguard/src/"]

RUN pwsh -NoProfile -Command "/tmp/safeguard/install-local.ps1 '/usr/local/share/powershell/Modules'; Remove-Item -Path /tmp/safeguard -recurse"

USER safeguard
WORKDIR /home/safeguard

ENTRYPOINT [ "pwsh" ]
CMD ["-NoExit", "-Command", "Get-SafeguardBanner"]
