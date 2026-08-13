# Contributing to safeguard-ps

Thanks for your interest in improving safeguard-ps, the PowerShell module
for the One Identity Safeguard Web API.

## Reporting issues

- **Bugs and feature requests:** open a GitHub Issue.
- **Security vulnerabilities:** do **not** open a public issue — follow
  [SECURITY.md](SECURITY.md).

## Prerequisites

- Windows PowerShell 5.1 (the module source stays 5.1-compatible) and
  [PowerShell 7](https://aka.ms/powershell) (required to run the tests and
  the linter).
- PSScriptAnalyzer (auto-installed by the lint script if missing).
- A live Safeguard for Privileged Passwords appliance for the test suites.

## Building

The module is pure PowerShell — there is no compile step. Reinstall it
locally after each change:

    ./cleanup-local.ps1
    ./install-local.ps1

Then verify:

    Import-Module safeguard-ps

## Testing

The suites run against a live appliance and require PowerShell 7:

    ./test/Invoke-SafeguardPsTests.ps1 -ListSuites
    ./test/Invoke-SafeguardPsTests.ps1 -Appliance <address> -AdminPassword <password>

## Coding conventions

All code must pass the linter in strict mode before merging:

    ./Invoke-PsLint.ps1 -Strict

Module source must stay Windows PowerShell 5.1-compatible (ASCII only). See
[AGENTS.md](AGENTS.md) for the full conventions.

## Submitting changes

1. Fork the repository and create a feature branch.
2. Keep commits focused with clear messages.
3. Ensure `./Invoke-PsLint.ps1 -Strict` passes.
4. Open a pull request describing the behavior you changed and the tests
   that prove it.