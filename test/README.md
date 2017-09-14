# Testing safeguard-ps
Automated tests to verify this Powershell module against a Safeguard appliance.

This cannot be considered a full test of each cmdlet, because for the most part
the scripts in this directory are meant to be non-interactive.  This means that
problems with command line parameter handling could creep in.

## Test Scripts
- licensing-test.ps1