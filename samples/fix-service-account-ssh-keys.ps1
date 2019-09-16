# BUG#777399 -- After patching to 2.2, tasks fail on assets with service accounts using SSH keys
# Support Reference: 4304990
[CmdletBinding()]
Param(
)

if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }

if (-not $SafeguardSession)
{
    throw "This script assumes you have already called Connect-Safeguard to create a session."
}

$script:Me = (Get-SafeguardLoggedInUser)
if (-not ($script:Me.AdminRoles -contains "AssetAdmin" -or $script:Me.IsPartitionOwner))
{
    throw "You must be an asset admin or a partition owner to fix SSH keys for asset service accounts."
}

# Build SSH key hash table
$script:SshKeys = (Invoke-SafeguardMethod Core GET SshKeys)
$script:SshKeyLookup = @{}
$script:SshKeys | ForEach-Object {
    $script:SshKeyLookup.Add($_.FingerPrint, $_.Id)
}

# Match keys to Assets
$script:AssetsWithSshKeyServiceAccounts = (Invoke-SafeguardMethod Core GET Assets -Parameters @{
        Filter = "ConnectionProperties.ServiceAccountCredentialType eq 'SshKey'"
    })
$script:AssetsWithSshKeyServiceAccounts | ForEach-Object {
    $script:SshKeyId = $script:SshKeyLookup[$_.ConnectionProperties.ServiceAccountSshKeyFingerprint]
    if ($script:SshKeyId)
    {
        Write-Host "Setting SSH key for '$($_.Name)' to SSH key ID: $($script:SshKeyId)"
        $_.ConnectionProperties.ServiceAccountSshKeyId = $script:SshKeyId
        Invoke-SafeguardMethod Core PUT "Assets/$($_.Id)" -Body $_ | Format-List Id,Name,ConnectionProperties
    }
    else
    {
        Write-Warning "Unable to find SSH key for '$($_.Name)' with fingerprint [$($_.ConnectionProperties.ServiceAccountSshKeyFingerprint)]"
    }
}