# safeguard-ps
One Identity Safeguard Powershell module and scripting resources.

## Getting Started
Once you have loaded the module, you can connect to Safeguard using the
`Connect-Safeguard` cmdlet.  If you do not have SSL properly configured, you
must use the `-Insecure` parameter to avoid SSL trust errors.

Authentication in Safeguard is based on OAuth2.  In most cases, the
`Connect-Safeguard` cmdlet uses the Resource Owner Grant of OAuth2.

```Powershell
> Connect-Safeguard -Insecure 192.168.123.123 local Admin
Password: ********
Login Successful.
```

The `Connect-Safeguard` cmdlet will create a session variable that includes
your access token and connection information.  This makes it easier to call
other cmdlets provided by the module.

Client certificate authentication is also available in `Connect-Safeguard`.
This can be done either using a PFX certificate file or a SHA-1 thumbprint
of a certificate store in the Current User personal certificate store.

Two-factor authentication can only be performed using the `-Gui` parameter,
so that the built-in secure token service can use the browser agent to
redirect you to multiple authentication providers.  This authentication
mechanism uses the Authorization Code Grant of OAuth2.

```Powershell
> Connect-Safeguard -Insecure 192.168.123.123 -Gui
Login Successful.
```

Once you are logged in, you can call any cmdlet listed below.  For example:

```Powershell
> Get-SafeguardUser Admin
```

If you do not have rights to access a particular portion of the Web API,
you will be presented with an error message saying authorization is
required.

```Powershell
> Get-SafeguardAsset
Invoke-RestMethod : {"Code":60108,"Message":"Authorization is required for this request.","InnerError":null}
```

When you are finished, you can close the session or call the
`Disconnect-Safeguard` cmdlet to invalidate and remove your access token.

## Powershell cmdlets
### Core
- Connect-Safeguard
- Disconnect-Safeguard
- Invoke-SafeguardMethod
- Get-SafeguardAccessTokenStatus
- Update-SafeguardAccessToken
### Data Types
- Get-SafeguardIdentityProviderType
- Get-SafeguardPlatform
- Find-SafeguardPlatform
- Get-SafeguardTimeZone
- Get-SafeguardTransferProtocol
### Licensing
- Install-SafeguardLicense
- Uninstall-SafeguardLicense
- Get-SafeguardLicense
### Certificates
- Install-SafeguardTrustedCertificate
- Uninstall-SafeguardTrustedCertificate
- Get-SafeguardTrustedCertificate
- Install-SafeguardSslCertificate
- Uninstall-SafeguardSslCertificate
- Get-SafeguardSslCertificate
- Set-SafeguardSslCertificateForAppliance
- Clear-SafeguardSslCertificateForAppliance
- Get-SafeguardSslCertificateForAppliance
- New-SafeguardTestCertificatePki
### Desktop Client
- Install-SafeguardDesktopClient
### Maintenance
- Get-SafeguardStatus
- Get-SafeguardVersion
- Get-SafeguardTime
- Get-SafeguardHealth
- Get-SafeguardApplianceName
- Set-SafeguardApplianceName
- Invoke-SafeguardApplianceShutdown
- Invoke-SafeguardApplianceReboot
- Invoke-SafeguardApplianceFactoryReset
- Get-SafeguardSupportBundle
- Install-SafeguardPatch
- New-SafeguardBackup
- Remove-SafeguardBackup
- Export-SafeguardBackup
- Import-SafeguardBackup
- Restore-SafeguardBackup
- Save-SafeguardBackupToArchive
- Get-SafeguardBackup
### Diagnostics
- Invoke-SafeguardPing
- Invoke-SafeguardSessionsPing
- Invoke-SafeguardTelnet
- Invoke-SafeguardSessionsTelnet
### Archive Servers
- Get-SafeguardArchiveServer
- New-SafeguardArchiveServer
- Test-SafeguardArchiveServer
- Remove-SafeguardArchiveServer
- Edit-SafeguardArchiveServer
### Access Requests
- Get-SafeguardAccessRequest
- Find-SafeguardAccessRequest
- New-SafeguardAccessRequest
- Edit-SafeguardAccessRequest
- Get-SafeguardActionableRequest
- Get-SafeguardRequestableAccount
- Find-SafeguardRequestableAccount
### Users
- Get-SafeguardIdentityProvider
- Get-SafeguardUser
- Find-SafeguardUser
- New-SafeguardUser
- Remove-SafeguardUser
- Set-SafeguardUserPassword
- Edit-SafeguardUser
- Enable-SafeguardUser
- Disable-SafeguardUser
- Rename-SafeguardUser
### Assets
- Get-SafeguardAsset
- Find-SafeguardAsset
- New-SafeguardAsset
- Test-SafeguardAsset
- Remove-SafeguardAsset
- Edit-SafeguardAsset
### Asset Accounts
- Get-SafeguardAssetAccount
- New-SafeguardAssetAccount
- Edit-SafeguardAssetAccount
- Set-SafeguardAssetAccountPassword
- New-SafeguardAssetAccountRandomPassword
- Test-SafeguardAssetAccountPassword
- Invoke-SafeguardAssetAccountPasswordChange
