[![Build status](https://ci.appveyor.com/api/projects/status/329lnisdof0jfsgh?svg=true)](https://ci.appveyor.com/project/petrsnd/safeguard-ps)
[![PowerShell Gallery](https://img.shields.io/powershellgallery/v/safeguard-ps.svg)](https://www.powershellgallery.com/packages/safeguard-ps)
[![Docker Hub](https://img.shields.io/badge/docker-oneidentity%2Fsafeguard--ps-blue.svg)](https://hub.docker.com/r/oneidentity/safeguard-ps/)
[![GitHub](https://img.shields.io/github/license/OneIdentity/safeguard-ps.svg)](https://github.com/OneIdentity/safeguard-ps/blob/master/LICENSE)

# safeguard-ps

One Identity Safeguard Powershell module and scripting resources.

## Installation

This Powershell module is published to the 
[PowerShell Gallery](https://www.powershellgallery.com/packages/safeguard-ps)
to facilitate install via `Import-Module`.  It can also be updated using the
`Update-Module` to get the latest functionality.

By default Powershell modules are installed for all users, and you need to be 
running as Administrator to install them.  The following one-liners are helpful:

```Powershell
> Start-Process powershell.exe -ArgumentList "Install-Module safeguard-ps -Verbose; pause" -Verb RunAs -Wait
```

```Powershell
> Start-Process powershell.exe -ArgumentList "Update-Module safeguard-ps -Verbose; pause" -Verb RunAs -Wait
```

Or, you can install them just for you:

```Powershell
> Install-Module safeguard-ps -Scope CurrentUser -Verbose
```

```Powershell
> Update-Module safeguard-ps -Scope CurrentUser -Verbose
```

## Upgrading

If you want to upgrade from the 
[PowerShell Gallery](https://www.powershellgallery.com/packages/safeguard-ps)
you should use:

```Powershell
> Update-Module safeguard-ps
```

as specified above.

## Getting Started

Once you have loaded the module, you can connect to Safeguard using the
`Connect-Safeguard` cmdlet.  If you do not have SSL properly configured, you
must use the `-Insecure` parameter to avoid SSL trust errors.

Authentication in Safeguard is based on OAuth2.  In most cases the
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

## Discover Available cmdlets

Use the `Get-SafeguardCommand` to see what is available from the module.

Since there are so many cmdlets in safeguard-ps you can use filters to find
exactly the cmdlet you are looking for.

For example:

```Powershell
> Get-SafeguardCmdlet Get Account Dir

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Function        Get-SafeguardDirectoryAccount                      2.1.0.9... safeguard-ps

```

## Module Versioning

The version of safeguard-ps mirrors the version of Safeguard that it was
developed and tested against.  However, the build numbers (fourth number)
should not be expected to match.

For Example:

safeguard-ps 2.1.0.55 would correspond to Safeguard 2.1.0.5687

This does not mean that safeguard-ps 2.1.0.55 won't work at all with
Safeguard 2.0.1.5037.  For the most part the cmdlets will still work, but
you may occasionally come across things that are broken.

For the best results, please try to match the first two version numbers of
the safeguard-ps module to the first two numbers of the Safeguard appliance
you are communicating with.  The most important thing for safeguard-ps is
the version of the Safeguard Web API, which will never change between
where only the third and fourth numbers differ.

### Moving to Three Digit Version Number

As of version 2.2.x, safeguard-ps began using a three digit version number.
It also now supports prerelease builds.  This is so the next version of
safeguard-ps can be developed in lock step with the Safeguard product.

Dropping the third number is insignificant as the Safeguard Web API never
changes in those releases.

## Powershell cmdlets

The following cmdlets are currently supported.  More will be added to this
list over time.  Every cmdlet in the list supports `Get-Help` to provide
additional information as to how it can be called.

Please file GitHub Issues for cmdlets that are not working and to request
cmdlets for functionality that is missing.

The following list of cmdlets might not be complete.  To see everything that
safeguard-ps can do run:

```Powershell
> Get-SafeguardCommand
```

### ManagementShell

- Get-SafeguardCommand
- Get-SafeguardBanner

### Core Functionality

- Connect-Safeguard
- Disconnect-Safeguard
- Invoke-SafeguardMethod
- Get-SafeguardAccessTokenStatus
- Update-SafeguardAccessToken
- Get-SafeguardLoggedInUser

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
- Install-SafeguardAuditLogSigningCertificate
- Get-SafeguardAuditLogSigningCertificate
- Install-SafeguardSslCertificate
- Uninstall-SafeguardSslCertificate
- Get-SafeguardSslCertificate
- Set-SafeguardSslCertificateForAppliance
- Clear-SafeguardSslCertificateForAppliance
- Get-SafeguardSslCertificateForAppliance
- Get-SafeguardCertificateSigningRequest (Get-SafeguardCsr)
- New-SafeguardCertificateSigningRequest (New-SafeguardCsr)
- Remove-SafeguardCertificateSigningRequest (Remove-SafeguardCsr)
- New-SafeguardTestCertificatePki

### Networking

- Get-SafeguardNetworkInterface
- Set-SafeguardNetworkInterface
- Get-SafeguardDnsSuffix
- Set-SafeguardDnsSuffix

### Desktop Client

- Install-SafeguardDesktopClient

### Maintenance

- Get-SafeguardStatus
- Get-SafeguardVersion
- Get-SafeguardApplianceVerification
- Get-SafeguardTime
- Get-SafeguardApplianceUptime
- Get-SafeguardHealth
- Get-SafeguardApplianceName
- Set-SafeguardApplianceName
- Invoke-SafeguardApplianceShutdown
- Invoke-SafeguardApplianceReboot
- Invoke-SafeguardApplianceFactoryReset
- Get-SafeguardSupportBundle
- Get-SafeguardPatch
- Clear-SafeguardPatch
- Install-SafeguardPatch
- New-SafeguardBackup
- Remove-SafeguardBackup
- Export-SafeguardBackup
- Import-SafeguardBackup
- Restore-SafeguardBackup
- Save-SafeguardBackupToArchive
- Get-SafeguardBackup
- Get-SafeguardBmcConfiguration
- Enable-SafeguardBmcConfiguration
- Disable-SafeguardBmcConfiguration
- Set-SafeguardBmcAdminPassword
- Get-SafeguardTls12OnlyStatus
- Enable-SafeguardTls12Only
- Disable-SafeguardTls12Only

### Clustering

- Add-SafeguardClusterMember
- Remove-SafeguardClusterMember
- Get-SafeguardClusterMember
- Get-SafeguardClusterHealth
- Get-SafeguardClusterPrimary
- Set-SafeguardClusterPrimary
- Enable-SafeguardClusterPrimary
- Get-SafeguardClusterOperationStatus
- Unlock-SafeguardCluster
- Get-SafeguardClusterSummary

### Diagnostics

- Invoke-SafeguardPing
- Invoke-SafeguardSessionsPing
- Invoke-SafeguardTelnet
- Invoke-SafeguardSessionsTelnet

### Session Module

- Get-SafeguardSessionContainerStatus
- Get-SafeguardSessionModuleStatus
- Get-SafeguardSessionModuleVersion
- Reset-SafeguardSessionModule
- Repair-SafeguardSessionModule
- Get-SafeguardSessionCertificate
- Install-SafeguardSessionCertificate
- Reset-SafeguardSessionCertificate
- Get-SafeguardSessionSshAlgorithms
- Set-SafeguardSessionSshAlgorithms
- Add-SafeguardSessionSshAlgorithm
- Remove-SafeguardSessionSshAlgorithm

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
- Get-SafeguardAccessRequestPassword (Get-SafeguardAccessRequestCheckoutPassword)

### Users

- Get-SafeguardIdentityProvider
- New-SafeguardStarling2faAuthentication
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
- Find-SafeguardAssetAccount
- New-SafeguardAssetAccount
- Edit-SafeguardAssetAccount
- Set-SafeguardAssetAccountPassword
- New-SafeguardAssetAccountRandomPassword
- Test-SafeguardAssetAccountPassword
- Invoke-SafeguardAssetAccountPasswordChange
- Invoke-SafeguardAssetSshHostKeyDiscovery
- Remove-SafeguardAssetAccount

### Directories

- Get-SafeguardDirectory
- New-SafeguardDirectory
- Test-SafeguardDirectory
- Remove-SafeguardDirectory
- Edit-SafeguardDirectory
- Sync-SafeguardDirectory

### Directory Accounts

- Get-SafeguardDirectoryAccount
- Find-SafeguardDirectoryAccount
- New-SafeguardDirectoryAccount
- Edit-SafeguardDirectoryAccount
- Set-SafeguardDirectoryAccountPassword
- New-SafeguardDirectoryAccountRandomPassword
- Test-SafeguardDirectoryAccountPassword
- Invoke-SafeguardDirectoryAccountPasswordChange
- Remove-SafeguardDirectoryAccount

### Groups (for use in entitlements & access policies)

- Get-SafeguardUserGroup
- New-SafeguardUserGroup
- Remove-SafeguardUserGroup
- Edit-SafeguardUserGroup
- Get-SafeguardAssetGroup
- New-SafeguardAssetGroup
- Remove-SafeguardAssetGroup
- Get-SafeguardAccountGroup
- New-SafeguardAccountGroup
- Remove-SafeguardAccountGroup

### Policy Assets and Policy Accounts (for use in entitlements & access policies)

- Get-SafeguardPolicyAsset
- Find-SafeguardPolicyAsset
- Get-SafeguardPolicyAccount
- Find-SafeguardPolicyAccount
- Get-SafeguardAccessPolicy
- Get-SafeguardAccessPolicyScopeItem
- Get-SafeguardAccessPolicyAccessRequestProperty
- Get-SafeguardAccessPolicySessionProperty
- Get-SafeguardEntitlement
- New-SafeguardEntitlement
- Get-SafeguardUserEntitlementReport
- Get-SafeguardUserLinkedAccount
- Add-SafeguardUserLinkedAccount
- Remove-SafeguardUserLinkedAccount

### Events

- Get-SafeguardEvent
- Get-SafeguardEventName
- Get-SafeguardEventSubscription
- Find-SafeguardEventSubscription
- New-SafeguardEventSubscription
- Remove-SafeguardEventSubscription
- Edit-SafeguardEventSubscription

### A2A

- Get-SafeguardA2aServiceStatus
- Enable-SafeguardA2aService
- Disable-SafeguardA2aService
- Get-SafeguardA2a
- New-SafeguardA2a
- Remove-SafeguardA2a
- Edit-SafeguardA2a
- Get-SafeguardA2aCredentialRetrieval
- Add-SafeguardA2aCredentialRetrieval
- Remove-SafeguardA2aCredentialRetrieval
- Get-SafeguardA2aCredentialRetrievalIpRestriction
- Set-SafeguardA2aCredentialRetrievalIpRestriction
- Clear-SafeguardA2aCredentialRetrievalIpRestriction
- Reset-SafeguardA2aCredentialRetrievalApiKey
- Get-SafeguardA2aCredentialRetrievalApiKey
- Get-SafeguardA2aAccessRequestBroker
- Set-SafeguardA2aAccessRequestBroker
- Clear-SafeguardA2aAccessRequestBroker
- Get-SafeguardA2aAccessRequestBrokerIpRestriction
- Set-SafeguardA2aAccessRequestBrokerIpRestriction
- Clear-SafeguardA2aAccessRequestBrokerIpRestriction
- Reset-SafeguardA2aAccessRequestBrokerApiKey
- Get-SafeguardA2aAccessRequestBrokerApiKey

### A2A -- Credential Retrieval

- Get-SafeguardA2aPassword
- Get-SafeguardA2aPrivateKey

### A2A -- Access Request Broker

- New-SafeguardA2aAccessRequest

### One Identity Starling

- Invoke-SafeguardStarlingJoin
- Get-SafeguardStarlingSubscription
- New-SafeguardStarlingSubscription
- Remove-SafeguardStarlingSubscription
- Get-SafeguardStarlingJoinUrl
- Get-SafeguardStarlingSetting
- Set-SafeguardStarlingSetting
