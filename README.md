[![Build status](https://ci.appveyor.com/api/projects/status/329lnisdof0jfsgh?svg=true)](https://ci.appveyor.com/project/petrsnd/safeguard-ps)
[![PowerShell Gallery](https://img.shields.io/powershellgallery/v/safeguard-ps.svg)](https://www.powershellgallery.com/packages/safeguard-ps)
[![Docker Hub](https://img.shields.io/badge/docker-oneidentity%2Fsafeguard--ps-blue.svg)](https://hub.docker.com/r/oneidentity/safeguard-ps/)
[![GitHub](https://img.shields.io/github/license/OneIdentity/safeguard-ps.svg)](https://github.com/OneIdentity/safeguard-ps/blob/master/LICENSE)

# safeguard-ps

One Identity Safeguard Powershell module and scripting resources.

-----------

<p align="center">
<i>Check out our <a href="samples">samples</a> to get started scripting to Safeguard!</i>
</p>

-----------

## Installation

This Powershell module is published to the
[PowerShell Gallery](https://www.powershellgallery.com/packages/safeguard-ps)
to make it as easy as possible to install using the built-in `Import-Module` cmdlet.
It can also be updated using the `Update-Module` to get the latest functionality.

By default Powershell modules are installed for all users, and you need to be
running Powershell as an Administrator to install for all users.

```Powershell
> Install-Module safeguard-ps
```

Or, you can install them just for you using the `-Scope` parameter which will
never require Administrator permission:

```Powershell
> Install-Module safeguard-ps -Scope CurrentUser
```

## Upgrading

If you want to upgrade from the
[PowerShell Gallery](https://www.powershellgallery.com/packages/safeguard-ps)
you should use:

```Powershell
> Update-Module safeguard-ps
```

Or, for a specific user:


```Powershell
> Update-Module safeguard-ps -Scope CurrentUser
```

If you run into errors while upgrading make sure that you upgrade for all users
if the module was originally installed for all users.  If the module was originally
installed for just the current user, be sure to use the `-Scope` parameter to again
specify `CurrentUser` when running the `Update-Module` cmdlet.

## Prerelease Versions

To install a pre-release version of safeguard-ps you need to use the latest version
of PowerShellGet if you aren't already. Windows comes with one installed, but you
want the newest and it requires the `-Force` parameter to get it.

If you don't have PowerShellGet, run:

```Powershell
> Install-Module PowerShellGet -Force
```

Then, you can install a pre-release version of safeguard-ps by running:

```Powershell
> Install-Module -Name safeguard-ps -AllowPrerelease
```

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
of a certificate stored in the Current User personal certificate store.

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
> Get-SafeguardCommand Get Account Dir

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Function        Get-SafeguardDirectoryAccount                      2.1.0.9... safeguard-ps

```

## Module Versioning

The version of safeguard-ps mirrors the version of Safeguard that it was
developed and tested against.  However, the build numbers (fourth number)
should not be expected to match.

For Example:

safeguard-ps 2.2.152 would correspond to Safeguard 2.2.0.6958.

This does not mean that safeguard-ps 2.2.152 won't work at all with
Safeguard 2.4.0.7846.  For the most part the cmdlets will still work, but
you may occasionally come across things that are broken.

For the best results, please try to match the first two version numbers of
the safeguard-ps module to the first two numbers of the Safeguard appliance
you are communicating with.  The most important thing for safeguard-ps is
the version of the Safeguard Web API, which will never change between
where only the third and fourth numbers differ.

### Pre-release Builds

As of version 2.2.x, safeguard-ps began using a three digit version number.
It also now supports prerelease builds.  This is so the next version of
safeguard-ps can be developed in lock step with the Safeguard product.

Dropping the third number is insignificant as the Safeguard Web API never
changes in those releases.

### API v3

Safeguard 2.7 shipped with a new version of the Safeguard API (v3).  The
safeguard-ps 2.7 module was updated to use the v3 API by default.  Safeguard
2.7 serves both the v2 and v3 APIs, but the v3 version of the API is the only
one guaranteed to work.  Please try to match the first and second version
numbers between Safeguard and safeguard-ps as instructed above to avoid any
compatibility issues.

## Getting Started With A2A

Once you have configured your A2A registration in Safeguard, you can get
the information to call Safeguard A2A by running the following:

```Powershell
> Get-SafeguardA2aCredentialRetrievalInformation
```

This will report the certificate thumbprint you need to use as well as the
API key required to request a specific account password.

The best practice is to install your user certificate in the Windows
User Certificate Store (user the Personal folder).  Then, you can reference
the certificate securely in safeguard-ps just using the thumbprint.

You can see the thumbprints of certificates currently installed in your Windows
User Certificate Store using the following command:

```Powershell
> Get-ChildItem Cert:\CurrentUser\My
```

To retrieve a password via A2A from PowerShell use `Get-SafeguardA2aPassword`.
For example:

```Powershell
> Get-SafeguardA2aPassword 10.5.5.5 -Thumbprint 756766BB590D7FA9CA9E1971A4AE41BB9CEC82F1 -ApiKey JeD9HIgGZM+CYZcVk6YHDNCp4W36DNsjS1TDi+S5HzI=
```

## Reporting and CSV output

Safeguard 2.6 added the capability of returning CSV from the API by passing in
an Accept header set to 'text/csv'.  Several reporting cmdlets were built on
this functionality.

Run:

```Powershell
> Get-SafeguardCommand report
```

to see all of these reporting cmdlets.

The following video shows how the reporting cmdlets work, including parameters
for opening the output directly in Excel.

[Reporting Cmdlet video](https://youtu.be/mWNaCH7eB70)

[![Reporting Cmdlet video](https://img.youtube.com/vi/mWNaCH7eB70/0.jpg)](https://www.youtube.com/watch?v=mWNaCH7eB70)

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

Please report anything you see from the output that is missing, and we will
update this list.

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
- Uninstall-SafeguardAuditLogSigningCertificate
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
- Get-SafeguardApplianceAvailability
- Get-SafeguardApplianceState
- Wait-SafeguardApplianceStateOnline
- Get-SafeguardVersion
- Get-SafeguardApplianceVerification
- Get-SafeguardTime
- Set-SafeguardTime
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
- SafeguardTls12Only
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
- Get-SafeguardClusterPlatformTaskLoadStatus
- Get-SafeguardClusterPlatformTaskQueueStatus

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

### Session Cluster Join

- Get-SafeguardSessionCluster
- Set-SafeguardSessionCluster
- Join-SafeguardSessionCluster
- Split-SafeguardSessionCluster
- Get-SafeguardSessionSplitCluster
- Remove-SafeguardSessionSplitCluster
- Enable-SafeguardSessionClusterAccessRequestBroker
- Disable-SafeguardSessionClusterAccessRequestBroker
- Get-SafeguardSessionClusterAccessRequestBroker
- Enable-SafeguardSessionClusterAuditStream
- Disable-SafeguardSessionClusterAuditStream
- Get-SafeguardSessionClusterAuditStream

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
- Get-SafeguardMyRequest
- Get-SafeguardMyApproval
- Get-SafeguardMyReview
- Get-SafeguardRequestableAccount (Get-SafeguardMyRequestable)
- Find-SafeguardRequestableAccount (Find-SafeguardMyRequestable)
- Get-SafeguardAccessRequestPassword (Get-SafeguardAccessRequestCheckoutPassword)
- Get-SafeguardAccessRequestRdpFile
- Get-SafeguardAccessRequestRdpUrl
- Get-SafeguardAccessRequestSshUrl
- Start-SafeguardAccessRequestSession
- Copy-SafeguardAccessRequestPassword
- Close-SafeguardAccessRequest
- Approve-SafeguardAccessRequest
- Deny-SafeguardAccessRequest (Revoke-SafeguardAccessRequest)
- Get-SafeguardAccessRequestActionLog
- Assert-SafeguardAccessRequest

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

### Asset Partitions

- Get-SafeguardAssetPartition
- New-SafeguardAssetPartition
- Remove-SafeguardAssetPartition
- Edit-SafeguardAssetPartition
- Enter-SafeguardAssetPartition
- Exit-SafeguardAssetPartition
- Get-SafeguardCurrentAssetPartition

### Assets

- Get-SafeguardAsset
- Find-SafeguardAsset
- New-SafeguardAsset
- Test-SafeguardAsset
- Remove-SafeguardAsset
- Edit-SafeguardAsset
- Sync-SafeguardDirectoryAsset

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

- Get-SafeguardDirectoryIdentityProvider
- New-SafeguardDirectoryIdentityProvider
- Remove-SafeguardDirectoryIdentityProvider
- Edit-SafeguardDirectoryIdentityProvider
- Sync-SafeguardDirectoryIdentityProvider
- Get-SafeguardDirectoryIdentityProviderDomain
- Get-SafeguardDirectoryIdentityProviderSchemaMapping
- Set-SafeguardDirectoryIdentityProviderSchemaMapping
- Get-SafeguardDirectory
- New-SafeguardDirectory
- Test-SafeguardDirectory
- Remove-SafeguardDirectory
- Edit-SafeguardDirectory
- Sync-SafeguardDirectory
- Get-SafeguardDirectoryMigrationData

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
- Edit-SafeguardAssetGroup
- Get-SafeguardAccountGroup
- New-SafeguardAccountGroup
- Remove-SafeguardAccountGroup
- Edit-SafeguardAccountGroup

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
- Remove-SafeguardEntitlement
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
- Get-SafeguardA2aCredentialRetrievalInformation
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

- Get-SafeguardA2aRetrievableAccounts
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

### One Identity Starling Access Certification

- Get-SafeguardAccessCertificationAll
- Get-SafeguardAccessCertificationAccount
- Get-SafeguardAccessCertificationGroup
- Get-SafeguardAccessCertificationEntitlement
- Get-SafeguardAccessCertificationIdentity
- Get-ADAccessCertificationIdentity
- Update-SafeguardAccessCertificationGroupFromAD

### Reports

- Get-SafeguardReportAccountWithoutPassword
- Get-SafeguardReportDailyAccessRequest
- Get-SafeguardReportDailyPasswordChangeFail
- Get-SafeguardReportDailyPasswordChangeSuccess
- Get-SafeguardReportDailyPasswordCheckFail
- Get-SafeguardReportDailyPasswordCheckSuccess
- Get-SafeguardReportUserEntitlement
- Get-SafeguardReportUserGroupMembership
- Get-SafeguardReportAssetManagementConfiguration
- Get-SafeguardReportA2aEntitlement
