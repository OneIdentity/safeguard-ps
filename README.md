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

## Support

One Identity open source projects are supported through [One Identity GitHub issues](https://github.com/OneIdentity/safeguard-ps/issues) and the [One Identity Community](https://www.oneidentity.com/community/). This includes all scripts, plugins, SDKs, modules, code snippets or other solutions. For assistance with any One Identity GitHub project, please raise a new Issue on the [One Identity GitHub project](https://github.com/OneIdentity/safeguard-ps/issues) page. You may also visit the [One Identity Community](https://www.oneidentity.com/community/) to ask questions.  Requests for assistance made through official One Identity Support will be referred back to GitHub and the One Identity Community forums where those requests can benefit all users.

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

Or you may need to use the new method:
```Powershell
> Install-PSResource -Name safeguard-ps
```
Note, `Install-PSResource` doesn't load the newly installed module into the current
session. You must import the new version or start a new session to use the updated
module.

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

Restart your Powershell shell. Then, you can install a pre-release version of safeguard-ps by running:

```Powershell
> Install-Module -Name safeguard-ps -AllowPrerelease
```

## Getting Started

Once you have loaded the module, you can connect to Safeguard using the
`Connect-Safeguard` cmdlet.  If you do not have SSL properly configured, you
must use the `-Insecure` parameter to avoid SSL trust errors.

Authentication in Safeguard is based on OAuth2.  Starting with recent versions
of Safeguard for Privileged Passwords, the **Resource Owner Grant (ROG) is
disabled by default**.  This means the traditional username/password login
requires the `-Pkce` parameter to use the Proof Key for Code Exchange (PKCE)
flow instead.

The recommended way to connect with a username and password is:

```Powershell
> Connect-Safeguard -Insecure 192.168.123.123 local Admin -Pkce
Password: ********
Login Successful.
```

Alternatively, you can use the `-Browser` parameter for a fully interactive
browser-based login.  This is the best option when using two-factor
authentication or external identity providers, as the built-in secure token
service can redirect you to multiple authentication providers through the
browser agent.  This authentication mechanism uses the Authorization Code
Grant of OAuth2.

```Powershell
> Connect-Safeguard -Insecure 192.168.123.123 -Browser
Login Successful.
```

For headless environments where a local browser is not available -- such as
Docker containers, remote SSH sessions, or CI runners -- use `-DeviceCode` to
authenticate via the OAuth 2.0 Device Authorization Grant (RFC 8628).  The
cmdlet displays a verification URL and short user code; you complete the
login from any browser on any device, and the token is delivered back to
PowerShell automatically.  This flow supports SSO and multi-factor
authentication just like `-Browser`.  It requires Safeguard appliance
firmware 7.4 or later with the **Device Code** OAuth2 grant type enabled
under *Appliance Management -> Safeguard Access -> Local Login Control*.

```Powershell
> Connect-Safeguard -Insecure 192.168.123.123 -DeviceCode

To sign in, use a web browser to open the page:
    https://192.168.123.123/RSTS/oauth2/device
and enter the code:
    ABCD-1234
Or open this URL directly to skip entering the code:
    https://192.168.123.123/RSTS/oauth2/device?user_code=ABCD-1234
The code expires in 300 seconds. Press Ctrl+C to cancel.

Login Successful.
```

You can pre-select an identity provider with `-IdentityProvider` so the user
is taken straight to that provider's login page instead of choosing from a
drop-down:

```Powershell
> Connect-Safeguard -Insecure 192.168.123.123 -DeviceCode -IdentityProvider extf14
```

If your appliance still has Resource Owner Grant enabled, the legacy login
style (without `-Pkce`, `-Browser`, or `-DeviceCode`) will continue to work:

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
Function        Get-SafeguardDirectoryAccount                      8.4.2      safeguard-ps

```

## Module Versioning

safeguard-ps follows [semantic versioning](https://semver.org/) (MAJOR.MINOR.PATCH).
The module version no longer tracks Safeguard appliance releases.  Any recent
version of safeguard-ps is expected to work against any currently supported
version of the Safeguard for Privileged Passwords appliance.  When the Safeguard
Web API gains new capabilities, safeguard-ps adds cmdlets or parameters to
expose them; older cmdlets continue to work against older appliances.

If you encounter a cmdlet that depends on an API feature your appliance does
not have, the call will return an error from the appliance -- upgrade either
the appliance or the module as appropriate.

Prerelease builds are also published to the PowerShell Gallery; see the
*Prerelease Versions* section above for installation instructions.

### API Version

safeguard-ps targets the Safeguard v4 API by default.  The v3 API is still
available for legacy scripts -- pass `-Version 3` to `Connect-Safeguard`,
`Invoke-SafeguardMethod`, or the A2A cmdlets, or call
`Switch-SafeguardConnectionVersion -Version 3` after connecting.

## Real-Time Event Listeners

safeguard-ps can listen for real-time events from the Safeguard appliance using
SignalR over Server-Sent Events (SSE).  This is useful for monitoring changes,
triggering automated workflows, or building integrations that react to events
as they happen.

### Listening for Events

After connecting with `Connect-Safeguard`, use `Wait-SafeguardEvent` to listen
for events.  The cmdlet runs continuously until interrupted with **Ctrl+C**.

When no `-Handler` or `-HandlerScript` is provided, events are emitted to the
pipeline so you can filter and process them:

```PowerShell
> Connect-Safeguard -Insecure 192.168.123.123 local Admin -Pkce
> Wait-SafeguardEvent -Insecure
```

You can filter to specific event types using the `-Event` parameter:

```PowerShell
> Wait-SafeguardEvent -Insecure -Event AssetAccountPasswordUpdated,AssetAccountSshKeyUpdated
```

### Using Handlers

Use `-Handler` to provide a script block, or `-HandlerScript` to point at an
external `.ps1` file.  These are mutually exclusive.  The handler receives the
event name and event body as arguments:

```PowerShell
> Wait-SafeguardEvent -Insecure -Handler { param($EventName, $EventBody) Write-Host "$EventName occurred" }
```

### A2A Event Listeners

For Application to Application (A2A) scenarios, use `Wait-SafeguardA2aEvent`
which authenticates with a client certificate and API key rather than an
interactive session.  It connects to the A2A-specific SignalR endpoint:

```PowerShell
> Wait-SafeguardA2aEvent -Appliance 192.168.123.123 -Insecure -CertificateFile C:\cert.pfx -Password $pwd -ApiKey $apiKey
```

The `Invoke-SafeguardA2aPasswordHandler` and `Invoke-SafeguardA2aSshKeyHandler`
cmdlets are higher-level wrappers that fetch the current credential immediately,
invoke your handler, then continue listening for changes.  Each time the
credential is updated on the appliance, the new value is fetched and delivered
to your handler:

```PowerShell
> Invoke-SafeguardA2aPasswordHandler 192.168.123.123 $apiKey -CertificateFile C:\cert.pfx -Password $pwd -Insecure `
    -Handler { param($EventName, $Password) Write-Host "$EventName -- new password received" }
```

## Getting Started With A2A

Once you have configured your A2A registration in Safeguard, you can get
the information to call Safeguard A2A by running the following:

```Powershell
> Get-SafeguardA2aCredentialRetrievalInformation
```

This will report the certificate thumbprint you need to use as well as the
API key required to request a specific account password.

The best practice is to install your user certificate in the Windows
User Certificate Store (use the Personal folder).  Then, you can reference
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

## Development
PowerShell development can be done many ways, this is just one way with Visual Studio Code.

### Requirements
* Install [Visual Studio Code](https://code.visualstudio.com/download)
* Clone this repository.

### Editing
* Start Visual Studio Code.
* Open root folder of safeguard-ps.
* Create or modify the scripts and save the changes.

### Executing
* Open a Terminal in Visual Studio Code and execute the following.

  If you have installed the safeguard-ps module uninstall it.
  ```
  Remove-Module safeguard-ps
  ```

  Install the new or modified scripts.
  ```
  ./install-local.ps1
  ```
* Test your changes

  Before testing any new changes you must run `Remove-Module safeguard-ps` `cleanup-local.ps1` and `install-local.ps1`.

## PowerShell Cmdlets

Every cmdlet supports `Get-Help` for detailed usage information. Use
`Get-SafeguardCommand` to search for cmdlets by keyword at any time.

Aliases are shown in parentheses where available.

### Management Shell

- `Get-SafeguardCommand`
- `Get-SafeguardBanner`
- `Open-CsvInExcel`

### Core Functionality

- `Connect-Safeguard`
- `Disconnect-Safeguard`
- `Invoke-SafeguardMethod`
- `Get-SafeguardAccessTokenStatus`
- `Update-SafeguardAccessToken`
- `Get-SafeguardLoggedInUser`
- `Switch-SafeguardConnectionVersion`
- `Confirm-SafeguardStaAcceptance`

### Data Types

- `Get-SafeguardIdentityProviderType`
- `Get-SafeguardPlatform`
- `Find-SafeguardPlatform`
- `Get-SafeguardTimeZone`
- `Get-SafeguardTransferProtocol`

### Licensing

- `Get-SafeguardLicense`
- `Install-SafeguardLicense`
- `Uninstall-SafeguardLicense`

### Certificates

- `Get-SafeguardTrustedCertificate`
- `Install-SafeguardTrustedCertificate`
- `Uninstall-SafeguardTrustedCertificate`
- `Get-SafeguardSslCertificate`
- `Install-SafeguardSslCertificate`
- `Uninstall-SafeguardSslCertificate`
- `Get-SafeguardSslCertificateForAppliance`
- `Set-SafeguardSslCertificateForAppliance`
- `Clear-SafeguardSslCertificateForAppliance`
- `Get-SafeguardAuditLogSigningCertificate`
- `Install-SafeguardAuditLogSigningCertificate`
- `Uninstall-SafeguardAuditLogSigningCertificate`
- `Get-SafeguardCertificateSigningRequest` (`Get-SafeguardCsr`)
- `New-SafeguardCertificateSigningRequest` (`New-SafeguardCsr`)
- `Remove-SafeguardCertificateSigningRequest` (`Remove-SafeguardCsr`)
- `New-SafeguardTestCertificatePki`

### Networking

- `Get-SafeguardNetworkInterface`
- `Set-SafeguardNetworkInterface`
- `Get-SafeguardDnsSuffix`
- `Set-SafeguardDnsSuffix`

### Maintenance

- `Get-SafeguardStatus`
- `Get-SafeguardVersion`
- `Test-SafeguardVersion`
- `Get-SafeguardHealth`
- `Get-SafeguardApplianceAvailability`
- `Get-SafeguardApplianceState`
- `Wait-SafeguardApplianceStateOnline`
- `Get-SafeguardApplianceVerification`
- `Get-SafeguardTime`
- `Set-SafeguardTime`
- `Get-SafeguardApplianceUptime`
- `Get-SafeguardApplianceName`
- `Set-SafeguardApplianceName`
- `Get-SafeguardApplianceDnsSuffix`
- `Set-SafeguardApplianceDnsSuffix`
- `Get-SafeguardApplianceDnsName`
- `Invoke-SafeguardApplianceShutdown`
- `Invoke-SafeguardApplianceReboot`
- `Invoke-SafeguardApplianceFactoryReset`
- `Get-SafeguardSupportBundle`
- `Get-SafeguardSupportBundleQuickGlance`
- `Get-SafeguardPatch`
- `Clear-SafeguardPatch`
- `Set-SafeguardPatch`
- `Install-SafeguardPatch`
- `Get-SafeguardBackup`
- `New-SafeguardBackup`
- `Remove-SafeguardBackup`
- `Export-SafeguardBackup`
- `Import-SafeguardBackup`
- `Restore-SafeguardBackup`
- `Save-SafeguardBackupToArchive`
- `Get-SafeguardBmcConfiguration`
- `Enable-SafeguardBmcConfiguration`
- `Disable-SafeguardBmcConfiguration`
- `Set-SafeguardBmcAdminPassword`
- `Get-SafeguardTls12OnlyStatus`
- `Enable-SafeguardTls12Only`
- `Disable-SafeguardTls12Only`
- `Test-SafeguardAuditLogArchive`

### Diagnostics

- `Invoke-SafeguardPing`
- `Invoke-SafeguardTelnet`
- `Invoke-SafeguardTraceroute`
- `Invoke-SafeguardArp`
- `Invoke-SafeguardNetstat`
- `Invoke-SafeguardNsLookup`
- `Invoke-SafeguardShowRoutes`
- `Invoke-SafeguardCldapPing`
- `Invoke-SafeguardClusterPing`
- `Invoke-SafeguardClusterThroughput`
- `Invoke-SafeguardMemberPing`
- `Invoke-SafeguardMemberThroughput`
- `Get-SafeguardDiagnosticPackage`
- `Set-SafeguardDiagnosticPackage`
- `Clear-SafeguardDiagnosticPackage`
- `Invoke-SafeguardDiagnosticPackage`
- `Get-SafeguardDiagnosticPackageLog`
- `Get-SafeguardDiagnosticPackageStatus`

### Clustering

- `Get-SafeguardClusterMember`
- `Add-SafeguardClusterMember`
- `Remove-SafeguardClusterMember`
- `Get-SafeguardClusterHealth`
- `Get-SafeguardClusterPrimary`
- `Set-SafeguardClusterPrimary`
- `Enable-SafeguardClusterPrimary`
- `Get-SafeguardClusterOperationStatus`
- `Unlock-SafeguardCluster` (`Clear-SafeguardClusterOperation`)
- `Get-SafeguardClusterSummary`
- `Get-SafeguardClusterPlatformTaskLoadStatus`
- `Get-SafeguardClusterPlatformTaskQueueStatus`
- `Get-SafeguardClusterVpnIpv6Address`

### Session Cluster Join

- `Get-SafeguardSessionCluster`
- `Set-SafeguardSessionCluster`
- `Join-SafeguardSessionCluster`
- `Split-SafeguardSessionCluster`
- `Get-SafeguardSessionSplitCluster`
- `Remove-SafeguardSessionSplitCluster`
- `Get-SafeguardSessionClusterAccessRequestBroker`
- `Enable-SafeguardSessionClusterAccessRequestBroker`
- `Disable-SafeguardSessionClusterAccessRequestBroker`
- `Get-SafeguardSessionClusterAuditStream`
- `Enable-SafeguardSessionClusterAuditStream`
- `Disable-SafeguardSessionClusterAuditStream`

### Safeguard for Privileged Sessions (SPS) Web API

- `Connect-SafeguardSps`
- `Disconnect-SafeguardSps`
- `Invoke-SafeguardSpsMethod`
- `Open-SafeguardSpsTransaction`
- `Close-SafeguardSpsTransaction` (`Save-SafeguardSpsTransaction`)
- `Get-SafeguardSpsTransaction`
- `Clear-SafeguardSpsTransaction`
- `Show-SafeguardSpsTransactionChange`
- `Show-SafeguardSpsEndpoint`
- `Get-SafeguardSpsInfo`
- `Get-SafeguardSpsVersion`
- `Get-SafeguardSpsLoginMethod`
- `Get-SafeguardSpsSupportBundle`
- `Get-SafeguardSpsWelcomeWizardStatus`
- `Complete-SafeguardSpsWelcomeWizard`
- `Enable-SafeguardSpsRemoteAccess` (`Enable-SafeguardSpsSra`)
- `Disable-SafeguardSpsRemoteAccess` (`Disable-SafeguardSpsSra`)
- `Invoke-SafeguardSpsStarlingJoinBrowser`
- `Remove-SafeguardSpsStarlingJoin`
- `Get-SafeguardSpsFirmwareSlot`
- `Import-SafeguardSpsFirmware`
- `Install-SafeguardSpsFirmware`
- `Install-SafeguardSpsUpgrade`
- `Test-SafeguardSpsFirmware`

### Users

- `Get-SafeguardIdentityProvider`
- `Get-SafeguardAuthenticationProvider`
- `Set-SafeguardAuthenticationProviderAsDefault`
- `Clear-SafeguardAuthenticationProviderAsDefault`
- `Get-SafeguardUser`
- `Find-SafeguardUser`
- `New-SafeguardUser`
- `Edit-SafeguardUser`
- `Remove-SafeguardUser`
- `Enable-SafeguardUser`
- `Disable-SafeguardUser`
- `Rename-SafeguardUser`
- `Set-SafeguardUserPassword`
- `Import-SafeguardUser`
- `New-SafeguardUserImportTemplate`
- `Get-SafeguardUserLinkedAccount`
- `Add-SafeguardUserLinkedAccount`
- `Remove-SafeguardUserLinkedAccount`
- `Get-SafeguardUserPreference`
- `Set-SafeguardUserPreference`
- `Remove-SafeguardUserPreference`
- `Sync-SafeguardUserGroupAuthenticationProvider`

### Asset Partitions

- `Get-SafeguardAssetPartition`
- `New-SafeguardAssetPartition`
- `Edit-SafeguardAssetPartition`
- `Remove-SafeguardAssetPartition`
- `Get-SafeguardAssetPartitionOwner`
- `Add-SafeguardAssetPartitionOwner`
- `Remove-SafeguardAssetPartitionOwner`
- `Enter-SafeguardAssetPartition`
- `Exit-SafeguardAssetPartition`
- `Get-SafeguardCurrentAssetPartition`

### Assets

- `Get-SafeguardAsset`
- `Find-SafeguardAsset`
- `New-SafeguardAsset`
- `Edit-SafeguardAsset`
- `Remove-SafeguardAsset`
- `Test-SafeguardAsset`
- `Import-SafeguardAsset`
- `New-SafeguardAssetImportTemplate`
- `Sync-SafeguardDirectoryAsset`

### Asset Accounts

- `Get-SafeguardAssetAccount`
- `Find-SafeguardAssetAccount`
- `New-SafeguardAssetAccount`
- `Edit-SafeguardAssetAccount`
- `Remove-SafeguardAssetAccount`
- `Enable-SafeguardAssetAccount`
- `Disable-SafeguardAssetAccount`
- `Set-SafeguardAssetAccountPassword`
- `New-SafeguardAssetAccountRandomPassword`
- `Test-SafeguardAssetAccountPassword`
- `Invoke-SafeguardAssetAccountPasswordChange`
- `Set-SafeguardAssetAccountSshKey`
- `Test-SafeguardAssetAccountSshKey`
- `Invoke-SafeguardAssetAccountSshKeyChange`
- `Invoke-SafeguardAssetSshHostKeyDiscovery`
- `Import-SafeguardAssetAccount`
- `Import-SafeguardAssetAccountPassword`
- `Import-SafeguardAssetAccountSshKey`
- `New-SafeguardAssetAccountImportTemplate`
- `New-SafeguardAssetAccountPasswordImportTemplate`
- `New-SafeguardAssetAccountSshKeyImportTemplate`

### Account Discovery

- `Get-SafeguardAccountDiscoverySchedule`
- `New-SafeguardAccountDiscoverySchedule`
- `Edit-SafeguardAccountDiscoverySchedule`
- `Remove-SafeguardAccountDiscoverySchedule`
- `Rename-SafeguardAccountDiscoverySchedule`
- `Copy-SafeguardAccountDiscoverySchedule`
- `Get-SafeguardAccountDiscoveryScheduleAsset`
- `Add-SafeguardAccountDiscoveryScheduleAsset`
- `Remove-SafeguardAccountDiscoveryScheduleAsset`
- `Get-SafeguardAccountDiscoveryRule`
- `Add-SafeguardAccountDiscoveryRule`
- `Remove-SafeguardAccountDiscoveryRule`
- `New-SafeguardAccountDiscoveryRuleUnix`
- `New-SafeguardAccountDiscoveryRuleWindows`
- `New-SafeguardAccountDiscoveryRuleDirectory`
- `New-SafeguardAccountDiscoveryRuleSps`
- `New-SafeguardAccountDiscoveryRuleStarlingConnect`
- `New-SafeguardAccountDiscoveryRuleRoleBased`
- `Get-SafeguardDiscoveredAccount`
- `Import-SafeguardDiscoveredAccount`
- `Set-SafeguardDiscoveredAccountStatus`
- `Invoke-SafeguardAssetAccountDiscovery`
- `Invoke-SafeguardAssetServiceDiscovery`

### Custom Platforms

- `Get-SafeguardCustomPlatform`
- `New-SafeguardCustomPlatform`
- `Edit-SafeguardCustomPlatform`
- `Remove-SafeguardCustomPlatform`
- `New-SafeguardCustomPlatformAsset`
- `Set-SafeguardCustomPlatformAssetParameter`
- `Get-SafeguardCustomPlatformScriptParameter`
- `Import-SafeguardCustomPlatformScript`
- `Export-SafeguardCustomPlatformScript`
- `Test-SafeguardCustomPlatformScript`

### Directories

- `Get-SafeguardDirectory`
- `New-SafeguardDirectory`
- `Edit-SafeguardDirectory`
- `Remove-SafeguardDirectory`
- `Test-SafeguardDirectory`
- `Sync-SafeguardDirectory`
- `Get-SafeguardDirectoryMigrationData`
- `Get-SafeguardDirectoryIdentityProvider`
- `New-SafeguardDirectoryIdentityProvider`
- `Edit-SafeguardDirectoryIdentityProvider`
- `Remove-SafeguardDirectoryIdentityProvider`
- `Sync-SafeguardDirectoryIdentityProvider`
- `Get-SafeguardDirectoryIdentityProviderDomain`
- `Get-SafeguardDirectoryIdentityProviderSchemaMapping`
- `Set-SafeguardDirectoryIdentityProviderSchemaMapping`

### Directory Accounts

- `Get-SafeguardDirectoryAccount`
- `Find-SafeguardDirectoryAccount`
- `New-SafeguardDirectoryAccount`
- `Edit-SafeguardDirectoryAccount`
- `Remove-SafeguardDirectoryAccount`
- `Set-SafeguardDirectoryAccountPassword`
- `New-SafeguardDirectoryAccountRandomPassword`
- `Test-SafeguardDirectoryAccountPassword`
- `Invoke-SafeguardDirectoryAccountPasswordChange`

### Profiles & Schedules

- `Get-SafeguardPasswordProfile`
- `New-SafeguardPasswordProfile`
- `Edit-SafeguardPasswordProfile`
- `Remove-SafeguardPasswordProfile`
- `Rename-SafeguardPasswordProfile`
- `Copy-SafeguardPasswordProfile`
- `Get-SafeguardPasswordProfileAccount`
- `Add-SafeguardPasswordProfileAccount`
- `Remove-SafeguardPasswordProfileAccount`
- `Get-SafeguardPasswordProfileAsset`
- `Add-SafeguardPasswordProfileAsset`
- `Remove-SafeguardPasswordProfileAsset`
- `Get-SafeguardAccountPasswordRule`
- `New-SafeguardAccountPasswordRule`
- `Edit-SafeguardAccountPasswordRule`
- `Remove-SafeguardAccountPasswordRule`
- `Rename-SafeguardAccountPasswordRule`
- `Copy-SafeguardAccountPasswordRule`
- `Get-SafeguardPasswordCheckSchedule`
- `New-SafeguardPasswordCheckSchedule`
- `Edit-SafeguardPasswordCheckSchedule`
- `Remove-SafeguardPasswordCheckSchedule`
- `Rename-SafeguardPasswordCheckSchedule`
- `Copy-SafeguardPasswordCheckSchedule`
- `Get-SafeguardPasswordChangeSchedule`
- `New-SafeguardPasswordChangeSchedule`
- `Edit-SafeguardPasswordChangeSchedule`
- `Remove-SafeguardPasswordChangeSchedule`
- `Rename-SafeguardPasswordChangeSchedule`
- `Copy-SafeguardPasswordChangeSchedule`
- `New-SafeguardSchedule`
- `New-SafeguardScheduleDaily`
- `New-SafeguardScheduleWeekly`
- `New-SafeguardScheduleMonthlyByDay`
- `New-SafeguardScheduleMonthlyByDayOfWeek`

### Groups

**User Groups:**
- `Get-SafeguardUserGroup`
- `New-SafeguardUserGroup`
- `Edit-SafeguardUserGroup`
- `Remove-SafeguardUserGroup`
- `Get-SafeguardUserGroupMember`
- `Add-SafeguardUserGroupMember`
- `Remove-SafeguardUserGroupMember`

**Asset Groups:**
- `Get-SafeguardAssetGroup`
- `New-SafeguardAssetGroup`
- `Edit-SafeguardAssetGroup`
- `Remove-SafeguardAssetGroup`
- `Get-SafeguardAssetGroupMember`
- `Add-SafeguardAssetGroupMember`
- `Remove-SafeguardAssetGroupMember`

**Account Groups:**
- `Get-SafeguardAccountGroup`
- `New-SafeguardAccountGroup`
- `Edit-SafeguardAccountGroup`
- `Remove-SafeguardAccountGroup`
- `Get-SafeguardAccountGroupMember`
- `Add-SafeguardAccountGroupMember`
- `Remove-SafeguardAccountGroupMember`

**Dynamic Groups:**
- `Get-SafeguardDynamicAssetGroup`
- `New-SafeguardDynamicAssetGroup`
- `Edit-SafeguardDynamicAssetGroup`
- `Get-SafeguardDynamicAccountGroup`
- `New-SafeguardDynamicAccountGroup`
- `Edit-SafeguardDynamicAccountGroup`

### Entitlements & Access Policies

- `Get-SafeguardEntitlement`
- `New-SafeguardEntitlement`
- `Edit-SafeguardEntitlement`
- `Remove-SafeguardEntitlement`
- `Add-SafeguardEntitlementMember`
- `Remove-SafeguardEntitlementMember`
- `Get-SafeguardAccessPolicy`
- `Add-SafeguardAccessPolicy`
- `Edit-SafeguardAccessPolicy`
- `Remove-SafeguardAccessPolicy`
- `Get-SafeguardAccessPolicyScopeItem`
- `Get-SafeguardAccessPolicyAccessRequestProperty`
- `Get-SafeguardAccessPolicySessionProperty`
- `Get-SafeguardPolicyAsset`
- `Find-SafeguardPolicyAsset`
- `Get-SafeguardPolicyAccount`
- `Find-SafeguardPolicyAccount`

### Access Requests

- `Get-SafeguardAccessRequest`
- `Find-SafeguardAccessRequest`
- `New-SafeguardAccessRequest`
- `Edit-SafeguardAccessRequest`
- `Close-SafeguardAccessRequest`
- `Approve-SafeguardAccessRequest`
- `Deny-SafeguardAccessRequest` (`Revoke-SafeguardAccessRequest`)
- `Assert-SafeguardAccessRequest`
- `Get-SafeguardActionableRequest`
- `Get-SafeguardMyRequest`
- `Get-SafeguardMyApproval`
- `Get-SafeguardMyReview`
- `Get-SafeguardRequestableAccount` (`Get-SafeguardMyRequestable`)
- `Find-SafeguardRequestableAccount` (`Find-SafeguardMyRequestable`)
- `Get-SafeguardAccessRequestPassword` (`Get-SafeguardAccessRequestCheckoutPassword`)
- `Copy-SafeguardAccessRequestPassword`
- `Get-SafeguardAccessRequestSshHostKey`
- `Get-SafeguardAccessRequestSshKey`
- `Get-SafeguardAccessRequestSshUrl`
- `Get-SafeguardAccessRequestRdpFile`
- `Get-SafeguardAccessRequestRdpUrl`
- `Get-SafeguardAccessRequestApiKey`
- `Get-SafeguardAccessRequestActionLog`
- `Start-SafeguardAccessRequestSession`
- `Start-SafeguardAccessRequestWebSession`

### Tags

- `Get-SafeguardTag`
- `Find-SafeguardTag`
- `New-SafeguardTag`
- `Update-SafeguardTag`
- `Remove-SafeguardTag`
- `Get-SafeguardTagOccurrence`
- `Get-SafeguardAssetTag`
- `Add-SafeguardAssetTag`
- `Remove-SafeguardAssetTag`
- `Update-SafeguardAssetTag`
- `Get-SafeguardAssetAccountTag`
- `Add-SafeguardAssetAccountTag`
- `Remove-SafeguardAssetAccountTag`
- `Update-SafeguardAssetAccountTag`
- `Test-SafeguardAssetTaggingRule`
- `Test-SafeguardAssetAccountTaggingRule`

### Events

- `Get-SafeguardEvent`
- `Find-SafeguardEvent`
- `Get-SafeguardEventName`
- `Get-SafeguardEventCategory`
- `Get-SafeguardEventProperty`
- `Get-SafeguardEventSubscription`
- `Find-SafeguardEventSubscription`
- `New-SafeguardEventSubscription`
- `Edit-SafeguardEventSubscription`
- `Remove-SafeguardEventSubscription`
- `Wait-SafeguardEvent`

### A2A

**Service:**
- `Get-SafeguardA2aServiceStatus`
- `Enable-SafeguardA2aService`
- `Disable-SafeguardA2aService`

**Registrations:**
- `Get-SafeguardA2a`
- `New-SafeguardA2a`
- `Edit-SafeguardA2a`
- `Remove-SafeguardA2a`

**Credential Retrieval Configuration:**
- `Get-SafeguardA2aCredentialRetrievalInformation`
- `Get-SafeguardA2aCredentialRetrieval`
- `Add-SafeguardA2aCredentialRetrieval`
- `Remove-SafeguardA2aCredentialRetrieval`
- `Get-SafeguardA2aCredentialRetrievalIpRestriction`
- `Set-SafeguardA2aCredentialRetrievalIpRestriction`
- `Clear-SafeguardA2aCredentialRetrievalIpRestriction`
- `Get-SafeguardA2aCredentialRetrievalApiKey`
- `Reset-SafeguardA2aCredentialRetrievalApiKey`

**Access Request Broker Configuration:**
- `Get-SafeguardA2aAccessRequestBroker`
- `Set-SafeguardA2aAccessRequestBroker`
- `Clear-SafeguardA2aAccessRequestBroker`
- `Get-SafeguardA2aAccessRequestBrokerIpRestriction`
- `Set-SafeguardA2aAccessRequestBrokerIpRestriction`
- `Clear-SafeguardA2aAccessRequestBrokerIpRestriction`
- `Get-SafeguardA2aAccessRequestBrokerApiKey`
- `Reset-SafeguardA2aAccessRequestBrokerApiKey`

**Credential Retrieval (calling A2A):**
- `Get-SafeguardA2aRetrievableAccount`
- `Get-SafeguardA2aPassword`
- `Set-SafeguardA2aPassword`
- `Get-SafeguardA2aPrivateKey`
- `Set-SafeguardA2aPrivateKey`
- `Get-SafeguardA2aApiKeySecret`

**Access Request Broker (calling A2A):**
- `New-SafeguardA2aAccessRequest`

**Event Listeners (calling A2A):**
- `Wait-SafeguardA2aEvent`
- `Invoke-SafeguardA2aPasswordHandler`
- `Invoke-SafeguardA2aSshKeyHandler`

### One Identity Starling

- `Invoke-SafeguardStarlingJoinBrowser`
- `Invoke-SafeguardStarlingJoin`
- `Get-SafeguardStarlingJoinUrl`
- `Get-SafeguardStarlingJoinInstance`
- `Get-SafeguardStarlingSubscription`
- `New-SafeguardStarlingSubscription`
- `Remove-SafeguardStarlingSubscription`
- `Get-SafeguardStarlingSetting`
- `Set-SafeguardStarlingSetting`

### Reports

- `Get-SafeguardReportA2aEntitlement`
- `Get-SafeguardReportAccountGroupMembership`
- `Get-SafeguardReportAccountWithoutPassword`
- `Get-SafeguardReportAssetAccountPasswordHistory` (`Get-SafeguardPasswordHistory`)
- `Get-SafeguardReportAssetGroupMembership`
- `Get-SafeguardReportAssetManagementConfiguration`
- `Get-SafeguardReportDailyAccessRequest`
- `Get-SafeguardReportDailyPasswordChangeFail`
- `Get-SafeguardReportDailyPasswordChangeSuccess`
- `Get-SafeguardReportDailyPasswordCheckFail`
- `Get-SafeguardReportDailyPasswordCheckSuccess`
- `Get-SafeguardReportPasswordLastChanged`
- `Get-SafeguardReportUserEntitlement`
- `Get-SafeguardReportUserGroupMembership`

### Archive Servers

- `Get-SafeguardArchiveServer`
- `New-SafeguardArchiveServer`
- `Edit-SafeguardArchiveServer`
- `Remove-SafeguardArchiveServer`
- `Test-SafeguardArchiveServer`

### Settings

- `Get-SafeguardApplianceSetting`
- `Set-SafeguardApplianceSetting`
- `Get-SafeguardCoreSetting`
- `Set-SafeguardCoreSetting`
- `Get-SafeguardOAuth2GrantType`
- `Enable-SafeguardOAuth2GrantType`
- `Disable-SafeguardOAuth2GrantType`
- `Get-SafeguardDebugSettings`
- `Set-SafeguardDebugSettings`
- `Enable-SafeguardTlsLogging`
- `Disable-SafeguardTlsLogging`
- `Get-SafeguardSyslogServer`
- `New-SafeguardSyslogServer`
- `Edit-SafeguardSyslogServer`
- `Remove-SafeguardSyslogServer`
- `Get-SafeguardUserPasswordRule`
- `Set-SafeguardUserPasswordRule`
- `New-SafeguardUserPassword`
- `Test-SafeguardUserPassword`
- `Get-SafeguardLoginMessage`
- `Set-SafeguardLoginMessage`
- `Get-SafeguardDailyMessage`
- `Set-SafeguardDailyMessage`

### Deleted Objects

- `Get-SafeguardDeletedAsset`
- `Remove-SafeguardDeletedAsset`
- `Restore-SafeguardDeletedAsset`
- `Get-SafeguardDeletedAssetAccount`
- `Remove-SafeguardDeletedAssetAccount`
- `Restore-SafeguardDeletedAssetAccount`
- `Get-SafeguardDeletedUser`
- `Remove-SafeguardDeletedUser`
- `Restore-SafeguardDeletedUser`
- `Get-SafeguardPurgeSettings`
- `Update-SafeguardPurgeSettings`
- `Reset-SafeguardPurgeSettings`

### Audit Log

- `Get-SafeguardAuditLog`
- `Get-SafeguardAuditLogAccessRequestActivity`
- `Get-SafeguardAuditLogAccessRequestSession`
- `Get-SafeguardAuditLogDiscoveredItem`
- `Get-SafeguardAuditLogMaintenanceConfig`
- `Set-SafeguardAuditLogMaintenanceConfig`
- `Invoke-SafeguardAuditLogMaintenance`
- `Get-SafeguardAuditLogObjectChange`
- `Get-SafeguardAuditLogPlatformScript`
- `Get-SafeguardAuditLogSigningCertificateHistory`
- `Get-SafeguardScheduledAuditLogReport`
- `New-SafeguardScheduledAuditLogReport`
- `Edit-SafeguardScheduledAuditLogReport`
- `Remove-SafeguardScheduledAuditLogReport`
- `Invoke-SafeguardScheduledAuditLogReport`

### Reason Codes

- `Get-SafeguardReasonCode`
- `Find-SafeguardReasonCode`
- `New-SafeguardReasonCode`
- `Edit-SafeguardReasonCode`
- `Remove-SafeguardReasonCode`
- `Get-SafeguardReasonCodeScope`

### Running Tasks

- `Get-SafeguardRunningTask`
- `Stop-SafeguardRunningTask`
- `Get-SafeguardTaskLog`
- `Clear-SafeguardTaskLog`
