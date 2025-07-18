#
# Module manifest for module 'safeguard-ps'
#
# Generated by: petrsnd
# Generated on: 9/1/2017
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'safeguard-ps.psm1'

# Version number of this module.
ModuleVersion = '8.0.99999'

# Supported PSEditions
# CompatiblePSEditions = @()

# ID used to uniquely identify this module
GUID = '6b12ac55-6cde-453f-a1b7-1cdf5cec05f2'

# Author of this module
Author = 'petrsnd'

# Company or vendor of this module
CompanyName = 'One Identity LLC'

# Copyright statement for this module
Copyright = '(c) 2025 One Identity LLC. All rights reserved.'

# Description of the functionality provided by this module
Description = 'Scripting tools for interacting with the One Identity Safeguard Web API.'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '5.1'

# Name of the Windows PowerShell host required by this module
# PowerShellHostName = ''

# Minimum version of the Windows PowerShell host required by this module
# PowerShellHostVersion = ''

# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# DotNetFrameworkVersion = ''

# Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# CLRVersion = ''

# Processor architecture (None, X86, Amd64) required by this module
# ProcessorArchitecture = ''

# Modules that must be imported into the global environment prior to importing this module
# RequiredModules = @()

# Assemblies that must be loaded prior to importing this module
# RequiredAssemblies = @()

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
# ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
# FormatsToProcess = @()

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
NestedModules = @(
    'sslhandling.psm1',
    'ps-utilities.psm1',
    'sg-utilities.psm1',
    'datatypes.psm1',
    'licensing.psm1',
    'certificates.psm1',
    'networking.psm1',
    'maintenance.psm1',
    'diagnostics.psm1',
    'sessionapi.psm1',
    'sessionjoin.psm1',
    'archives.psm1',
    'requests.psm1',
    'users.psm1',
    'assets.psm1',
    'assetpartitions.psm1',
    'schedules.psm1',
    'profiles.psm1',
    'directories.psm1',
    'groups.psm1',
    'policies.psm1',
    'managementShell.psm1',
    'events.psm1',
    'clustering.psm1',
    'a2a.psm1',
    'a2acallers.psm1',
    'starling.psm1',
    'entitlements.psm1',
    'reports.psm1',
    'settings.psm1',
    'deleted.psm1',
    'service.psm1',
    'syslog.psm1',
    'auditlog.psm1',
    'tags.psm1'
    )

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = @(
    # sslhandling.psm1 is just a helper module -- no functions exported
    # ps-utilities.psm1 is just a helper module -- no functions exported
    # safeguard-ps.psm1
    'Connect-Safeguard','Disconnect-Safeguard','Invoke-SafeguardMethod',
    'Get-SafeguardAccessTokenStatus','Update-SafeguardAccessToken',
    'Get-SafeguardLoggedInUser','Confirm-SafeguardStaAcceptance',
    'Switch-SafeguardConnectionVersion'
    # csv utility (also in safeguard-ps.psm1)
    'Open-CsvInExcel',
    # datatypes.psm1
    'Get-SafeguardIdentityProviderType','Get-SafeguardPlatform','Find-SafeguardPlatform',
    'Get-SafeguardTimeZone','Get-SafeguardTransferProtocol',
    # licensing.psm1
    'Install-SafeguardLicense','Uninstall-SafeguardLicense','Get-SafeguardLicense',
    # certificates.psm1
    'Install-SafeguardTrustedCertificate','Uninstall-SafeguardTrustedCertificate','Get-SafeguardTrustedCertificate',
    'Install-SafeguardAuditLogSigningCertificate','Uninstall-SafeguardAuditLogSigningCertificate','Get-SafeguardAuditLogSigningCertificate',
    'Install-SafeguardSslCertificate','Uninstall-SafeguardSslCertificate','Get-SafeguardSslCertificate',
    'Set-SafeguardSslCertificateForAppliance','Clear-SafeguardSslCertificateForAppliance','Get-SafeguardSslCertificateForAppliance',
    'Get-SafeguardCertificateSigningRequest','New-SafeguardCertificateSigningRequest','Remove-SafeguardCertificateSigningRequest',
    'New-SafeguardTestCertificatePki',
    # networking.psm1
    'Get-SafeguardNetworkInterface','Set-SafeguardNetworkInterface','Get-SafeguardDnsSuffix','Set-SafeguardDnsSuffix',
    # maintenance.psm1
    'Get-SafeguardStatus','Get-SafeguardApplianceAvailability','Get-SafeguardApplianceState','Wait-SafeguardApplianceStateOnline',
    'Get-SafeguardVersion','Test-SafeguardVersion','Get-SafeguardApplianceVerification','Get-SafeguardTime','Set-SafeguardTime',
    'Get-SafeguardApplianceUptime','Get-SafeguardHealth','Get-SafeguardApplianceName','Set-SafeguardApplianceName',
    'Get-SafeguardApplianceDnsSuffix','Set-SafeguardApplianceDnsSuffix','Get-SafeguardApplianceDnsName',
    'Invoke-SafeguardApplianceShutdown','Invoke-SafeguardApplianceReboot','Invoke-SafeguardApplianceFactoryReset',
    'Get-SafeguardSupportBundle','Get-SafeguardSupportBundleQuickGlance','Get-SafeguardPatch','Clear-SafeguardPatch','Install-SafeguardPatch', 'Set-SafeguardPatch',
    'New-SafeguardBackup','Remove-SafeguardBackup','Export-SafeguardBackup','Import-SafeguardBackup',
    'Restore-SafeguardBackup','Save-SafeguardBackupToArchive','Get-SafeguardBackup',
    'Get-SafeguardBmcConfiguration','Enable-SafeguardBmcConfiguration','Disable-SafeguardBmcConfiguration',
    'Set-SafeguardBmcAdminPassword','Enable-SafeguardTls12Only','Disable-SafeguardTls12Only',
    'Get-SafeguardTls12OnlyStatus',
    'Test-SafeguardAuditLogArchive',
    # diagnostics.psm1
    'Invoke-SafeguardPing','Invoke-SafeguardTelnet',
    'Get-SafeguardDiagnosticPackage','Set-SafeguardDiagnosticPackage','Clear-SafeguardDiagnosticPackage',
    'Invoke-SafeguardDiagnosticPackage','Get-SafeguardDiagnosticPackageStatus','Get-SafeguardDiagnosticPackageLog',
    'Invoke-SafeguardMemberThroughput','Invoke-SafeguardClusterThroughput',
    'Invoke-SafeguardMemberPing','Invoke-SafeguardClusterPing',
    # sessionjoin.psm1
    'Get-SafeguardSessionCluster','Set-SafeguardSessionCluster','Join-SafeguardSessionCluster','Split-SafeguardSessionCluster',
    'Get-SafeguardSessionSplitCluster','Remove-SafeguardSessionSplitCluster',
    'Enable-SafeguardSessionClusterAccessRequestBroker','Disable-SafeguardSessionClusterAccessRequestBroker',
    'Get-SafeguardSessionClusterAccessRequestBroker','Enable-SafeguardSessionClusterAuditStream',
    'Disable-SafeguardSessionClusterAuditStream','Get-SafeguardSessionClusterAuditStream',
    # sessionapi.psm1
    'Get-SafeguardSpsWelcomeWizardStatus','Complete-SafeguardSpsWelcomeWizard',
    'Connect-SafeguardSps','Disconnect-SafeguardSps','Invoke-SafeguardSpsMethod',
    'Open-SafeguardSpsTransaction','Close-SafeguardSpsTransaction','Get-SafeguardSpsTransaction','Clear-SafeguardSpsTransaction',
    'Show-SafeguardSpsTransactionChange','Show-SafeguardSpsEndpoint','Invoke-SafeguardSpsStarlingJoinBrowser',
    'Remove-SafeguardSpsStarlingJoin','Enable-SafeguardSpsRemoteAccess','Disable-SafeguardSpsRemoteAccess',
    'Get-SafeguardSpsFirmwareSlot','Import-SafeguardSpsFirmware','Test-SafeguardSpsFirmware','Install-SafeguardSpsFirmware',
    'Install-SafeguardSpsUpgrade','Get-SafeguardSpsInfo','Get-SafeguardSpsVersion',
    'Get-SafeguardSpsSupportBundle',
    # archives.psm1
    'Get-SafeguardArchiveServer','New-SafeguardArchiveServer','Test-SafeguardArchiveServer',
    'Remove-SafeguardArchiveServer','Edit-SafeguardArchiveServer',
    # requests.psm1
    'Get-SafeguardAccessRequest','Find-SafeguardAccessRequest','New-SafeguardAccessRequest','Edit-SafeguardAccessRequest',
    'Get-SafeguardActionableRequest','Get-SafeguardRequestableAccount','Find-SafeguardRequestableAccount',
    'Get-SafeguardMyRequest','Get-SafeguardMyApproval','Get-SafeguardMyReview',
    'Get-SafeguardAccessRequestPassword','Get-SafeguardAccessRequestSshKey','Get-SafeguardAccessRequestApiKey',
    'Get-SafeguardAccessRequestSshHostKey',
    'Get-SafeguardAccessRequestRdpFile','Get-SafeguardAccessRequestSshUrl','Get-SafeguardAccessRequestRdpUrl',
    'Start-SafeguardAccessRequestSession','Start-SafeguardAccessRequestWebSession','Copy-SafeguardAccessRequestPassword',
    'Close-SafeguardAccessRequest','Approve-SafeguardAccessRequest','Deny-SafeguardAccessRequest',
    'Get-SafeguardAccessRequestActionLog','Assert-SafeguardAccessRequest',
    # users.psm1
    'Get-SafeguardIdentityProvider','Get-SafeguardAuthenticationProvider',
    'Set-SafeguardAuthenticationProviderAsDefault','Clear-SafeguardAuthenticationProviderAsDefault',
    'Get-SafeguardUser','Find-SafeguardUser','New-SafeguardUser','Remove-SafeguardUser','Set-SafeguardUserPassword',
    'Edit-SafeguardUser','Enable-SafeguardUser','Disable-SafeguardUser','Rename-SafeguardUser',
    'Get-SafeguardUserPreference','Set-SafeguardUserPreference', 'Remove-SafeguardUserPreference',
    'New-SafeguardUserImportTemplate','Import-SafeguardUser',
    # assets.psm1
    'Get-SafeguardAsset','Find-SafeguardAsset','New-SafeguardAsset','Test-SafeguardAsset',
    'Remove-SafeguardAsset','Edit-SafeguardAsset', 'Sync-SafeguardDirectoryAsset',
    'Get-SafeguardAssetAccount','Find-SafeguardAssetAccount','New-SafeguardAssetAccount','Edit-SafeguardAssetAccount',
    'Set-SafeguardAssetAccountPassword','Set-SafeguardAssetAccountSshKey','New-SafeguardAssetAccountRandomPassword',
    'Test-SafeguardAssetAccountPassword','Invoke-SafeguardAssetAccountPasswordChange',
    'Test-SafeguardAssetAccountSshKey','Invoke-SafeguardAssetAccountSshKeyChange',
    'Remove-SafeguardAssetAccount','Invoke-SafeguardAssetSshHostKeyDiscovery',
    'New-SafeguardAssetImportTemplate','Import-SafeguardAsset',
    'New-SafeguardAssetAccountImportTemplate','Import-SafeguardAssetAccount',
    'New-SafeguardAssetAccountPasswordImportTemplate','Import-SafeguardAssetAccountPassword',
    'New-SafeguardAssetAccountSshKeyImportTemplate','Import-SafeguardAssetAccountSshKey',
    # assetpartitions.psm1
    'Get-SafeguardAssetPartition','New-SafeguardAssetPartition','Remove-SafeguardAssetPartition','Edit-SafeguardAssetPartition',
    'Get-SafeguardAssetPartitionOwner','Add-SafeguardAssetPartitionOwner','Remove-SafeguardAssetPartitionOwner',
    'Get-SafeguardCurrentAssetPartition','Enter-SafeguardAssetPartition','Exit-SafeguardAssetPartition',
    # schedules.psm1 -- used for creating/updating profile components
    'New-SafeguardSchedule','New-SafeguardScheduleMonthlyByDayOfWeek','New-SafeguardScheduleMonthlyByDay',
    'New-SafeguardScheduleWeekly','New-SafeguardScheduleDaily',
    # profiles.psm1
    'Get-SafeguardAccountPasswordRule','New-SafeguardAccountPasswordRule','Remove-SafeguardAccountPasswordRule',
    'Rename-SafeguardAccountPasswordRule','Copy-SafeguardAccountPasswordRule','Edit-SafeguardAccountPasswordRule',
    'Get-SafeguardPasswordCheckSchedule','New-SafeguardPasswordCheckSchedule','Remove-SafeguardPasswordCheckSchedule',
    'Rename-SafeguardPasswordCheckSchedule','Copy-SafeguardPasswordCheckSchedule','Edit-SafeguardPasswordCheckSchedule',
    'Get-SafeguardPasswordChangeSchedule','New-SafeguardPasswordChangeSchedule','Remove-SafeguardPasswordChangeSchedule',
    'Rename-SafeguardPasswordChangeSchedule','Copy-SafeguardPasswordChangeSchedule','Edit-SafeguardPasswordChangeSchedule',
    'Get-SafeguardPasswordProfile','New-SafeguardPasswordProfile','Remove-SafeguardPasswordProfile',
    'Rename-SafeguardPasswordProfile','Copy-SafeguardPasswordProfile','Edit-SafeguardPasswordProfile',
    # directories.psm1
    'Get-SafeguardDirectoryIdentityProvider','New-SafeguardDirectoryIdentityProvider',
    'Remove-SafeguardDirectoryIdentityProvider','Edit-SafeguardDirectoryIdentityProvider',
    'Get-SafeguardDirectoryIdentityProviderDomain','Sync-SafeguardDirectoryIdentityProvider',
    'Get-SafeguardDirectoryIdentityProviderSchemaMapping','Set-SafeguardDirectoryIdentityProviderSchemaMapping',
    'Get-SafeguardDirectory','New-SafeguardDirectory','Test-SafeguardDirectory',
    'Remove-SafeguardDirectory','Edit-SafeguardDirectory','Sync-SafeguardDirectory',
    'Get-SafeguardDirectoryAccount','Find-SafeguardDirectoryAccount','New-SafeguardDirectoryAccount',
    'Set-SafeguardDirectoryAccountPassword','New-SafeguardDirectoryAccountRandomPassword',
    'Test-SafeguardDirectoryAccountPassword','Invoke-SafeguardDirectoryAccountPasswordChange',
    'Edit-SafeguardDirectoryAccount','Remove-SafeguardDirectoryAccount','Get-SafeguardDirectoryMigrationData',
    # groups.psm1
    'Get-SafeguardUserGroup','New-SafeguardUserGroup','Remove-SafeguardUserGroup','Edit-SafeguardUserGroup',
    'Get-SafeguardUserGroupMember','Add-SafeguardUserGroupMember','Remove-SafeguardUserGroupMember',
    'Get-SafeguardAssetGroup','New-SafeguardAssetGroup','Remove-SafeguardAssetGroup','Edit-SafeguardAssetGroup',
    'Get-SafeguardAssetGroupMember','Add-SafeguardAssetGroupMember','Remove-SafeguardAssetGroupMember',
    'Get-SafeguardAccountGroup','New-SafeguardAccountGroup','Remove-SafeguardAccountGroup','Edit-SafeguardAccountGroup',
    'Get-SafeguardAccountGroupMember','Add-SafeguardAccountGroupMember','Remove-SafeguardAccountGroupMember',
    'Sync-SafeguardUserGroupAuthenticationProvider',
    # groups.psm1 (dynamic)
    'Get-SafeguardDynamicAccountGroup','New-SafeguardDynamicAccountGroup','Edit-SafeguardDynamicAccountGroup',
    'Get-SafeguardDynamicAssetGroup','New-SafeguardDynamicAssetGroup','Edit-SafeguardDynamicAssetGroup',
    # policies.psm1
    'Get-SafeguardPolicyAsset','Find-SafeguardPolicyAsset','Get-SafeguardPolicyAccount','Find-SafeguardPolicyAccount',
    'Get-SafeguardAccessPolicy','Get-SafeguardAccessPolicyScopeItem','Get-SafeguardAccessPolicyAccessRequestProperty',
    'Get-SafeguardAccessPolicySessionProperty','Get-SafeguardUserLinkedAccount','Add-SafeguardUserLinkedAccount',
    'Remove-SafeguardUserLinkedAccount',
    # events.psm1
    'Get-SafeguardEvent','Get-SafeguardEventCategory','Get-SafeguardEventName','Get-SafeguardEventProperty','Find-SafeguardEvent',
    'Get-SafeguardEventSubscription', 'Find-SafeguardEventSubscription',
    'New-SafeguardEventSubscription', 'Remove-SafeguardEventSubscription', 'Edit-SafeguardEventSubscription',
    # clustering.psm1
    'Get-SafeguardClusterMember','Get-SafeguardClusterHealth','Get-SafeguardClusterOperationStatus',
    'Add-SafeguardClusterMember','Remove-SafeguardClusterMember','Get-SafeguardClusterPrimary','Set-SafeguardClusterPrimary',
    'Enable-SafeguardClusterPrimary','Unlock-SafeguardCluster','Get-SafeguardClusterSummary',
    'Get-SafeguardClusterPlatformTaskLoadStatus','Get-SafeguardClusterPlatformTaskQueueStatus','Get-SafeguardClusterVpnIpv6Address',
    # a2a.psm1
    'Get-SafeguardA2aServiceStatus','Enable-SafeguardA2aService','Disable-SafeguardA2aService',
    'Get-SafeguardA2a','New-SafeguardA2a','Remove-SafeguardA2a','Edit-SafeguardA2a',
    # a2a.psm1 -- credential retrieval
    'Get-SafeguardA2aCredentialRetrieval','Add-SafeguardA2aCredentialRetrieval','Remove-SafeguardA2aCredentialRetrieval',
    'Get-SafeguardA2aCredentialRetrievalIpRestriction','Set-SafeguardA2aCredentialRetrievalIpRestriction',
    'Clear-SafeguardA2aCredentialRetrievalIpRestriction',
    'Reset-SafeguardA2aCredentialRetrievalApiKey','Get-SafeguardA2aCredentialRetrievalApiKey',
    'Get-SafeguardA2aCredentialRetrievalInformation',
    # a2a.psm1 -- access request broker
    'Get-SafeguardA2aAccessRequestBroker','Set-SafeguardA2aAccessRequestBroker','Clear-SafeguardA2aAccessRequestBroker',
    'Get-SafeguardA2aAccessRequestBrokerIpRestriction','Set-SafeguardA2aAccessRequestBrokerIpRestriction',
    'Clear-SafeguardA2aAccessRequestBrokerIpRestriction',
    'Reset-SafeguardA2aAccessRequestBrokerApiKey','Get-SafeguardA2aAccessRequestBrokerApiKey',
    # a2acallers.psm1
    'Get-SafeguardA2aRetrievableAccount','Get-SafeguardA2aPassword','Get-SafeguardA2aPrivateKey','Get-SafeguardA2aApiKeySecret',
    'New-SafeguardA2aAccessRequest','Set-SafeguardA2aPassword','Set-SafeguardA2aPrivateKey',
    # starling.psm1
    'Get-SafeguardStarlingSubscription','New-SafeguardStarlingSubscription','Remove-SafeguardStarlingSubscription',
    'Get-SafeguardStarlingJoinUrl','Invoke-SafeguardStarlingJoin','Invoke-SafeguardStarlingJoinBrowser',
    'Get-SafeguardStarlingSetting','Set-SafeguardStarlingSetting','Get-SafeguardStarlingJoinInstance',
    # managementShell.psm1
    'Get-SafeguardCommand', 'Get-SafeguardBanner',
    # entitlements.psm1
    'New-SafeguardEntitlement','Get-SafeguardEntitlement','Remove-SafeguardEntitlement',
    # reports.psm1
    'Get-SafeguardReportAccountWithoutPassword','Get-SafeguardReportDailyAccessRequest',
    'Get-SafeguardReportDailyPasswordCheckFail','Get-SafeguardReportDailyPasswordCheckSuccess',
    'Get-SafeguardReportDailyPasswordChangeFail','Get-SafeguardReportDailyPasswordChangeSuccess',
    'Get-SafeguardReportUserEntitlement',
    'Get-SafeguardReportUserGroupMembership','Get-SafeguardReportAssetGroupMembership','Get-SafeguardReportAccountGroupMembership',
    'Get-SafeguardReportAssetManagementConfiguration',
    'Get-SafeguardReportA2aEntitlement','Get-SafeguardReportPasswordLastChanged',
    'Get-SafeguardReportAssetAccountPasswordHistory',
    # setting.psm1
    'Get-SafeguardApplianceSetting','Set-SafeguardApplianceSetting','Get-SafeguardCoreSetting','Set-SafeguardCoreSetting'
    # deleted.psm1
    'Get-SafeguardDeletedAsset','Remove-SafeguardDeletedAsset','Restore-SafeguardDeletedAsset',
    'Get-SafeguardDeletedAssetAccount','Remove-SafeguardDeletedAssetAccount','Restore-SafeguardDeletedAssetAccount',
    'Get-SafeguardDeletedUser','Remove-SafeguardDeletedUser','Restore-SafeguardDeletedUser',
    'Get-SafeguardPurgeSettings','Update-SafeguardPurgeSettings','Reset-SafeguardPurgeSettings',
    # service.psm1
    'Get-SafeguardDebugSettings', 'Set-SafeguardDebugSettings','Enable-SafeguardTlsLogging', 'Disable-SafeguardTlsLogging',
    # syslog.psm1
    'Get-SafeguardSyslogServer','New-SafeguardSyslogServer','Remove-SafeguardSyslogServer','Edit-SafeguardSyslogServer',
    # auditlog.psm1
    'Get-SafeguardAuditLog',
    # tags.psm1
    'Get-SafeguardTag', 'Get-SafeguardTagOccurence', 'Get-SafeguardAssetTag', 'Update-SafeguardAssetTag', 'Get-SafeguardAssetAccountTag',
    'Update-SafeguardAssetAccountTag', 'Find-SafeguardTag', 'New-SafeguardTag', 'Update-SafeguardTag', 'Remove-SafeguardTag',
    'Test-SafeguardAssetTaggingRule', 'Test-SafeguardAssetAccountTaggingRule'
)

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = @()

# Variables to export from this module
VariablesToExport = @('SafeguardSession')

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
AliasesToExport = @(
    # certificates.psm1
    'Get-SafeguardCsr','New-SafeguardCsr','Remove-SafeguardCsr',
    # requests.psm1
    'Get-SafeguardAccessRequestCheckoutPassword',
    'Get-SafeguardMyRequestable','Find-SafeguardMyRequestable',
    'Revoke-SafeguardAccessRequest',
    # clustering.psm1
    'Clear-SafeguardClusterOperation',
    # reports.psm1
    'Get-SafeguardPasswordHistory',
    # sessionapi.psm1
    'Save-SafeguardSpsTransaction','Enable-SafeguardSpsSra','Disable-SafeguardSpsSra'
)

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
FileList = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = @('OneIdentity', 'Safeguard', 'Powershell', 'CLI')

        # A URL to the license for this module.
        LicenseUri = 'https://github.com/OneIdentity/safeguard-ps/blob/master/LICENSE'

        # A URL to the main website for this project.
        ProjectUri = 'https://github.com/OneIdentity/safeguard-ps'

        # A URL to an icon representing this module.
        IconUri = 'https://raw.githubusercontent.com/OneIdentity/safeguard-ps/master/SafeguardLogo.ico'

        # Pre-release tag
        Prerelease = 'pre'

        # ReleaseNotes of this module
        ReleaseNotes = @"
safeguard-ps Release Notes:

- bug fixes
"@

    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}

