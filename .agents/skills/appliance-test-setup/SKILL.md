---
name: appliance-test-setup
description: >-
  Use when setting up test objects on a Safeguard appliance for integration
  testing. Covers the creation sequence for users, assets, accounts,
  certificates, A2A registrations, and cleanup.
---

# Appliance Test Setup

Use this skill when you need to create test objects on a live Safeguard
appliance for integration testing, then clean them up afterward.

## Prerequisites

- A connected safeguard-ps session (`Connect-Safeguard`)
- An admin user with AssetAdmin, PolicyAdmin, and ApplianceAdmin roles
- The bootstrap admin (local\Admin) cannot have its roles modified and may
  lack AssetAdmin/PolicyAdmin — create a dedicated test admin first

## Object creation sequence

Objects have dependencies — create them in this order:

1. **Test admin user** (with all admin roles)
2. **Asset** (requires PlatformId and AssetPartitionId)
3. **Account** on the asset
4. **Client certificate** (for A2A)
5. **Install certificate** as TrustedCertificate on appliance
6. **Certificate user** (provider -2, linked by thumbprint)
7. **A2A registration** (linked to certificate user)
8. **Credential retrieval** on the A2A registration

## Step-by-step

### 1. Create test admin

```powershell
$pw = ConvertTo-SecureString "TestAdmin123!" -AsPlainText -Force
New-SafeguardUser -Provider -1 -NewUserName "TestAdmin" -AdminRoles `
    GlobalAdmin,ApplianceAdmin,AssetAdmin,PolicyAdmin,UserAdmin,HelpdeskAdmin,OperationsAdmin,SystemAuditor
Set-SafeguardUserPassword -UserToEdit "TestAdmin" -NewPassword $pw
```

### 2. Create asset

```powershell
# Use Get-SafeguardPlatform to find valid PlatformId values
$asset = New-SafeguardAsset -Name "TestAsset" -NetworkAddress "10.0.0.99" `
    -Platform 56 -AssetPartitionId -1
```

Key notes:
- `PlatformId` is an integer (use `Get-SafeguardPlatform` to list)
- `AssetPartitionId` -1 means the Default Partition
- Use `-Description` for test identification

### 3. Create account on asset

```powershell
$acctPw = ConvertTo-SecureString "AccountP@ss1" -AsPlainText -Force
$account = New-SafeguardAssetAccount -ParentAsset $asset.Id -NewAccountName "testacct"
Set-SafeguardAssetAccountPassword -AccountToSet $account.Id -NewPassword $acctPw
```

### 4. Generate client certificate

```powershell
# Using OpenSSL (or any cert tool)
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem `
    -days 7 -nodes -subj "/CN=TestA2A"
openssl pkcs12 -export -in cert.pem -inkey key.pem -out cert.pfx -passout pass:test123
```

### 5. Install trusted certificate

```powershell
Install-SafeguardTrustedCertificate -CertificateFile cert.pem
```

### 6. Create certificate user

```powershell
$thumbprint = (Get-PfxCertificate cert.pfx).Thumbprint
New-SafeguardUser -Provider -2 -NewUserName "TestCertUser" -Thumbprint $thumbprint
```

### 7. Create A2A registration

```powershell
$a2a = New-SafeguardA2a -CertificateUser "TestCertUser" -Name "TestA2A"
```

### 8. Add credential retrieval

```powershell
$retrieval = Add-SafeguardA2aCredentialRetrieval -ParentA2a $a2a.Id -Account $account.Id
$apiKey = $retrieval.ApiKey
```

### 9. Enable A2A service (if not already)

```powershell
Enable-SafeguardA2aService
# Verify:
Get-SafeguardA2aServiceStatus
```

## Cleanup sequence (reverse order)

Always clean up in reverse dependency order:

```powershell
# 1. Remove A2A registration
Remove-SafeguardA2a -A2aToDelete $a2a.Id

# 2. Remove certificate user
Invoke-SafeguardMethod Core DELETE "Users/$certUserId"

# 3. Remove trusted certificate
Uninstall-SafeguardTrustedCertificate -Thumbprint $thumbprint

# 4. Remove account (deletes with asset, or explicitly)
Invoke-SafeguardMethod Core DELETE "AssetAccounts/$($account.Id)"

# 5. Remove asset
Invoke-SafeguardMethod Core DELETE "Assets/$($asset.Id)"

# 6. Remove test admin (must be logged in as a different admin)
Invoke-SafeguardMethod Core DELETE "Users/$testAdminId"
```

## Common gotchas

- The bootstrap admin (Id: -2) returns 403 when you try to modify its roles
- `New-SafeguardAsset` requires integer `PlatformId`, not a platform name or object
- Certificate identity provider Id is always `-2`
- Local identity provider Id is always `-1`
- Default Asset Partition Id is `-1`
- A2A service must be enabled before credential retrieval works
- `Remove-SafeguardA2a` uses `-A2aToDelete` (not `-ParentA2a` or `-Id`)
