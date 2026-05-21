---
name: a2a-workflow
description: Use when working on safeguard-ps A2A registrations, certificate authentication, credential retrieval, brokering, or A2A event listeners.
---

# A2A Workflow

Use this skill when you need to configure Safeguard A2A from PowerShell, retrieve credentials with mutual TLS, broker access requests, or keep long-running handlers in sync with A2A events.

## 1. What A2A is

A2A in `safeguard-ps` is the certificate-authenticated application-to-application path for retrieving or updating managed credentials without using a bearer token session. The management-side cmdlets in `src\a2a.psm1` create and maintain A2A registrations under `Core/A2ARegistrations`, while the caller-side cmdlets in `src\a2acallers.psm1` use a client certificate plus an `A2A <ApiKey>` authorization header against the `/service/a2a/v4/...` endpoints. The module supports direct credential retrieval, bidirectional updates, access-request brokering, and real-time SignalR listeners.

## 2. Setup flow

### Start with the appliance service

Before any caller workflow works, the appliance-side A2A service must be enabled.

Useful cmdlets here are `Get-SafeguardA2aServiceStatus`, `Enable-SafeguardA2aService`, and `Disable-SafeguardA2aService`.

Typical check:

```powershell
Get-SafeguardA2aServiceStatus -Appliance <address> -Insecure
Enable-SafeguardA2aService -Appliance <address> -AccessToken $token -Insecure
```

### Register the certificate user

The A2A registration points at a certificate-authenticated Safeguard user.

Relevant evidence in the repo:

- `samples\certificate-user-demo.ps1` shows certificate-user creation with a thumbprint
- A2A tests create a certificate user by posting `PrimaryAuthenticationProvider = @{ Id = -2; Identity = <thumbprint> }`
- test certs live under `test\TestData\CERTS\`

A representative flow is:

1. install the trusted root/intermediate certificates with `Install-SafeguardTrustedCertificate`
2. create or identify a certificate-authenticated user
3. capture the certificate thumbprint that will authenticate future A2A calls

The tests use this sequence with `RootCA.pem`, `IntermediateCA.pem`, and `UserCert.pfx`.

### Create the A2A registration

Use the management cmdlets in `a2a.psm1`:

```powershell
New-SafeguardA2a "Ticket System" TicketSystemUser -Description "Ticket System Requester" -VisibleToCertificateUsers
Get-SafeguardA2a "Ticket System"
Edit-SafeguardA2a "Ticket System" -Description "Updated description"
```

Key management cmdlets are `New-SafeguardA2a`, `Get-SafeguardA2a`, `Edit-SafeguardA2a`, and `Remove-SafeguardA2a`.

### Add credential retrieval and capture the API key

After the registration exists, add retrievable accounts and fetch the generated API key:

```powershell
Add-SafeguardA2aCredentialRetrieval "Ticket System" <asset> <account>
Get-SafeguardA2aCredentialRetrieval "Ticket System" <asset> <account>
Get-SafeguardA2aCredentialRetrievalApiKey "Ticket System" <asset> <account>
```

Other useful management helpers are `Reset-SafeguardA2aCredentialRetrievalApiKey`, `Get-SafeguardA2aCredentialRetrievalInformation`, `Set-SafeguardA2aCredentialRetrievalIpRestriction`, and `Clear-SafeguardA2aCredentialRetrievalIpRestriction`.

### When bidirectional updates matter

The caller cmdlets `Set-SafeguardA2aPassword` and `Set-SafeguardA2aPrivateKey` write new secrets back through A2A. The integration tests explicitly create registrations with `BidirectionalEnabled = $true` by calling `Invoke-SafeguardMethod` directly, because `New-SafeguardA2a` does not currently expose that flag. If your workflow needs caller-side secret updates, verify the registration is configured for bidirectional use.

## 3. Credential retrieval

### Authentication parameter sets

Every caller cmdlet uses one of three mutual-TLS modes:

- `-CertificateFile [-Password]`
- `-Thumbprint`
- `-CertificateObject`

`-CertificateObject` is worth preferring for integrations that load certificates from another secret store, because the help text explicitly calls out in-memory `X509Certificate2` use without persisting a PFX to disk.

If you use `-CertificateFile` without `-Password`, the file-based cmdlets prompt with `Read-Host -AsSecureString`.

### Discovery cmdlet

`Get-SafeguardA2aRetrievableAccount` enumerates the accounts a certificate user can retrieve. It returns an object that includes:

- `AppName`
- `Description`
- `Disabled`
- `CertificateUser`
- `CertificateUserThumbprint`
- `ApiKey`
- `AssetName`
- `AccountName`
- `DomainName`

That makes it the quickest way to discover which API key maps to which account.

### Direct retrieval and update cmdlets

Password flow uses `Get-SafeguardA2aPassword` and `Set-SafeguardA2aPassword`. SSH key flow uses `Get-SafeguardA2aPrivateKey` and `Set-SafeguardA2aPrivateKey`, with `-KeyFormat OpenSsh|Ssh2|Putty` when needed. API key secret retrieval uses `Get-SafeguardA2aApiKeySecret`.

Representative examples from the help:

```powershell
Get-SafeguardA2aPassword <appliance> <apiKey> -Thumbprint <thumbprint> -Insecure
Get-SafeguardA2aPassword <appliance> $apiKey -CertificateObject $cert
Get-SafeguardA2aPrivateKey <appliance> $apiKey -CertificateObject $cert -KeyFormat Putty
Set-SafeguardA2aPassword <appliance> $apiKey -CertificateObject $cert -NewPassword $securePassword
Set-SafeguardA2aPrivateKey <appliance> $apiKey -CertificateObject $cert -PrivateKey $key
```

### Management-side query helpers

Use the `a2a.psm1` cmdlets when you are configuring or auditing registrations rather than calling them:

- `Get-SafeguardA2aCredentialRetrieval`
- `Add-SafeguardA2aCredentialRetrieval`
- `Remove-SafeguardA2aCredentialRetrieval`
- `Get-SafeguardA2aCredentialRetrievalApiKey`
- `Reset-SafeguardA2aCredentialRetrievalApiKey`

`Get-SafeguardA2aCredentialRetrieval` supports:

- lookup by A2A name or ID
- lookup by asset/account names or IDs
- `-QueryFilter`
- `-Fields`
- `-OrderBy`

The test suite covers both valid and invalid filter cases, so malformed filters should be treated as user input errors, not as a signal to silently retry with a different shape.

## 4. Brokering

A2A brokering is supported.

Management-side broker cmdlets in `a2a.psm1` are `Get-SafeguardA2aAccessRequestBroker`, `Set-SafeguardA2aAccessRequestBroker`, `Clear-SafeguardA2aAccessRequestBroker`, `Get/Set/Clear-SafeguardA2aAccessRequestBrokerIpRestriction`, and `Get/Reset-SafeguardA2aAccessRequestBrokerApiKey`.

`Set-SafeguardA2aAccessRequestBroker` requires at least one of:

- `-Users`
- `-Groups`

It also validates every `-IpRestrictions` value with `Test-IpAddress` before sending the PUT.

Caller-side request creation lives in `New-SafeguardA2aAccessRequest`.

Important parameters supported by that cmdlet:

- `-ApiKey`
- `-ForUserName` or `-ForUserId`
- `-AssetToUse`/`-AccountToUse` or `-AssetIdToUse`/`-AccountIdToUse`
- `-ForProviderName`
- `-Emergency`
- `-ReasonCode`
- `-ReasonComment`
- `-TicketNumber`
- `-RequestedFor`
- `-RequestedDurationDays|Hours|Minutes`

Accepted access request types include these aliases:

- `Password`
- `SSHKey` or `SSH`
- `RemoteDesktop` or `RDP`
- `RemoteDesktopApplication`, `RDPApplication`, or `RDPApp`
- `Telnet`
- `APIKey`
- `File`

The help text notes that brokering creates the access request on behalf of another user and the target user will then be notified via SignalR.

## 5. Event listeners / SignalR

### Core listener

`Wait-SafeguardA2aEvent` is the low-level real-time listener. It:

1. negotiates against `/service/a2a/signalr/`
2. opens an SSE stream
3. sends the SignalR handshake
4. validates the handshake response
5. reads and filters events until interrupted
6. reconnects with exponential backoff for non-fatal failures

You can use it in three modes:

- pipeline output only
- `-Handler { ... }`
- `-HandlerScript <path>`

If no handler is provided, it emits `PSCustomObject` items with `EventName` and `EventBody`.

Example:

```powershell
Wait-SafeguardA2aEvent <appliance> $apiKey -Thumbprint <thumbprint> -Insecure -Event AssetAccountPasswordUpdated
```

### Higher-level handlers

`Invoke-SafeguardA2aPasswordHandler`:

- fetches the current password first
- calls the handler with event name `InitialPassword`
- subscribes only to `AssetAccountPasswordUpdated`
- re-fetches the password after each matching event

`Invoke-SafeguardA2aSshKeyHandler`:

- fetches the current key first
- calls the handler with event name `InitialSshKey`
- subscribes only to `AssetAccountSshKeyUpdated`
- re-fetches the private key after each matching event
- respects `-KeyFormat OpenSsh|Ssh2|Putty`

These handler cmdlets require exactly one of `-Handler` or `-HandlerScript`.

## 6. Error scenarios and troubleshooting

### Certificate and trust problems

`Invoke-SafeguardA2aMethodWithCertificate` contains an explicit Windows warning: even when you provide a PFX file, the issuing CA may still need to be installed in the **Intermediate Certificate Authorities** store or Windows may fail to send the client certificate during the HTTPS handshake.

Also watch for:

- `Certificate with thumbprint '<value>' not found in CurrentUser\My store`
- wrong PFX password when using `-CertificateFile`
- a certificate chain that was never installed with `Install-SafeguardTrustedCertificate`

### Service and registration problems

Common checks:

- verify `Get-SafeguardA2aServiceStatus`
- confirm the registration exists with `Get-SafeguardA2a`
- confirm the account is configured with `Get-SafeguardA2aCredentialRetrieval`
- fetch the current key with `Get-SafeguardA2aCredentialRetrievalApiKey`
- ensure bidirectional registration settings if using `Set-SafeguardA2aPassword` or `Set-SafeguardA2aPrivateKey`

### Handler and listener problems

The listener code throws on these usage errors:

- `You must specify -Handler or -HandlerScript`
- `You may specify -Handler or -HandlerScript but not both`
- `Handler script not found: <path>`

For `Wait-SafeguardA2aEvent`, fatal 4xx-class errors are treated as non-retryable; other connection failures log a warning and reconnect with backoff.

### Input validation issues

- IP restrictions are validated locally; non-IP strings throw before the REST call.
- `Get-SafeguardA2aCredentialRetrieval` surfaces bad `-QueryFilter` input as an error.
- `Set-SafeguardA2aAccessRequestBroker` throws if neither `-Users` nor `-Groups` is supplied.

### Practical debugging checklist

1. Check the appliance service status.
2. Confirm the certificate user and thumbprint mapping.
3. Confirm the A2A registration and account linkage.
4. Re-read or regenerate the relevant API key.
5. Retry the caller cmdlet with `-Verbose`.
6. For event issues, start with `Wait-SafeguardA2aEvent` before layering on the password or SSH-key handlers.
