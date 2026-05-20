---
name: architecture
description: >-
  Use when working on module internals, understanding the module manifest,
  SignalR event listeners, dynamic groups, custom platform scripts, or
  tracing how feature modules interact with the root module and global state.
---

# Safeguard-PS Architecture

Use this skill when you need to reason about how the `safeguard-ps` module is wired together internally, not just how to call a public cmdlet.

## When to use

- Adding or moving feature modules
- Tracing how a cmdlet reaches `Invoke-SafeguardMethod`
- Understanding login, token refresh, and session reuse
- Working on SignalR event listeners or SSE streaming
- Modifying dynamic group rule handling
- Updating custom platform script parameter behavior
- Auditing global state usage before making a change

## 1. Module Manifest -- `src/safeguard-ps.psd1`

The manifest is the source of truth for module composition and exports.

- `RootModule = 'safeguard-ps.psm1'`
- `NestedModules` defines every helper and feature module loaded into the module
- `FunctionsToExport` is the public surface -- do not assume every function in a nested module is public
- `PowerShellVersion = '5.1'` means `src/` code must stay PS 5.1 compatible

When adding a new feature module:

1. Create `src/<feature>.psm1`
2. Append it to `NestedModules`
3. Add its public cmdlets to `FunctionsToExport`

Actual `NestedModules` order from the manifest:

```text
sslhandling.psm1
ps-utilities.psm1
sg-utilities.psm1
signalr-utilities.psm1
datatypes.psm1
licensing.psm1
certificates.psm1
networking.psm1
maintenance.psm1
diagnostics.psm1
sessionapi.psm1
sessionjoin.psm1
archives.psm1
requests.psm1
users.psm1
assets.psm1
assetpartitions.psm1
schedules.psm1
profiles.psm1
directories.psm1
groups.psm1
policies.psm1
managementShell.psm1
events.psm1
clustering.psm1
a2a.psm1
a2acallers.psm1
starling.psm1
entitlements.psm1
reports.psm1
settings.psm1
deleted.psm1
service.psm1
syslog.psm1
auditlog.psm1
tags.psm1
customplatforms.psm1
reasoncodes.psm1
runningtasks.psm1
discovery.psm1
```

Practical rule: if a new cmdlet is not exported from the manifest, agents and users will not see it even if the function exists in a `.psm1` file.

## 2. Root Module -- `src/safeguard-ps.psm1`

The root module owns session bootstrap, authentication, URL construction, REST dispatch, and a few core utilities.

### What it initializes

At import time it resets and recreates global session variables:

- `$SafeguardSession`
- `$SafeguardSpsSession`

It also clears both on module removal.

### Key internal helpers

- `Get-SessionConnectionIdentifier` -- builds the window-title/session label
- `Resolve-ProviderToRstsId` -- maps a provider name or domain name to the RSTS provider ID
- `Get-RstsTokenFromBrowser` -- browser login flow using compiled C# PKCE helper
- `Get-RstsCsrfTokenAndSession` -- starts the RSTS interactive session used by 2FA helpers
- `Submit-RstsPrimaryCredential` / `Submit-RstsMultiFactorCredential` / `Submit-RstsMultifactorPost` -- password and MFA login sequence
- `Get-RstsTokenWithPkce` -- non-interactive PKCE login path
- `New-SafeguardUrl` -- central request URL builder
- `Invoke-WithoutBody` / `Invoke-WithBody` / `Invoke-Internal` -- low-level REST execution
- `Wait-LongRunningTask` -- polls task state for APIs that return async task objects

### Connection flow

`Connect-Safeguard` is the main entry point.

1. Normalizes SSL behavior with `Edit-SslVersionSupport`
2. If `-Insecure` is set, temporarily disables certificate verification
3. Fetches configured identity providers from `service/core/v<version>/AuthenticationProviders`
4. Normalizes built-in providers such as `local` and `certificate`
5. Chooses one of these auth paths:
   - Browser/GUI flow via `Get-RstsTokenFromBrowser`
   - Username/password RSTS token grant
   - PKCE flow via `Get-RstsTokenWithPkce`
   - 2FA flow via the RSTS helper chain
   - Client certificate auth via certificate object, PFX file, or Windows cert store thumbprint
6. Exchanges the RSTS token with `POST service/core/v<version>/Token/LoginResponse`
7. Falls back one API version if `LoginResponse` returns 404
8. Either returns the user token (`-NoSessionVariable`) or populates `$SafeguardSession`

### Browser PKCE detail

`Get-RstsTokenFromBrowser` compiles `RstsAccessTokenExtractor` with `Add-Type`.
That helper:

- creates a loopback TCP listener
- generates a PKCE verifier/challenge pair
- launches the browser to `https://<appliance>/RSTS/Login`
- captures the redirect request locally
- extracts the authorization code
- redeems it at `https://<appliance>/RSTS/oauth2/token`

### Session shape

`$SafeguardSession` stores at least:

- `Appliance`
- `Version`
- `IdentityProvider`
- `Username`
- `AccessToken`
- `Thumbprint`
- `CertificateFile`
- `CertificatePassword`
- `CertificateObject`
- `Insecure`
- `Gui`
- `NoWindowTitle`
- `AssetPartitionId`

### Core request flow

`Invoke-SafeguardMethod` is the generic REST wrapper that most public cmdlets delegate to.

- pulls `Appliance`, `Version`, `Insecure`, and `AccessToken` from `$SafeguardSession` when omitted
- can auto-connect if no token/session exists
- builds auth and content headers
- routes to `Invoke-Internal`
- can retry on 404 using `RetryUrl` and `RetryVersion`
- supports `-LongRunningTask`, `-OutFile`, `-InFile`, `-Parameters`, and `-JsonOutput`

Internal guardrails:

- Use `-Body` for PowerShell objects
- Use `-JsonBody` for raw JSON strings
- When serializing objects, use `ConvertTo-Json -Depth 100`

## 3. Feature Modules -- `src/<feature>.psm1`

Feature modules group related cmdlets by domain such as assets, users, groups, policies, events, A2A, and custom platforms.

Common pattern:

```powershell
Import-Module -Name "$PSScriptRoot\sg-utilities.psm1" -Scope Local
```

Common structure and conventions:

- related public cmdlets live together in one feature module
- helper modules are imported locally instead of exported publicly
- modules often import sibling feature modules locally when they need a resolver or helper
- many modules define internal `Resolve-Safeguard*` helpers that accept an ID or name and return the canonical ID
- public cmdlets usually accept `-Appliance`, `-AccessToken`, and `-Insecure`, then fall back to `$SafeguardSession`

Practical rule: before adding a raw REST call, check whether another feature module already has a resolver or cmdlet you can reuse.

## 4. Utility Modules -- not exported

These are loaded by the manifest but are support code, not the public API.

### `sslhandling.psm1`

Purpose: TLS setup and certificate-validation control.

Key functions:

- `Disable-SslVerification` -- on PS 7 uses `SkipCertificateCheck`; on Windows PowerShell installs a `ServicePointManager.ServerCertificateValidationCallback`
- `Enable-SslVerification` -- reverses the above
- `Edit-SslVersionSupport` -- removes SSLv3 and ensures TLS 1.0/1.1/1.2 flags are present

### `ps-utilities.psm1`

Purpose: generic PowerShell and certificate helpers.

Key functions:

- `Get-Confirmation` -- yes/no prompt wrapper
- `Show-SshHostKeyPrompt` -- interactive SSH host key acceptance prompt
- `Test-IpAddress` -- quick IP string check
- `Get-CertificateFileContents` -- reads PEM or converts file bytes to Base64 text
- `Get-Tool` -- recursive tool lookup under supplied paths
- `Use-CertificateFile` -- loads a certificate object from a file for client-auth flows

### `sg-utilities.psm1`

Purpose: shared Safeguard helpers, error shaping, wait loops, resolvers, and formatting.

Key functions:

- `Out-SafeguardExceptionIfPossible` -- unwraps Safeguard/SPS HTTP errors and throws typed exceptions
- `New-LongRunningTaskException` -- wraps failed async task logs in a typed exception
- `Test-SafeguardMinVersionInternal` -- checks appliance version gates
- `Wait-ForSafeguardStatus` / `Wait-ForSafeguardOnlineStatus` -- appliance state polling
- `Wait-ForSessionModuleState` / `Wait-ForClusterOperation` / `Wait-ForPatchDistribution` -- async state waiters
- `Resolve-SafeguardAssetId` / `Resolve-SafeguardAccountIdWithAssetId` / `Resolve-SafeguardAccountIdWithoutAssetId` -- common object resolution helpers
- `Resolve-ReasonCodeId` and `Resolve-DomainNameFromIdentityProvider` -- targeted lookup helpers
- `Format-UtcDateTimeAsString`, `Format-DateTimeAsString`, `Get-EntireAuditLogStartDateAsString`, `Get-VpnIpv6Address` -- formatting and misc helpers

### `signalr-utilities.psm1`

Purpose: shared SignalR over SSE plumbing for event listeners.

Key functions:

- `Get-SignalRConnectionToken`
- `Send-SignalRHandshake`
- `Open-SignalRSseStream`
- `Read-SignalRSseDataBlock`
- `Read-SignalRHandshakeResponse`
- `Read-SignalREvents`
- `Test-SignalRFatalError`

### `grouptag-utilities.psm1`

Purpose: dynamic group rule serialization and parsing.

Key functions:

- `Resolve-ObjectAttributeForAccount`
- `Resolve-ObjectAttributeForAsset`
- `Resolve-LogicalJoinType`
- `Convert-PredicateObjectToString`
- `Convert-ConditionToString`
- `Convert-ConditionGroupToString`
- `Convert-RuleToString`
- `Convert-StringToPredicateObject`
- `Convert-StringToCondition`
- `Convert-StringToConditionGroup`
- `Convert-StringToRule`

It is a hand-rolled parser/serializer, not a generic expression engine.

## 5. Global State

Global session state is deeply wired through the module.

- `$SafeguardSession` holds Safeguard connection state
- `$SafeguardSpsSession` holds SPS/session-module connection state
- many cmdlets silently fall back to these globals for appliance, token, version, and trust settings
- `Invoke-SafeguardMethod` depends on them for implicit appliance/token reuse
- `Update-SafeguardAccessToken` replays the original login path from stored session metadata

Do not refactor global state in a small edit. It is cross-cutting and tightly coupled to nearly every module.

## 6. SignalR Event Listeners

There are two main SSE modes:

- User mode -- `/service/event/signalr/` with Bearer token
- A2A mode -- `/service/a2a/signalr/` with client cert plus `A2A <ApiKey>` auth header

### Actual connection flow

1. `Get-SignalRConnectionToken` sends `POST https://<appliance>/service/<servicePath>/signalr/negotiate?negotiateVersion=1`
2. It adds either Bearer or A2A auth headers
3. It verifies `availableTransports` includes `ServerSentEvents`
4. `Send-SignalRHandshake` posts to `https://<appliance>/service/<servicePath>/signalr?id=<escaped connectionToken>`
5. The handshake payload is `{"protocol":"json","version":1}` plus record separator `0x1E`
6. `Open-SignalRSseStream` opens a long-lived `GET` request with `Accept: text/event-stream`
7. `Read-SignalRHandshakeResponse` consumes the first SSE data block and fails if the handshake response contains an error
8. `Read-SignalREvents` loops over SSE blocks, splits frames on `0x1E`, parses JSON, ignores pings (`type = 6`), stops on close (`type = 7`), and dispatches `NotifyEventAsync` payloads

### Runtime differences

- PS 7+ uses `HttpClient` and `HttpClientHandler`
- On PS 7+, `-Insecure` uses `DangerousAcceptAnyServerCertificateValidator`
- On PS 5.1, SSE uses `HttpWebRequest`
- On PS 5.1, SSL bypass relies on the `ServicePointManager` callback configured by `Disable-SslVerification`
- Client certificates are attached per request when needed
- `Test-SignalRFatalError` treats 4xx responses as fatal and non-retryable

Practical rule: if you change SignalR listener code, think in terms of negotiate -> handshake -> open stream -> validate handshake response -> dispatch frames.

## 7. Dynamic Group Gotchas

Known behavior:

1. GET may omit null properties such as `Description` -- use `Add-Member -Force` before PUT if you must preserve/set them
2. `Convert-RuleToString` requires a non-null rule -- always pass `-GroupingRule` when creating dynamic groups
3. Rule syntax requires parenthesized condition groups -- use `([Name contains 'x'])`, not `[Name contains 'x']`
4. Attribute names differ between account and asset groups

Actual `ValidateSet` values from `grouptag-utilities.psm1`:

### Account group attributes

- `AllowPasswordRequests`
- `AllowSessionRequests`
- `AllowSSHKeyRequests`
- `AssetName`
- `AssetTag`
- `Description`
- `DirectoryContainer`
- `Disabled`
- `DiscoveredGroupDistinguishedName`
- `DiscoveredGroupName`
- `DiscoveryJobName`
- `DistinguishedName`
- `DomainName`
- `EffectiveProfileName`
- `ProfileName`
- `Name`
- `NetBiosName`
- `PartitionName`
- `Platform`
- `PlatformName`
- `PlatformVersion`
- `IsServiceAccount`
- `ObjectSid`
- `Tag`

### Asset group attributes

- `AllowSessionRequests`
- `Description`
- `DirectoryContainer`
- `Disabled`
- `DiscoveredGroupDistinguishedName`
- `DiscoveredGroupName`
- `DiscoveryJobName`
- `EffectiveProfileName`
- `ProfileName`
- `Name`
- `NetworkAddress`
- `PartitionName`
- `Platform`
- `PlatformName`
- `PlatformVersion`
- `Tag`

Other rule enums used by the parser:

- Logical join: `And`, `Or`
- Predicate types: `IsTrue`, `IsFalse`, `Contains`, `DoesNotContain`, `StartsWith`, `EndsWith`, `EqualTo`, `NotEqualTo`, `RegexCompare`

## 8. Custom Script Parameters on Assets

The custom-platform script parameter model is split across platform definition and asset instance.

- Platform schema lives under `Platform.CustomScriptProperties.Parameters`
- Platform parameter definitions expose metadata such as `Name`, `Type`, `TaskName`, and `DefaultValue`
- Asset values live under `Asset.CustomScriptParameters`
- Asset parameter instances store mutable `Value`
- Parameters are per operation, keyed by `TaskName`

Relevant cmdlets:

- `Get-SafeguardCustomPlatformScriptParameter`
- `New-SafeguardCustomPlatformAsset`
- `Set-SafeguardCustomPlatformAssetParameter`

### Actual behavior from the source

- `Get-SafeguardCustomPlatformScriptParameter` can read definitions from an existing platform or validate a raw script file through `POST Platforms/ValidateScript/Raw`
- `New-SafeguardCustomPlatformAsset` creates the asset first, then uses a GET-then-PUT pass to apply custom parameter overrides
- interactive asset creation prompts once per unique parameter name and uses the platform `DefaultValue` in the prompt text
- `Set-SafeguardCustomPlatformAssetParameter` resolves the asset, GETs the full asset object, edits matching `CustomScriptParameters[n].Value`, optionally filters by `TaskName`, then PUTs the whole asset back

Practical rule: when changing custom parameter behavior, think in terms of POST asset -> GET full asset -> mutate `CustomScriptParameters` -> PUT full asset.

## Cross-cutting internals to remember

- Prefer existing public cmdlets and resolve helpers over new raw REST calls
- Keep `src/` compatible with Windows PowerShell 5.1
- Keep file content ASCII only in `src/`
- Use `ConvertTo-Json -Depth 100` for nested Safeguard objects
- Do not pass raw JSON strings to `-Body` -- use `-JsonBody`
- Small edits should preserve the current global-state model instead of trying to modernize it
