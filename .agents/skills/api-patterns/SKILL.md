---
name: api-patterns
description: >-
  Use when making Safeguard API calls, working with Invoke-SafeguardMethod,
  using filters or query parameters, exploring the API via Swagger, or
  troubleshooting API errors. Covers REST conventions, cmdlet preference,
  query/filter syntax, and common pitfalls.
---

# Safeguard API patterns

Use this skill when working directly with the Safeguard Web API, debugging cmdlets that wrap the API, or adding new cmdlet coverage for API endpoints.

## 0. Cmdlet discovery

Before writing any safeguard-ps code, use the built-in discovery tools:

- **`Get-SafeguardCommand`** — searches available cmdlets by up to 3 keywords.
  Returns matching cmdlet names so you don't have to guess.
  ```powershell
  Get-SafeguardCommand User           # all cmdlets with "User" in the name
  Get-SafeguardCommand A2A Password   # A2A-related password cmdlets
  Get-SafeguardCommand Trusted Cert   # trusted certificate management
  ```

- **`Get-Help <Cmdlet> -Full`** — shows complete parameter names, types, and
  examples for any cmdlet. Always check this before guessing parameter names.
  ```powershell
  Get-Help New-SafeguardA2a -Full
  Get-Help Add-SafeguardA2aCredentialRetrieval -Full
  ```

Common naming pitfalls (discovered through testing):

| What you might guess | Actual cmdlet/parameter |
|---|---|
| `New-SafeguardA2aRegistration` | `New-SafeguardA2a` |
| `-AccountToAdd` | `-Account` |
| `-ParentA2a` (on Remove) | `-A2aToDelete` |
| `Remove-SafeguardTrustedCertificate` | `Uninstall-SafeguardTrustedCertificate` |
| `Install-SafeguardCertificate` | `Install-SafeguardTrustedCertificate` |

**Rule: always run `Get-SafeguardCommand` first, then `Get-Help` to confirm
parameter names before calling any cmdlet.**

## Quick rules

- Prefer existing `Get-Safeguard*`, `Find-Safeguard*`, `New-Safeguard*`, `Edit-Safeguard*`, `Remove-Safeguard*`, and `Close-Safeguard*` cmdlets over raw `Invoke-SafeguardMethod`.
- Use `Get-SafeguardCommand <keyword>` before adding a new raw API call.
- Default API version is `v4`.
- Use `-Body` for PowerShell objects and `-JsonBody` for raw JSON strings.
- Always use `ConvertTo-Json -Depth 100`.
- Pass query options through `-Parameters`.
- Use short filter operators such as `sw`, `ew`, and `contains`.

## 1. Exploring the Safeguard API

A live appliance is required to browse Swagger UI.

Swagger UI per service:

- `https://<appliance>/service/core/swagger` -- Core (assets, users, platforms, policies)
- `https://<appliance>/service/appliance/swagger` -- Appliance (networking, diagnostics, backups)
- `https://<appliance>/service/notification/swagger` -- Notification (events, subscriptions)
- `https://<appliance>/service/event/swagger` -- Event (signalr streaming)

For ad-hoc exploration, connect with PKCE because Resource Owner Grant is disabled by default:

```powershell
$secPwd = ConvertTo-SecureString "<password>" -AsPlainText -Force
Connect-Safeguard -Appliance <address> -IdentityProvider Local -Username Admin `
    -Password $secPwd -Insecure -Pkce
```

Use `-Insecure` only for development or lab appliances, not production guidance.

## 2. API versioning

- Default API version is **v4** since module version 7.0.
- `Invoke-SafeguardMethod` is the generic REST caller that most cmdlets delegate to.
- Public cmdlets usually accept `-Appliance`, `-AccessToken`, and `-Insecure`, then fall back to `$SafeguardSession` if you are already connected.

Use raw `Invoke-SafeguardMethod` when:

- no higher-level cmdlet exists yet
- you are validating API behavior before adding or fixing a cmdlet
- you need a one-off troubleshooting call against a specific endpoint

## 3. Prefer cmdlets over Invoke-SafeguardMethod

Prefer the higher-level cmdlets whenever possible:

- `Get-Safeguard*`
- `Find-Safeguard*`
- `New-Safeguard*`
- `Edit-Safeguard*`
- `Remove-Safeguard*`
- `Close-Safeguard*`

This applies to scripts, interactive usage, and test suites.

Why this matters:

- cmdlets already handle common parameter patterns and session state
- cmdlets usually hide endpoint-specific quirks
- tests should exercise supported public behavior, not reimplement the REST contract

To discover existing coverage:

```powershell
Get-SafeguardCommand Platform
Get-SafeguardCommand AccessRequest
```

## 4. Get- vs Find- cmdlets

- **`Get-`** -- retrieve by ID, or retrieve data scoped to the current user/session.
- **`Find-`** -- system-wide text search using the API `q` parameter. Use this for broader cross-user or cross-object lookups.

General rule:

- If you already know the object ID, use `Get-`.
- If you are searching by name or free text across the system, use `Find-`.

## 5. `-Body` vs `-JsonBody` -- critical trap

- **`-Body`** -- accepts a PowerShell object and auto-serializes it to JSON. Use this for most API calls.
- **`-JsonBody`** -- accepts a JSON string and sends it as-is. Use this for raw JSON content uploads.

Trap: passing a JSON string to `-Body` double-serializes it, so the API receives quoted JSON instead of an object.

```powershell
# WRONG -- double-serializes:
Invoke-SafeguardMethod Core PUT "..." -Body $jsonString

# RIGHT -- sends raw JSON:
Invoke-SafeguardMethod Core PUT "..." -JsonBody $jsonString
```

If you built the payload as a PowerShell object, use `-Body`.
If you already built the payload as a JSON string, use `-JsonBody`.

## 6. ConvertTo-Json depth

Always use `ConvertTo-Json -Depth 100`.

Why:

- PowerShell defaults to depth 2
- nested Safeguard objects are common
- default depth silently truncates deeper structures into type-name strings

```powershell
$payload | ConvertTo-Json -Depth 100
```

## 7. Query parameters and filtering

Pass query parameters through `-Parameters` on `Invoke-SafeguardMethod`:

```powershell
Invoke-SafeguardMethod -Insecure Core GET "Platforms" `
    -Parameters @{ filter = "PlatformFamily eq 'Custom'" }
```

Supported parameters:

- `fields`
- `orderby` -- prefix with `-` for descending sort
- `count`
- `page`
- `limit`
- `q` -- text search
- `filter`

Supported filter operators:

- `eq`
- `ieq`
- `ne`
- `gt`
- `ge`
- `lt`
- `le`
- `sw`
- `isw`
- `ew`
- `iew`
- `contains`
- `icontains`
- `in`
- `and`
- `or`
- `not`

Important filtering rules:

- Use short forms only: `sw`, `ew`, `contains`.
- Do not use `startswith` or `endswith` -- the API returns error `70003`.
- Escape quotes, asterisks, and backslashes with `\` when building filter strings.
- Use `q` for broad text search and `filter` for structured predicates.

## 8. Built-in Admin role limitations

The built-in `Admin` user is not a full-role admin for every scenario.

- It has `Authorizer` and `UserAdmin`.
- It lacks `AssetAdmin` and `PolicyAdmin`.
- Those missing roles cannot be added to built-in `Admin` -- the API returns error `50100`.
- The test runner creates `SgPsTest_RunAdmin` with all roles when broad admin coverage is needed.

If an API call fails due to missing admin scope, verify which role the endpoint actually requires before assuming the API is broken.

## 9. POST-then-PUT pattern -- prefer fixing the cmdlet first

Some POST endpoints have historically ignored certain properties during create, leading to a follow-up PUT pattern.

Better approach:

- First, check whether the `New-Safeguard*` cmdlet is missing a parameter that should be included in the POST body.
- Prefer fixing the cmdlet so it sends the property correctly on create.
- Only fall back to POST-then-PUT when the API genuinely requires a second update call.

Legacy workaround:

```powershell
$local:Result = Invoke-SafeguardMethod Core POST "Platforms" -Body $local:Body
$local:Result.SomeProperty = $Value
$local:Result = Invoke-SafeguardMethod Core PUT "Platforms/$($local:Result.Id)" -Body $local:Result
```

Use this pattern as a last resort, not the default design for new cmdlet work.

## 10. Close-SafeguardAccessRequest -- universal cleanup

`Close-SafeguardAccessRequest` transitions an access request to its terminal state regardless of current state.

It will cancel, check in, close, or acknowledge as appropriate.

Use it for:

- bulk cleanup in integration tests
- teardown code in scripts
- clearing existing requests before creating new overlapping requests

## 11. Access request overlap constraint

Error `90001` means a new access request overlaps an existing request for the same asset/account and time window.

Resolution:

- close or cancel the prior request first
- use `Close-SafeguardAccessRequest` for cleanup when you do not want to hand-code state-specific transitions

## 12. Common error codes reference

| Error Code | Meaning | Resolution |
|-----------|---------|------------|
| 50100 | Cannot add role to built-in Admin | Use a custom admin user with all roles |
| 60031 | Platform script ID not unique or contains invalid characters | Use globally unique alphanumeric IDs |
| 70003 | Invalid filter operator such as `startswith` | Use short forms: `sw`, `ew`, `contains` |
| 90001 | Access request time overlap | Close or cancel existing requests first |

## API troubleshooting checklist

When a Safeguard API call behaves unexpectedly:

1. Check whether a higher-level cmdlet already exists.
2. Confirm you are using the right service path and Swagger page.
3. Confirm the session or token has the required role.
4. Verify whether the payload should be sent with `-Body` or `-JsonBody`.
5. Rebuild JSON with `ConvertTo-Json -Depth 100`.
6. Inspect `-Parameters` for bad filter operators or escaping mistakes.
7. For create flows, verify whether the missing property should be added to the `New-Safeguard*` cmdlet instead of patched with a second PUT.

Keep raw API experiments narrow, then promote successful patterns into the corresponding public cmdlet so future callers do not need to rediscover the same endpoint quirks.
