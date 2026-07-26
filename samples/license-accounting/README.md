# Safeguard License Accounting

`Get-SppLicenseAccounting.ps1` reads a running Safeguard for Privileged Passwords
(SPP) cluster and reports how many identities fall into each licensed category,
so you can compare real usage against what you are licensed for. It only reads
from the appliance; it never changes anything.

The script is read-only and non-interactive. Point it at an appliance, give it an
account that can read the audit and directory data, and it writes a small set of
CSV files you can open in a spreadsheet.

## What it counts

Every user is placed in exactly one primary category, using the same rules the
Safeguard licensing model uses:

- **Privileged** — a user who holds any administrative role, owns a partition,
  asset, or account, or ran more than the session threshold (10 by default) of
  privileged sessions in any single calendar month within the window.
- **LimitedPrivileged** — a user who can request access (a policy requester,
  approver, or reviewer) or ran some privileged sessions, but stayed at or below
  the monthly session threshold.
- **NHI** (non-human identity) — counted from application-to-application (A2A)
  configuration: one per unique registration-and-retrievable-account pair, plus
  one per configured access-request broker. Disabled registrations are skipped.
- **Workforce** — an add-on flag for users who are entitled to the Personal
  Password Vault (also known as the Enterprise Password Vault), which has since
  been renamed the Workforce Password Vault (WPV). It is an add-on: the flag is
  reported alongside the user's primary category, not instead of it, and it is
  applied independently — so even a user who is otherwise **Uncounted** still
  consumes a Workforce add-on if they hold this entitlement.

Two groups never consume a license and are reported separately:

- **Excluded** — built-in system pseudo-users (negative IDs, session-connection
  users) that appear in audit data but are never a licensed person.
- **Uncounted** — real users with no administrative role, no ownership, no
  request rights, and no sessions in the window.

Users who were deleted but still have sessions in the window are recovered from
the deleted-user store so their sessions are still attributed. When their record
has been purged, they are reported as session-only orphans.

## How sessions are counted

Privileged sessions are counted **per access request, not per connection event**.
A single access request that is initialized many times counts as **one** session.
The count is de-duplicated per user, per calendar month.

## Requirements

- PowerShell 5.1 or PowerShell 7+.
- The [safeguard-ps](https://github.com/OneIdentity/safeguard-ps) module.
- An account that can read audit and directory data: an **Auditor** or
  **ApplicationAuditor**, or the **PolicyAdmin + UserAdmin** pair. The script
  checks this up front and refuses to run without it.

## Running it

With an account and password prompt:

```powershell
$cred = Get-Credential
.\Get-SppLicenseAccounting.ps1 -Appliance safeguard.example.com -Credential $cred
```

On an appliance where the **Resource Owner** OAuth2 grant is disabled (Appliance
Management > Safeguard Access > OAuth2 Grant Types), connect with the
non-interactive PKCE flow instead. It uses the same credential and never opens a
browser:

```powershell
$cred = Get-Credential
.\Get-SppLicenseAccounting.ps1 -Appliance safeguard.example.com -Pkce -Credential $cred
```

Add `-IncludeCurrentMonth` to also count the current, still-in-progress month as
a partial bucket (labeled with a trailing `*`). By default the window covers only
complete calendar months. Use `-Insecure` against an appliance with an untrusted
certificate, and `-OutputDirectory` to choose where the CSVs are written. Run
`Get-Help .\Get-SppLicenseAccounting.ps1 -Full` for every parameter.

## Output

The script writes three timestamped CSV files:

- **totals** — one row of category counts for the whole run.
- **user detail** — one row per user, with the category, the reason it was
  chosen, roles, ownership, entitlement source, and per-month session peak.
- **NHI detail** — one row per counted non-human identity (retrievable account or
  broker).

## Sample output

The `sample-output/` folder shows what a run looks like across every category.
The numbers, categories, and reasons are **real output** from a live appliance;
only the identifying details (appliance name, user names, provider, A2A
registration and account names) have been replaced with generic examples. Your
own results will look the same in shape.

The sample is deliberately small so it is easy to read. A real customer
environment will usually produce many more rows — the user detail and NHI files
grow with the number of users and A2A registrations on the appliance — but the
columns and the way each identity is categorized are exactly the same.

In that sample you can see the session de-duplication at work: user `dadams` ran
many session-initialization events during the month but is reported with a peak
of **12** — the number of distinct access requests, not the raw event count.
