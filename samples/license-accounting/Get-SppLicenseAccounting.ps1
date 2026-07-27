#Requires -Modules safeguard-ps

<#
.SYNOPSIS
    License-usage accounting report for a running Safeguard for Privileged Passwords
    (SPP) cluster, counting the license cohorts defined by the Safeguard licensing model.

.DESCRIPTION
    Counts the four license cohorts defined by the Safeguard licensing model over a
    rolling 12-month span, read LIVE from the cluster's existing SPP APIs via the
    safeguard-ps module.

    Cohorts:
      * Privileged        - has an admin right, OR owns a partition, asset, or account,
                            OR crossed the privileged-session threshold in ANY single
                            calendar month within the window (peak-month rule).
      * LimitedPrivileged - has credential access (assigned to any entitlement) but is
                            not Privileged. Includes no-session and approver/reviewer
                            users. Never crosses the threshold in any month.
      * NHI               - non-human identities: unique (A2A registration + retrievable
                            account) pairs, plus one per configured access-request broker.
                            Point-in-time (current) only.
      * Workforce         - users with the Workforce Password Vault (WPV) permission
                            (AllowPersonalAccounts = true), counted whether used or not.
                            Additive to Privileged / LimitedPrivileged. Current only.

    Classification model (as defined by the Safeguard licensing model):
      - The window is up to 12 full calendar months, ending with the last COMPLETE
        calendar month (or as much history as the audit log retains).
      - Sessions are summed per (user, calendar month); a user's PEAK month decides
        Privileged-vs-Limited. Crossing the threshold in any one month => Privileged
        for the whole span.
      - Admin right and ownership (partition, asset, or account) are current-state and
        always force Privileged.
      - NHI and Workforce are current/point-in-time (no history is available for them).

    EXCLUSIONS (applied before cohorting; excluded identities appear in the detail CSV
    with Cohort = "Excluded" and the reason):
      - Built-in system pseudo-users (negative Id, e.g. SessionConnectionUser_*, the
        bootstrap admin at -2). These are never a licensed human but DO show up in
        session audit rows, so they must be filtered explicitly.
      - Disabled users who had NO sessions in the window. A disabled user WITH
        sessions still consumed a license and is kept and cohorted normally;
        -IncludeDisabledUsers keeps disabled users even when they have no sessions.
      NOTE: A2A certificate users are NOT excluded. A cert user used only for an A2A
      registration has no admin role, ownership, entitlement, or interactive session,
      so it falls naturally into Uncounted; a cert user that IS granted a permission,
      entitlement, or approver/reviewer role (or has sessions) is counted as
      Limited/Privileged like any other user. The A2A registration itself is still
      counted under NHI.

    DATA SOURCES AND SCOPE (also printed in the report banner):
      - Session history is read from the access-request audit log, so it is bounded by
        audit-log retention.
      - Ownership is resolved at all three SPP levels: partition, asset, and account
        (from each object's owners / ManagedBy). Policy and audit ownership are not
        counted.
      - Approver/reviewer/requester membership is resolved from the live Roles +
        AccessPolicies (authoritative), with user groups expanded to members.

.PARAMETER Appliance
    SPP appliance/cluster network address. Omit if you pass -UseExistingConnection.

.PARAMETER Credential
    PSCredential for local/directory auth (an Auditor-role account is sufficient).

.PARAMETER IdentityProvider
    Authentication provider name (default 'local').

.PARAMETER UseExistingConnection
    Reuse the connection already established by a prior Connect-Safeguard in this session.

.PARAMETER Insecure
    Skip TLS validation (lab/test clusters).

.PARAMETER MonthsBack
    Number of full calendar months to include, ending with the last complete month.
    Default 12. Months with no retained audit data simply contribute zero.

.PARAMETER SessionThreshold
    Privileged-session threshold. MORE THAN this many distinct sessions in a single
    calendar month = Privileged. Default 10.

.PARAMETER Pkce
    Connect using the non-interactive PKCE flow instead of the Resource Owner grant.
    Required on appliances where the Resource Owner grant (Appliance Management >
    Safeguard Access > OAuth2 Grant Types) is disabled. Supply the account via
    -Credential; the script passes it to the PKCE flow so no browser opens.

.PARAMETER IncludeCurrentMonth
    Also count the current, still-in-progress calendar month as an extra (partial)
    bucket, labeled with a trailing '*'. Off by default so results cover only complete
    calendar months, matching the licensing model's 12-month window. Useful for mid-month
    runs where the most recent activity would otherwise be excluded.

.PARAMETER IncludeDisabledUsers
    Keep disabled users even when they have NO sessions in the window. By default a
    disabled user is only excluded if they had zero sessions; a disabled user who had
    sessions is always counted. This switch additionally keeps the zero-session ones.

.PARAMETER OutputDirectory
    Where CSVs are written. Default: current directory.

.EXAMPLE
    $c = Get-Credential
    .\Get-SppLicenseAccounting.ps1 -Appliance sg-appliance.example.com -Credential $c -Insecure

.EXAMPLE
    # Appliance with the Resource Owner grant disabled (non-interactive PKCE), plus the
    # current partial month:
    $c = Get-Credential
    .\Get-SppLicenseAccounting.ps1 -Appliance sg-appliance.example.com -Pkce -Credential $c -Insecure -IncludeCurrentMonth

.NOTES
    The caller must hold Auditor or ApplicationAuditor, or the
    PolicyAdmin+UserAdmin pair; the script preflights this and refuses to run otherwise
    (GlobalAdmin/SystemAuditor alone cannot read the AccessRequest audit log). Session
    counting mirrors Safeguard's shipped daily access-request report (Action eq
    'InitializeSession', via Get-SafeguardAuditLogAccessRequestActivity over a
    startDate/endDate window).
#>
[CmdletBinding()]
param(
    [string]$Appliance,
    [pscredential]$Credential,
    [string]$IdentityProvider = "local",
    [switch]$Pkce,
    [switch]$UseExistingConnection,
    [switch]$Insecure,
    [ValidateRange(1, 120)]
    [int]$MonthsBack = 12,
    [ValidateRange(0, [int]::MaxValue)]
    [int]$SessionThreshold = 10,
    [switch]$IncludeCurrentMonth,
    [switch]$IncludeDisabledUsers,
    [string]$OutputDirectory = (Get-Location).Path
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Return the first non-null/non-empty property value from a list of candidate names.
function Get-FirstProp {
    param([object]$Object, [string[]]$Names)
    if ($null -eq $Object) { return $null }
    foreach ($n in $Names) {
        if ($Object.PSObject.Properties.Name -contains $n) {
            $v = $Object.$n
            if ($null -ne $v -and "$v" -ne "") { return $v }
        }
    }
    return $null
}

# Page a GET that returns an array, using page/limit, until a short page is
# returned. Accumulates and returns all rows.
#
# The Safeguard Web API paginates list endpoints with `page` (0-based) + `limit`.
# It SILENTLY IGNORES `take`/`skip` -- passing those returns the full result set
# on every request, so a take/skip loop never sees a short page and spins forever,
# re-appending the whole set each pass (unbounded memory, never terminates). Use
# page/limit only. Past-the-end pages come back as a single empty Object[] wrapper
# rather than an empty body, so those wrappers are filtered out before counting;
# a page that reduces to zero real rows ends the loop.
function Invoke-PagedGet {
    param(
        [string]$Service,
        [string]$Path,
        [hashtable]$Parameters = @{},
        [int]$PageSize = 1000
    )
    $out  = New-Object System.Collections.Generic.List[object]
    $page = 0
    $lastFirstId = $null
    while ($true) {
        $p = @{}
        foreach ($k in $Parameters.Keys) { $p[$k] = $Parameters[$k] }
        $p["page"]  = $page
        $p["limit"] = $PageSize
        # Drop nulls and the empty-array wrapper an out-of-range page returns, so a
        # spent result set collapses to an empty batch and terminates the loop.
        $batch = @(Invoke-SafeguardMethod $Service GET $Path -Parameters $p |
                   Where-Object { $null -ne $_ -and -not ($_ -is [System.Array]) })
        if ($batch.Count -eq 0) { break }

        # Defensive guard against an endpoint that ignores paging entirely: if a
        # later page hands back the same first row as the previous one, the server
        # is returning the whole set each time -- stop rather than loop forever.
        $firstId = "$(Get-FirstProp $batch[0] @('Id'))"
        if ($page -gt 0 -and $firstId -ne '' -and $firstId -eq $lastFirstId) {
            Write-Warning ("Paging not honored for '{0}' (page {1} repeated the first row); stopping at {2} rows." -f $Path, $page, $out.Count)
            break
        }
        $lastFirstId = $firstId

        foreach ($b in $batch) { $out.Add($b) }
        if ($batch.Count -lt $PageSize) { break }
        $page++
    }
    $out.ToArray()
}

function Write-Banner {
    param([string]$Text)
    Write-Host ""
    Write-Host ("=" * 78) -ForegroundColor Cyan
    Write-Host $Text -ForegroundColor Cyan
    Write-Host ("=" * 78) -ForegroundColor Cyan
}

# ---------------------------------------------------------------------------
# 1. Connect
# ---------------------------------------------------------------------------
if (-not $UseExistingConnection) {
    if (-not $Appliance) { throw "Specify -Appliance (or use -UseExistingConnection)." }
    Write-Host "Connecting to $Appliance ..." -ForegroundColor Green
    $connectArgs = @{ Appliance = $Appliance; IdentityProvider = $IdentityProvider; Insecure = [bool]$Insecure }
    if ($Pkce) {
        # Non-interactive PKCE: Connect-Safeguard's -Pkce parameter set takes an
        # explicit -Username/-Password (it does NOT accept -Credential), so split
        # the PSCredential here. With both supplied, the PKCE flow completes
        # without opening a browser.
        $connectArgs.Pkce = $true
        if ($Credential) {
            $connectArgs.Username = $Credential.UserName
            $connectArgs.Password = $Credential.Password
        }
    }
    elseif ($Credential) {
        $connectArgs.Credential = $Credential
    }
    Connect-Safeguard @connectArgs | Out-Null
}

# ---------------------------------------------------------------------------
# 2. Preflight: verify the connected caller can actually read everything this
#    report needs. Reading the AccessRequest audit log (session counts) and the
#    full user/entitlement set requires an auditor role, or the policy+user admin
#    pair. GlobalAdmin/SystemAuditor alone canNOT read AuditLog/AccessRequests
#    (verified live: an admin with GlobalAdmin+SystemAuditor got 0 activity rows;
#    the same pull as an Auditor returned the full set).
# ---------------------------------------------------------------------------
try {
    $me = Get-SafeguardLoggedInUser
} catch {
    throw "Preflight failed: could not read the current user via Get-SafeguardLoggedInUser ($($_.Exception.Message)). Is a connection established?"
}
$myName  = if ($me -and ($me.PSObject.Properties.Name -contains 'Name')) { $me.Name } else { '<unknown>' }
$myRoles = @()
if ($me -and ($me.PSObject.Properties.Name -contains 'AdminRoles') -and $me.AdminRoles) {
    $myRoles = @($me.AdminRoles | Where-Object { $_ })
}
$hasAuditor    = ($myRoles -contains 'Auditor') -or ($myRoles -contains 'ApplicationAuditor')
$hasPolicyUser = ($myRoles -contains 'PolicyAdmin') -and ($myRoles -contains 'UserAdmin')
if (-not ($hasAuditor -or $hasPolicyUser)) {
    throw ("The connected user '{0}' has roles [{1}], which are not sufficient to run this report.`n" -f $myName, ($myRoles -join ', ')) +
          "Reading the access-request audit log (session counts) and the full user + entitlement set requires ONE of:`n" +
          "  * Auditor`n" +
          "  * ApplicationAuditor`n" +
          "  * PolicyAdmin AND UserAdmin`n" +
          "Reconnect as a user holding one of those role sets and re-run. Note: GlobalAdmin or SystemAuditor alone canNOT read the AccessRequest activity log."
}
Write-Host ("Preflight OK: '{0}' has roles [{1}]" -f $myName, ($myRoles -join ', ')) -ForegroundColor Green


# ---------------------------------------------------------------------------
# 3. Determine the window from the APPLIANCE clock (last N full calendar months, UTC)
# ---------------------------------------------------------------------------
try {
    $applianceNow = [datetime]::Parse((Get-SafeguardTime).CurrentTime).ToUniversalTime()
} catch {
    Write-Warning "Could not read appliance time; falling back to local UTC clock. ($($_.Exception.Message))"
    $applianceNow = [datetime]::UtcNow
}

$firstOfThisMonth = [datetime]::new($applianceNow.Year, $applianceNow.Month, 1, 0, 0, 0, [DateTimeKind]::Utc)
$windowEndExclusive = $firstOfThisMonth                       # up to, not including, the current (partial) month
$windowStart        = $firstOfThisMonth.AddMonths(-$MonthsBack)

# Ordered list of calendar months in the window: label + half-open [start, next) bounds.
$months = @()
for ($i = $MonthsBack; $i -ge 1; $i--) {
    $ms = $firstOfThisMonth.AddMonths(-$i)
    $months += [pscustomobject]@{
        Label     = $ms.ToString('yyyy-MM')
        Start     = $ms
        Next      = $ms.AddMonths(1)
        IsPartial = $false
    }
}

# Optionally add the current, still-in-progress calendar month as one more bucket.
# It is a PARTIAL month (month-to-date on the appliance clock), so it is labeled as
# such; a user who already exceeds the session threshold within it still counts as
# Privileged. Off by default because the licensing model's 12-month window uses only
# complete calendar months; this switch is for mid-month runs.
if ($IncludeCurrentMonth) {
    # Partial month = month-to-date: cap the upper bound at the appliance clock so the
    # bucket is genuinely MTD (not the whole calendar month) and no future-dated audit
    # rows can slip in. windowEndExclusive tracks the same cap for the summary header.
    $months += [pscustomobject]@{
        Label     = $firstOfThisMonth.ToString('yyyy-MM') + '*'
        Start     = $firstOfThisMonth
        Next      = $applianceNow
        IsPartial = $true
    }
    $windowEndExclusive = $applianceNow
}

$windowLabel = "{0:yyyy-MM} .. {1} ({2} months{3}, UTC)" -f `
    $windowStart, ($months[-1].Label), $months.Count, $(if ($IncludeCurrentMonth) { "; last is partial MTD" } else { "" })

Write-Banner "SPP LICENSE USAGE ACCOUNTING`nAppliance now (UTC): $($applianceNow.ToString('o'))`nWindow: $windowLabel`nPeak-month rule: > $SessionThreshold sessions in ANY single calendar month = Privileged"

# ---------------------------------------------------------------------------
# 4. Pre-fetch A2A registrations (used by the NHI count in section 11).
#    We deliberately do NOT build a certificate-user exclusion set: a cert user
#    used only for an A2A registration has no admin role, ownership, entitlement,
#    or interactive session and lands in Uncounted on its own, while a cert user
#    that DOES hold a permission/entitlement/approver role (or has sessions) should
#    count like any other user. The registration is still counted under NHI.
# ---------------------------------------------------------------------------
$a2aRegistrations = @()
try {
    $a2aRegistrations = @(Invoke-PagedGet Core "A2ARegistrations" @{ fields = 'Id,AppName,Disabled,CertificateUserId' })
} catch {
    Write-Warning "Could not enumerate A2A registrations (needed for the NHI count): $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# 5. Load the user universe (paged) and apply exclusions
# ---------------------------------------------------------------------------
Write-Host "Loading users ..." -ForegroundColor Green
$allUsers = @(Invoke-PagedGet Core "Users" @{ fields = 'Id,Name,AdminRoles,AllowPersonalAccounts,Disabled,PrimaryAuthenticationProvider' })

$records  = @{}   # in-scope users, keyed by Id
$excluded = New-Object System.Collections.Generic.List[object]      # excluded users, for the detail CSV
$allUserIds = New-Object 'System.Collections.Generic.HashSet[int]'  # every current user Id, any state
foreach ($u in $allUsers) {
    $id       = [int](Get-FirstProp $u @('Id'))
    [void]$allUserIds.Add($id)
    $name     = Get-FirstProp $u @('Name', 'UserName')
    $disabled = [bool](Get-FirstProp $u @('Disabled'))
    $adminRoles = @()
    if (($u.PSObject.Properties.Name -contains 'AdminRoles') -and $u.AdminRoles) {
        $adminRoles = @($u.AdminRoles | Where-Object { $_ })
    }
    $apa      = [bool](Get-FirstProp $u @('AllowPersonalAccounts'))
    $provObj  = Get-FirstProp $u @('PrimaryAuthenticationProvider')
    $provider = if ($provObj) { Get-FirstProp $provObj @('Name', 'DisplayName') } else { $null }

    # The only up-front exclusion is for system pseudo-users (negative Id), e.g.
    # SessionConnectionUser_* and the bootstrap admin: internal accounts that are
    # never a licensed human but DO appear in session audit rows, so they must be
    # filtered explicitly. Everyone else -- including A2A certificate users -- is
    # cohorted on their real signals (a cert-only user has none and lands in
    # Uncounted). Disabled users are NOT excluded here; a disabled user who had
    # sessions still consumed a license, so the "disabled with NO sessions"
    # exclusion is deferred until after session counting (see step 9).
    $exclReason = $null
    if ($id -le 0) { $exclReason = "system pseudo-user (negative Id)" }

    if ($exclReason) {
        $excluded.Add([pscustomobject]@{
            UserId = $id; UserName = $name; DisplayName = $null; Provider = $provider; Disabled = $disabled
            Cohort = "Excluded"; Reason = $exclReason
            HasAdminRight = ($adminRoles.Count -gt 0); AdminRoles = ($adminRoles -join ';')
            IsPartitionOwner = $false; IsAssetOwner = $false; IsAccountOwner = $false
            HasEntitlement = $false; EntitlementVia = $null
            PeakMonth = $null; PeakSessionCount = 0; TotalSessions = 0
            AllowPersonalAccounts = $apa; IsWorkforce = $false
        })
        continue
    }

    $records[$id] = [pscustomobject]@{
        UserId                = $id
        UserName              = $name
        DisplayName           = $null
        Provider              = $provider
        Disabled              = $disabled
        AdminRoles            = ($adminRoles -join ';')
        HasAdminRight         = ($adminRoles.Count -gt 0)
        IsPartitionOwner      = $false
        IsAssetOwner          = $false
        IsAccountOwner        = $false
        HasEntitlement        = $false
        EntitlementVia        = $null
        PeakMonth             = $null
        PeakSessionCount      = 0
        TotalSessions         = 0
        AllowPersonalAccounts = $apa
        IsWorkforce           = $false
        Cohort                = $null
        Reason                = $null
    }
}
Write-Host ("  {0} users total; {1} in scope, {2} excluded (system pseudo-users)" -f `
    $allUsers.Count, $records.Count, $excluded.Count)

# ---------------------------------------------------------------------------
# 6. Entitlement membership -> LimitedPrivileged eligibility.
#    A user counts (as at least LimitedPrivileged) only if they appear in an
#    ACTUAL entitlement, in one of three roles:
#      - Requester : a member of an entitlement (Role.Members)
#      - Approver  : listed in an access policy's ApproverSets[].Approvers
#      - Reviewer  : listed in an access policy's Reviewers
#    Merely being a user on the box (no role, no session) is NOT enough -> that
#    user stays Uncounted. Group principals (PrincipalKind = 'Group') are
#    expanded to their member users via UserGroups/{id}/Members; nested groups
#    are followed once with a visited guard so a membership cycle can't loop.
#    Membership is read directly from Roles + AccessPolicies (not the
#    UserEntitlement report), for the same reason ownership is in step 7.
# ---------------------------------------------------------------------------
Write-Host "Resolving entitlement requesters + policy approvers/reviewers ..." -ForegroundColor Green

$groupMemberCache = @{}   # groupId -> int[] resolved member user Ids (memoized)

# Add every user Id behind a principal (User, or Group expanded to its members)
# into the caller-supplied $Into set. We populate a passed-in set rather than
# RETURN one on purpose: PowerShell unrolls a returned collection onto the
# pipeline, so returning a HashSet would hand the caller a scalar (single
# member) or $null (empty) instead of the set. Nested groups are followed once,
# guarded by $Visited so a membership cycle can't loop forever.
function Add-PrincipalUserIds {
    param(
        $Principal,
        [System.Collections.Generic.HashSet[int]]$Into,
        [System.Collections.Generic.HashSet[int]]$Visited
    )
    if ($null -eq $Principal) { return }
    $rawId = Get-FirstProp $Principal @('Id')
    if ($null -eq $rawId) { return }
    $principalId = [int]$rawId
    $kind = "$(Get-FirstProp $Principal @('PrincipalKind'))"
    if ($kind -eq 'Group') {
        if (-not $groupMemberCache.ContainsKey($principalId)) {
            $tmp = New-Object 'System.Collections.Generic.HashSet[int]'
            if ($Visited.Add($principalId)) {   # cycle guard
                try {
                    # Project to Id only: this endpoint returns full ~40-field user
                    # objects by default, and its members are always users (it does
                    # not expose PrincipalKind, so a member is never a nested-group
                    # principal here). Id is all the accumulator needs; a member with
                    # no PrincipalKind is treated as a user, which is the intended and
                    # pre-existing behavior.
                    $gm = @(Invoke-SafeguardMethod Core GET "UserGroups/$principalId/Members" -Parameters @{ fields = 'Id' })
                    foreach ($sub in $gm) { Add-PrincipalUserIds -Principal $sub -Into $tmp -Visited $Visited }
                } catch {
                    Write-Warning "Could not expand user group $principalId ($($_.Exception.Message)); its members are not counted."
                }
            }
            # HashSet[T] has no instance ToArray() (that is a LINQ extension method,
            # which PowerShell cannot call); enumerate into an int[] instead.
            $groupMemberCache[$principalId] = [int[]]@($tmp)
        }
        foreach ($id in $groupMemberCache[$principalId]) { [void]$Into.Add($id) }
    } else {
        [void]$Into.Add($principalId)   # User principal
    }
}

# Mark each in-scope user Id as entitled via the given role. Returns the count
# of in-scope users marked (scalar), used only for the summary line.
function Set-EntitlementVia {
    param([System.Collections.Generic.HashSet[int]]$Ids, [string]$Via)
    $n = 0
    foreach ($id in $Ids) {
        if (-not $records.ContainsKey($id)) { continue }   # excluded/system/unknown: skip
        $records[$id].HasEntitlement = $true
        $existing = $records[$id].EntitlementVia
        if ([string]::IsNullOrEmpty($existing)) {
            $records[$id].EntitlementVia = $Via
        } elseif (($existing -split ';') -notcontains $Via) {
            $records[$id].EntitlementVia = "$existing;$Via"
        }
        $n++
    }
    return $n
}

try {
    $reqMarks = 0; $apprMarks = 0; $revMarks = 0

    # Requesters: members of every entitlement (Role). The Roles list already
    # carries each entitlement's Members inline, so read it in ONE request with
    # the fields projected to what we use (Id, Name, Members) instead of issuing
    # a separate Roles/{id}/Members GET per entitlement -- that per-role fan-out
    # was the dominant cost of this phase and scaled linearly with entitlement
    # count.
    $roles = @(Invoke-SafeguardMethod Core GET "Roles" -Parameters @{ fields = 'Id,Name,Members' })
    foreach ($role in $roles) {
        foreach ($mem in @($role.Members)) {
            $ids = New-Object 'System.Collections.Generic.HashSet[int]'
            Add-PrincipalUserIds -Principal $mem -Into $ids -Visited (New-Object 'System.Collections.Generic.HashSet[int]')
            $reqMarks += (Set-EntitlementVia -Ids $ids -Via 'Requester')
        }
    }

    # Approvers + reviewers: from every access policy. Project to the two fields
    # we read (ApproverSets, Reviewers) so the large per-policy properties we do
    # not use (scope items, request/session properties, etc.) are never fetched.
    $policies = @(Invoke-SafeguardMethod Core GET "AccessPolicies" -Parameters @{ fields = 'Id,Name,ApproverSets,Reviewers' })
    foreach ($pol in $policies) {
        foreach ($set in $pol.ApproverSets) {
            foreach ($ap in $set.Approvers) {
                $ids = New-Object 'System.Collections.Generic.HashSet[int]'
                Add-PrincipalUserIds -Principal $ap -Into $ids -Visited (New-Object 'System.Collections.Generic.HashSet[int]')
                $apprMarks += (Set-EntitlementVia -Ids $ids -Via 'Approver')
            }
        }
        foreach ($rv in $pol.Reviewers) {
            $ids = New-Object 'System.Collections.Generic.HashSet[int]'
            Add-PrincipalUserIds -Principal $rv -Into $ids -Visited (New-Object 'System.Collections.Generic.HashSet[int]')
            $revMarks += (Set-EntitlementVia -Ids $ids -Via 'Reviewer')
        }
    }

    Write-Host ("  {0} entitlements, {1} access policies; in-scope marks requester/approver/reviewer = {2}/{3}/{4}; {5} users entitled" -f `
        $roles.Count, $policies.Count, $reqMarks, $apprMarks, $revMarks, @($records.Values | Where-Object HasEntitlement).Count)
} catch {
    Write-Warning "Entitlement/policy enumeration failed ($($_.Exception.Message)); LimitedPrivileged detection is degraded."
}

# ---------------------------------------------------------------------------
# 7. Asset, account & partition ownership -> Privileged.
#    SPP grants ownership at three independent levels: partition, asset, and
#    account -- all resolved here by reading each object's owners directly. A
#    user listed in an object's ManagedBy owns that object; a group in ManagedBy
#    makes each of its members an owner (expanded with the same accumulator as
#    step 6). Owning ANY securable forces Privileged so ownership can't be
#    handed off to dodge the session count (anti-abuse). ManagedBy is
#    returned on the LIST endpoints when asked for via the fields filter, so the
#    asset/account passes are two paged scans of (Id, ManagedBy) -- not a call
#    per object. Partition owners are read per partition from the dedicated
#    owners endpoint (partitions are few, and their count is independent of the
#    user count). Ownership is read directly (not from the UserEntitlement
#    report): that report only lists users who hold an asset/account/policy
#    grant, so a user whose ONLY privileged tie is owning a partition (a common
#    delegated-admin case) would be absent from it and silently missed ->
#    Privileged undercount. (Policy and audit ownership are not counted.)
# ---------------------------------------------------------------------------
Write-Host "Resolving asset, account & partition ownership ..." -ForegroundColor Green

# Mark each in-scope user Id with the given ownership flag. Returns the count
# of in-scope users marked (scalar), used only for the summary line.
function Set-OwnerFlag {
    param([System.Collections.Generic.HashSet[int]]$Ids, [string]$Field)
    $n = 0
    foreach ($id in $Ids) {
        if (-not $records.ContainsKey($id)) { continue }   # excluded/system/unknown: skip
        $records[$id].$Field = $true
        $n++
    }
    return $n
}

$assetOwnerMarks = 0; $acctOwnerMarks = 0
try {
    $ownedAssets = Invoke-PagedGet Core 'Assets' @{ fields = 'Id,ManagedBy' }
    foreach ($as in $ownedAssets) {
        foreach ($owner in $as.ManagedBy) {
            $ids = New-Object 'System.Collections.Generic.HashSet[int]'
            Add-PrincipalUserIds -Principal $owner -Into $ids -Visited (New-Object 'System.Collections.Generic.HashSet[int]')
            $assetOwnerMarks += (Set-OwnerFlag -Ids $ids -Field 'IsAssetOwner')
        }
    }
} catch {
    Write-Warning "Asset ownership scan failed ($($_.Exception.Message)); asset-owner detection is degraded."
}
try {
    $ownedAccounts = Invoke-PagedGet Core 'AssetAccounts' @{ fields = 'Id,ManagedBy' }
    foreach ($ac in $ownedAccounts) {
        foreach ($owner in $ac.ManagedBy) {
            $ids = New-Object 'System.Collections.Generic.HashSet[int]'
            Add-PrincipalUserIds -Principal $owner -Into $ids -Visited (New-Object 'System.Collections.Generic.HashSet[int]')
            $acctOwnerMarks += (Set-OwnerFlag -Ids $ids -Field 'IsAccountOwner')
        }
    }
} catch {
    Write-Warning "Account ownership scan failed ($($_.Exception.Message)); account-owner detection is degraded."
}
# Partition ownership: read each partition's owners directly (authoritative).
# NOT from the UserEntitlement report -- that only lists users who hold a grant,
# so a pure partition owner (no other entitlement) would be absent and missed.
# Owner objects come back as the empty [object[]] wrapper for ownerless
# partitions, so filter to real principals (with an Id) before marking.
$partOwnerMarks = 0
try {
    $partitions = @(Get-SafeguardAssetPartition)
    foreach ($part in $partitions) {
        $powners = @()
        try {
            $powners = @(Get-SafeguardAssetPartitionOwner -AssetPartitionToGet $part.Id |
                        Where-Object { $null -ne $_ -and -not ($_ -is [System.Array]) -and $null -ne $_.Id })
        } catch {
            Write-Warning "Could not read owners of partition $($part.Id) '$($part.Name)' ($($_.Exception.Message))."
        }
        foreach ($owner in $powners) {
            $ids = New-Object 'System.Collections.Generic.HashSet[int]'
            Add-PrincipalUserIds -Principal $owner -Into $ids -Visited (New-Object 'System.Collections.Generic.HashSet[int]')
            $partOwnerMarks += (Set-OwnerFlag -Ids $ids -Field 'IsPartitionOwner')
        }
    }
} catch {
    Write-Warning "Asset-partition enumeration failed ($($_.Exception.Message)); partition-ownership detection is degraded."
}
Write-Host ("  in-scope owner marks partition/asset/account = {0}/{1}/{2}" -f $partOwnerMarks, $assetOwnerMarks, $acctOwnerMarks)

# ---------------------------------------------------------------------------
# Session-counting core (pure, no I/O) -- factored out of section 8 so the
# licensing-critical math (per-month RequestId de-dup, month-boundary half-open
# windowing, peak-vs-total selection, in-scope/excluded/orphan routing) can be
# exercised by a synthetic-row harness. The live audit log is immutable and can't
# be backdated, so these branches (>10-in-a-month, multi-month peak, dedup,
# disabled-with-sessions) can only be proven against crafted rows. Section 8 calls
# these exactly where the inline code used to run, so live behavior is unchanged.
# ---------------------------------------------------------------------------

# Fold one month's already-fetched InitializeSession rows into the accumulators.
# Mutates $MonthlyByUser / $Unmatched / $UnmatchedNames in place. A request is
# keyed by RequestId (one authorized request = one count, no matter how many
# connection events it emits). Rows are re-filtered to the month's half-open
# window [Start, Next) so a boundary event can't be double-counted across two
# adjacent months. Routing: in-scope current user -> monthly; known-but-excluded
# system pseudo-user -> ignored (never resurrected as an orphan); anything else
# with a RequesterId -> deleted/renamed orphan bucket keyed by the stable Id.
function Add-SessionActivityRows {
    [CmdletBinding()]
    param(
        [object[]] $Rows,
        $Month,
        [hashtable] $MonthlyByUser,
        [hashtable] $Unmatched,
        [hashtable] $UnmatchedNames,
        [System.Collections.Generic.HashSet[int]] $InScopeUserIds,
        [System.Collections.Generic.HashSet[int]] $AllUserIds
    )
    foreach ($a in $Rows) {
        if ($null -eq $a -or ($a -is [System.Array])) { continue }
        $lt = Get-FirstProp $a @('LogTime')
        if ($null -ne $lt) {
            try {
                if ($lt -is [datetime]) {
                    $ltUtc = $lt.ToUniversalTime()
                } else {
                    $ltUtc = [datetime]::Parse([string]$lt, [System.Globalization.CultureInfo]::InvariantCulture,
                                 [System.Globalization.DateTimeStyles]::AssumeUniversal -bor
                                 [System.Globalization.DateTimeStyles]::AdjustToUniversal)
                }
                if ($ltUtc -lt $Month.Start -or $ltUtc -ge $Month.Next) { continue }
            } catch { }
        }

        $uidRaw = Get-FirstProp $a @('RequesterId', 'UserId')
        $uname  = Get-FirstProp $a @('RequesterName', 'UserName', 'UserDisplayName')
        $rid    = Get-FirstProp $a @('RequestId', 'AccessRequestId')
        if ($null -eq $rid) { Write-Warning "InitializeSession row with no RequestId in $($Month.Label); skipped."; continue }
        $sessionKey = "r:$rid"
        $uid = if ($null -ne $uidRaw) { [int]$uidRaw } else { $null }

        if ($null -ne $uid -and $InScopeUserIds.Contains($uid)) {
            if (-not $MonthlyByUser.ContainsKey($uid)) { $MonthlyByUser[$uid] = @{} }
            if (-not $MonthlyByUser[$uid].ContainsKey($Month.Label)) {
                $MonthlyByUser[$uid][$Month.Label] = New-Object 'System.Collections.Generic.HashSet[string]'
            }
            [void]$MonthlyByUser[$uid][$Month.Label].Add($sessionKey)
        }
        elseif ($null -ne $uid -and $AllUserIds.Contains($uid)) {
            continue
        }
        elseif ($null -ne $uid) {
            if (-not $Unmatched.ContainsKey($uid)) { $Unmatched[$uid] = @{} }
            if (-not $Unmatched[$uid].ContainsKey($Month.Label)) {
                $Unmatched[$uid][$Month.Label] = New-Object 'System.Collections.Generic.HashSet[string]'
            }
            [void]$Unmatched[$uid][$Month.Label].Add($sessionKey)
            if ($null -ne $uname) { $UnmatchedNames[$uid] = $uname }
        }
    }
}

# Reduce a (userId -> month -> HashSet[requestKey]) map to per-user peak month,
# peak count, and total. Peak uses strict '>' over months walked in chronological
# order, so on a tie the EARLIEST month keeps the PeakMonth label (display only).
# Returns userId -> {Peak,PeakMonth,Total}.
function Get-PeakSessionStats {
    [CmdletBinding()]
    param([hashtable] $MonthlyByUser)
    $result = @{}
    foreach ($uid in $MonthlyByUser.Keys) {
        $peak = 0; $peakMonth = $null; $total = 0
        # Sort the month labels (yyyy-MM sorts chronologically) so the tie-break is
        # deterministic: Hashtable.Keys has no defined order, so without this the
        # earliest-month promise above would depend on internal bucket ordering.
        foreach ($lbl in ($MonthlyByUser[$uid].Keys | Sort-Object)) {
            $c = $MonthlyByUser[$uid][$lbl].Count
            $total += $c
            if ($c -gt $peak) { $peak = $c; $peakMonth = $lbl }
        }
        $result[$uid] = [pscustomobject]@{ Peak = $peak; PeakMonth = $peakMonth; Total = $total }
    }
    return $result
}

# ---------------------------------------------------------------------------
# 8. Session counts per (user, calendar month) from the audit log -> peak month.
#    Source: AuditLog/AccessRequests/Activities, Action eq 'InitializeSession'
#    (the "Session Initiated" event). Distinct access RequestId per user per
#    month -> one count per authorized request. We key on RequestId, NOT
#    SessionId: SessionId is only populated once SPS actually brokers the
#    connection, so keying on it would drop authorized requests that never
#    connected. RequestId is always present on the request.
#    Reduced inline per month so memory stays ~ distinct requests, not events.
# ---------------------------------------------------------------------------
Write-Host "Counting privileged sessions per calendar month ..." -ForegroundColor Green
$monthlyByUser   = @{}   # userId       -> (monthLabel -> HashSet[requestKey])
$unmatched       = @{}   # deletedUserId -> (monthLabel -> HashSet[requestKey])  (Ids not in the table)
$unmatchedNames  = @{}   # deletedUserId -> last-seen RequesterName (for display only)
$actFields       = 'LogTime,RequestId,RequesterId,RequesterName,Action,SessionId'

# In-scope = current users we loaded into $records (populated in section 5, not yet
# pruned -- the disabled-with-no-sessions drop happens later in step 9). Snapshot the Id
# set now for the row-router. $allUserIds already holds every current user Id.
$inScopeUserIds = New-Object 'System.Collections.Generic.HashSet[int]'
foreach ($k in $records.Keys) { [void]$inScopeUserIds.Add([int]$k) }

# Pull session-start (InitializeSession) events per month via the supported
# cmdlet. It returns deserialized objects whose LogTime is already a UTC
# DateTime (Kind=Utc); StartDate/EndDate scope the query server-side (the cmdlet
# normalizes them to UTC). Each month's rows are folded in by Add-SessionActivityRows,
# which re-filters every row against this month's half-open window.
foreach ($m in $months) {
    try {
        # For a zero-result window the cmdlet emits a single empty [object[]]
        # wrapper rather than no output; drop nulls and any array wrapper so an
        # empty month contributes no bogus "row" (which would otherwise trip the
        # no-RequestId warning below). Populated months return flat record objects.
        $rows = @(Get-SafeguardAuditLogAccessRequestActivity -StartDate $m.Start -EndDate $m.Next `
                    -QueryFilter "Action eq 'InitializeSession'" -Fields ($actFields -split ',') |
                  Where-Object { $null -ne $_ -and -not ($_ -is [System.Array]) })
        Add-SessionActivityRows -Rows $rows -Month $m `
            -MonthlyByUser $monthlyByUser -Unmatched $unmatched -UnmatchedNames $unmatchedNames `
            -InScopeUserIds $inScopeUserIds -AllUserIds $allUserIds
    } catch {
        Write-Warning "Session query failed for month $($m.Label): $($_.Exception.Message)"
    }
}

# Reduce monthly sets to per-user peak + total and stamp onto the in-scope records.
$sessionStats = Get-PeakSessionStats -MonthlyByUser $monthlyByUser
foreach ($uid in $sessionStats.Keys) {
    $records[$uid].PeakSessionCount = $sessionStats[$uid].Peak
    $records[$uid].PeakMonth        = $sessionStats[$uid].PeakMonth
    $records[$uid].TotalSessions    = $sessionStats[$uid].Total
}
Write-Host ("  sessions attributed to {0} in-scope users; {1} session-owners not in scope" -f `
    $monthlyByUser.Count, $unmatched.Count)

# ---------------------------------------------------------------------------
# 9. Deferred disabled-user exclusion. Now that sessions are known, drop disabled
#    users who had NO sessions in the window (unless -IncludeDisabledUsers). A
#    disabled user WITH sessions still consumed a license, so it stays and is
#    cohorted normally. (This is also why disabled users are loaded into $records
#    up front rather than excluded there: their sessions must attribute to them,
#    not fall through to the deleted-user orphan path.)
# ---------------------------------------------------------------------------
if (-not $IncludeDisabledUsers) {
    $droppedDisabled = 0
    foreach ($id in @($records.Keys)) {
        $r = $records[$id]
        if ($r.Disabled -and $r.TotalSessions -eq 0) {
            $r.Cohort = "Excluded"
            $r.Reason = "disabled user with no sessions in window"
            $excluded.Add($r)
            [void]$records.Remove($id)
            $droppedDisabled++
        }
    }
    if ($droppedDisabled -gt 0) {
        Write-Host ("  {0} disabled users with no sessions excluded" -f $droppedDisabled)
    }
}

# ---------------------------------------------------------------------------
# 10. Classify each in-scope identity once (peak-month rule).
#     Privileged > LimitedPrivileged > Uncounted.
# ---------------------------------------------------------------------------
foreach ($r in $records.Values) {
    $reasons = @()
    if ($r.HasAdminRight)                          { $reasons += "admin-role[$($r.AdminRoles)]" }
    if ($r.IsPartitionOwner)                       { $reasons += "partition-owner" }
    if ($r.IsAssetOwner)                           { $reasons += "asset-owner" }
    if ($r.IsAccountOwner)                         { $reasons += "account-owner" }
    if ($r.PeakSessionCount -gt $SessionThreshold) { $reasons += "peak $($r.PeakSessionCount) sessions in $($r.PeakMonth) > $SessionThreshold" }

    if ($reasons.Count -gt 0) {
        $r.Cohort = "Privileged"
        $r.Reason = ($reasons -join '; ')
    }
    elseif ($r.HasEntitlement -or $r.TotalSessions -gt 0) {
        $r.Cohort = "LimitedPrivileged"
        $r.Reason = if ($r.HasEntitlement) { "entitlement ($($r.EntitlementVia)); peak $($r.PeakSessionCount) <= $SessionThreshold" }
                    else { "sessions only; peak $($r.PeakSessionCount) <= $SessionThreshold" }
    }
    else {
        $r.Cohort = "Uncounted"
        $r.Reason = "no admin/ownership/entitlement/sessions"
    }
}

# Session-only owners not in the current user table. Every orphan here came out of
# the audit-log session sweep, so each already has >=1 session in the window; its
# RequesterId simply no longer resolves to a live user. Enrich from the deleted-user
# store (Deleted/Users) when possible: a deleted record's Id IS the original user Id,
# so it matches the orphan RequesterId directly. This (a) confirms the orphan is a
# real deleted user, (b) recovers name/provider/attributes for the CSV, and (c)
# recovers the admin-role / partition-owner state as of deletion so the orphan is
# classified the same way a live user would be, not on session count alone.
# Limitation: the deleted record exposes partition ownership only; asset/account
# ownership links are removed on delete and cannot be recovered.
$syntheticRecords = New-Object System.Collections.Generic.List[object]
$deletedById = @{}
if ($unmatched.Count -gt 0) {
    try {
        foreach ($du in @(Get-SafeguardDeletedUser)) {
            $dId = Get-FirstProp $du @('Id')
            if ($null -ne $dId) { $deletedById[[int]$dId] = $du }
        }
        Write-Host ("  {0} deleted users available for orphan enrichment" -f $deletedById.Count) -ForegroundColor DarkGray
    } catch {
        Write-Warning "Could not read Deleted/Users for orphan enrichment: $($_.Exception.Message). Falling back to session-only display."
    }
}

foreach ($uid in $unmatched.Keys) {
    $peak = 0; $peakMonth = $null; $total = 0
    foreach ($lbl in $unmatched[$uid].Keys) {
        $c = $unmatched[$uid][$lbl].Count
        $total += $c
        if ($c -gt $peak) { $peak = $c; $peakMonth = $lbl }
    }

    $del      = if ($deletedById.ContainsKey([int]$uid)) { $deletedById[[int]$uid] } else { $null }
    $dispName = if ($unmatchedNames.ContainsKey($uid)) { $unmatchedNames[$uid] } else { $null }

    if ($null -ne $del) {
        # Recovered from the deleted-user store.
        $dName      = Get-FirstProp $del @('Name')
        $dDisplay   = Get-FirstProp $del @('DisplayName')
        $dProvObj   = Get-FirstProp $del @('IdentityProvider')
        $dProv      = if ($dProvObj) { Get-FirstProp $dProvObj @('Name') } else { $null }
        $dDisabled  = Get-FirstProp $del @('Disabled')
        $dPartOwner = [bool](Get-FirstProp $del @('IsPartitionOwner'))
        $dApa       = [bool](Get-FirstProp $del @('AllowPersonalAccounts'))
        $dRolesRaw  = Get-FirstProp $del @('AdminRoles')
        $dRoles     = @(); if ($dRolesRaw) { $dRoles = @($dRolesRaw) }
        $dDeleted   = Get-FirstProp $del @('DeletedDate')
        $dDeletedStr = if ($dDeleted -is [datetime]) { $dDeleted.ToString('yyyy-MM-dd') } elseif ($dDeleted) { [string]$dDeleted } else { $null }

        # Classify like a live user: admin role or partition ownership => Privileged,
        # then fall back to the peak-month session rule. Entitlement/requester signals
        # are gone with the deletion and cannot be recovered.
        $reasons = @()
        if ($dRoles.Count -gt 0) { $reasons += "admin-role[$($dRoles -join ';')]" }
        if ($dPartOwner)         { $reasons += "partition-owner" }
        if ($peak -gt $SessionThreshold) { $reasons += "peak $peak sessions in $peakMonth (> $SessionThreshold)" }

        if ($reasons.Count -gt 0) {
            $cohort = "Privileged"
            $reason = "deleted user (recovered): " + ($reasons -join '; ')
        } else {
            $cohort = "LimitedPrivileged"
            $reason = "deleted user (recovered): $total session(s) in window (<= $SessionThreshold/mo)"
        }
        if ($dDeletedStr) { $reason += "; deleted $dDeletedStr" }

        $syntheticRecords.Add([pscustomobject]@{
            UserId = $uid
            UserName = if ($dName) { $dName } else { $dispName }
            DisplayName = $dDisplay; Provider = $dProv; Disabled = $dDisabled
            AdminRoles = ($dRoles -join ';'); HasAdminRight = ($dRoles.Count -gt 0)
            IsPartitionOwner = $dPartOwner; IsAssetOwner = $false; IsAccountOwner = $false
            HasEntitlement = $false; EntitlementVia = $null
            PeakMonth = $peakMonth; PeakSessionCount = $peak; TotalSessions = $total
            AllowPersonalAccounts = $dApa; IsWorkforce = $false
            Cohort = $cohort; Reason = $reason
        })
    } else {
        # Not found in the deleted-user store (purged, or an Id that never resolved).
        # Keep the session-only fallback: classify on the peak-month rule alone.
        $syntheticRecords.Add([pscustomobject]@{
            UserId = $uid; UserName = $dispName; DisplayName = $null; Provider = $null; Disabled = $null
            AdminRoles = $null; HasAdminRight = $false; IsPartitionOwner = $false; IsAssetOwner = $false; IsAccountOwner = $false; HasEntitlement = $false; EntitlementVia = $null
            PeakMonth = $peakMonth; PeakSessionCount = $peak; TotalSessions = $total
            AllowPersonalAccounts = $false; IsWorkforce = $false
            Cohort = if ($peak -gt $SessionThreshold) { "Privileged" } else { "LimitedPrivileged" }
            Reason = "session-only user not found in the deleted-user store (purged or renamed)"
        })
    }
}

# ---------------------------------------------------------------------------
# 11. NHI = unique (A2A registration + retrievable account) pairs + brokers.
#     Skip DISABLED registrations. Point-in-time (current) count.
# ---------------------------------------------------------------------------
Write-Host "Counting NHI (A2A registrations, retrievable accounts, brokers) ..." -ForegroundColor Green
$nhiPairs  = New-Object 'System.Collections.Generic.HashSet[string]'
$nhiDetail = New-Object System.Collections.Generic.List[object]
$skippedDisabledRegs = 0
foreach ($reg in $a2aRegistrations) {
    if ([bool](Get-FirstProp $reg @('Disabled'))) { $skippedDisabledRegs++; continue }
    $regId   = Get-FirstProp $reg @('Id')
    if ($null -eq $regId) { continue }   # phantom/blank registration row -> nothing to count
    $regName = Get-FirstProp $reg @('AppName', 'Name')

    # Retrievable accounts -> one NHI per unique (registration, account).
    try {
        foreach ($ra in @(Get-SafeguardA2aCredentialRetrieval -ParentA2a $regId)) {
            $acctId = Get-FirstProp $ra @('AccountId', 'Id')
            $key = "reg:$regId|acct:$acctId"
            if ($nhiPairs.Add($key)) {
                $nhiDetail.Add([pscustomobject]@{
                    Type = "RetrievableAccount"; RegistrationId = $regId; Registration = $regName
                    Account = (Get-FirstProp $ra @('AccountName')); Key = $key
                })
            }
        }
    } catch { Write-Warning "Retrievable accounts for registration $regId failed: $($_.Exception.Message)" }

    # Access-request broker -> one NHI IF configured. A 404/empty means no broker.
    try {
        $broker = Get-SafeguardA2aAccessRequestBroker -ParentA2a $regId -ErrorAction Stop
        if ($broker) {
            $key = "reg:$regId|broker"
            if ($nhiPairs.Add($key)) {
                $nhiDetail.Add([pscustomobject]@{
                    Type = "AccessRequestBroker"; RegistrationId = $regId; Registration = $regName; Account = $null; Key = $key
                })
            }
        }
    } catch {
        # A 404 / Not Found means this registration simply has no broker configured
        # (expected -- not all registrations have one). Anything else (auth, timeout,
        # 5xx) is a real failure that would UNDERCOUNT NHI, so surface it rather than
        # silently treating it as "no broker".
        $bmsg = "$($_.Exception.Message)"
        if ($bmsg -notmatch '404' -and $bmsg -notmatch 'Not\s*Found') {
            Write-Warning "Broker lookup for registration $regId failed (not a 404): $bmsg"
        }
    }
}
$nhiCount = $nhiPairs.Count

# ---------------------------------------------------------------------------
# 12. Workforce = ENABLED users with AllowPersonalAccounts = true (WPV permission).
#     Decided purely on the enabled + WPV state, independent of the step 9
#     session-based disabled drop: an enabled WPV user counts whether or not they
#     have any sessions/entitlements, and a disabled user never counts (a disabled
#     account cannot log in, so it cannot consume WPV). Additive to P / LP.
# ---------------------------------------------------------------------------
foreach ($r in $records.Values) { if ($r.AllowPersonalAccounts -and -not $r.Disabled) { $r.IsWorkforce = $true } }
$workforceCount = @($records.Values | Where-Object IsWorkforce).Count

# ---------------------------------------------------------------------------
# 13. Totals + output
# ---------------------------------------------------------------------------
$allRecords = @($records.Values) + $syntheticRecords.ToArray()
$privCount  = @($allRecords | Where-Object Cohort -eq 'Privileged').Count
$lpCount    = @($allRecords | Where-Object Cohort -eq 'LimitedPrivileged').Count

$stamp    = [datetime]::UtcNow.ToString("yyyyMMdd-HHmmss")
$applName = if ($Appliance) { $Appliance } else { "existing-connection" }

$totals = [pscustomobject]@{
    Appliance          = $applName
    GeneratedUtc       = [datetime]::UtcNow.ToString("o")
    ApplianceNowUtc    = $applianceNow.ToString("o")
    WindowStartUtc     = $windowStart.ToString("o")
    WindowEndExclUtc   = $windowEndExclusive.ToString("o")
    Months             = $months.Count
    IncludesPartialMonth = [bool]$IncludeCurrentMonth
    SessionThreshold   = $SessionThreshold
    Privileged         = $privCount
    LimitedPrivileged  = $lpCount
    NHI                = $nhiCount
    Workforce          = $workforceCount
    UsersInScope       = $records.Count
    UsersExcluded      = $excluded.Count
    SessionOnlyOrphans = $syntheticRecords.Count
    DisabledRegsSkipped = $skippedDisabledRegs
}

if (-not (Test-Path $OutputDirectory)) { New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null }
$totalsCsv = Join-Path $OutputDirectory "spp-license-totals-$stamp.csv"
$detailCsv = Join-Path $OutputDirectory "spp-license-user-detail-$stamp.csv"
$nhiCsv    = Join-Path $OutputDirectory "spp-license-nhi-detail-$stamp.csv"

$detailRows = @(@($allRecords) + $excluded.ToArray()) |
    Select-Object UserId, UserName, DisplayName, Provider, Disabled, Cohort, Reason,
                  HasAdminRight, AdminRoles, IsPartitionOwner, IsAssetOwner, IsAccountOwner, HasEntitlement, EntitlementVia,
                  PeakMonth, PeakSessionCount, TotalSessions, AllowPersonalAccounts, IsWorkforce |
    Sort-Object Cohort, UserName

# Numeric/boolean columns are already typed (Int32/Boolean) in the objects above;
# Export-Csv's default quotes EVERY field, which some strict/typed consumers
# (Power BI, DB bulk-load, pandas) ingest as text. -UseQuotes AsNeeded emits bare
# numerics/booleans and only quotes fields that need it. That switch is PowerShell
# 6+ only, so fall back to default (quote-all) quoting on Windows PowerShell 5.1.
$csvArgs = @{ NoTypeInformation = $true }
if ($PSVersionTable.PSVersion.Major -ge 6) { $csvArgs.UseQuotes = 'AsNeeded' }

$totals     | Export-Csv -Path $totalsCsv @csvArgs
$detailRows | Export-Csv -Path $detailCsv @csvArgs
if ($nhiDetail.Count -gt 0) { $nhiDetail | Export-Csv -Path $nhiCsv @csvArgs }

Write-Banner "RESULTS (see notes below)"
$totals | Format-List
Write-Host "Cohort counts:" -ForegroundColor Green
Write-Host ("  Privileged        : {0}" -f $privCount)
Write-Host ("  LimitedPrivileged : {0}" -f $lpCount)
Write-Host ("  NHI               : {0}" -f $nhiCount)
Write-Host ("  Workforce (add-on): {0}" -f $workforceCount)
Write-Host ""
Write-Host "CSV output:" -ForegroundColor Green
Write-Host "  Totals      : $totalsCsv"
Write-Host "  User detail : $detailCsv"
if ($nhiDetail.Count -gt 0) { Write-Host "  NHI detail  : $nhiCsv" }

Write-Host ""
Write-Host "NOTES:" -ForegroundColor Yellow
Write-Host "  * Session history comes from the access-request audit log (bounded by retention)." -ForegroundColor Yellow
Write-Host "  * Peak-month rule: a user Privileged in any single calendar month is Privileged for the whole span." -ForegroundColor Yellow
Write-Host "  * Ownership counts partition, asset, and account owners (via ManagedBy); policy and audit ownership are not counted." -ForegroundColor Yellow
Write-Host "  * NHI and Workforce are current/point-in-time; no history is available for them." -ForegroundColor Yellow
Write-Host "  * Deleted users with sessions in the window are recovered from the deleted-user store (name, provider, admin roles, partition ownership as of deletion); asset/account ownership can't be recovered, and purged users fall back to session-only classification." -ForegroundColor Yellow
