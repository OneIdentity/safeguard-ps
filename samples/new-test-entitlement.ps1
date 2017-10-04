Param(
    [Parameter(Mandatory=$true)]
    [string]$EntitlementName,
    [Parameter(Mandatory=$true)]
    [string]$ApproverUserName
)

$ErrorActionPreference = "Stop"

if (-not $SafeguardSession)
{
    throw "This script assumes you have already called Connect-Safeguard to create a session."
}

if (-not (Get-SafeguardUser $ApproverUserName))
{
    throw "The $ApproverUserName user must actually exist."
}

$local:RequesterGroupId = (Invoke-SafeguardMethod Core POST UserGroups -Body @{
    Name = "$EntitlementName Requesters"
}).Id
$local:ApproverGroupId = (Invoke-SafeguardMethod Core POST UserGroups -Body @{
    Name = "$EntitlementName Approvers"
}).Id
Invoke-SafeguardMethod Core PUT "UserGroups/$($local:ApproverGroupId)/Members" -Body @(Get-Safeguarduser $ApproverUserName)
$local:EntitlementId = (Invoke-SafeguardMethod Core POST Roles -Body @{
    Name = "$EntitlementName Test Entitlement"
}).Id
Invoke-SafeguardMethod Core PUT "Roles/$($local:EntitlementId)/Members" -Body @(@{
    Id = $local:RequesterGroupId;
    PrincipalKind = "Group"
})
Invoke-SafeguardMethod Core POST AccessPolicies -Body "{
    `"Name`": `"Basic Password`",
    `"RoleId`": $local:EntitlementId,
    `"AccessRequestProperties`": {
        `"AccessRequestType`": `"Password`",
        `"AllowSimultaneousAccess`": true
    },
    `"ApproverProperties`": {
        `"RequireApproval`": false
    }
}"
Invoke-SafeguardMethod Core POST AccessPolicies -Body "{
    `"Name`": `"Basic SSH`",
    `"RoleId`": $local:EntitlementId,
    `"AccessRequestProperties`": {
        `"AccessRequestType`": `"Ssh`",
        `"AllowSimultaneousAccess`": true
    },
    `"ApproverProperties`": {
        `"RequireApproval`": true
    },
    `"ApproverSets`": [{
        `"RequiredApprovers`": 1,
        `"Approvers`": [{
            `"Id`": $local:ApproverGroupId,
            `"PrincipalKind`": `"Group`"
        }]
    }]
}"
Invoke-SafeguardMethod Core POST AccessPolicies -Body "{
    `"Name`": `"Basic RDP`",
    `"RoleId`": $local:EntitlementId,
    `"AccessRequestProperties`": {
        `"AccessRequestType`": `"RemoteDesktop`",
        `"AllowSimultaneousAccess`": true
    },
    `"ApproverProperties`": {
        `"RequireApproval`": true
    },
    `"ApproverSets`": [{
        `"RequiredApprovers`": 1,
        `"Approvers`": [{
            `"Id`": $local:ApproverGroupId,
            `"PrincipalKind`": `"Group`"
        }]
    }]
}"
