# Helpers
$script:SgAccessRequestFields = "Id","AccessRequestType","State","TicketNumber","IsEmergency","AssetId","AssetName","AssetNetworkAddress","AccountId","AccountDomainName","AccountName"
function Resolve-SafeguardRequestableAssetId
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$Asset
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($Asset.Id -as [int])
    {
        $Asset = $Asset.Id
    }

    if (-not ($Asset -as [int]))
    {
        try
        {
            $local:Assets = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Me/AccessRequestAssets" `
                                 -Parameters @{ filter = "Name ieq '$Asset'" })
            if (-not $local:Assets)
            {
                $local:Assets = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Me/AccessRequestAssets" `
                                     -Parameters @{ filter = "NetworkAddress ieq '$Asset'" })
            }
        }
        catch
        {
            Write-Verbose $_
            Write-Verbose "Caught exception with ieq filter, trying with q parameter"
            $local:Assets = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Me/AccessRequestAssets" `
                                 -Parameters @{ q = $Asset })
        }
        if (-not $local:Assets)
        {
            throw "Unable to find a requestable asset matching '$Asset'"
        }
        if ($local:Assets.Count -ne 1)
        {
            throw "Found $($local:Assets.Count) requestable assets matching '$Asset'"
        }
        $local:Assets[0].Id
    }
    else
    {
        $Asset
    }
}
function Resolve-SafeguardRequestableAccountId
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true)]
        [int]$AssetId,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$Account
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($Account.Id -as [int])
    {
        $Account = $Account.Id
    }

    if (-not ($Account -as [int]))
    {
        $local:RelativeUrl = "Me/RequestEntitlements"
        try
        {
            $local:Accounts = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET $local:RelativeUrl `
                                   -Parameters @{ assetIds = "$AssetId"; filter = "Name ieq '$Account'" }).Account
        }
        catch
        {
            Write-Verbose $_
            Write-Verbose "Caught exception with ieq filter, trying with q parameter"
            $local:Accounts = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET $local:RelativeUrl `
                                   -Parameters @{ assetIds = "$AssetId"; q = $Account }).Account
        }
        if (-not $local:Accounts)
        {
            throw "Unable to find a requestable account matching '$Account'"
        }
        if ($local:Accounts.Count -ne 1)
        {
            throw "Found $($local:Accounts.Count) requestable accounts matching '$Account'"
        }
        $local:Accounts[0].Id
    }
    else
    {
        $Account
    }
}
function New-RequestableAccountObject
{
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [object]$Asset,
        [Parameter(Mandatory=$true,Position=1)]
        [object]$Account,
        [Parameter(Mandatory=$true,Position=2)]
        [object]$Policy,
        [Parameter(Mandatory=$true)]
        [switch]$AllFields
    )

    if ($AllFields)
    {
        New-Object PSObject -Property ([ordered]@{
            AssetId = $Asset.Id;
            AssetName = $Asset.Name;
            NetworkAddress = $Asset.NetworkAddress;
            AssetDescription = $Asset.Description;
            PlatformId = $Asset.Platform.Id;
            PlatformType = $Asset.Platform.PlatformType;
            PlatformDisplayName = $Asset.Platform.DisplayName;
            SshHostKey = $Asset.SshHostKey.SshHostKey;
            SshHostKeyFingerprint = $Asset.SshHostKey.Fingerprint;
            SshHostKeyFingerprintSha256 = $Asset.SshHostKey.FingerprintSha256;
            SshSessionPort = $Asset.SessionAccessProperties.SshSessionPort;
            RdpSessionPort = $Asset.SessionAccessProperties.RemoteDesktopSessionPort;
            AccountId = $Account.Id;
            AccountDomainName = $Account.DomainName;
            AccountName = $Account.Name;
            AccountDescription = $Account.Description;
            AccountRequestType = $Policy.AccessRequestProperties.AccessRequestType;
            RequireReasonCode = $Policy.RequesterProperties.RequireReasonCode;
            RequireReasonComment = $Policy.RequesterProperties.RequireReasonComment;
            RequireServiceTicket = $Policy.RequesterProperties.RequireServiceTicket;
        })
    }
    else
    {
        New-Object PSObject -Property ([ordered]@{
            AssetId = $Asset.Id;
            AssetName = $Asset.Name;
            NetworkAddress = $Asset.NetworkAddress;
            PlatformDisplayName = $Asset.Platform.DisplayName;
            AccountId = $Account.Id;
            AccountDomainName = $Account.DomainName;
            AccountName = $Account.Name;
            AccountRequestType = $Policy.AccessRequestProperties.AccessRequestType;
        })
    }
}

<#
.SYNOPSIS
Get an access request or all access requests via the Web API.

.DESCRIPTION
GET from the AccessRequests endpoint.  If an ID is provided then a single
access request will be returned, otherwise all access requests will be
returned.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER RequestId
A string containing the ID of the access request.

.PARAMETER AllFields
Return all properties that can be displayed.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardAccessRequest -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardAccessRequest 123
#>
function Get-SafeguardAccessRequest
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false, Position=0)]
        [string]$RequestId,
        [Parameter(Mandatory=$false)]
        [switch]$AllFields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Parameters = $null
    if (-not $AllFields)
    {
        $local:Parameters = @{ fields = ($script:SgAccessRequestFields -join ",") }
    }

    if ($PSBoundParameters.ContainsKey("RequestId"))
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            GET "AccessRequests/$RequestId" -Parameters $local:Parameters
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            GET "AccessRequests" -Parameters $local:Parameters
    }
}

<#
.SYNOPSIS
Search for an access request via the Web API.

.DESCRIPTION
Search through all access requests for string properties containing
the SearchString.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER SearchString
A string containing the ID of the access request.

.PARAMETER QueryFilter
A string to pass to the -filter query parameter in the Safeguard Web API.

.PARAMETER AllFields
Return all properties that can be displayed.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Find-SafeguardAccessRequest 123

.EXAMPLE
Find-SafeguardAccessRequest -SearchString testString -AllFields

.EXAMPLE
Find-SafeguardAccessRequest -QueryFilter "(AssetName eq 'Linux') and (AccountName eq 'root')"
#>
function Find-SafeguardAccessRequest
{
    [CmdletBinding(DefaultParameterSetName="Search")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0, ParameterSetName="Search")]
        [string]$SearchString,
        [Parameter(Mandatory=$true,Position=0,ParameterSetName="Query")]
        [string]$QueryFilter,
        [Parameter(Mandatory=$false)]
        [switch]$AllFields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSCmdlet.ParameterSetName -eq "Search")
    {
        $local:Parameters = @{ q = $SearchString }
    }
    else
    {
        $local:Parameters = @{ filter = $QueryFilter }
    }
    if (-not $AllFields)
    {
        $local:Parameters["fields"] = ($script:SgAccessRequestFields -join ",")
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
        GET "AccessRequests" -Parameters $local:Parameters
}

<#
.SYNOPSIS
Create a new access request via the Web API.

.DESCRIPTION
POST to the AccessRequests endpoint.  This script does not support all
possible options yet.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetToUse
An integer containing the ID of the asset to request or a string containing the name.

.PARAMETER AccountToUse
An integer containing the ID of the account to request or a string containing the name.

.PARAMETER AccessRequestType
A string containing the access request type: Password, Ssh, RemoteDesktop.

.PARAMETER AllFields
Return all properties that can be displayed.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
New-SafeguardAccessRequest testAsset testAccount Password
#>
function New-SafeguardAccessRequest
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [object]$AssetToUse,
        [Parameter(Mandatory=$false, Position=1)]
        [object]$AccountToUse,
        [Parameter(Mandatory=$true, Position=2)]
        [ValidateSet("Password", "SSHKey", "SSH", "RemoteDesktop", "RDP", "RemoteDesktopApplication", "RDPApplication", "RDPApp", "Telnet", IgnoreCase=$true)]
        [string]$AccessRequestType,
        [Parameter(Mandatory=$false)]
        [switch]$Emergency = $false,
        [Parameter(Mandatory=$false)]
        [object]$ReasonCode,
        [Parameter(Mandatory=$false)]
        [string]$ReasonComment,
        [Parameter(Mandatory=$false)]
        [string]$TicketNumber,
        [Parameter(Mandatory=$false)]
        [switch]$AllFields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($AllFields)
    {
        $local:RequestFields = $null
    }
    else
    {
        $local:RequestFields = $script:SgAccessRequestFields
    }

    if ($AccessRequestType -ieq "RDP")
    {
        $AccessRequestType = "RemoteDesktop"
    }
    elseif ($AccessRequestType -ieq "RDPApplication" -or $AccessRequestType -ieq "RDPApp")
    {
        $AccessRequestType = "RemoteDesktopApplication"
    }

    $local:AssetId = (Resolve-SafeguardRequestableAssetId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AssetToUse)
    $local:Body = @{
        AssetId = $local:AssetId;
        AccessRequestType = "$AccessRequestType"
    }

    if ($AccessRequestType -ieq "Password")
    {
        # Accounts are required for password requests, but not for sessions where you can use bring your own account
        if (-not $AccountToUse)
        {
            $AccountToUse = (Read-Host "AccountToUse")
        }
    }
    if ($AccountToUse)
    {
        $local:AccountId = (Resolve-SafeguardRequestableAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetId $local:AssetId $AccountToUse)
    }
    else
    {
        if ($PSBoundParameters.ContainsKey("AccountToUse"))
        {
            # Try to resolve AccountId, but do not fail on error
            try {
                $local:AccountId = (Resolve-SafeguardRequestableAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetId $local:AssetId $AccountToUse)
            }
            catch {
                Write-Warning $_
            }
        }
    }
    if ($local:AccountId) { $local:Body["AccountId"] = $local:AccountId }

    if ($Emergency) { $local:Body["IsEmergency"] = $true }
    if ($ReasonCode)
    {
        Import-Module -Name "$PSScriptRoot\sg-utilities.psm1" -Scope Local
        $local:ReasonCodeId = (Resolve-ReasonCodeId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $ReasonCode)
        $local:Body["ReasonCodeId"] = $local:ReasonCodeId
    }
    if ($ReasonComment) { $local:Body["ReasonComment"] = $ReasonComment }
    if ($TicketNumber) { $local:Body["TicketNumber"] = $TicketNumber }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
         POST "AccessRequests" -Body $local:Body | Select-Object -Property $local:RequestFields
}

<#
.SYNOPSIS
Perform an action on an access request via the Web API.

.DESCRIPTION
POST to the AccessRequests endpoint.  This script will allow you to Approve,
Deny, Review, Cancel, Close, CheckIn, CheckOutPassword, and InitializeSession
on an open access request.  You can also Acknowledge a closed request to remove
it from your actionable requests list.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER RequestId
A string containing the ID of the access request.

.PARAMETER Action
A string containing the action to perform.

.PARAMETER Comment
An optional string to comment on the action being performed.

.PARAMETER AllFields
Return all properties that can be displayed.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Edit-SafeguardAccessRequest 123 Approve

.EXAMPLE
Edit-SafeguardAccessRequest 123 Deny -Comment "testComment"
#>
function Edit-SafeguardAccessRequest
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [HashTable]$Parameters,
        [Parameter(Mandatory=$true, Position=0)]
        [string]$RequestId,
        [Parameter(Mandatory=$true, Position=1)]
        [ValidateSet("Approve", "Deny", "Review", "Cancel", "Close", "CheckIn", "CheckOutPassword", "CheckOutSshKey", "CheckOut", "InitializeSession", "Acknowledge", IgnoreCase=$true)]
        [string]$Action,
        [Parameter(Mandatory=$false)]
        [string]$Comment,
        [Parameter(Mandatory=$false)]
        [switch]$AllFields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    # Allow case insensitive actions to translate to appropriate case sensitive URL path
    switch ($Action)
    {
        "approve" { $Action = "Approve"; break }
        "deny" { $Action = "Deny"; break }
        "review" { $Action = "Review"; break }
        "cancel" { $Action = "Cancel"; break }
        "close" { $Action = "Close"; break }
        "checkin" { $Action = "CheckIn"; break }
        "checkout" { $Action = "CheckOutPassword"; break }
        "checkoutpassword" { $Action = "CheckOutPassword"; break }
        "checkoutsshkey" { $Action = "CheckOutSshKey"; break }
        "initializesession" { $Action = "InitializeSession"; break }
        "acknowledge" { $Action = "Acknowledge"; break }
    }

    if ($AllFields -or $Action -eq "CheckOutPassword" -or $Action -eq "CheckOutSshKey" -or $Action -eq "InitializeSession")
    {
        $local:RequestFields = $null
    }
    else
    {
        $local:RequestFields = $script:SgAccessRequestFields
    }

    if ($Comment)
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            POST "AccessRequests/$RequestId/$Action" -Parameters $Parameters -Body "$Comment" | Select-Object -Property $local:RequestFields
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            POST "AccessRequests/$RequestId/$Action" -Parameters $Parameters | Select-Object -Property $local:RequestFields
    }
}

<#
.SYNOPSIS
Get all access requests that this user can take action on via the Web API.

.DESCRIPTION
Call the Me endpoint to see all actionable requests.  This will return access
requests for which this user is the requester, an approver, or a reviewer.  If
this user is a policy admininstrator all access requests will also be returned
in the admin context.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER RequestRole
A string containing the request role: Admin, Approver, Requester, Reviewer

.PARAMETER AllFields
Return all properties that can be displayed.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardActionableRequest -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardActionableRequest Requester
#>
function Get-SafeguardActionableRequest
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false, Position=0)]
        [ValidateSet("Admin", "Approver", "Requester", "Reviewer",IgnoreCase=$true)]
        [string]$RequestRole,
        [Parameter(Mandatory=$false)]
        [switch]$AllFields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Parameters = $null
    if (-not $AllFields)
    {
        $local:Parameters = @{ fields = ($script:SgAccessRequestFields -join ",") }
    }

    # Allow case insensitive actions to translate to appropriate case sensitive URL path
    switch ($RequestRole)
    {
        "requester" { $RequestRole = "Requester"; break }
        "admin" {
            $RequestRole = "Admin";
            if ($local:Parameters)
            {
                $local:Parameters["fields"] = "$($local:Parameters.fields),WasCheckedOut"
            }
            break
        }
        "approver" {
            $RequestRole = "Approver";
            if ($local:Parameters)
            {
                $local:Parameters["fields"] += ",ApprovedByMe,CurrentApprovalCount,RequiredApprovalCount"
            }
            break
        }
        "reviewer" {
            $RequestRole = "Reviewer";
            if ($local:Parameters)
            {
                $local:Parameters["fields"] += ",RequireReviewerComment,CurrentReviewerCount,RequiredReviewerCount"
            }
            break
        }
    }

    if ($RequestRole)
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            GET "Me/ActionableRequests/$RequestRole" -Parameters $local:Parameters
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Me/ActionableRequests"
    }
}

<#
.SYNOPSIS
Get all access requests that this user has requested via the Web API.

.DESCRIPTION
Call the Me endpoint to see all actionable requests.  This will return access
requests for which this user is the requester.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AllFields
Return all properties that can be displayed.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardMyRequest -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardMyRequest
#>
function Get-SafeguardMyRequest
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [switch]$AllFields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Get-SafeguardActionableRequest -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Requester -AllFields:$AllFields
}

<#
.SYNOPSIS
Get all access requests that this user can approve via the Web API.

.DESCRIPTION
Call the Me endpoint to see all actionable requests.  This will return access
requests for which this user is an approver.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AllFields
Return all properties that can be displayed.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardMyApproval -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardMyApproval
#>
function Get-SafeguardMyApproval
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [switch]$AllFields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Get-SafeguardActionableRequest -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Approver -AllFields:$AllFields
}

<#
.SYNOPSIS
Get all access requests that this user can review via the Web API.

.DESCRIPTION
Call the Me endpoint to see all actionable requests.  This will return access
requests for which this user is a reviewer.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AllFields
Return all properties that can be displayed.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardMyReview -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardMyReview
#>
function Get-SafeguardMyReview
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [switch]$AllFields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Get-SafeguardActionableRequest -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Reviewer -AllFields:$AllFields
}

<#
.SYNOPSIS
Get all requestable accounts in Safeguard for this user via the Web API.

.DESCRIPTION
First call the Me endpoint for requestable Safeguard assets, then call
each in succession to get all accounts for those assets.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AllFields
Return all properties that can be displayed.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardRequestableAccount -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardRequestableAccount -AllFields
#>
function Get-SafeguardRequestableAccount
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [switch]$AllFields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            GET "Me/AccessRequestAssets") | ForEach-Object {
        $local:Asset = $_
        (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                Core GET "Me/RequestEntitlements" -Parameters @{ assetIds = "$($local:Asset.Id)" }) | ForEach-Object {
            New-RequestableAccountObject $local:Asset $_.Account $_.Policy -AllFields:$AllFields
        }
    }
}
New-Alias -Name Get-SafeguardMyRequestable -Value Get-SafeguardRequestableAccount

<#
.SYNOPSIS
Find requestable accounts in Safeguard for this user via the Web API.

.DESCRIPTION
Search for a requestable account

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER SearchString
A string containing the ID of the access request.

.PARAMETER AssetQueryFilter
A string to pass to the -filter query parameter for Assets in the Safeguard Web API.

.PARAMETER AccountQueryFilter
A string to pass to the -filter query parameter for Accounts in the Safeguard Web API.

.PARAMETER AllFields
Return all properties that can be displayed.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Find-SafeguardRequestableAccount -SearchString testString

.EXAMPLE
Find-SafeguardRequestableAccount -AssetQueryFilter "PlatformType eq 'Ubuntu'" -AccountQueryFilter "AccountRequestTypes contains 'LocalPassword'"
#>
function Find-SafeguardRequestableAccount
{
    [CmdletBinding(DefaultParameterSetName="Search")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0,ParameterSetName="Search")]
        [string]$SearchString,
        [Parameter(Mandatory=$false,ParameterSetName="Query")]
        [string]$AssetQueryFilter,
        [Parameter(Mandatory=$false,ParameterSetName="Query")]
        [string]$AccountQueryFilter,
        [Parameter(Mandatory=$false)]
        [switch]$AllFields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSCmdlet.ParameterSetName -eq "Search")
    {
        (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                GET "Me/AccessRequestAssets") | ForEach-Object {
            $local:Asset = $_
            (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                    GET "Me/RequestEntitlements" -Parameters @{ assetIds = "$($local:Asset.Id)"; q = $SearchString }) | ForEach-Object {
                New-RequestableAccountObject $local:Asset $_.Account $_.Policy -AllFields:$AllFields
            }
        }
    }
    else
    {
        if ($AssetQueryFilter)
        {
            if ($AccountQueryFilter)
            {
                (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                        GET "Me/AccessRequestAssets" -Parameters @{ filter = $AssetQueryFilter }) | ForEach-Object {
                    $local:Asset = $_
                    (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                            GET "Me/RequestEntitlements" -Parameters @{ assetIds = "$($local:Asset.Id)"; filter = $AccountQueryFilter }) | ForEach-Object {
                        New-RequestableAccountObject $local:Asset $_.Account $_.Policy -AllFields:$AllFields
                    }
                }
            }
            else
            {
                (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                        GET "Me/AccessRequestAssets" -Parameters @{ filter = $AssetQueryFilter }) | ForEach-Object {
                    $local:Asset = $_
                    (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                            GET "Me/RequestEntitlements" -Parameters @{ assetIds = "$($local:Asset.Id)" }) | ForEach-Object {
                        New-RequestableAccountObject $local:Asset $_.Account $_.Policy -AllFields:$AllFields
                    }
                }
            }
        }
        else
        {
            (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                    GET "Me/AccessRequestAssets") | ForEach-Object {
                $local:Asset = $_
                (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                        GET "Me/RequestEntitlements" -Parameters @{ assetIds = "$($local:Asset.Id)"; filter = $AccountQueryFilter }) | ForEach-Object {
                    New-RequestableAccountObject $local:Asset $_.Account $_.Policy -AllFields:$AllFields
                }
            }
        }
    }
}
New-Alias -Name Find-SafeguardMyRequestable -Value Find-SafeguardRequestableAccount

<#
.SYNOPSIS
Checks out the password for an access request via the Web API.

.DESCRIPTION
POST to the AccessRequests endpoint.  This script allows you to CheckoutPassword
on an approved access request.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER RequestId
A string containing the ID of the access request.

.INPUTS
None.

.OUTPUTS
A string containing the password.

.EXAMPLE
Get-SafeguardAccessRequestPassword 8518-1-18B1694CF1C0-0026
#>
function Get-SafeguardAccessRequestPassword
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [string]$RequestId
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Edit-SafeguardAccessRequest -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $RequestId CheckOutPassword
}
New-Alias -Name Get-SafeguardAccessRequestCheckoutPassword -Value Get-SafeguardAccessRequestPassword

<#
.SYNOPSIS
Checks out the password for an access request via the Web API and copies it to the clipboard.

.DESCRIPTION
POST to the AccessRequests endpoint.  This script allows you to CheckoutPassword
on an approved access request.  Then puts the value on the clipboard without displaying it.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER RequestId
A string containing the ID of the access request.

.INPUTS
None.

.OUTPUTS
None.

.EXAMPLE
Copy-SafeguardAccessRequestPassword 8518-1-18B1694CF1C0-0026
#>
function Copy-SafeguardAccessRequestPassword
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [string]$RequestId
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Password = (Get-SafeguardAccessRequestPassword -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $RequestId)
    try
    {
        Set-Clipboard -Value $local:Password
    }
    catch
    {
        try
        {
            Set-ClipboardText $local:Password
        }
        catch
        {
            Write-Host -ForegroundColor Yellow "Try to use the ClipboardText module, run 'Install-Module -Name ClipboardText'"
            throw $_
        }
    }
}

<#
.SYNOPSIS
Gets the SSH host key for an access request via the Web API.

.DESCRIPTION
This script allows you to get the SSH host key for an access request which can
be useful to safely communicate with a target asset.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER RequestId
A string containing the ID of the access request.

.INPUTS
None.

.OUTPUTS
None.

.EXAMPLE
Get-SafeguardAccessRequestSshHostKey 21-1-1-3901-1-4419154e2128482f9232e3e0a1708f41-0001
#>
function Get-SafeguardAccessRequestSshHostKey
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [string]$RequestId
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    (Get-SafeguardAccessRequest -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $RequestId -AllFields).AssetSshHostKey
}

<#
.SYNOPSIS
Gets the SSH private key for an access request via the Web API.

.DESCRIPTION
This script allows you to get the SSH private key for an access request which can
be useful to safely communicate with a target asset.  By default, it writes the
private key as a file, puts an SSH command in your command history, and writes the
passphrase to the clipboard.  That way you can use the private key by pressing
arrow-up to get the SSH command and pasting the password to decrypt the private key.

This default behavior can be modified using cmdlet parameters.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER RequestId
A string containing the ID of the access request.

.PARAMETER KeyFormat
A string containing which format to use for the private key.  The options are:
  - OpenSsh: OpenSSH legacy PEM format (default)
  - Ssh2: Tectia format for use with tools from SSH.com
  - Putty: Putty format for use with PuTTY tools

.PARAMETER ShowPassphrase
Whether or not to show the private key passphrase; by default it is copied to
the clipboard so it can be pasted.

.PARAMETER Raw
This parameter will cause the output of the API to be returned rather than
writing the private key to a file or adding a command to your command history.

.PARAMETER

.INPUTS
None.

.OUTPUTS
None.

.EXAMPLE
Get-SafeguardAccessRequestSshKey 21-1-1-3901-1-4419154e2128482f9232e3e0a1708f41-0001

.EXAMPLE
Get-SafeguardAccessRequestSshKey 21-1-1-3901-1-4419154e2128482f9232e3e0a1708f41-0001 -Raw

.EXAMPLE
Get-SafeguardAccessRequestSshKey 21-1-1-3901-1-4419154e2128482f9232e3e0a1708f41-0001 -ShowPassphrase -KeyFormat Ssh2
#>
function Get-SafeguardAccessRequestSshKey
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [string]$RequestId,
        [Parameter(Mandatory=$false)]
        [ValidateSet("OpenSsh", "Ssh2", "Putty", IgnoreCase=$true)]
        [string]$KeyFormat = "OpenSsh",
        [Parameter(Mandatory=$false)]
        [switch]$ShowPassphrase,
        [Parameter(Mandatory=$false)]
        [switch]$Raw
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Request = (Get-SafeguardAccessRequest -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $RequestId -AllFields)
    $local:Response = (Edit-SafeguardAccessRequest -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $RequestId `
                           -Parameters @{keyFormat = $KeyFormat} CheckOutSshKey)
    if ($Raw)
    {
        $local:Response
    }
    else
    {
        if ($KeyFormat -ieq "Putty")
        {
            $local:FileName = "id_$($local:Request.AccountName)_$($local:Request.AccountId).ppk"
        }
        else
        {
            $local:FileName = "id_$($local:Request.AccountName)_$($local:Request.AccountId).pk"
        }
        Out-File $local:FileName -Encoding ASCII -InputObject $local:Response.PrivateKey
        if ($PSVersionTable.PSEdition -eq "Core")
        {
            # TODO: change file permissions
        }
        else
        {
            try
            {
                $local:Rights = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $Env:USERNAME,2032127,0
                $local:Acl = (Get-Acl $local:FileName)
                $local:Acl.AddAccessRule($local:Rights)
                $local:Acl.SetAccessRuleProtection($true, $false)
                (Get-Item $local:FileName).SetAccessControl($local:Acl)
            }
            catch
            {
                Write-Host -ForegroundColor Yellow "Unable to set permissions on private key file: $($_.Exception.Message)"
            }
        }
        Write-Host "Private key: " -NoNewline
        Write-Host -ForegroundColor Green "$(Resolve-Path $local:FileName)"
        if ($local:Response.Passphrase)
        {
            if ($ShowPassphrase)
            {
                Write-Host "Passphrase: $($local:Response.Passphrase)"
            }
            else
            {
                try
                {
                    Set-Clipboard -Value $local:Response.Passphrase
                    Write-Host "Passphrase: (" -NoNewline
                    Write-Host -ForegroundColor Magenta "COPIED TO CLIPBOARD" -NoNewline
                    Write-Host ")"
                }
                catch
                {
                    try
                    {
                        Set-ClipboardText $local:Response.Passphrase
                        Write-Host "Passphrase: (" -NoNewline
                        Write-Host -ForegroundColor Magenta "COPIED TO CLIPBOARD" -NoNewline
                        Write-Host ")"
                    }
                    catch
                    {
                        Write-Host "Unable to copy passphrase to clipboard, if clipboard doesn't work try -ShowPassphrase or -Raw for full output"
                        Write-Host -ForegroundColor Yellow "Try to add clipboard support with the ClipboardText module, run 'Install-Module -Name ClipboardText'"
                        throw $_
                    }
                }
            }
        }
        else
        {
            Write-Host "Passphrase: <none>"
        }
        Write-Host "Command (" -NoNewline
        Write-Host -ForegroundColor Magenta "PRESS UP ARROW" -NoNewline
        Write-Host ") -- it has been inserted into your command history:"
        if ($KeyFormat -ieq "Putty")
        {
            $local:CommandLine = "putty.exe -ssh -i $(Resolve-Path $local:FileName) $($local:Request.AccountName)@$($local:Request.AssetNetworkAddress)"
        }
        else
        {
            $local:CommandLine = "ssh -i $(Resolve-Path $local:FileName) $($local:Request.AccountName)@$($local:Request.AssetNetworkAddress)"
        }
        Write-Host "  $($local:CommandLine)"
        [Microsoft.PowerShell.PSConsoleReadLine]::AddToHistory($local:CommandLine)
    }
}

<#
.SYNOPSIS
Generate an RDP file for an access request via the Web API.

.DESCRIPTION
POST to the AccessRequests endpoint.  This script allows you to InitializeSession
on an approved access request and save the resulting RDP file with the token
and the fake 'sg' password embedded to avoid prompts.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER RequestId
A string containing the ID of the access request.

.PARAMETER

.INPUTS
None.

.OUTPUTS
Path to the RDP file.

.EXAMPLE
Get-SafeguardAccessRequestRdpFile 8518-1-18B1694CF1C0-0026
#>
function Get-SafeguardAccessRequestRdpFile
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [string]$RequestId,
        [Parameter(Mandatory=$false)]
        [string]$OutFile
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:SessionData = (Edit-SafeguardAccessRequest -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $RequestId InitializeSession)
    if (-not $local:SessionData.RdpConnectionFile)
    {
        throw "Initialized session did not return RDP file data"
    }

    if (-not $OutFile)
    {
        $OutFile = "$RequestId.rdp"
    }

    $local:SessionData.RdpConnectionFile | Out-File -Encoding ASCII -FilePath $OutFile

    # add the fake password 'sg' on Windows
    if ($PSVersionTable.Platform -ne "Unix")
    {
        if (-not ([System.Management.Automation.PSTypeName]"RdpPasswordEncrypter").Type)
        {
            Add-Type -TypeDefinition @"
using System;
using System.Text;
using System.Security.Cryptography;
public class RdpPasswordEncrypter {
    public string GetEncryptedPassword(string password)
    {
        if (password == null) return null;
        try
        {
            byte[] byteArray = Encoding.UTF8.GetBytes("sg");
            var cypherData = ProtectedData.Protect(byteArray, null, DataProtectionScope.CurrentUser);
            StringBuilder hex = new StringBuilder(cypherData.Length * 2);
            foreach (byte b in cypherData) { hex.AppendFormat("{0:x2}", b); }
            return hex.ToString();
        }
        catch (Exception) { return null; }
    }
}
"@ -ReferencedAssemblies System.Security
        }
        $local:Encrypter = New-Object RdpPasswordEncrypter
        $local:FakePassword = $local:Encrypter.GetEncryptedPassword("sg")
        Write-Output "password 51:b:$($local:FakePassword)" | Out-File -Append -Encoding ASCII -FilePath $OutFile
    }
    # return outfile name
    (Resolve-Path $OutFile).Path
}

<#
.SYNOPSIS
Generate an SSH URL for an access request via the Web API.

.DESCRIPTION
POST to the AccessRequests endpoint.  This script allows you to InitializeSession
on an approved access request and generate an SSH URL that works with OpenSSH client.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER RequestId
A string containing the ID of the access request.

.PARAMETER

.INPUTS
None.

.OUTPUTS
A string containing the SSH URL.

.EXAMPLE
Get-SafeguardAccessRequestSshUrl 8518-1-18B1694CF1C0-0026
#>
function Get-SafeguardAccessRequestSshUrl
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [string]$RequestId
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:SessionData = (Edit-SafeguardAccessRequest -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $RequestId InitializeSession)
    if (-not $local:SessionData.SshConnectionString)
    {
        throw "Initialized session did not return SSH connection information"
    }

    $local:SessionData.ConnectionUri
}

<#
.SYNOPSIS
Generate an RDP URL for an access request via the Web API.

.DESCRIPTION
POST to the AccessRequests endpoint.  This script allows you to InitializeSession
on an approved access request and generate an RDP URL that can be used with an
RDP client.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER RequestId
A string containing the ID of the access request.

.PARAMETER

.INPUTS
None.

.OUTPUTS
A string containing the RDP URL.

.EXAMPLE
Get-SafeguardAccessRequestRdpUrl 8518-1-18B1694CF1C0-0026
#>
function Get-SafeguardAccessRequestRdpUrl
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [string]$RequestId
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:SessionData = (Edit-SafeguardAccessRequest -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $RequestId InitializeSession)
    if (-not $local:SessionData.RdpConnectionString)
    {
        throw "Initialized session did not return RDP connection information"
    }

    $local:SessionData.ConnectionUri
}

<#
.SYNOPSIS
Launch an SSH or RDP session for an access request via the Web API.

.DESCRIPTION
This cmdlet launches an SSH or RDP session from an approved access request.
It requires the OpenSSH client for SSH sessions.  It is installed be default
on the latest versions of Windows 10.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER RequestId
A string containing the ID of the access request.

.PARAMETER

.INPUTS
None.

.OUTPUTS
None.

.EXAMPLE
Start-SafeguardAccessRequestSession 8518-1-18B1694CF1C0-0026
#>
function Start-SafeguardAccessRequestSession
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [string]$RequestId
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:AccessRequest = (Get-SafeguardAccessRequest -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $RequestId)
    switch ($local:AccessRequest.AccessRequestType)
    {
        "Ssh" {
            & ssh (Get-SafeguardAccessRequestSshUrl $RequestId)
            break
        }
        "RemoteDesktop" {
            $local:OutFile = "$(Join-Path $([System.IO.Path]::GetTempPath()) "$($local:AccessRequest.Id).rdp")"
            Write-Verbose "RDP file location: $($local:OutFile)"
            & (Get-SafeguardAccessRequestRdpFile $RequestId -OutFile $local:OutFile)
            break
        }
        "Password" {
            throw "You cannot launch a session for a password request"
            break
        }
        "SSHKey" {
            throw "You cannot launch a session for an SSH Key request"
            break
        }
        "Telnet" {
            throw "You must start telnet sessions manually, safeguard-ps cannot launch your client"
        }
        default {
            throw "Unrecognized access request type '$($local:AccessRequest.AccessRequestType)', don't know how to launch it"
            break
        }
    }
}

<#
.SYNOPSIS
Launch an SSH or RDP session for an access request through SRA.

.DESCRIPTION
This cmdlet launches an SSH or RDP session from an approved access request.
It requires that SPP and SPS be set up to integrate with SRA.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER RequestId
A string containing the ID of the access request.

.PARAMETER

.INPUTS
None.

.OUTPUTS
None.

.EXAMPLE
Start-SafeguardAccessRequestWebSession 8518-1-18B1694CF1C0-0026
#>
function Start-SafeguardAccessRequestWebSession
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [string]$RequestId
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:SessionData = (Edit-SafeguardAccessRequest -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $RequestId InitializeSession)
    if (-not $local:SessionData.SraConnectionUri)
    {
        throw "Initialized session did not return SRA URL connection information"
    }

    Start-Process $local:SessionData.SraConnectionUri
}

<#
.SYNOPSIS
End an access request via the Web API.

.DESCRIPTION
This cmdlet ends an access request.  Depending on the state of the request
it will cancel, check in, close, or acknowledge the access request so that
it start transitioning toward the complete state.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER RequestId
A string containing the ID of the access request.

.PARAMETER AllFields
Return all properties that can be displayed.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Close-SafeguardAccessRequest 8518-1-18B1694CF1C0-0026
#>
function Close-SafeguardAccessRequest
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [string]$RequestId,
        [Parameter(Mandatory=$false)]
        [switch]$AllFields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:AccessRequest = (Get-SafeguardAccessRequest -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                                $RequestId -AllFields)
    $local:MyUser = (Get-SafeguardLoggedInUser -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -Fields Id,AdminRoles)
    if ($local:AccessRequest.RequesterId -eq $local:MyUser.Id -or $local:MyUser.AdminRoles -contains "PolicyAdmin")
    {
        if ($local:AccessRequest.RequesterId -eq $local:MyUser.Id)
        {
            switch ($local:AccessRequest.State)
            {
                { "New","PendingApproval","Approved","PendingTimeRequested","RequestAvailable","PendingAccountRestored","PendingPasswordReset" `
                        -contains $_ } {
                    Edit-SafeguardAccessRequest -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $RequestId Cancel -AllFields:$AllFields
                }
                { "PasswordCheckedOut","SshKeyCheckedOut","SessionInitialized" -contains $_ } {
                    Edit-SafeguardAccessRequest -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $RequestId CheckIn -AllFields:$AllFields
                }
                { "RequestCheckedIn","Terminated","PendingReview","PendingAccountSuspended" -contains $_ } {
                    Edit-SafeguardAccessRequest -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $RequestId Close -AllFields:$AllFields
                }
                { "Expired","PendingAcknowledgment" -contains $_ } {
                    Edit-SafeguardAccessRequest -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $RequestId Acknowledge -AllFields:$AllFields
                }
                { "Closed","Complete","Reclaimed" -contains $_ } {
                    Write-Verbose "Doing nothing for state '$($local:AccessRequest.State)'"
                }
                default {
                    Write-Host -ForegroundColor Yellow "Unrecognized state '$($local:AccessRequest.State)'"
                }
            }
        }
        else
        {
            Edit-SafeguardAccessRequest -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $RequestId Close -AllFields:$AllFields
        }
    }
    else
    {
        throw "You didn't request '$RequestId' and you are not a policy admin"
    }
}

<#
.SYNOPSIS
Approve an access request via the Web API.

.DESCRIPTION
This cmdlet approves an access request.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER RequestId
A string containing the ID of the access request.

.PARAMETER AllFields
Return all properties that can be displayed.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Approve-SafeguardAccessRequest 8518-1-18B1694CF1C0-0026
#>
function Approve-SafeguardAccessRequest
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [string]$RequestId,
        [Parameter(Mandatory=$false)]
        [switch]$AllFields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Edit-SafeguardAccessRequest -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $RequestId Approve -AllFields:$AllFields
}

<#
.SYNOPSIS
Deny an access request via the Web API.

.DESCRIPTION
This cmdlet denies or revokes an access request.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER RequestId
A string containing the ID of the access request.

.PARAMETER AllFields
Return all properties that can be displayed.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Deny-SafeguardAccessRequest 8518-1-18B1694CF1C0-0026
#>
function Deny-SafeguardAccessRequest
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [string]$RequestId,
        [Parameter(Mandatory=$false)]
        [switch]$AllFields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Edit-SafeguardAccessRequest -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $RequestId Deny -AllFields:$AllFields
}
New-Alias -Name Revoke-SafeguardAccessRequest -Value Deny-SafeguardAccessRequest

<#
.SYNOPSIS
Get action log to review an access request via the Web API.

.DESCRIPTION
You can use this cmdlet to review before calling the
Assert-SafeguardAccessRequest cmdlet.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER RequestId
A string containing the ID of the access request.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardAccessRequestActionLog 8518-1-18B1694CF1C0-0026
#>
function Get-SafeguardAccessRequestActionLog
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [string]$RequestId
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    (Get-SafeguardAccessRequest -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $RequestId -AllFields).WorkflowActions
}

<#
.SYNOPSIS
Mark an access request as reviewed via the Web API.

.DESCRIPTION
This cmdlet marks an access request as reviewed.  You can use the
Get-SafeguardAccessRequestActionLog to review before calling this cmdlet.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER RequestId
A string containing the ID of the access request.

.PARAMETER AllFields
Return all properties that can be displayed.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Assert-SafeguardAccessRequest 8518-1-18B1694CF1C0-0026
#>
function Assert-SafeguardAccessRequest
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [string]$RequestId,
        [Parameter(Mandatory=$false)]
        [switch]$AllFields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Edit-SafeguardAccessRequest -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $RequestId Review -AllFields:$AllFields
}
