# Helper
function Resolve-SafeguardRequestableAssetId
{
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

    $ErrorActionPreference = "Stop"

    if (-not ($Asset -as [int]))
    {
        $local:Assets = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Me/RequestableAssets" `
                                                -Parameters @{ filter = "Name ieq '$Asset'" })
        if (-not $local:Assets)
        {
            $local:Assets = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Me/RequestableAssets" `
                                                    -Parameters @{ filter = "NetworkAddress ieq '$Asset'" })
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

    $ErrorActionPreference = "Stop"

    if (-not ($Account -as [int]))
    {
        $local:RelativeUrl = "Me/RequestableAssets/$AssetId/Accounts"
        $local:Accounts = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET $local:RelativeUrl `
                                                  -Parameters @{ filter = "Name ieq '$Account'" })
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

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.
#>
function Get-SafeguardAccessRequest
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false, Position=0)]
        [string]$RequestId
    )

    $ErrorActionPreference = "Stop"

    if ($PSBoundParameters.ContainsKey("RequestId"))
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "AccessRequests/$RequestId"
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "AccessRequests"
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

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.
#>
function Find-SafeguardAccessRequest
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [string]$SearchString
    )

    $ErrorActionPreference = "Stop"

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "AccessRequests" `
        -Parameters @{ q = $SearchString }
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

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.
#>
function New-SafeguardAccessRequest
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [object]$AssetToUse,
        [Parameter(Mandatory=$true, Position=1)]
        [object]$AccountToUse,
        [Parameter(Mandatory=$true, Position=2)]
        [ValidateSet("Password", "SSH", "RemoteDesktop", "RDP", IgnoreCase=$true)]
        [string]$AccessRequestType
    )

    $ErrorActionPreference = "Stop"

    if ($AccessRequestType -ieq "RDP")
    {
        $AccessRequestType = "RemoteDesktop"
    }

    $local:AssetId = (Resolve-SafeguardRequestableAssetId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AssetToUse)
    $local:AccountId = (Resolve-SafeguardRequestableAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetId $local:AssetId $AccountToUse)

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "AccessRequests" -Body @{
        SystemId = $local:AssetId;
        AccountId = $local:AccountId;
        AccessRequestType = "$AccessRequestType"
    }
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

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.
#>
function Edit-SafeguardAccessRequest
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [string]$RequestId,
        [Parameter(Mandatory=$true, Position=1)]
        [ValidateSet("Approve", "Deny", "Review", "Cancel", "Close", "CheckIn", "CheckOutPassword", "CheckOut", "InitializeSession", "Acknowledge", IgnoreCase=$true)]
        [string]$Action,
        [Parameter(Mandatory=$false)]
        [string]$Comment
    )

    $ErrorActionPreference = "Stop"

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
        "initializesession" { $Action = "InitializeSession"; break }
        "acknowledge" { $Action = "Acknowledge"; break }
    }

    if ($Comment)
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "AccessRequests/$RequestId/$Action" -Body "$Comment"
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "AccessRequests/$RequestId/$Action"
    }
}

<#
.SYNOPSIS
Get all requestable Safeguard accounts for this user via the Web API.

.DESCRIPTION
Call the Me endpoint to see all actionable requests.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER RequestRole
A string containing the request role: Admin, Approver, Requester, Reviewer

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.
#>
function Get-SafeguardActionableRequest
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false, Position=0)]
        [ValidateSet("Admin", "Approver", "Requester", "Reviewer",IgnoreCase=$true)]
        [string]$RequestRole
    )

    $ErrorActionPreference = "Stop"

    # Allow case insensitive actions to translate to appropriate case sensitive URL path
    switch ($Action)
    {
        "admin" { $Action = "Admin"; break }
        "approver" { $Action = "Approver"; break }
        "requester" { $Action = "Requester"; break }
        "reviewer" { $Action = "Reviewer"; break }
    }

    if ($RequestRole)
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Me/ActionableRequests/$RequestRole"
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Me/ActionableRequests"
    }
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

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.
#>
function Get-SafeguardRequestableAccount
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure
    )

    $ErrorActionPreference = "Stop"

    (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Me/RequestableAssets") | ForEach-Object {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Me/RequestableAssets/$($_.Id)/Accounts"
    }
}

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

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.
#>
function Find-SafeguardRequestableAccount
{
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [string]$SearchString
    )

    $ErrorActionPreference = "Stop"

    (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Me/RequestableAssets") | ForEach-Object {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Me/RequestableAssets/$($_.Id)/Accounts" `
            -Parameters @{ q = $SearchString }
    }
}