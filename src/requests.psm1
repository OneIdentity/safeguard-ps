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
            $local:Assets = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Me/RequestableAssets" `
                                 -Parameters @{ filter = "Name ieq '$Asset'" })
            if (-not $local:Assets)
            {
                $local:Assets = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Me/RequestableAssets" `
                                     -Parameters @{ filter = "NetworkAddress ieq '$Asset'" })
            }
        }
        catch
        {
            Write-Verbose $_
            Write-Verbose "Caught exception with ieq filter, trying with q parameter"
            $local:Assets = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Me/RequestableAssets" `
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
        $local:RelativeUrl = "Me/RequestableAssets/$AssetId/Accounts"
        try
        {
            $local:Accounts = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET $local:RelativeUrl `
                                   -Parameters @{ filter = "Name ieq '$Account'" })
        }
        catch
        {
            Write-Verbose $_
            Write-Verbose "Caught exception with ieq filter, trying with q parameter"
            $local:Accounts = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET $local:RelativeUrl `
                                   -Parameters @{ q = $Account })
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
            PlatformId = $Asset.PlatformId;
            PlatformType = $Asset.PlatformType;
            PlatformDisplayName = $Asset.PlatformDisplayName;
            SshHostKey = $Asset.SshHostKey;
            SshHostKeyFingerprint = $Asset.SshHostKeyFingerprint;
            SessionAccessProperties = $Asset.SessionAccessProperties;
            AccountId = $Account.Id;
            AccountNetBiosName = $Account.NetBiosName;
            AccountDomainName = $Account.DomainName;
            AccountName = $Account.Name;
            AccountDescription = $Account.Description;
            SuspendAccountWhenCheckedIn = $Account.SuspendAccountWhenCheckedIn;
            AccountRequestTypes = $Account.AccountRequestTypes;
        })
    }
    else
    {
        New-Object PSObject -Property ([ordered]@{
            AssetId = $Asset.Id;
            AssetName = $Asset.Name;
            NetworkAddress = $Asset.NetworkAddress;
            AccountId = $Account.Id;
            AccountDomainName = $Account.DomainName;
            AccountName = $Account.Name;
            AccountRequestTypes = $Account.AccountRequestTypes;
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
        [ValidateSet("Password", "SSH", "RemoteDesktop", "RDP", IgnoreCase=$true)]
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

    $local:AssetId = (Resolve-SafeguardRequestableAssetId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AssetToUse)
    $local:Body = @{
        SystemId = $local:AssetId;
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
        [Parameter(Mandatory=$true, Position=0)]
        [string]$RequestId,
        [Parameter(Mandatory=$true, Position=1)]
        [ValidateSet("Approve", "Deny", "Review", "Cancel", "Close", "CheckIn", "CheckOutPassword", "CheckOut", "InitializeSession", "Acknowledge", IgnoreCase=$true)]
        [string]$Action,
        [Parameter(Mandatory=$false)]
        [string]$Comment,
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
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            POST "AccessRequests/$RequestId/$Action" -Body "$Comment" | Select-Object -Property $local:RequestFields
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            POST "AccessRequests/$RequestId/$Action" | Select-Object -Property $local:RequestFields
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
            GET "Me/RequestableAssets") | ForEach-Object {
        $local:Asset = $_
        (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                Core GET "Me/RequestableAssets/$($local:Asset.Id)/Accounts") | ForEach-Object {
            New-RequestableAccountObject $local:Asset $_ -AllFields:$AllFields
        }
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
                GET "Me/RequestableAssets") | ForEach-Object {
            $local:Asset = $_
            (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                    GET "Me/RequestableAssets/$($local:Asset.Id)/Accounts" -Parameters @{ q = $SearchString }) | ForEach-Object {
                New-RequestableAccountObject $local:Asset $_ -AllFields:$AllFields
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
                        GET "Me/RequestableAssets" -Parameters @{ filter = $AssetQueryFilter }) | ForEach-Object {
                    $local:Asset = $_
                    (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                            GET "Me/RequestableAssets/$($local:Asset.Id)/Accounts" -Parameters @{ filter = $AccountQueryFilter }) | ForEach-Object {
                        New-RequestableAccountObject $local:Asset $_ -AllFields:$AllFields
                    }
                }
            }
            else
            {
                (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                        GET "Me/RequestableAssets" -Parameters @{ filter = $AssetQueryFilter }) | ForEach-Object {
                    $local:Asset = $_
                    (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                            GET "Me/RequestableAssets/$($local:Asset.Id)/Accounts" ) | ForEach-Object {
                        New-RequestableAccountObject $local:Asset $_ -AllFields:$AllFields
                    }
                }
            }
        }
        else
        {
            (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                    GET "Me/RequestableAssets") | ForEach-Object {
                $local:Asset = $_
                (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
                        GET "Me/RequestableAssets/$($local:Asset.Id)/Accounts" -Parameters @{ filter = $AccountQueryFilter }) | ForEach-Object {
                    New-RequestableAccountObject $local:Asset $_ -AllFields:$AllFields
                }
            }
        }
    }
}

<#
.SYNOPSIS
Checkouts out password for an access request via the Web API.

.DESCRIPTION
POST to the AccessRequests endpoint.  This script allows you to CheckoutPassword
on an approved pull request.

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
Get-SafeguardAccessRequestPassword 123
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

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "AccessRequests/$RequestId/CheckoutPassword"
}
New-Alias -Name Get-SafeguardAccessRequestCheckoutPassword -Value Get-SafeguardAccessRequestPassword