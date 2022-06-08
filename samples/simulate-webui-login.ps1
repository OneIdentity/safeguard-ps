[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$Appliance,
    [Parameter(Mandatory=$true)]
    [string]$IdentityProvider,
    [Parameter(Mandatory=$true)]
    [string]$UserName,
    [Parameter(Mandatory=$true)]
    [SecureString]$Password,
    [Parameter(Mandatory=$false)]
    [Switch]$Insecure = $false,
    [Parameter(Mandatory=$true)]
    [string]$AssetName,
    [Parameter(Mandatory=$true)]
    [string]$AccountName
)

if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }

# GET notification/v3/Status
Write-Host -ForegroundColor Yellow  "GET status"
$status = Get-SafeguardStatus -Appliance $Appliance -Insecure:$Insecure

# GET appliance/v3/Version
Write-Host -ForegroundColor Yellow  "GET version"
$ver = Get-SafeguardVersion -Appliance $Appliance -Insecure:$Insecure

# -- Login --
Write-Host -ForegroundColor Yellow  "login"
Connect-Safeguard -Appliance $Appliance -IdentityProvider $IdentityProvider -Username $UserName -Password $Password -Insecure:$Insecure

# GET core/v3/ClusterStatus
Write-Host -ForegroundColor Yellow  "GET Cluster Status:"
$status = Invoke-SafeguardMethod Core GET "Cluster/Status"

# GET core/v3/Me
Write-Host -ForegroundColor Yellow  "GET Me"
$me = Invoke-SafeguardMethod Core GET "Me"

# GET core/v3/DailyMessage
Write-Host -ForegroundColor Yellow  "GET Daily Message:"
$dm = Invoke-SafeguardMethod Core GET "DailyMessage"

# GET core/v3/LoginMessage
Write-Host -ForegroundColor Yellow  "GET Login Message:"
$lm = Invoke-SafeguardMethod Core GET "LoginMessage"

# GET core/v3/RequestFavorites
Write-Host -ForegroundColor Yellow  "GET Request Favorites:"
$requestFavorites = Invoke-SafeguardMethod Core GET "Me/RequestFavorites"

# GET core/v3/Me/ActionableRequests
Write-Host -ForegroundColor Yellow  "GET Actionable Requests:"
$actionableRequests = Invoke-SafeguardMethod Core GET "Me/ActionableRequests"

# GET core/v3/Me?fields=Id
Write-Host -ForegroundColor Yellow  "GET Me.Id"
$userId = Invoke-SafeguardMethod Core GET "Me?fields=Id"

# GET core/v3/Me/AccessRequestAssets?filter=Disabled%20eq%20false&fields=Id,Name,NetworkAddress,PlatformDisplayName&orderby=Name
Write-Host -ForegroundColor Yellow  "GET Requestable Assets"
$accessRequestAssets = Invoke-SafeguardMethod Core GET "Me/AccessRequestAssets?filter=Disabled%20eq%20false&fields=Id,Name,NetworkAddress,PlatformDisplayName&orderby=Name"

# -- select asset --
Write-Host -ForegroundColor Yellow  "Selecting Asset $AssetName"
$selectedAsset = $accessRequestAssets | Where-Object Name -eq $AssetName
if($selectedAsset -eq $null)
{
    throw "Specified asset is not a Requestable Asset"
}

# GET core/v3/Me/RequestEntitlements?assetIds=<num>
Write-Host -ForegroundColor Yellow  "GET Request Entitlements"
$requestEntitlements = Invoke-SafeguardMethod Core GET "Me/RequestEntitlements?assetIds=[$($selectedAsset.Id)]"

# -- select account --
Write-Host -ForegroundColor Yellow  "Selecting Account $AccountName"
$selectedEntitlement = $requestEntitlements | Where-Object {$_.Account.Name -eq $AccountName}
$selectedAccount = $selectedEntitlement.Account
if($selectedAccount -eq $null)
{
    throw "Specified account is not a Requestable Account"
}


# POST core/v3/AccessRequests/BatchCreate

$body = @( @{
    IsEmergency = $false
    RequestedDurationDays = 0
    RequestedDurationHours = 10
    RequestedDurationMinutes = 0
    AssetId = $($selectedAsset.Id)
    AccountId = $($selectedAccount.Id)
    AccessRequestType = "Password"
    })

Write-Host -ForegroundColor Yellow  "POST BatchCreate"
$batchCreateResponse = Invoke-SafeguardMethod Core POST "AccessRequests/BatchCreate" -Body $body

# GET core/v3/Me/ActionableRequests
Write-Host -ForegroundColor Yellow  "GET Actionable Requests"
$actionableRequests = Invoke-SafeguardMethod Core GET "Me/ActionableRequests"

# GET core/v3/Me/RequestableAssets/<num>/Accounts/<num>/Policies
Write-Host -ForegroundColor Yellow  "GET Policies"
$Policies = Invoke-SafeguardMethod -Version 3 Core GET "Me/RequestableAssets/$($selectedAsset.Id)/Accounts/$($selectedAccount.Id)/Policies"

# POST core/v3/AccessRequests/<request_id>/CheckoutPassword
Write-Host -ForegroundColor Yellow  "POST CheckoutPassword"
$accountPassword = Invoke-SafeguardMethod Core POST "AccessRequests/$($batchCreateResponse.Response.Id)/CheckoutPassword"

# GET core/v3/Me/ActionableRequests
Write-Host -ForegroundColor Yellow  "GET ActionableRequests"
$actionableRequests = Invoke-SafeguardMethod Core GET "Me/ActionableRequests"

# GET core/v3/Me/RequestableAssets/<num>/Accounts/<num>/Policies
Write-Host -ForegroundColor Yellow  "GET Policies"
$Policies = Invoke-SafeguardMethod -Version 3 Core GET "Me/RequestableAssets/$($selectedAsset.Id)/Accounts/$($selectedAccount.Id)/Policies"

# POST core/v3/AccessRequests/<request_id>/CheckIn
Write-Host -ForegroundColor Yellow  "POST CheckIn"
$checkInResponse = Invoke-SafeguardMethod Core POST "AccessRequests/$($batchCreateResponse.Response.Id)/CheckIn"

# GET core/v3/Me/ActionableRequests
Write-Host -ForegroundColor Yellow  "GET Actionable Request"
$actionableRequests = Invoke-SafeguardMethod Core GET "Me/ActionableRequests"

# -- Logout --
Disconnect-Safeguard