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

if($Insecure)
{
    # GET notification/v3/Status
    echo "GET status"
    $status = Get-SafeguardStatus -Appliance $Appliance -Insecure

    # GET appliance/v3/Version
    echo "GET version"
    $ver = Get-SafeguardVersion -Appliance $Appliance -Insecure

    # -- Login --
    echo "login"
    Connect-Safeguard -Appliance $Appliance -IdentityProvider $IdentityProvider -Username $UserName -Password $Password -Insecure
}
else
{
    # GET notification/v3/Status
    echo "GET status" 
    Get-SafeguardStatus -Appliance $Appliance

    # GET appliance/v3/Version
    echo "GET version"
    Get-SafeguardVersion -Appliance $Appliance

    # -- Login --
    echo "login"
    Connect-Safeguard -Appliance $Appliance -IdentityProvider $IdentityProvider -Username $UserName -Password $Password
}

# GET core/v3/ClusterStatus
echo "GET Cluster Status:"
$status = Invoke-SafeguardMethod Core GET "Cluster/Status"

# GET core/v3/Me
echo "GET Me" 
$me = Invoke-SafeguardMethod Core GET "Me"

# GET core/v3/DailyMessage
echo "GET Daily Message:" 
$dm = Invoke-SafeguardMethod Core GET "DailyMessage"

# GET core/v3/LoginMessage
echo "GET Login Message:" 
$lm = Invoke-SafeguardMethod Core GET "LoginMessage"

# GET core/v3/RequestFavorites
echo "GET Request Favorites:"
$requestFavorites = Invoke-SafeguardMethod Core GET "Me/RequestFavorites"

# GET core/v3/Me/ActionableRequests
echo "GET Actionable Requests:"
$actionableRequests = Invoke-SafeguardMethod Core GET "Me/ActionableRequests"

# GET core/v3/Me?fields=Id
echo "GET Me.Id" 
$userId = Invoke-SafeguardMethod Core GET "Me?fields=Id"

# GET core/v3/Me/AccessRequestAssets?filter=Disabled%20eq%20false&fields=Id,Name,NetworkAddress,PlatformDisplayName&orderby=Name
echo "GET Requestable Assets"
$accessRequestAssets = Invoke-SafeguardMethod Core GET "Me/AccessRequestAssets?filter=Disabled%20eq%20false&fields=Id,Name,NetworkAddress,PlatformDisplayName&orderby=Name"

# -- select asset --
echo "Selecting Asset $AssetName"
$selectedAsset = $accessRequestAssets | Where-Object Name -eq $AssetName
if($selectedAsset -eq $null)
{
    throw "Specified asset is not a Requestable Asset"
}

# GET core/v3/Me/RequestEntitlements?assetIds=<num>
echo "GET Request Entitlements"
$requestEntitlements = Invoke-SafeguardMethod Core GET "Me/RequestEntitlements?assetIds=[$($selectedAsset.Id)]"

# -- select account --
echo "Selecting Account $AccountName"
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
    SystemId = $($selectedAsset.Id)
    AccountId = $($selectedAccount.Id)
    AccessRequestType = "Password"
    })

echo "POST BatchCreate"
$batchCreateResponse = Invoke-SafeguardMethod Core POST "AccessRequests/BatchCreate" -Body $body

# GET core/v3/Me/ActionableRequests
echo "GET Actionable Requests"
$actionableRequests = Invoke-SafeguardMethod Core GET "Me/ActionableRequests"

# GET core/v3/Me/RequestableAssets/<num>/Accounts/<num>/Policies
echo "GET Policies"
$Policies = Invoke-SafeguardMethod Core GET "Me/RequestableAssets/$($selectedAsset.Id)/Accounts/$($selectedAccount.Id)/Policies"

# POST core/v3/AccessRequests/<request_id>/CheckoutPassword
echo "POST CheckoutPassword"
$accountPassword = Invoke-SafeguardMethod Core POST "AccessRequests/$($batchCreateResponse.Response.Id)/CheckoutPassword"

# GET core/v3/Me/ActionableRequests
echo "GET ActionableRequests"
$actionableRequests = Invoke-SafeguardMethod Core GET "Me/ActionableRequests"

# GET core/v3/Me/RequestableAssets/<num>/Accounts/<num>/Policies
echo "GET Policies"
$Policies = Invoke-SafeguardMethod Core GET "Me/RequestableAssets/$($selectedAsset.Id)/Accounts/$($selectedAccount.Id)/Policies"

# POST core/v3/AccessRequests/<request_id>/CheckIn
echo "POST CheckIn"
$checkInResponse = Invoke-SafeguardMethod Core POST "AccessRequests/$($batchCreateResponse.Response.Id)/CheckIn"

# GET core/v3/Me/ActionableRequests
echo "GET Actionable Request" 
$actionableRequests = Invoke-SafeguardMethod Core GET "Me/ActionableRequests"