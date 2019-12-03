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
    [Parameter(Mandatory=$false)]
    [string]$AssetPartitionName,
    [Parameter(Mandatory=$true, Position=0)]
    [int]$Quantity,
    [Parameter(Mandatory=$false)]
    [switch]$NoAccounts
)

function Add-OneThousand
{
    if ($script:Remaining -ge 1000)
    {
        $local:Chunk = 1000
    }
    else
    {
        $local:Chunk = $script:Remaining
    }

    Write-Host -ForegroundColor Green ("[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)) -NoNewline
    Write-Host -ForegroundColor Yellow "-- Adding $local:Chunk assets -- $script:Prefix-$($script:FormatString -f $script:Index) through $script:Prefix-$($script:FormatString -f ($script:Index + $local:Chunk - 1))" | Out-Host

    $local:Body = @()
    for ($local:i = 1; $local:i -le $local:Chunk; $local:i++)
    {
        $local:Body += @{
            Name = "$script:Prefix-$($script:FormatString -f $script:Index)";
            Description = "Generated Asset";
            PlatformId = $script:PlatformId;
            AssetPartitionId = $script:AssetPartitionId;
            ConnectionProperties = @{
                ServiceAccountCredentialType = "Custom"
            }
        }
        $script:Index++
    }
    $local:NewAssetIds = (Invoke-SafeguardMethod -Appliance $Appliance -AccessToken $script:Token -Insecure:$Insecure core POST Assets/BatchCreate -Body $local:Body -Timeout 3600).Response.Id
    if (-not $NoAccounts)
    {
        Write-Host -ForegroundColor Green ("[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)) -NoNewline
        Write-Host -ForegroundColor Yellow "-- Adding $local:Chunk accounts to those assets" | Out-Host
        $local:Body = @()
        foreach ($local:NewAssetId in $local:NewAssetIds)
        {
            $local:Body += @{
                AssetId = $local:NewAssetId;
                Name = "root"
            }
        }
        Invoke-SafeguardMethod -Appliance $Appliance -AccessToken $script:Token -Insecure:$Insecure core POST AssetAccounts/BatchCreate -Body $local:Body -Timeout 3600 | Out-Null
    }
    $script:Remaining -= $local:Chunk
}

$ErrorActionPreference = "Stop"

$script:Prefix = ((65..90) | Get-Random -Count 5 | ForEach-Object { [char]$_ }) -join ""
$script:Token = (Connect-Safeguard -Appliance $Appliance -IdentityProvider $IdentityProvider -Username $UserName -Password $Password -Insecure:$Insecure -NoSessionVariable)

$script:Remaining = $Quantity
$script:FormatString = "{0:d$(([string]$Quantity).Length)}"
$script:Index = 1

$script:PlatformId = (Get-SafeguardPlatform -Appliance $Appliance -AccessToken $script:Token -Insecure:$Insecure 'Other Managed').Id

if ($AssetPartitionName)
{
    $script:AssetPartitionId = (Get-SafeguardAssetPartition -Appliance $Appliance -AccessToken $script:Token -Insecure:$Insecure $AssetPartitionName).Id
}
else
{
    $script:AssetPartitionId = -1
}

Write-Host -ForegroundColor Magenta "Generating $Quantity Assets of type 'Other Managed' with random prefix '$script:Prefix-'"
while ($script:Remaining -gt 0)
{
    Add-OneThousand
}
