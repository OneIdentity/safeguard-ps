[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false)]
    [string]$AssetPartitionName,
    [Parameter(Mandatory=$true, Position=0)]
    [int]$Quantity,
    [Parameter(Mandatory=$false)]
    [ValidateSet("OtherManaged","Linux")]
    [string]$Platform = "OtherManaged",
    [Parameter(Mandatory=$false)]
    [string]$AssetPrefix,
    [Parameter(Mandatory=$false)]
    [string]$AccountName = "root",
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
            NetworkAddress = "generated.fake.dns";
            PlatformId = $script:PlatformId;
            AssetPartitionId = $script:AssetPartitionId;
            ConnectionProperties = $script:ConnectionProps
        }
        $script:Index++
    }
    Write-Host -ForegroundColor Green ("[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)) -NoNewline
    Write-Host -ForegroundColor Yellow "-- Request prepared, sending" | Out-Host
    $local:NewAssetIds = (Invoke-SafeguardMethod core POST Assets/BatchCreate -Body $local:Body -Timeout 3600).Response.Id
    if (-not $NoAccounts)
    {
        Write-Host -ForegroundColor Green ("[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)) -NoNewline
        Write-Host -ForegroundColor Yellow "-- Adding $local:Chunk accounts to those assets" | Out-Host
        $local:Body = @()
        foreach ($local:NewAssetId in $local:NewAssetIds)
        {
            $local:Body += @{
                AssetId = $local:NewAssetId;
                Name = $AccountName
            }
        }
        Write-Host -ForegroundColor Green ("[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)) -NoNewline
        Write-Host -ForegroundColor Yellow "-- Request prepared, sending" | Out-Host
        Invoke-SafeguardMethod core POST AssetAccounts/BatchCreate -Body $local:Body -Timeout 3600 | Out-Null
    }
    $script:Remaining -= $local:Chunk
}

$ErrorActionPreference = "Stop"

if (-not $SafeguardSession)
{
    throw "This cmdlet requires that you log in with the Connect-Safeguard cmdlet"
}

if ($AssetPrefix)
{
    $script:Prefix = $AssetPrefix
}
else
{
    $script:Prefix = ((65..90) | Get-Random -Count 5 | ForEach-Object { [char]$_ }) -join ""
}


$script:Remaining = $Quantity
$script:FormatString = "{0:d$(([string]$Quantity).Length)}"
$script:Index = 1

if ($Platform -ieq "Linux")
{
    $script:ConnectionProps = @{ ServiceAccountCredentialType = "None" }
    $script:PlatformId = (Get-SafeguardPlatform  'Other Linux').Id
}
else
{
    $script:ConnectionProps = @{ ServiceAccountCredentialType = "Custom" }
    $script:PlatformId = (Get-SafeguardPlatform  'Other Managed').Id
}

if ($AssetPartitionName)
{
    $script:AssetPartitionId = (Get-SafeguardAssetPartition $AssetPartitionName).Id
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
