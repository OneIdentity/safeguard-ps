# Helpers
function Resolve-SafeguardProfileItemId
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
        [object]$AssetPartition = $null,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true)]
        [ValidateSet("PasswordRule", "CheckSchedule", "ChangeSchedule", "Profile", IgnoreCase=$true)]
        [string]$ItemType,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$Item
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    switch ($ItemType)
    {
        "passwordrule" { $local:ResourceName = "PasswordRules"; $local:ErrorResource = "account password rule"; break}
        "checkschedule" { $local:ResourceName = "CheckSchedules"; $local:ErrorResource = "password check schedule"; break }
        "changeschedule" { $local:ResourceName = "ChangeSchedules"; $local:ErrorResource = "password change schedule"; break }
        "profile" { $local:ResourceName = "Profiles"; $local:ErrorResource = "password profile"; break }
    }

    if ($Item.Id -as [int])
    {
        $Item = $Item.Id
    }

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                             -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId)
    if ($AssetPartitionId)
    {
        $local:RelPath = "AssetPartitions/$AssetPartitionId/$($local:ResourceName)"
        $local:ErrMsgSuffix = " in asset partition (Id=$AssetPartitionId)"
    }
    else
    {
        $local:RelPath = "AssetPartitions/$($local:ResourceName)"
        $local:ErrMsgSuffix = ""
    }

    if (-not ($Item -as [int]))
    {
        try
        {
            $local:ItemList = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" `
                                   -Parameters @{ filter = "Name ieq '$Item'"; fields = "Id" })
        }
        catch
        {
            Write-Verbose $_
            Write-Verbose "Caught exception with ieq filter, trying with q parameter"
            $local:ItemList = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" `
                                   -Parameters @{ q = $Item; fields = "Id" })
        }
        if (-not $local:ItemList)
        {
            throw "Unable to find $($local:ErrorResource) matching '$Item'$($local:ErrMsgSuffix)"
        }
        if ($local:ItemList.Count -ne 1)
        {
            throw "Found $($local:ItemList.Count) $($local:ErrorResource)s matching '$Item'$($local:ErrMsgSuffix)"
        }
        $local:ItemList[0].Id
    }
    else
    {
        if ($AssetPartitionId)
        {
            # Make sure it actually exists
            $local:ItemList = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" `
                                   -Parameters @{ filter = "Id eq $Item and AssetPartitionId eq $AssetPartitionId"; fields = "Id" })
            if (-not $local:ItemList)
            {
                throw "Unable to find $($local:ErrorResource) matching '$Item'$($local:ErrMsgSuffix)"
            }
        }
        $Item
    }
}
function Resolve-SafeguardAccountPasswordRuleId
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
        [object]$AssetPartition = $null,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$AccountPasswordRule
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Resolve-SafeguardProfileItemId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
        -AssetPartition $AssetPartition -AssetPartitionId $AssetPartition -ItemType "PasswordRule" -Item $AccountPasswordRule
}
function Resolve-SafeguardPasswordCheckScheduleId
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
        [object]$AssetPartition = $null,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$PasswordCheckSchedule
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Resolve-SafeguardProfileItemId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
        -AssetPartition $AssetPartition -AssetPartitionId $AssetPartition -ItemType "CheckSchedule" -Item $PasswordCheckSchedule
}
function Resolve-SafeguardPasswordChangeScheduleId
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
        [object]$AssetPartition = $null,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$PasswordChangeSchedule
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Resolve-SafeguardProfileItemId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
        -AssetPartition $AssetPartition -AssetPartitionId $AssetPartition -ItemType "ChangeSchedule" -Item $PasswordChangeSchedule
}
function Resolve-SafeguardPasswordProfileId
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
        [object]$AssetPartition = $null,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$PasswordProfile
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Resolve-SafeguardProfileItemId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
        -AssetPartition $AssetPartition -AssetPartitionId $AssetPartition -ItemType "Profile" -Item $PasswordProfile
}
function Get-SafeguardProfileItem
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
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true)]
        [ValidateSet("PasswordRule", "CheckSchedule", "ChangeSchedule", "Profile", IgnoreCase=$true)]
        [string]$ItemType,
        [Parameter(Mandatory=$false,Position=0)]
        [object]$ItemToGet,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    switch ($ItemType)
    {
        "passwordrule" { $local:ResourceName = "PasswordRules"; break}
        "checkschedule" { $local:ResourceName = "CheckSchedules"; break }
        "changeschedule" { $local:ResourceName = "ChangeSchedules"; break }
        "profile" { $local:ResourceName = "Profiles"; break }
    }

    $local:Parameters = $null
    if ($Fields)
    {
        $local:Parameters = @{ fields = ($Fields -join ",")}
    }

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                            -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId)

    if ($AssetPartitionId)
    {
        $local:RelPath = "AssetPartitions/$AssetPartitionId/$($local:ResourceName)"
    }
    else
    {
        $local:RelPath = "AssetPartitions/$($local:ResourceName)"
    }

    if ($ItemToGet)
    {
        $local:ItemId = (Resolve-SafeguardProfileItemId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                                -AssetPartitionId $AssetPartitionId -ItemType $ItemType $ItemToGet)
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
            Core GET "$($local:RelPath)/$($local:ItemId)" -Parameters $local:Parameters
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
            Core GET "$($local:RelPath)" -Parameters $local:Parameters
    }
}
function Remove-SafeguardProfileItem
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
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true)]
        [ValidateSet("PasswordRule", "CheckSchedule", "ChangeSchedule", "Profile", IgnoreCase=$true)]
        [string]$ItemType,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$ItemToDelete
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    switch ($ItemType)
    {
        "passwordrule" { $local:ResourceName = "PasswordRules"; break}
        "checkschedule" { $local:ResourceName = "CheckSchedules"; break }
        "changeschedule" { $local:ResourceName = "ChangeSchedules"; break }
        "profile" { $local:ResourceName = "Profiles"; break }
    }

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                            -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -UseDefault)

    $local:RelPath = "AssetPartitions/$AssetPartitionId/$($local:ResourceName)"

    $local:ItemId = (Resolve-SafeguardProfileItemId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                       -AssetPartitionId $AssetPartitionId -ItemType $ItemType -Item $ItemToDelete)

    Invoke-SafeguardMethod -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure Core DELETE "$($local:RelPath)/$($local:ItemId)"
}
function Rename-SafeguardProfileItem
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
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true)]
        [ValidateSet("PasswordRule", "CheckSchedule", "ChangeSchedule", "Profile", IgnoreCase=$true)]
        [string]$ItemType,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$ItemToEdit,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$NewName
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    switch ($ItemType)
    {
        "passwordrule" { $local:ResourceName = "PasswordRules"; break}
        "checkschedule" { $local:ResourceName = "CheckSchedules"; break }
        "changeschedule" { $local:ResourceName = "ChangeSchedules"; break }
        "profile" { $local:ResourceName = "Profiles"; break }
    }

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                            -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -UseDefault)

    $local:RelPath = "AssetPartitions/$AssetPartitionId/$($local:ResourceName)"

    $local:Item = (Get-SafeguardProfileItem -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                       -AssetPartitionId $AssetPartitionId -ItemType $ItemType -ItemToGet $ItemToEdit)

    $local:Item.Name = $NewName

    Invoke-SafeguardMethod -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure Core PUT "$($local:RelPath)/$($local:Item.Id)" -Body $local:Item
}
function Copy-SafeguardProfileItem
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
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true)]
        [ValidateSet("PasswordRule", "CheckSchedule", "ChangeSchedule", "Profile", IgnoreCase=$true)]
        [string]$ItemType,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$ItemToCopy,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$CopyName
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    switch ($ItemType)
    {
        "passwordrule" { $local:ResourceName = "PasswordRules"; break}
        "checkschedule" { $local:ResourceName = "CheckSchedules"; break }
        "changeschedule" { $local:ResourceName = "ChangeSchedules"; break }
        "profile" { $local:ResourceName = "Profiles"; break }
    }

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                            -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -UseDefault)

    $local:RelPath = "AssetPartitions/$AssetPartitionId/$($local:ResourceName)"

    $local:Item = (Get-SafeguardProfileItem -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                       -AssetPartitionId $AssetPartitionId -ItemType $ItemType -ItemToGet $ItemToCopy)

    $local:Item.Id = 0 # <== gets ignored for POST
    $local:Item.Name = $CopyName

    Invoke-SafeguardMethod -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure Core POST "$($local:RelPath)" -Body $local:Item
}


# account password rules

<#
.SYNOPSIS
Get account password rules in Safeguard via the Web API.

.DESCRIPTION
Get one or all account password rules that can be associated to a password profile
which can be assigned to partitions, assets, and accounts.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to get account password rules from.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to get account password rules from.
(If specified, this will override the AssetPartition parameter)

.PARAMETER PasswordRuleToGet
An integer containing the ID of the account password rule to get or a string containing the name.

.PARAMETER Fields
An array of the account password rule property names to return.
#>
function Get-SafeguardAccountPasswordRule
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
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$false,Position=0)]
        [object]$PasswordRuleToGet = $null,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields = $null
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Get-SafeguardProfileItem -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
        -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -ItemType "PasswordRule" -ItemToGet $PasswordRuleToGet -Fields $Fields
}

<#
.SYNOPSIS
Create a new account password rule in Safeguard via the Web API.

.DESCRIPTION
Create a new account password rule that can be associated to a password profile
which can be assigned to partitions, assets, and accounts.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to create the account password rule in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to create the account password rule in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER Name
A string containing the name of the new account password rule.

.PARAMETER Description
A string containing the description of the new account password rule.

.PARAMETER MinCharacters
An integer of the minimum number of characters (default: 8)

.PARAMETER MaxCharacters
An integer of the maximum number of characters (default: 12)

.PARAMETER AllowUppercase
A boolean of whether or not to allow uppercase characters (default: true)

.PARAMETER MinUppercase
An integer of the minimum number of uppercase characters (default: 1)

.PARAMETER MaxConsecutiveUppercase
An integer of the maximum number of consecutive uppercase characters (default: not set)

.PARAMETER InvalidUppercase
A string containing all of the invalid uppercase characters (default: not set)
Example: "ATXYZ", meaning none of those characters will show up in passwords

.PARAMETER AllowLowercase
A boolean of whether or not to allow lowercase characters (default: true)

.PARAMETER MinLowercase
An integer of the minimum number of lowercase characters (default: 1)

.PARAMETER MaxConsecutiveLowercase
An integer of the maximum number of consecutive lowercase characters (default: not set)

.PARAMETER InvalidLowercaseChars
A string containing all of the invalid lowercase characters (default: not set)
Example: "aefbkdjs", meaning none of those characters will show up in passwords

.PARAMETER AllowNumeric
A boolean of whether or not to allow numeric characters (default: true)

.PARAMETER MinNumeric
An integer of the minimum number of numeric characters (default: 1)

.PARAMETER MaxConsecutiveNumeric
An integer of the maximum number of consecutive numeric characters (default: not set)

.PARAMETER InvalidNumericChars
A string containing all of the invalid numeric characters (default: not set)
Example: "12590", meaning none of those characters will show up in passwords

.PARAMETER AllowSymbols
A boolean of whether or not to allow symbol characters (default: false)

.PARAMETER MinSymbols
An integer of the minimum number of symbol characters (default: 0)

.PARAMETER MaxConsecutiveSymbols
An integer of the maximum number of consecutive symbol characters (default: not set)

.PARAMETER InvalidSymbolChars
A string containing all of the invalid symbol characters (default: not set)
Example: "%^=,", meaning none of those characters will show up in passwords
This parameter is mutually exclusive with AllowedSymbolChars

.PARAMETER AllowedSymbolChars
A string containing all of the symbol characters to allow (default: not set)
Example: "@#$%&", meaning only those characters will be used as symbols in passwords

.PARAMETER AllowedFirstCharType
A string containing which type of character to start the password with (default: not set)

.PARAMETER AllowedLastCharType
A string containing which type of character to end the password with (default: not set)

.PARAMETER MaxConsecutiveAlpha
An integer of the maximum number of consecutive alphabetic characters (default: not set)

.PARAMETER MaxConsecutiveAlphanumeric
An integer of the maximum number of consecutive alphanumeric characters (default: not set)

.PARAMETER RepeatedCharRestriction
A string containing the repeated character restriction setting for new passwords (default: "NoConsecutiveRepeatedCharacters")
#>
function New-SafeguardAccountPasswordRule
{
    [CmdletBinding(DefaultParameterSetName="Exclude")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [string]$Description,
        [Parameter(Mandatory=$false)]
        [int]$MinCharacters = 8,
        [Parameter(Mandatory=$false)]
        [int]$MaxCharacters = 12,
        [Parameter(Mandatory=$false)]
        [bool]$AllowUppercase = $true,
        [Parameter(Mandatory=$false)]
        [int]$MinUppercase = 1,
        [Parameter(Mandatory=$false)]
        [int]$MaxConsecutiveUppercase = $null,
        [Parameter(Mandatory=$false)]
        [string[]]$InvalidUppercaseChars = $null,
        [Parameter(Mandatory=$false)]
        [bool]$AllowLowercase = $true,
        [Parameter(Mandatory=$false)]
        [int]$MinLowercase = 1,
        [Parameter(Mandatory=$false)]
        [int]$MaxConsecutiveLowercase = $null,
        [Parameter(Mandatory=$false)]
        [string]$InvalidLowercaseChars = $null,
        [Parameter(Mandatory=$false)]
        [bool]$AllowNumeric = $true,
        [Parameter(Mandatory=$false)]
        [int]$MinNumeric = 1,
        [Parameter(Mandatory=$false)]
        [int]$MaxConsecutiveNumeric = $null,
        [Parameter(Mandatory=$false)]
        [string]$InvalidNumericChars = $null,
        [Parameter(Mandatory=$false)]
        [bool]$AllowSymbols = $false,
        [Parameter(Mandatory=$false)]
        [int]$MinSymbols = 0,
        [Parameter(Mandatory=$false)]
        [int]$MaxConsecutiveSymbols = $null,
        [Parameter(Mandatory=$false,ParameterSetName="Exclude")]
        [string]$InvalidSymbolChars = $null,
        [Parameter(Mandatory=$false,ParameterSetName="Include")]
        [string]$AllowedSymbolChars = $null,
        [Parameter(Mandatory=$false)]
        [ValidateSet("All", "AlphaNumeric", "Alphabetic", IgnoreCase=$true)]
        [string]$AllowedFirstCharType = $null,
        [Parameter(Mandatory=$false)]
        [ValidateSet("All", "AlphaNumeric", "Alphabetic", IgnoreCase=$true)]
        [string]$AllowedLastCharType = $null,
        [Parameter(Mandatory=$false)]
        [int]$MaxConsecutiveAlpha = $null,
        [Parameter(Mandatory=$false)]
        [int]$MaxConsecutiveAlphanumeric = $null,
        [Parameter(Mandatory=$false)]
        [ValidateSet("NotSpecified", "NoConsecutiveRepeatedCharacters", "NoRepeatedCharacters", "AllowRepeatedCharacters", IgnoreCase=$true)]
        [string]$RepeatedCharRestriction = "NoConsecutiveRepeatedCharacters"
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                            -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -UseDefault)

    $local:Body = @{
        "Name" = $Name;
        "Description" = $Description;
        "MinCharacters" = $MinCharacters;
        "MaxCharacters" = $MaxCharacters;
        "AllowUppercaseCharacters" = $AllowUppercase;
        "MinUppercaseCharacters" = $MinUppercase;
        "AllowLowercaseCharacters" = $AllowLowercase;
        "MinLowercaseCharacters" = $MinLowercase;
        "AllowNumericCharacters" = $AllowNumeric;
        "MinNumericCharacters" = $MinNumeric;
        "AllowNonAlphaNumericCharacters" = $AllowSymbols;
        "MinNonAlphaNumericCharacters" = $MinSymbols;
        "RepeatedCharacterRestriction" = $RepeatedCharRestriction;
    }

    if ($MaxConsecutiveUppercase) { $local:Body.MaxConsecutiveUppercaseCharacters = $MaxConsecutiveUppercase }
    if ($InvalidUppercaseChars) { $local:Body.InvalidUppercaseCharacters = $InvalidUppercaseChars }

    if ($MaxConsecutiveLowercase) { $local:Body.MaxConsecutiveLowercaseCharacters = $MaxConsecutiveLowercase }
    if ($InvalidLowercaseChars) { $local:Body.InvalidLowercaseCharacters = [string[]]($InvalidLowercaseChars -split "(?<=.)(?=.)") }

    if ($MaxConsecutiveNumeric) { $local:Body.MaxConsecutiveNumericCharacters = $MaxConsecutiveNumeric }
    if ($InvalidNumericChars) { $local:Body.InvalidNumericCharacters = [string[]]($InvalidNumericChars -split "(?<=.)(?=.)") }

    if ($MaxConsecutiveSymbols) { $local:Body.MaxConsecutiveNonAlphaNumericCharacters = $MaxConsecutiveSymbols }
    if ($SymbolRestrictionType) { $local:Body.NonAlphaNumericRestrictionType = $SymbolRestrictionType }
    if ($InvalidSymbolChars)
    {
        $local:Body.InvalidNonAlphaNumericCharacters = [string[]]($InvalidSymbolChars -split "(?<=.)(?=.)")
        $local:Body.NonAlphaNumericRestrictionType = "Exclude"
    }
    if ($AllowedSymbolChars)
    {
        $local:Body.AllowedNonAlphaNumericCharacters = [string[]]($AllowedSymbolChars -split "(?<=.)(?=.)")
        $local:Body.NonAlphaNumericRestrictionType = "Include"
    }

    if ($AllowedFirstCharType) { $local:Body.AllowedFirstCharacterType = $AllowedFirstCharType }
    if ($AllowedLastCharType) { $local:Body.AllowedLastCharacterType = $AllowedLastCharType }

    if ($MaxConsecutiveAlpha) { $local:Body.MaxConsecutiveAlphabeticCharacters = $MaxConsecutiveAlpha }
    if ($MaxConsecutiveAlphanumeric) { $local:Body.MaxConsecutiveAlphaNumericCharacters = $MaxConsecutiveAlpha }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
        POST "AssetPartitions/$($local:AssetPartitionId)/PasswordRules" -Body $local:Body
}

<#
.SYNOPSIS
Delete an account password rule from Safeguard via the Web API.

.DESCRIPTION
Delete an account password rule. It must not be associated with a password profile
in order to be able to delete it.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to delete the account password rule from.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to delete the account password rule from.
(If specified, this will override the AssetPartition parameter)

.PARAMETER PasswordRuleToDelete
An integer containing the ID of the account password rule to delete or a string containing the name.
#>
function Remove-SafeguardAccountPasswordRule
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
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$PasswordRuleToDelete
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Remove-SafeguardProfileItem -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
        -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -ItemType "PasswordRule" -ItemToDelete $PasswordRuleToDelete
}

<#
.SYNOPSIS
Rename an account password rule in Safeguard via the Web API.

.DESCRIPTION
Rename an account password rule without changing any of its configuration.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to rename the account password rule in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to rename the account password rule in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER PasswordRuleToEdit
An integer containing the ID of the account password rule to rename or a string containing the name.

.PARAMETER NewName
A string containing the new name for the account password rule.
#>
function Rename-SafeguardAccountPasswordRule
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
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$PasswordRuleToEdit,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$NewName
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Rename-SafeguardProfileItem -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetPartition $AssetPartition `
        -AssetPartitionId $AssetPartitionId -ItemType "PasswordRule" -ItemToEdit $PasswordRuleToEdit -NewName $NewName
}

<#
.SYNOPSIS
Copy an account password rule in Safeguard via the Web API.

.DESCRIPTION
Copy an account password rule without changing any of its configuration.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to copy the account password rule in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to copy the account password rule in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER PasswordRuleToCopy
An integer containing the ID of the account password rule to copy or a string containing the name.

.PARAMETER CopyName
A string containing the name for the new account password rule.
#>
function Copy-SafeguardAccountPasswordRule
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
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$PasswordRuleToCopy,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$CopyName
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Copy-SafeguardProfileItem -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetPartition $AssetPartition `
        -AssetPartitionId $AssetPartitionId -ItemType "PasswordRule" -ItemToCopy $PasswordRuleToCopy -CopyName $CopyName
}

# password check schedules

<#
.SYNOPSIS
Get password check schedules in Safeguard via the Web API.

.DESCRIPTION
Get one or all password check schedules that can be associated to a password profile
which can be assigned to partitions, assets, and accounts.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to get password check schedules from.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to get password check schedules.
(If specified, this will override the AssetPartition parameter)

.PARAMETER CheckScheduleToGet
An integer containing the ID of the password check schedule to get or a string containing the name.

.PARAMETER Fields
An array of the password check schedule property names to return.
#>
function Get-SafeguardPasswordCheckSchedule
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
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$false,Position=0)]
        [object]$CheckScheduleToGet,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Get-SafeguardProfileItem -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
        -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -ItemType "CheckSchedule" -ItemToGet $CheckScheduleToGet -Fields $Fields
}

<#
.SYNOPSIS
Create a new password check schedule in Safeguard via the Web API.

.DESCRIPTION
Create a new password check schedule that can be associated to a password profile
which can be assigned to partitions, assets, and accounts.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to create the password check schedule in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to create the password check schedule in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER Name
A string containing the name of the new password check schedule.

.PARAMETER Description
A string containing the description of the new password check schedule.

.PARAMETER ChangePasswordOnMismatch
Whether to change the password if a password mismatch is found (does not apply to manual check tasks).

.PARAMETER NotifyOwnersOnMismatch
Whether to notify delegated owners if a password mismatch is found (does not apply to manual check tasks).

.PARAMETER Schedule
A Safeguard schedule object of when to run password checks, see New-SafeguardSchedule and associated cmdlets.

.EXAMPLE
New-SafeguardPasswordCheckSchedule "Daily Check at Noon" -ChangePasswordOnMismatch -Schedule (New-SafeguardScheduleDaily -StartTime "12:00")
#>
function New-SafeguardPasswordCheckSchedule
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
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [string]$Description,
        [Parameter(Mandatory=$false)]
        [switch]$ChangePasswordOnMismatch,
        [Parameter(Mandatory=$false)]
        [switch]$NotifyOwnersOnMismatch,
        [Parameter(Mandatory=$false)]
        [HashTable]$Schedule
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                            -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -UseDefault)

    $local:Body = @{
        "Name" = $Name;
        "Description" = $Description;
        "ResetPasswordOnMismatch" = [bool]$ChangePasswordOnMismatch;
        "NotifyOwnersOnMismatch" = [bool]$NotifyOwnersOnMismatch;
    }

    if ($Schedule)
    {
        Import-Module -Name "$PSScriptRoot\schedules.psm1" -Scope Local
        $local:Body = (Copy-ScheduleToDto -Schedule $Schedule -Dto $local:Body)
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
        POST "AssetPartitions/$($local:AssetPartitionId)/CheckSchedules" -Body $local:Body
}

<#
.SYNOPSIS
Delete a password check schedule from Safeguard via the Web API.

.DESCRIPTION
Delete a password check schedule. It must not be associated with a password profile
in order to be able to delete it.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to delete the password check schedule from.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to the delete password check schedule from.
(If specified, this will override the AssetPartition parameter)

.PARAMETER CheckScheduleToDelete
An integer containing the ID of the password check schedule to delete or a string containing the name.
#>
function Remove-SafeguardPasswordCheckSchedule
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
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$CheckScheduleToDelete
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Remove-SafeguardProfileItem -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
        -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -ItemType "CheckSchedule" -ItemToDelete $CheckScheduleToDelete
}

<#
.SYNOPSIS
Rename a password check schedule in Safeguard via the Web API.

.DESCRIPTION
Rename a password check schedule without changing any of its configuration.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to rename the password check schedule in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to rename the password check schedule in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER CheckScheduleToEdit
An integer containing the ID of the password check schedule to rename or a string containing the name.

.PARAMETER NewName
A string containing the new name for the password check schedule.
#>
function Rename-SafeguardPasswordCheckSchedule
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
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$CheckScheduleToEdit,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$NewName
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Rename-SafeguardProfileItem -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetPartition $AssetPartition `
        -AssetPartitionId $AssetPartitionId -ItemType "CheckSchedule" -ItemToEdit $CheckScheduleToEdit -NewName $NewName
}

<#
.SYNOPSIS
Copy a password check schedule in Safeguard via the Web API.

.DESCRIPTION
Copy a password check schedule without changing any of its configuration.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to copy the password check schedule in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to copy the password check schedule in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER CheckScheduleToEdit
An integer containing the ID of the password check schedule to copy or a string containing the name.

.PARAMETER CopyName
A string containing the name for the new password check schedule.
#>
function Copy-SafeguardPasswordCheckSchedule
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
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$CheckScheduleToCopy,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$CopyName
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Copy-SafeguardProfileItem -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetPartition $AssetPartition `
        -AssetPartitionId $AssetPartitionId -ItemType "CheckSchedule" -ItemToCopy $CheckScheduleToCopy -CopyName $CopyName
}

# password change schedules

<#
.SYNOPSIS
Get password change schedules in Safeguard via the Web API.

.DESCRIPTION
Get one or all password change schedules that can be associated to a password profile
which can be assigned to partitions, assets, and accounts.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to get password change schedules from.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to get password change schedules.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ChangeScheduleToGet
An integer containing the ID of the password change schedule to get or a string containing the name.

.PARAMETER Fields
An array of the password change schedule property names to return.
#>
function Get-SafeguardPasswordChangeSchedule
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
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$false,Position=0)]
        [object]$ChangeScheduleToGet,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Get-SafeguardProfileItem -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
        -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -ItemType "ChangeSchedule" -ItemToGet $ChangeScheduleToGet -Fields $Fields
}

<#
.SYNOPSIS
Create a new password change schedule in Safeguard via the Web API.

.DESCRIPTION
Create a new password change schedule that can be associated to a password profile
which can be assigned to partitions, assets, and accounts.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to create the password change schedule in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to create the password change schedule in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER Name
A string containing the name of the new password change schedule.

.PARAMETER Description
A string containing the description of the new password change schedule.

.PARAMETER ChangePasswordIfInUse
Whether or not to change the password even if it is currently checked out.

.PARAMETER RequireCurrentPassword
Whether to require the current password to change to a new password.

.PARAMETER SuspendAccountWhenCheckedIn
Whether to disable the account when password is not checked out. (limited platform support)

.PARAMETER ChangePasswordsManually
Whether or not to require asset administrators to change passwords manually.

.PARAMETER UpdateServices
Whether or not to update Windows services when passwords are changed.

.PARAMETER RestartServices
Whether or not to restart Windows services when passwords are changed.

.PARAMETER UpdateIisAppPools
Whether or not to update Windows IIS app pools when passwords are changed.

.PARAMETER UpdateComPlus
Whether or not to update Windows COM+ services when passwords are changed.

.PARAMETER UpdateTasks
Whether or not to update Windows tasks when passwords are changed.

.PARAMETER Schedule
A Safeguard schedule object of when to run password changes, see New-SafeguardSchedule and associated cmdlets.

.EXAMPLE
New-SafeguardPasswordChangeSchedule "Daily Change at Noon" -Schedule (New-SafeguardScheduleDaily -StartTime "12:00")

.EXAMPLE
New-SafeguardPasswordChangeSchedule "Windows Daily at 7pm" -Description "Changes passwords and restarts services" -Schedule (New-SafeguardScheduleDaily -StartTime "19:00") -ChangePasswordIfInUse -UpdateServices -RestartServices -UpdateTasks
#>
function New-SafeguardPasswordChangeSchedule
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
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [string]$Description,
        [Parameter(Mandatory=$false)]
        [switch]$ChangePasswordIfInUse,
        [Parameter(Mandatory=$false)]
        [switch]$RequireCurrentPassword,
        [Parameter(Mandatory=$false)]
        [switch]$SuspendAccountWhenCheckedIn,
        [Parameter(Mandatory=$false)]
        [switch]$ChangePasswordsManually,
        [Parameter(Mandatory=$false)]
        [switch]$UpdateServices,
        [Parameter(Mandatory=$false)]
        [switch]$RestartServices,
        [Parameter(Mandatory=$false)]
        [switch]$UpdateIisAppPools,
        [Parameter(Mandatory=$false)]
        [switch]$UpdateComPlus,
        [Parameter(Mandatory=$false)]
        [switch]$UpdateTasks,
        [Parameter(Mandatory=$false)]
        [HashTable]$Schedule
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                            -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -UseDefault)

    $local:Body = @{
        "Name" = $Name;
        "Description" = $Description;
        "AllowPasswordChangeWhenReleased" = [bool]$ChangePasswordIfInUse;
        "RequireCurrentPassword" = [bool]$RequireCurrentPassword;
        "SuspendAccountWhenCheckedIn" = [bool]$SuspendAccountWhenCheckedIn;
        "NotifyOwnersOnly" = [bool]$ChangePasswordsManually;
        # Windows service stuff
        "UpdateWindowsServiceOnPasswordChange" = [bool]$UpdateServices;
        "RestartWindowsServiceOnPasswordChange" = [bool]$RestartServices;
        "UpdateIisPoolsOnPasswordChange" = [bool]$UpdateIisAppPools;
        "UpdateComPlusOnPasswordChange" = [bool]$UpdateComPlus;
        "UpdateWindowsTasksOnPasswordChange" = [bool]$UpdateTasks;
        # backwards compat for prior to SSH key management
        "ManagePassword" = $true;
    }

    if ($Schedule)
    {
        Import-Module -Name "$PSScriptRoot\schedules.psm1" -Scope Local
        $local:Body = (Copy-ScheduleToDto -Schedule $Schedule -Dto $local:Body)
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
        POST "AssetPartitions/$($local:AssetPartitionId)/ChangeSchedules" -Body $local:Body
}

<#
.SYNOPSIS
Delete a password change schedule from Safeguard via the Web API.

.DESCRIPTION
Delete a password change schedule. It must not be associated with a password profile
in order to be able to delete it.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to delete the password change schedule from.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to the delete password change schedule from.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ChangeScheduleToDelete
An integer containing the ID of the password change schedule to delete or a string containing the name.
#>
function Remove-SafeguardPasswordChangeSchedule
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
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$ChangeScheduleToDelete
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Remove-SafeguardProfileItem -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
        -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -ItemType "ChangeSchedule" -ItemToDelete $ChangeScheduleToDelete
}

<#
.SYNOPSIS
Rename a password change schedule in Safeguard via the Web API.

.DESCRIPTION
Rename a password change schedule without changing any of its configuration.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to rename the password change schedule in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to rename the password change schedule in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ChangeScheduleToEdit
An integer containing the ID of the password change schedule to rename or a string containing the name.

.PARAMETER NewName
A string containing the new name for the password change schedule.
#>
function Rename-SafeguardPasswordChangeSchedule
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
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$ChangeScheduleToEdit,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$NewName
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Rename-SafeguardProfileItem -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetPartition $AssetPartition `
        -AssetPartitionId $AssetPartitionId -ItemType "ChangeSchedule" -ItemToEdit $ChangeScheduleToEdit -NewName $NewName
}
<#
.SYNOPSIS
Copy a password change schedule in Safeguard via the Web API.

.DESCRIPTION
Copy a password change schedule without changing any of its configuration.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to copy the password change schedule in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to copy the password change schedule in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ChangeScheduleToEdit
An integer containing the ID of the password change schedule to copy or a string containing the name.

.PARAMETER CopyName
A string containing the name for the new password change schedule.
#>
function Copy-SafeguardPasswordChangeSchedule
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
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$ChangeScheduleToCopy,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$CopyName
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Copy-SafeguardProfileItem -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetPartition $AssetPartition `
        -AssetPartitionId $AssetPartitionId -ItemType "ChangeSchedule" -ItemToCopy $ChangeScheduleToCopy -CopyName $CopyName
}

# password profiles

<#
.SYNOPSIS
Get password profiles in Safeguard via the Web API.

.DESCRIPTION
Get one or all password profiles that can be assigned to partitions, assets, and accounts.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to get password profiles from.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to get password profiles.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ProfileToGet
An integer containing the ID of the password profiles to get or a string containing the name.

.PARAMETER Fields
An array of the password profiles property names to return.
#>
function Get-SafeguardPasswordProfile
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
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$false,Position=0)]
        [object]$ProfileToGet,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Get-SafeguardProfileItem -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
        -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -ItemType "Profile" -ItemToGet $ProfileToGet -Fields $Fields
}


function New-SafeguardPasswordProfile
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
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Name,
        [Parameter(Mandatory=$false,Position=1)]
        [string]$Description = $null
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Import-Module -Name "$PSScriptRoot\assetpartitions.psm1" -Scope Local
    $AssetPartitionId = (Resolve-AssetPartitionIdFromSafeguardSession -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure `
                            -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -UseDefault)

    $local:Body = @{
        "Name" = $Name;
        "Description" = $Description
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
        POST "AssetPartitions/$($local:AssetPartitionId)/Profiles" -Body $local:Body
}

<#
.SYNOPSIS
Delete a password profile from Safeguard via the Web API.

.DESCRIPTION
Delete a password profile. It must not the default password profile of an asset partition
in order to be able to delete it.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to delete the password profile from.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to the delete password profile from.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ProfileToDelete
An integer containing the ID of the password profile to delete or a string containing the name.
#>
function Remove-SafeguardPasswordProfile
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
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$ProfileToDelete
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Remove-SafeguardProfileItem -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
        -AssetPartition $AssetPartition -AssetPartitionId $AssetPartitionId -ItemType "Profile" -ItemToDelete $ProfileToDelete
}

<#
.SYNOPSIS
Rename a password profile in Safeguard via the Web API.

.DESCRIPTION
Rename a password profile without changing any of its configuration.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to rename the password profile in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to rename the password profile in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ProfileToEdit
An integer containing the ID of the password profile to rename or a string containing the name.

.PARAMETER NewName
A string containing the new name for the password profile.
#>
function Rename-SafeguardPasswordProfile
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
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$ProfileToEdit,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$NewName
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Rename-SafeguardProfileItem -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetPartition $AssetPartition `
        -AssetPartitionId $AssetPartitionId -ItemType "Profile" -ItemToEdit $ProfileToEdit -NewName $NewName
}

<#
.SYNOPSIS
Copy a password profile in Safeguard via the Web API.

.DESCRIPTION
Copy a password profile without changing any of its configuration.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetPartition
An integer containing an ID or a string containing the name of the asset partition
to copy the password profile in.

.PARAMETER AssetPartitionId
An integer containing the asset partition ID to copy the password profile in.
(If specified, this will override the AssetPartition parameter)

.PARAMETER ProfileToEdit
An integer containing the ID of the password profile to copy or a string containing the name.

.PARAMETER CopyName
A string containing the name for the new password profile.
#>
function Copy-SafeguardPasswordProfile
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
        [object]$AssetPartition,
        [Parameter(Mandatory=$false)]
        [int]$AssetPartitionId = $null,
        [Parameter(Mandatory=$true,Position=0)]
        [object]$ProfileToCopy,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$CopyName
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Copy-SafeguardProfileItem -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetPartition $AssetPartition `
        -AssetPartitionId $AssetPartitionId -ItemType "Profile" -ItemToCopy $ProfileToCopy -CopyName $CopyName
}
