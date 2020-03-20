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
