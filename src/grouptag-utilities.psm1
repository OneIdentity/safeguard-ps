# helpers for parsing/generating rules and conditions

function Resolve-ObjectAttributeForAccount
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("AllowPasswordRequests","AllowSessionRequests","AllowSSHKeyRequests","AssetName","AssetTag","Description",
                     "DirectoryContainer","Disabled","DiscoveredGroupDistinguishedName","DiscoveredGroupName","DiscoveryJobName",
                     "DistinguishedName","DomainName","EffectiveProfileName","ProfileName","Name","NetBiosName","PartitionName",
                     "Platform","IsServiceAccount","ObjectSid","Tag",IgnoreCase=$true)]
        [string]$ObjectAttribute
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $ObjectAttribute
}
function Resolve-ObjectAttributeForAsset
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("AllowSessionRequests","Description","DirectoryContainer","Disabled","DiscoveredGroupDistinguishedName",
                     "DiscoveredGroupName","DiscoveryJobName","EffectiveProfileName","ProfileName","Name","NetworkAddress",
                     "PartitionName","Platform","Tag",IgnoreCase=$true)]
        [string]$ObjectAttribute
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $ObjectAttribute
}
function Resolve-LogicalJoinType
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("And","Or",IgnoreCase=$true)]
        [string]$LogicalJoinType
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $LogicalJoinType
}

# convert object to string
function Convert-PredicateObjectToString
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("IsTrue","IsFalse","Contains","DoesNotContain","StartsWith","EndsWith","EqualTo","NotEqualTo","RegexCompare",IgnoreCase=$true)]
        [string]$CompareType,
        [Parameter(Mandatory=$false)]
        [string]$CompareValue
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    switch ($CompareType)
    {
        "IsTrue" { " eq true"; break }
        "IsFalse" { " eq false"; break }
        "Contains" { " contains '$CompareValue'"; break }
        "DoesNotContain" { " notcontains '$CompareValue'"; break }
        "StartsWith" { " startswith '$CompareValue'"; break }
        "EndsWith" { " endswith '$CompareValue'"; break }
        "EqualTo" { " eq '$CompareValue'"; break }
        "NotEqualTo" { " ne '$CompareValue'"; break }
        "RegexCompare" { " match '$CompareValue'"; break }
        default {
            throw "Unrecognized CompareType '$CompareType' in Condition"
        }
    }
}
function Convert-LogicalJoinTypeToString
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$LogicalJoinType
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    (" " + (Resolve-LogicalJoinType $LogicalJoinType).ToLower() + " ")
}
function Convert-ConditionToString
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [object]$Condition,
        [Parameter(Mandatory=$true)]
        [ValidateSet("account","asset",IgnoreCase=$true)]
        [string]$Type
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($Condition.PSObject.Properties.Name -contains "ObjectAttribute")
    {
        if ($Condition.PSObject.Properties.Name -contains "CompareType")
        {
            if ($Condition.PSObject.Properties.Name -contains "CompareValue")
            {
                if ($Type -ieq "account")
                {
                    $local:String = (Resolve-ObjectAttributeForAccount $Condition.ObjectAttribute)
                }
                else
                {
                    $local:String = (Resolve-ObjectAttributeForAsset $Condition.ObjectAttribute)
                }
                ("[" + $local:String + (Convert-PredicateObjectToString $Condition.CompareType $Condition.CompareValue) + "]")
            }
            else
            {
                throw ("Condition does not include CompareValue: " + (ConvertTo-Json $Condition -Compress))
            }
        }
        else
        {
            throw ("Condition does not include CompareType: " + (ConvertTo-Json $Condition -Compress))
        }
    }
    else
    {
        throw ("Condition does not include ObjectAttribute: " + (ConvertTo-Json $Condition -Compress))
    }
}
function Convert-ConditionGroupToString
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [object]$ConditionGroup,
        [Parameter(Mandatory=$true)]
        [ValidateSet("account","asset",IgnoreCase=$true)]
        [string]$Type
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($ConditionGroup.PSObject.Properties.Name -contains "LogicalJoinType")
    {
        if ($ConditionGroup.PSObject.Properties.Name -contains "Children")
        {
            if ($ConditionGroup.Children.TaggingGroupingCondition)
            {
                $local:String = $null
                foreach ($local:ChildCondition in $ConditionGroup.Children.TaggingGroupingCondition)
                {
                    if (-not $local:ChildCondition) { continue }
                    $local:ChildString = (Convert-ConditionToString $local:ChildCondition $Type)
                    if ($local:String)
                    {
                        $local:String += ((Convert-LogicalJoinTypeToString $ConditionGroup.LogicalJoinType) + $local:ChildString)
                    }
                    else
                    {
                        $local:String = $local:ChildString
                    }
                }
            }
            if ($ConditionGroup.Children.TaggingGroupingConditionGroup)
            {
                $local:GroupString = $null
                foreach ($local:ChildConditionGroup in $ConditionGroup.Children.TaggingGroupingConditionGroup)
                {
                    if (-not $local:ChildConditionGroup) { continue }
                    $local:Recurse = ("(" + (Convert-ConditionGroupToString $local:ChildConditionGroup $Type) + ")")
                    if ($local:GroupString)
                    {
                        $local:GroupString += ((Convert-LogicalJoinTypeToString $ConditionGroup.LogicalJoinType) + $local:Recurse)
                    }
                    else
                    {
                        $local:GroupString = $local:Recurse
                    }
                }
            }
            if ($local:String -and $local:GroupString)
            {
                ($local:String + (Convert-LogicalJoinTypeToString $ConditionGroup.LogicalJoinType) + $local:GroupString)
            }
            elseif ($local:String)
            {
                $local:String
            }
            elseif ($local:GroupString)
            {
                $local:GroupString
            }
        }
        else
        {
            throw ("ConditionGroup does not include Children: " + (ConvertTo-Json $ConditionGroup -Compress))
        }
    }
    else
    {
        throw ("ConditionGroup does not include LogicalJoinType: " + (ConvertTo-Json $ConditionGroup -Compress))
    }
}
function Convert-RuleToString
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [object]$Rule,
        [Parameter(Mandatory=$true)]
        [ValidateSet("account","asset",IgnoreCase=$true)]
        [string]$Type
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    (Convert-ConditionGroupToString $Rule.RuleConditionGroup $Type)
}

# convert string to object
function Convert-StringToPredicateObject
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$String
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    # TODO:
}
function Convert-StringToCondition
{

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [ref]$StringBuf,
        [Parameter(Mandatory=$true)]
        [ValidateSet("account","asset",IgnoreCase=$true)]
        [string]$Type
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Condition = @{
        ObjectAttribute = "Unknown";
        CompareType = "Unknown";
        CompareValue = "Unknown";
    }

    # First find the end of this condition--
    # Opening '[' is parsed off, and no nesting is allowed
    $local:ClosingBracket = $false;
    $local:InQuote = $false # only single quotes supported
    for ($local:Char = $StringBuf.Str[$StringBuf.Pos];
         $StringBuf.Pos -lt $StringBuf.Str.Length ; $StringBuf.Pos++)
    {
        if ($local:Char -eq ']' -and -not $InQuote)
        {
            $local:ClosingBracket = $true; $StringBuf.Pos++; break;
        }
        elseif ($local:Char -eq '''')
        {
            $local:InQuote = (-not $local:InQuote)
        }
        $local:SubString += $local:Char
    }
    if (-not $local:ClosingBracket) { throw "Mismatched bracket while reading condition substring: $($StringBuf.Str)" }

    # Start parsing children in this group
    $local:StringParts = $local:SubString.(" `t`n", 3, 1)
    if ($Type -ieq "account")
    {
        $local:Condition.ObjectAttribute = (Resolve-ObjectAttributeForAccount $local:StringParts[0])
    }
    else
    {
        $local:Condition.ObjectAttribute = (Resolve-ObjectAttributeForAsset $local:StringParts[0])
    }

    # TODO:
    #$local:Predicate = ()

    $local:Condition
}
function Convert-StringToConditionGroup
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [ref]$StringBuf,
        [Parameter(Mandatory=$true)]
        [ValidateSet("account","asset",IgnoreCase=$true)]
        [string]$Type
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:ConditionGroup = @{
        LogicalJoinType = "And"
        Children = @()
    }

    # First find the end of this group--
    # Opening '(' is parsed off, which means end of this group will be unmatched ')' or end of string
    $local:Parens = 0; $local:ClosingParen = $false;
    $local:InQuote = $false # only single quotes supported
    for ($local:Char = $StringBuf.Str[$StringBuf.Pos];
         $StringBuf.Pos -lt $StringBuf.Str.Length ; $StringBuf.Pos++)
    {
        if ($local:Char -eq ')')
        {
            if (-not $InQuote ) { $local:Parens-- }
            if ($local:Parens -lt 0) { $local:ClosingParen = $true; $StringBuf.Pos++; break; }
        }
        elseif ($local:Char -eq '(')
        {
            if (-not $local:InQuote) { $local:Parens++ }
        }
        elseif ($local:Char -eq '''')
        {
            $local:InQuote = (-not $local:InQuote)
        }
        $local:SubString += $local:Char
    }
    if ($local:InQuote) { throw "Unterminated quote while reading condition group substring: $($StringBuf.Str)" }
    if ($local:Parens -gt 0 -or ($local:Parens -eq 0 -and -not $local:ClosingParen)) { throw "Mismatched parenthesis while reading condition group substring: $($StringBuf.Str)" }

    # Start parsing children in this group
    $local:SubStringBuf = (New-Object PSObject -Property @{ Str = $local:SubString; Pos = 0 })
    for ($local:Char = $local:SubStringBuf.Str[$local:SubStringBuf.Pos];
         $local:SubStringBuf.Pos -lt $local:SubStringBuf.Str.Length ; $local:SubStringBuf.Pos++)
    {
        # Ignore superfluous whitespace
        if ($local:Char -in ' ','`t','`n') { continue }
        # Parse condition
        if ($local:Char -eq '[')
        {
            $local:SubStringBuf.Pos++
            $local:ConditionGroup.Children += @{
                TaggingGroupingCondition = (Convert-StringToCondition ([ref]$local:SubStringBuf) $Type);
                TaggingGroupingConditionGroup = $null;
            }
        }
        # Parse condition group
        elseif ($local:Char -eq '(')
        {
            $local:SubStringBuf.Pos++
            $local:ConditionGroup.Children += @{
                TaggingGroupingCondition = $null;
                TaggingGroupingConditionGroup = (Convert-StringToConditionGroup ([ref]$local:SubStringBuf) $Type)
            }
        }
        # Parse logical join type -- this will be the same every time
        elseif ($local:Char -in 'a','A')
        {
            if ($local:SubStringBuf.Str[$local:SubStringBuf.Pos + 1] -in 'n','N' `
                -and $local:SubStringBuf.Str[$local:SubStringBuf.Pos + 2] -in 'd','D')
            {
                $local:ConditionGroup.LogicalJoinType = "And"
                $local:SubStringBuf.Pos += 2
            }
            else
            {
                throw "Unrecognized character at position $($local:SubStringBuf.Pos) in condition group substring: $($local:SubString.Str)"
            }
        }
        elseif ($local:Char -in 'o','O')
        {
            if ($local:SubStringBuf.Str[$local:SubStringBuf.Pos + 1] -in 'r','R')
            {
                $local:ConditionGroup.LogicalJoinType = "Or"
                $local:SubStringBuf.Pos++
            }
            else
            {
                throw "Unrecognized character at position $($local:SubStringBuf.Pos) in condition group substring: $($local:SubString.Str)"
            }
        }
        else
        {
            throw "Unrecognized character at position $($local:SubStringBuf.Pos) in condition group substring: $($local:SubString.Str)"
        }
    }

    $local:ConditionGroup
}
function Convert-StringToRule
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$String,
        [Parameter(Mandatory=$true)]
        [ValidateSet("account","asset",IgnoreCase=$true)]
        [string]$Type
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Rule = @{
        Enabled = $true;
        Description = $null;
    }

    $local:StringBuf = (New-Object PSObject -Property @{ Str = $String; Pos = 0 })
    $local:Rule.RuleConditionGroup = (Convert-StringToConditionGroup ([ref]$local:StringBuf) $Type)

    $local:Rule
}
