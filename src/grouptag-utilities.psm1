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
<#
function Convert-StringToCondition
{

}
function Convert-StringToConditionGroup
{

}
function Convert-StringToRule
{

}
#>