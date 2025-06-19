# How to use manage tags

# Example: create a new tag
$assetPartitionId = 1 # create the tag in Asset Partition 1. Note, this is a custom partition. The ID for macrocosm = -1
$name = "Tag1"
$description = "Description for test tag"
$assetTaggingRule = '{
  "Description": null,
  "Enabled": true,
  "RuleConditionGroup": {
    "LogicalJoinType": "And",
    "Children": [
      {
        "TaggingGroupingCondition": {
          "ObjectAttribute": "Name",
          "CompareType": "Contains",
          "CompareValue": "prd.local"
        },
        "TaggingGroupingConditionGroup": null
      }
    ]
  }
}' | ConvertFrom-Json
$assetAccountTaggingRule='{
  "Description": null,
  "Enabled": true,
  "RuleConditionGroup": {
    "LogicalJoinType": "And",
    "Children": [
      {
        "TaggingGroupingCondition": {
          "ObjectAttribute": "Name",
          "CompareType": "Contains",
          "CompareValue": "domadm"
        },
        "TaggingGroupingConditionGroup": null
      }
    ]
  }
}' | ConvertFrom-Json
$owners = @("sglocaladmin", "approver")
New-SafeguardTag -AssetPartitionId $assetPartitionId -Name $name -Description $description -AssetTaggingRule $assetTaggingRule -AssetAccountTaggingRule $assetAccountTaggingRule -Owners $owners


# Example: get a tag based on the name from Asset Partition 1
# If the tag exists in a custom Asset Partition, then you must specify the Asset Partition Id.
# If the tag exists in the macrocosm then no need to specify the AssetPartitionId.
$tagObject = Get-SafeguardTag -AssetPartitionId 1 -TagToGet "Tag1"
Write-Host "Retrieved tag $($tagObject.Name) with description '$($tagObject.Description)'"


# Example: Find a tag
Find-SafeguardTag -QueryFilter "Name contains 'tag'" -Fields Id,Name,Description -OrderBy Name


# Example: Assign two tags to an Asset
$tags= @("Prod", "Tag2")
Update-SafeguardAssetTags -Asset "dc01.oneidentity.demo" -Tags $tags


# Example: Get the tags on a specific asset
Get-SafeguardAssetTags "dc01.oneidentity.demo"


# Example: remove all tags from an asset
Update-SafeguardAssetTags -Asset "dc01.oneidentity.demo" -Tags @()


# Example: Assign two tags to an account
$tags= @("Prod", "Tag2")
Update-SafeguardAccountTags -Account "root" -Tags $tags


# Example: Get the tags on a specific account
Get-SafeguardAccountTags -Account "root"


# Example: remove all tags from an account
Update-SafeguardAccountTags -Account "root" -Tags @()


# Example: Get the Tag occurrences for tag "prod"
Get-SafeguardTagOccurences "prod"


# Example: Update a tag
Update-SafeguardTag -TagId 1 -Name "new Tag Name" -Description "Some new description" -Owners "Admin1","Admin2","New Owner3"
# Note: any parameters not passed in will be cleared (eg: asset and account tagging rules).


# Example: test an AssetTagging rule
$taggingRule = '{"Description": null,"Enabled": true,"RuleConditionGroup": {"LogicalJoinType": "And","Children": [{"TaggingGroupingCondition": {"ObjectAttribute": "Name","CompareType": "Contains","CompareValue": ".demo"},"TaggingGroupingConditionGroup": null}]}}' | ConvertFrom-Json
Test-SafeguardAssetTaggingRule -AssetPartitionId 1 -Tag prod -TaggingRule $taggingRule


# Example test an AssetAccountTagging rule
$taggingRule = '{"Description": null,"Enabled": true,"RuleConditionGroup": {"LogicalJoinType": "And","Children": [{"TaggingGroupingCondition": {"ObjectAttribute": "Name","CompareType": "Contains","CompareValue": "domadmin"},"TaggingGroupingConditionGroup": null}]}}' | ConvertFrom-Json
Test-SafeguardAssetAccountTaggingRule -AssetPartitionId 1 -Tag prod -TaggingRule $taggingRule


# Example: delete a safeguard tag
Remove-SafeguardTag prod

