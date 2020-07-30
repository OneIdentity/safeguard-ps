########################################################################################
# ASSETS 
########################################################################################

# Helper
function Resolve-SafeguardDeletedAssetId
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

    $local:RelPath = "Deleted/Assets"
    $local:ErrMsgSuffix = " in deleted assets"
    $local:Assets = $null

    if (-not ($Asset -as [int]))
    {
        try
        {
            $local:Assets = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" `
                                 -Parameters @{ filter = "Name ieq '$Asset'"; fields = "Id" })
            if (-not $local:Assets)
            {
                $local:Assets = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" `
                                     -Parameters @{ filter = "NetworkAddress ieq '$Asset'"; fields = "Id" })
            }
        }
        catch
        {
            Write-Verbose $_
            Write-Verbose "Caught exception with ieq filter, trying with q parameter"
            $local:Assets = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" `
                                 -Parameters @{ q = $Asset; fields = "Id" })
        }
        if (-not $local:Assets)
        {
            throw "Unable to find asset matching '$Asset'$($local:ErrMsgSuffix)"
        }
        if ($local:Assets.Count -ne 1)
        {
            throw "Found $($local:Assets.Count) assets matching '$Asset'$($local:ErrMsgSuffix)"
        }
        $local:Assets[0].Id
    }
    else
    {
        # Make sure it actually exists
        $local:Assets = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" `
            -Parameters @{ filter = "Id eq $Asset"; fields = "Id" })
        if (-not $local:Assets)
        {
            throw "Unable to find asset matching '$Asset'$($local:ErrMsgSuffix)"
        }
        $Asset
    }
}

<#
.SYNOPSIS
Get deleted assets.

.DESCRIPTION
Returns a list of assets that have been soft-deleted from Safeguard. These assets can
be restored with the Restore-SafeguardDeletedAsset command.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetToGet
An integer containing the ID of the deleted asset to get or a string containing the name.

.PARAMETER Fields
An array of the deleted asset property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardDeletedAsset -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardDeletedAsset -Fields Id,Name,NetworkAddress
#>
function Get-SafeguardDeletedAsset
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [object]$AssetToGet,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:RelPath = "Deleted/Assets"
    $local:Parameters = $null
    if ($Fields)
    {
        $local:Parameters = @{ fields = ($Fields -join ",")}
    }

    if ($PSBoundParameters.ContainsKey("AssetToGet"))
    {
        $local:AssetId = (Resolve-SafeguardDeletedAssetId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AssetToGet)
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)/$($local:AssetId)" -Parameters $local:Parameters
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" -Parameters $local:Parameters
    }
}

<#
.SYNOPSIS
Purge a deleted asset.

.DESCRIPTION
Purge a deleted asset from Safeguard making it unrecoverable. Purging an asset will also
purge any asset accounts that depend on it.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetToDelete
An object representing the deleted asset to purge or an integer 
containing the ID of the asset or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardDeletedAsset -AccessToken $token -Appliance 10.5.32.54 -Insecure 5

.EXAMPLE
Remove-SafeguardDeletedAsset 5
#>
function Remove-SafeguardDeletedAsset
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
        [object]$AssetToDelete
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:AssetId = (Resolve-SafeguardDeletedAssetId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AssetToDelete)
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "Deleted/Assets/$($local:AssetId)"
}

<#
.SYNOPSIS
Restore a soft-deleted asset to its previous (un-deleted) state.

.DESCRIPTION
Restore a soft-deleted asset to its previous (un-deleted) state. Restoring an asset does not
automatically restore soft-deleted asset accounts associated with the asset.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AssetToRestore
An object representing the deleted asset to restore or an integer 
containing the ID of the asset account or a string containing the name. When
AssetToRestore is an object returned by Get-SafeguardDeletedAsset, any modifications 
to property values will take precedent when restoring the asset.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Restore-SafeguardDeletedAsset -AccessToken $token -Appliance 10.5.32.54 -Insecure 5

.EXAMPLE
Restore-SafeguardDeletedAsset 5
#>
function Restore-SafeguardDeletedAsset
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
        [object]$AssetToRestore
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Asset = $AssetToRestore
    if($AssetToRestore -as [int] -or $AssetToRestore -is [string]) {
        $local:Asset = (Get-SafeguardDeletedAsset -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AssetToRestore)[0]
    }
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure  Core POST `
        "Deleted/Assets/$($local:Asset.Id)/Restore" -Body $local:Asset
}

########################################################################################
# ASSET ACCOUNTS
########################################################################################

# Helper
function Resolve-SafeguardDeletedAssetAccountId
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
        [object]$AssetAccount
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($AssetAccount.Id -as [int])
    {
        $AssetAccount = $AssetAccount.Id
    }

    $local:RelPath = "Deleted/AssetAccounts"
    $local:ErrMsgSuffix = " in deleted asset accounts"
    $local:AssetAccounts = $null

    if (-not ($AssetAccount -as [int]))
    {
        try
        {
            $local:AssetAccounts = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" `
                                -Parameters @{ filter = "Name ieq '$AssetAccount'"; fields = "Id" })
        }
        catch
        {
            Write-Verbose $_
            Write-Verbose "Caught exception with ieq filter, trying with q parameter"
            $local:AssetAccounts = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" `
                                 -Parameters @{ q = $AssetAccount; fields = "Id" })
        }
        if (-not $local:AssetAccounts)
        {
            throw "Unable to find asset account matching '$AssetAccount'$($local:ErrMsgSuffix)"
        }
        if ($local:AssetAccounts.Count -ne 1)
        {
            throw "Found $($local:AssetAccounts.Count) asset accounts matching '$AssetAccount'$($local:ErrMsgSuffix)"
        }
        $local:AssetAccounts[0].Id
    }
    else
    {
        # Make sure it actually exists
        $local:AssetAccounts = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" `
            -Parameters @{ filter = "Id eq $AssetAccount"; fields = "Id" })
        if (-not $local:AssetAccounts)
        {
            throw "Unable to find asset account matching '$AssetAccount'$($local:ErrMsgSuffix)"
        }
        $AssetAccount
    }
}

<#
.SYNOPSIS
Get deleted asset accounts.

.DESCRIPTION
Returns a list of asset accounts that have been soft-deleted from Safeguard. These accounts can
be restored with the Restore-SafeguardDeletedAssetAccount command.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AccountToGet
An integer containing the ID of the deleted asset account to get or a string containing the name.

.PARAMETER Fields
An array of the deleted asset account property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardDeletedAssetAccount -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardDeletedAssetAccount -Fields Id,Name,AssetNetworkAddress
#>
function Get-SafeguardDeletedAssetAccount
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [object]$AccountToGet,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:RelPath = "Deleted/AssetAccounts"
    $local:Parameters = $null
    if ($Fields)
    {
        $local:Parameters = @{ fields = ($Fields -join ",")}
    }

    if ($PSBoundParameters.ContainsKey("AccountToGet"))
    {
        $local:AssetAccountId = (Resolve-SafeguardDeletedAssetAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AccountToGet)
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)/$($local:AssetAccountId)" -Parameters $local:Parameters
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" -Parameters $local:Parameters
    }
}

<#
.SYNOPSIS
Purge a deleted asset account.

.DESCRIPTION
Purge a deleted asset account from Safeguard making it unrecoverable.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AccountToDelete
An object representing the deleted asset account to delete or an integer 
containing the ID of the asset account or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardDeletedAssetAccount -AccessToken $token -Appliance 10.5.32.54 -Insecure 5

.EXAMPLE
Remove-SafeguardDeletedAssetAccount 5
#>
function Remove-SafeguardDeletedAssetAccount
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
        [object]$AccountToDelete
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:AssetAccountId = (Resolve-SafeguardDeletedAssetAccountId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AccountToDelete)
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "Deleted/AssetAccounts/$($local:AssetAccountId)"
}

<#
.SYNOPSIS
Restore a soft-deleted asset account to its previous (un-deleted) state.

.DESCRIPTION
Restore a soft-deleted asset account to its previous (un-deleted) state. An asset account can only be
restored if it's parent asset exists. You may need to restore the asset first if it was 
previously deleted.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER AccountToRestore
An object representing the deleted asset account to restore or an integer 
containing the ID of the asset account or a string containing the name. When
AccountToRestore is an object returned by Get-SafeguardDeletedAssetAccount, any modifications 
to property values will take precedent when restoring the asset account.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Restore-SafeguardDeletedAssetAccount -AccessToken $token -Appliance 10.5.32.54 -Insecure 5

.EXAMPLE
Restore-SafeguardDeletedAssetAccount 5
#>
function Restore-SafeguardDeletedAssetAccount
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
        [object]$AccountToRestore
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:AssetAccount = $AccountToRestore
    if($AccountToRestore -as [int] -or $AccountToRestore -is [string]) {
        $local:AssetAccount = (Get-SafeguardDeletedAssetAccount -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $AccountToRestore)[0]
    }
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure  Core POST `
        "Deleted/AssetAccounts/$($local:AssetAccount.Id)/Restore" -Body $local:AssetAccount
}

########################################################################################
# USERS
########################################################################################

# Helper
function Resolve-SafeguardDeletedUserId
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
        [object]$User
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($User.Id -as [int])
    {
        $User = $User.Id
    }

    $local:RelPath = "Deleted/Users"
    $local:ErrMsgSuffix = " in deleted users"
    $local:Users = $null

    if (-not ($User -as [int]))
    {
        try
        {
            $local:Users = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" `
                                 -Parameters @{ filter = "Name ieq '$User' or DisplayName ieq '$User'"; fields = "Id" })
        }
        catch
        {
            Write-Verbose $_
            Write-Verbose "Caught exception with ieq filter, trying with q parameter"
            $local:Users = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" `
                                 -Parameters @{ q = $User; fields = "Id" })
        }
        if (-not $local:Users)
        {
            throw "Unable to find user matching '$User'$($local:ErrMsgSuffix)"
        }
        if ($local:Users.Count -ne 1)
        {
            throw "Found $($local:Users.Count) users matching '$User'$($local:ErrMsgSuffix)"
        }
        $local:Users[0].Id
    }
    else
    {
        # Make sure it actually exists
        $local:Users = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" `
            -Parameters @{ filter = "Id eq $User"; fields = "Id" })
        if (-not $local:Users)
        {
            throw "Unable to find user matching '$User'$($local:ErrMsgSuffix)"
        }
        $User
    }
}

<#
.SYNOPSIS
Get deleted users.

.DESCRIPTION
Returns a list of users that have been soft-deleted from Safeguard. These users can
be restored with the Restore-SafeguardDeletedUser command.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER UserToGet
An integer containing the ID of the deleted user to get or a string containing the name.

.PARAMETER Fields
An array of the deleted user property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardDeletedUser -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardDeletedUser -Fields Id,Name,DisplayName
#>
function Get-SafeguardDeletedUser
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [object]$UserToGet,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:RelPath = "Deleted/Users"
    $local:Parameters = $null
    if ($Fields)
    {
        $local:Parameters = @{ fields = ($Fields -join ",")}
    }

    if ($PSBoundParameters.ContainsKey("UserToGet"))
    {
        $local:UserId = (Resolve-SafeguardDeletedUserId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $UserToGet)
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)/$($local:UserId)" -Parameters $local:Parameters
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "$($local:RelPath)" -Parameters $local:Parameters
    }
}

<#
.SYNOPSIS
Purge a deleted user.

.DESCRIPTION
Purge a deleted user from Safeguard making it unrecoverable.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER UserToDelete
An object representing the deleted user to remove or an integer 
containing the ID of the user or a string containing the name.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardDeletedUser -AccessToken $token -Appliance 10.5.32.54 -Insecure 5

.EXAMPLE
Remove-SafeguardDeletedUser 5
#>
function Remove-SafeguardDeletedUser
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
        [object]$UserToDelete
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:UserId = (Resolve-SafeguardDeletedUserId -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $UserToDelete)
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "Deleted/Users/$($local:UserId)" 
}

<#
.SYNOPSIS
Restore a deleted user to its previous (un-deleted) state.

.DESCRIPTION
Restore a deleted user to its previous (un-deleted) state. 

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER UserToRestore
An object representing the deleted user to remove or an integer 
containing the ID of the user or a string containing the name. When
UserToRestore is an object returned by Get-SafeguardDeletedUser, any modifications 
to property values will take precedent when restoring the user.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Restore-SafeguardDeletedUser -AccessToken $token -Appliance 10.5.32.54 -Insecure 5

.EXAMPLE
Restore-SafeguardDeletedUser 5
#>
function Restore-SafeguardDeletedUser
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
        [object]$UserToRestore
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:User = $UserToRestore
    if($UserToRestore -is [string] -or $UserToRestore -as [int]) {
        $local:User = (Get-SafeguardDeletedUser -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $UserToRestore)[0]
    }
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure  Core POST `
        "Deleted/Users/$($local:User.Id)/Restore" -Body $local:User
}

########################################################################################
# PURGE SETTINGS
########################################################################################

<#
.SYNOPSIS
Get the current automatic purge settings.

.DESCRIPTION
Returns the current automatic purge settings. Automatic purge settings control whether
Safeguard will automatically purge deleted objects after a specified retention period.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardPurgeSettings -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardPurgeSettings 
#>
function Get-SafeguardPurgeSettings
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure  Core GET `
        "Deleted/PurgeSettings"
}


<#
.SYNOPSIS
Update the current automatic purge settings.

.DESCRIPTION
Update the current automatic purge settings as specified. 

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Settings
An object representing the new settings to apply. Use the
Get-SafeguardPurgeSettings command to obtain the settings and
adjust the properties as desired.

.PARAMETER AutoPurgeAssets
Indicates whether to automatically purge deleted asset objects 
after the corresponding retention period expires.

.PARAMETER AutoPurgeAssetAccounts
Indicates whether to automatically purge deleted asset account objects 
after the corresponding retention period expires.

.PARAMETER AutoPurgeUsers
Indicates whether to automatically purge deleted users objects 
after the corresponding retention period expires.

.PARAMETER DeletedAssetRetentionInDays
The number of days to retain deleted asset objects before
automatically purging them. Has no effect if AutoPurgeAssets is false.

.PARAMETER DeletedAssetAccountRetentionInDays
The number of days to retain deleted asset account objects before
automatically purging them. Has no effect if AutoPurgeAssetAccounts is false.

.PARAMETER DeletedUserRetentionInDays
The number of days to retain deleted user objects before
automatically purging them. Has no effect if AutoPurgeUsers is false.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Update-SafeguardPurgeSettings -AccessToken $token -Appliance 10.5.32.54 -Insecure -Settings $settings

.EXAMPLE
Update-SafeguardPurgeSettings -Settings $settings
#>
function Update-SafeguardPurgeSettings
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
        [bool]$AutoPurgeAssets,
        [Parameter(Mandatory=$false)]
        [bool]$AutoPurgeAssetAccounts,
        [Parameter(Mandatory=$false)]
        [bool]$AutoPurgeUsers,
        [Parameter(Mandatory=$false)]
        [int]$DeletedAssetRetentionInDays,
        [Parameter(Mandatory=$false)]
        [int]$DeletedAssetAccountRetentionInDays,
        [Parameter(Mandatory=$false)]
        [int]$DeletedUserRetentionInDays,
        [Parameter(Mandatory=$false,Position=0)]
        [object]$Settings
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:PurgeSettings = $Settings
    if(-not $local:PurgeSettings) {
        $local:PurgeSettings = Get-SafeguardPurgeSettings
    }
    if($PSBoundParameters.ContainsKey("AutoPurgeAssets")) {
        $local:PurgeSettings.AutoPurgeAssets = $AutoPurgeAssets
    }
    if($PSBoundParameters.ContainsKey("AutoPurgeAssetAccounts")) {
        $local:PurgeSettings.AutoPurgeAssetAccounts = $AutoPurgeAssetAccounts
    }
    if($PSBoundParameters.ContainsKey("AutoPurgeUsers")) {
        $local:PurgeSettings.AutoPurgeUsers = $AutoPurgeUsers
    }
    if($PSBoundParameters.ContainsKey("DeletedAssetRetentionInDays")) {
        $local:PurgeSettings.DeletedAssetRetentionInDays = $DeletedAssetRetentionInDays
    }
    if($PSBoundParameters.ContainsKey("DeletedAssetAccountRetentionInDays")) {
        $local:PurgeSettings.DeletedAssetAccountRetentionInDays = $DeletedAssetAccountRetentionInDays
    }
    if($PSBoundParameters.ContainsKey("DeletedUserRetentionInDays")) {
        $local:PurgeSettings.DeletedUserRetentionInDays = $DeletedUserRetentionInDays
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure  Core PUT `
        "Deleted/PurgeSettings" -Body $local:PurgeSettings
}

<#
.SYNOPSIS
Reset the automatic purge settings to default values

.DESCRIPTION
Resets the automatic purge settings to their default values and returns them. By default,
deleted objects are never purged automatically.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Reset-SafeguardPurgeSettings -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Reset-SafeguardPurgeSettings
#>
function Reset-SafeguardPurgeSettings
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure  Core PUT `
        "Deleted/PurgeSettings" -Body ""
}