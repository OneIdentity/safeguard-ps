# This file contains random Safeguard utilities required by some modules
# Nothing is exported from here
function Out-SafeguardExceptionIfPossible
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [object]$ThrownException
    )

    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not ([System.Management.Automation.PSTypeName]"Ex.SafeguardMethodException").Type)
    {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.Serialization;

namespace Ex
{
    public class SafeguardMethodException : System.Exception
    {
        public SafeguardMethodException()
            : base("Unknown SafeguardMethodException") {}
        public SafeguardMethodException(int httpCode, string httpMessage, int errorCode, string errorMessage, string errorJson)
            : base(httpCode + ": " + httpMessage + " -- " + errorCode + ": " + errorMessage)
        {
            HttpStatusCode = httpCode;
            ErrorCode = errorCode;
            ErrorMessage = errorMessage;
            ErrorJson = errorJson;
        }
        public SafeguardMethodException(string message, Exception innerException)
            : base(message, innerException) {}
        protected SafeguardMethodException
            (SerializationInfo info, StreamingContext context)
            : base(info, context) {}
        public int HttpStatusCode { get; set; }
        public int ErrorCode { get; set; }
        public string ErrorMessage { get; set; }
        public string ErrorJson { get; set; }
    }
}
"@
    }
    $local:ExceptionToThrow = $ThrownException
    if ($ThrownException.Response)
    {
        Write-Verbose "---Response Status---"
        Write-Verbose "$([int]$ThrownException.Response.StatusCode) $($ThrownException.Response.StatusDescription)"
        Write-Verbose "---Response Body---"
        $local:Stream = $ThrownException.Response.GetResponseStream()
        $local:Reader = New-Object System.IO.StreamReader($local:Stream)
        $local:Reader.BaseStream.Position = 0
        $local:Reader.DiscardBufferedData()
        $local:ResponseBody = $local:Reader.ReadToEnd()
        Write-Verbose $local:ResponseBody
        $local:Reader.Dispose()
        try # try/catch is a workaround for this bug in PowerShell:
        {   # https://stackoverflow.com/questions/41272128/does-convertfrom-json-respect-erroraction
            $local:ResponseObject = (ConvertFrom-Json $local:ResponseBody) # -ErrorAction SilentlyContinue
        }
        catch {}
        if ($local:ResponseObject.Code) # Safeguard error
        {
            $local:ExceptionToThrow = (New-Object Ex.SafeguardMethodException -ArgumentList @(
                [int]$ThrownException.Response.StatusCode, $ThrownException.Response.StatusDescription,
                $local:ResponseObject.Code, $local:ResponseObject.Message, $local:ResponseBody
            ))
        }
        elseif ($local:ResponseObject.error_description) # rSTS error
        {
            $local:ExceptionToThrow = (New-Object Ex.SafeguardMethodException -ArgumentList @(
                [int]$ThrownException.Response.StatusCode, $ThrownException.Response.StatusDescription,
                0, $local:ResponseObject.error_description, $local:ResponseBody
            ))
        }
        else # ??
        {
            $local:ExceptionToThrow = (New-Object Ex.SafeguardMethodException -ArgumentList @(
                [int]$ThrownException.Response.StatusCode, $ThrownException.Response.StatusDescription,
                0, "", $local:ResponseBody
            ))
        }
    }
    Write-Verbose "---Exception---"
    $ThrownException | Format-List * -Force | Out-String | Write-Verbose
    if ($ThrownException.InnerException)
    {
        Write-Verbose "---Inner Exception---"
        $ThrownException.InnerException | Format-List * -Force | Out-String | Write-Verbose
    }
    throw $local:ExceptionToThrow
}
function Wait-ForSafeguardStatus
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [int]$Timeout = 600,
        [Parameter(Mandatory=$true)]
        [string]$DesiredStatus
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Start-Sleep 5 # up front wait to solve new transition timing issues

    $local:StartTime = (Get-Date)
    $local:Status = "Unreachable"
    $local:TimeElapsed = 10
    do {
        Write-Progress -Activity "Waiting for $DesiredStatus Status" -Status "Current: $($local:Status)" -PercentComplete (($local:TimeElapsed / $Timeout) * 100)
        try
        {
            $local:Status = (Get-SafeguardStatus -Appliance $Appliance -Insecure:$Insecure).ApplianceCurrentState
        }
        catch {}
        Start-Sleep 2
        $local:TimeElapsed = (((Get-Date) - $local:StartTime).TotalSeconds)
        if ($local:TimeElapsed -gt $Timeout)
        {
            throw "Timed out waiting for $DesiredStatus Status, timeout was $Timeout seconds"
        }
    } until ($local:Status -ieq $DesiredStatus)
    Write-Progress -Activity "Waiting for $DesiredStatus Status" -Status "Current: $($local:Status)" -PercentComplete 100
}
function Wait-ForSafeguardOnlineStatus
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [int]$Timeout = 600
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Wait-ForSafeguardStatus -Appliance $Appliance -Insecure:$Insecure -Timeout $Timeout -DesiredStatus "Online"
    Write-Host "Safeguard is back online."
}

function Wait-ForSessionModuleState
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
        [string]$ContainerState,
        [Parameter(Mandatory=$false,Position=1)]
        [string]$ModuleState,
        [Parameter(Mandatory=$false,Position=2)]
        [int]$Timeout = 180
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:StartTime = (Get-Date)
    if ($ContainerState -and $ModuleState)
    {
        $local:DesiredStatus = "$ContainerState, $ModuleState"
    }
    elseif ($ContainerState)
    {
        $local:DesiredStatus = "$ContainerState, Any"
    }
    elseif ($ModuleState)
    {
        $local:DesiredStatus = "Any, $ModuleState"
    }
    else
    {
        $local:DesiredStatus = "Any, Any"
    }
    $local:StatusString = "Unreachable, Unreachable"
    $local:TimeElapsed = 4
    do {
        Write-Progress -Activity "Waiting for Session Module Status: $($local:DesiredStatus)" -Status "Current: $($local:StatusString)" -PercentComplete (($local:TimeElapsed / $Timeout) * 100)
        try
        {
            $local:StateFound = $false
            $local:Status = (Get-SafeguardSessionContainerStatus -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure)
            $local:StatusString = "$($local:Status.SessionContainerState), $($local:Status.SessionModuleState)"
            if ($ContainerState -and $ModuleState)
            {
                $local:StateFound = ($local:Status.SessionContainerState -eq $ContainerState -and $local:Status.SessionModuleState -eq $ModuleState)
            }
            elseif ($ContainerState)
            {
                $local:StateFound = ($local:Status.SessionContainerState -eq $ContainerState)
            }
            elseif ($ModuleState)
            {
                $local:StateFound = ($local:Status.SessionModuleState -eq $ModuleState)
            }
            else
            {
                $local:StateFound = $true
            }
        }
        catch 
        {
            $local:StatusString = "Unreachable, Unreachable"
        }
        Start-Sleep 2
        $local:TimeElapsed = (((Get-Date) - $local:StartTime).TotalSeconds)
        if ($local:TimeElapsed -gt $Timeout)
        {
            throw "Timed out waiting for Session Module Status, timeout was $Timeout seconds"
        }
    } until ($local:StateFound)
    Write-Progress -Activity "Waiting for Session Module Status: $($local:DesiredStatus)" -Status "Current: $($local:StatusString)" -PercentComplete 100
}

function Wait-ForClusterOperation
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
        [int]$Timeout = 600
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:StartTime = (Get-Date)
    $local:Status = "Unknown"
    $local:TimeElapsed = 10
    do {
        Write-Progress -Activity "Waiting for cluster operation to finish" -Status "Cluster Operation: $($local:Status)" -PercentComplete (($local:TimeElapsed / $Timeout) * 100)
        try
        {
            $local:Status = (Invoke-SafeguardMethod -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure Core GET ClusterStatus).Operation
        }
        catch {}
        Start-Sleep 2
        $local:TimeElapsed = (((Get-Date) - $local:StartTime).TotalSeconds)
        if ($local:TimeElapsed -gt $Timeout)
        {
            throw "Timed out waiting for cluster operation to finish, timeout was $Timeout seconds"
        }
    } until ($local:Status -eq "None")
    Write-Progress -Activity "Waiting for cluster operation to finish" -Status "Current: $($local:Status)" -PercentComplete 100
    Write-Host "Safeguard cluster operation completed...~$($local:TimeElapsed) seconds"
}

function Wait-ForPatchDistribution
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
        [int]$Timeout = 600
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:TimeElapsed = 0

    if ((Invoke-SafeguardMethod -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure Core GET "Cluster/Members" `
        -RetryUrl "ClusterMembers").Count -gt 1)
    {
        $local:StartTime = (Get-Date)
        $local:Status = "Unknown"
        $local:TimeElapsed = 10
        do {
            Write-Progress -Activity "Waiting for patch distribution" -Status "Cluster Operation: $($local:Status)" -PercentComplete (($local:TimeElapsed / $Timeout) * 100)
            try
            {
                $local:Members = (Invoke-SafeguardMethod -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure Core GET ClusterStatus/PatchDistribution).Members
                $local:StagingStatuses = ($local:Members.StagingStatus | Sort-Object)
                $local:Status = $local:StagingStatuses -join ","
            }
            catch {}
            Start-Sleep 2
            $local:TimeElapsed = (((Get-Date) - $local:StartTime).TotalSeconds)
            if ($local:TimeElapsed -gt $Timeout)
            {
                throw "Timed out waiting for cluster operation to finish, timeout was $Timeout seconds"
            }
        } until (@($local:StagingStatuses | Select-Object -Unique).Count -eq 1 -and $local:StagingStatuses[0] -eq "Staged")
        Write-Progress -Activity "Waiting for patch distribution" -Status "Current: $($local:Status)" -PercentComplete 100
    }
    Write-Host "Safeguard patch distribution completed...~$($local:TimeElapsed) seconds"
}

function Resolve-SafeguardSystemId
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
        [object]$System
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    try
    {
        Import-Module -Name "$PSScriptRoot\assets.psm1" -Scope Local
        Resolve-SafeguardAssetId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure $System
    }
    catch
    {
        Write-Verbose "Unable to resolve to asset ID, trying directories"
        try 
        {
            Import-Module -Name "$PSScriptRoot\directories.psm1" -Scope Local
            Resolve-SafeguardDirectoryId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure $System
        }
        catch
        {
            Write-Verbose "Unable to resolve to directory ID"
            throw "Cannot determine system ID for '$System'"
        }
    }
}

function Resolve-SafeguardAccountIdWithoutSystemId
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
        [object]$Account
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    try
    {
        Import-Module -Name "$PSScriptRoot\assets.psm1" -Scope Local
        Resolve-SafeguardAssetAccountId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure $Account
    }
    catch
    {
        Write-Verbose "Unable to resolve to asset account ID, trying directories"
        try 
        {
            Import-Module -Name "$PSScriptRoot\directories.psm1" -Scope Local
            Resolve-SafeguardDirectoryAccountId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure $Account
        }
        catch
        {
            Write-Verbose "Unable to resolve to directory account ID"
            throw "Cannot determine account ID for '$Account'"
        }
    }
}

function Resolve-SafeguardAccountIdWithSystemId
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
        [int]$SystemId,
        [Parameter(Mandatory=$true,Position=1)]
        [object]$Account
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    try
    {
        Import-Module -Name "$PSScriptRoot\assets.psm1" -Scope Local
        Resolve-SafeguardAssetAccountId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure -AssetId $SystemId $Account
    }
    catch
    {
        Write-Verbose "Unable to resolve to asset account ID, trying directories"
        try 
        {
            Import-Module -Name "$PSScriptRoot\directories.psm1" -Scope Local
            Resolve-SafeguardDirectoryAccountId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure -DirectoryId $SystemId $Account
        }
        catch
        {
            Write-Verbose "Unable to resolve to directory account ID"
            throw "Cannot determine system ID for '$System'"
        }
    }
}

function Resolve-ReasonCodeId
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
        [object]$ReasonCode
    )

    $ErrorActionPreference = "Stop"
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not ($ReasonCode -as [int]))
    {
        try
        {
            $local:ReasonCodes = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                                      Core GET ReasonCodes -Parameters @{ filter = "Name ieq '$ReasonCode'" })
        }
        catch
        {
            Write-Verbose $_
            Write-Verbose "Caught exception with ieq filter, trying with q parameter"
            $local:ReasonCodes = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure `
                                      Core GET ReasonCodes -Parameters @{ q = $ReasonCode })
        }
        if (-not $local:ReasonCodes)
        {
            throw "Unable to find reason code registration matching '$ReasonCode'"
        }
        if ($local:ReasonCodes.Count -ne 1)
        {
            throw "Found $($local:ReasonCodes.Count) reason code registration matching '$ReasonCode'"
        }
        $local:ReasonCodes[0].Id
    }
    else
    {
        $ReasonCode
    }
}