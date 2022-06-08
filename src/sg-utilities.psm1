# This file contains random Safeguard utilities required by some modules
# Nothing is exported from here
function Out-SafeguardExceptionIfPossible
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [object]$PsExceptionObject
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:ThrownException = $PsExceptionObject.Exception

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
    $local:ExceptionToThrow = $local:ThrownException
    if ($local:ThrownException.Response)
    {
        Write-Verbose "---Response Status---"
        if ($local:ThrownException.Response | Get-Member StatusDescription -MemberType Properties)
        {
            $local:StatusDescription = $local:ThrownException.Response.StatusDescription
        }
        elseif ($local:ThrownException.Response | Get-Member ReasonPhrase -MemberType Properties)
        {
            $local:StatusDescription = $local:ThrownException.Response.ReasonPhrase
        }
        Write-Verbose "$([int]$local:ThrownException.Response.StatusCode) $($local:StatusDescription)"
        Write-Verbose "---Response Body---"
        $local:ResponseBody = $PsExceptionObject.ErrorDetails.Message
        if (-not $local:ResponseBody)
        {
            Write-Verbose "Unable to read ErrorDetails.Message, trying to read response stream"
            try
            {
                # try to read again, some runtimes and PowerShell versions fail to populate ErrorDetails
                if ($local:ThrownException.Response | Get-Member GetResponseStream)
                {
                    $local:Reader = [System.IO.StreamReader]::new($local:ThrownException.Response.GetResponseStream())
                    $local:ResponseBody = $local:Reader.ReadToEnd()
                    $local:Reader.Close()
                }
                else
                {
                    $local:Reader = [System.IO.StreamReader]::new($local:ThrownException.Response.Content.ReadAsStream())
                    $local:ResponseBody = $local:Reader.ReadToEnd()
                    $local:Reader.Close()
                }
            }
            catch {}
        }
        if ($local:ResponseBody)
        {
            Write-Verbose $local:ResponseBody
            try # try/catch is a workaround for this bug in PowerShell:
            {   # https://stackoverflow.com/questions/41272128/does-convertfrom-json-respect-erroraction
                $local:ResponseObject = (ConvertFrom-Json $local:ResponseBody) # -ErrorAction SilentlyContinue
            }
            catch {}
            if ($local:ResponseObject.Code) # Safeguard error
            {
                $local:Message = $local:ResponseObject.Message
                if ($local:ResponseObject.ModelState)
                {
                    $local:Properties = ($local:ResponseObject.ModelState | Get-Member | Where-Object { $_.MemberType -eq "NoteProperty" }).Name
                    $local:Properties | ForEach-Object {
                        $local:Message += (" " + $_ + ": " + ($local:ResponseObject.ModelState."$_" -join ","))
                    }
                }
                $local:ExceptionToThrow = (New-Object Ex.SafeguardMethodException -ArgumentList @(
                    [int]$local:ThrownException.Response.StatusCode, $local:StatusDescription,
                    $local:ResponseObject.Code, $local:Message, $local:ResponseBody
                ))
            }
            elseif ($local:ResponseObject.error_description) # rSTS error
            {
                $local:ExceptionToThrow = (New-Object Ex.SafeguardMethodException -ArgumentList @(
                    [int]$local:ThrownException.Response.StatusCode, $local:StatusDescription,
                    0, $local:ResponseObject.error_description, $local:ResponseBody
                ))
            }
            else # ??
            {
                $local:ExceptionToThrow = (New-Object Ex.SafeguardMethodException -ArgumentList @(
                    [int]$local:ThrownException.Response.StatusCode, $local:StatusDescription,
                    0, "<could not parse response content>", $local:ResponseBody
                ))
            }
        }
        else # ??
        {
            $local:ResponseBody = "<unable to retrieve response content>"
            if ($local:ThrownException.Response | Get-Member ContentLength)
            {
                if ($local:ThrownException.Response.ContentLength -eq 0)
                {
                    $local:ErrorDescription = "<no content in response>"
                }
                else
                {
                    $local:ErrorDescription = "<could not read response content>"
                }
            }
            elseif ($local:ThrownException.Response | Get-Member Content)
            {
                if (($local:ThrownException.Response.Content.Headers | Where-Object { $_.Key -eq "Content-Length" }).Value[0] -eq 0)
                {
                    $local:ErrorDescription = "<no content in response>"
                }
                else
                {
                    $local:ErrorDescription = "<could not read response content>"
                }
            }
            $local:ExceptionToThrow = (New-Object Ex.SafeguardMethodException -ArgumentList @(
                [int]$local:ThrownException.Response.StatusCode, $local:StatusDescription,
                0, $local:ErrorDescription, $local:ResponseBody
            ))
        }
    }
    if ($local:ThrownException.Status -eq "TrustFailure")
    {
        Write-Host -ForegroundColor Magenta "To ignore SSL/TLS trust failure use the -Insecure parameter to bypass server certificate validation."
    }
    Write-Verbose "---Exception---"
    $local:ThrownException | Format-List * -Force | Out-String | Write-Verbose
    if ($local:ThrownException.InnerException)
    {
        Write-Verbose "---Inner Exception---"
        $local:ThrownException.InnerException | Format-List * -Force | Out-String | Write-Verbose
    }
    throw $local:ExceptionToThrow
}
function New-LongRunningTaskException
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$TaskResult,
        [Parameter(Mandatory=$true,Position=1)]
        [object]$TaskResponse
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not ([System.Management.Automation.PSTypeName]"Ex.SafeguardLongRunningTaskException").Type)
    {
        Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Management.Automation;

namespace Ex
{
    public class SafeguardTaskLog
    {
        public SafeguardTaskLog(PSObject log)
        {
            Timestamp =  log.Properties["Timestamp"].Value.ToString();
            Status = log.Properties["Status"].Value.ToString();
            Message = log.Properties["Message"].Value.ToString();
        }
        public string Timestamp { get; set; }
        public string Status { get; set; }
        public string Message { get; set; }
        public override string ToString()
        {
            return Timestamp.ToString() + " Status=" + Status + " Message=" + Message;
        }
    }
    public class SafeguardLongRunningTaskException : System.Exception
    {
        public SafeguardLongRunningTaskException()
            : base("Unknown SafeguardMethodException") {}
        public SafeguardLongRunningTaskException(string message, PSObject[] log)
            : base(message)
        {
            var list = new List<SafeguardTaskLog>();
            foreach (var entry in log)
                list.Add(new SafeguardTaskLog(entry));
            TaskLog = list.ToArray();
        }
        protected SafeguardLongRunningTaskException
            (SerializationInfo info, StreamingContext context)
            : base(info, context) {}
        public SafeguardTaskLog[] TaskLog { get; set; }
    }
}
"@
    }

    (New-Object Ex.SafeguardLongRunningTaskException -ArgumentList @($TaskResult, $TaskResponse.Log))
}
function Test-SafeguardMinVersionInternal
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true)]
        [ValidatePattern("^\d+\.\d+")]
        [string]$MinVersion
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    [int]$local:Major,[int]$local:Minor = $MinVersion.split(".")
    $local:CurrentVersion = (Invoke-SafeguardMethod -Anonymous -Appliance $Appliance -Insecure:$Insecure Appliance GET Version -RetryVersion 2)
    if (([int]$local:CurrentVersion.Major) -gt $local:Major `
        -or (([int]$local:CurrentVersion.Major) -eq $local:Major -and ([int]$local:CurrentVersion.Minor) -ge $local:Minor))
    {
        $true
    }
    else
    {
        $false
    }
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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Start-Sleep 5 # up front wait to solve new transition timing issues

    $local:StartTime = (Get-Date)
    $local:Status = "Unreachable"
    $local:TimeElapsed = 10
    if ($Timeout -lt 10) { $Timeout = 10 }
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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:StartTime = (Get-Date)
    $local:Status = "Unknown"
    $local:TimeElapsed = 10
    do {
        Write-Progress -Activity "Waiting for cluster operation to finish" -Status "Cluster Operation: $($local:Status)" -PercentComplete (($local:TimeElapsed / $Timeout) * 100)
        try
        {
            $local:Status = (Invoke-SafeguardMethod -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure Core GET "Cluster/Status").Operation
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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:TimeElapsed = 0

    if ((Invoke-SafeguardMethod -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure Core GET "Cluster/Members").Count -gt 1)
    {
        $local:StartTime = (Get-Date)
        $local:Status = "Unknown"
        $local:TimeElapsed = 10
        do {
            Write-Progress -Activity "Waiting for patch distribution" -Status "Cluster Operation: $($local:Status)" -PercentComplete (($local:TimeElapsed / $Timeout) * 100)
            try
            {
                $local:Members = (Invoke-SafeguardMethod -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure Core GET "Cluster/Status/PatchDistribution").Members
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

function Resolve-SafeguardAssetId
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

    try
    {
        Import-Module -Name "$PSScriptRoot\assets.psm1" -Scope Local
        Resolve-SafeguardAssetId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure $Asset
    }
    catch
    {
        Write-Verbose "Unable to resolve to asset ID, trying directories"
        try
        {
            Import-Module -Name "$PSScriptRoot\directories.psm1" -Scope Local
            Resolve-SafeguardDirectoryId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure $Asset
        }
        catch
        {
            Write-Verbose "Unable to resolve to directory ID"
            throw "Cannot determine asset ID for '$Asset'"
        }
    }
}

function Resolve-SafeguardAccountIdWithoutAssetId
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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
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

function Resolve-SafeguardAccountIdWithAssetId
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
        [int]$AssetId,
        [Parameter(Mandatory=$true,Position=1)]
        [object]$Account
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    try
    {
        Import-Module -Name "$PSScriptRoot\assets.psm1" -Scope Local
        Resolve-SafeguardAssetAccountId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure -AssetId $AssetId $Account
    }
    catch
    {
        Write-Verbose "Unable to resolve to asset account ID, trying directories"
        try
        {
            Import-Module -Name "$PSScriptRoot\directories.psm1" -Scope Local
            Resolve-SafeguardDirectoryAccountId -Appliance $Appliance -AccessToken $AccessToken -Insecure:$Insecure -DirectoryId $AssetId $Account
        }
        catch
        {
            Write-Verbose "Unable to resolve to directory account ID"
            throw "Cannot determine asset ID for '$Asset'"
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

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($ReasonCode.Id -as [int])
    {
        $ReasonCode = $ReasonCode.Id
    }

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

function Resolve-DomainNameFromIdentityProvider
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true)]
        [object]$IdentityProvider
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:DirectoryIdentityProvider = (Get-SafeguardDirectoryIdentityProvider -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $IdentityProvider)
    if ($local:DirectoryIdentityProvider)
    {
        $local:Domains = $local:DirectoryIdentityProvider.DirectoryProperties.Domains
        if ($null -eq $local:Domains) # backwards compat
        {
            $local:Domains = $local:DirectoryIdentityProvider.Domains
        }
        if (-not ($local:Domains -is [array]))
        {
            $local:DomainName = $local:Domains.DomainName
        }
        else
        {
            if ($local:Domains.Count -eq 1)
            {
                $local:DomainName = $local:Domains[0].DomainName
            }
            elseif ($local:Domains | Where-Object { $_.DomainName -ieq $IdentityProvider })
            {
                $local:DomainName = ($local:Domains | Where-Object { $_.DomainName -ieq $IdentityProvider }).DomainName
            }
            else
            {
                Write-Host "Domains in Directory ($IdentityProvider):"
                Write-Host "["
                $local:Domains | ForEach-Object -Begin { $index = 0 } -Process {  Write-Host ("    {0,3} - {1}" -f $index,$_.DomainName); $index++ }
                Write-Host "]"
                $local:DomainNameIndex = (Read-Host "Select a DomainName by number")
                $local:DomainName = $local:Domains[$local:DomainNameIndex].DomainName
            }
        }
        $local:DomainName
    }
}

# Helper function for formatting dates (useful for passing to audit log query parameters)
function Format-UtcDateTimeAsString
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [DateTime]$DateTime
    )

    "$($DateTime.ToString("yyyy-MM-ddTHH:mm:ssZ"))"
}
function Format-DateTimeAsString
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [DateTime]$DateTime
    )

    "$($DateTime.ToString("yyyy-MM-ddTHH:mm:sszzz"))"
}
# Helper function to get begin time for audit log
function Get-EntireAuditLogStartDateAsString
{
    [CmdletBinding()]
    Param(
    )

    Format-DateTimeAsString ((Get-Date -Month 1 -Day 1 -Year 2017 -Hour 0 -Minute 0 -Second 0).ToUniversalTime())
}
# Helper function to determine the IPv6 address of the VPN adapter
function Get-VpnIpv6Address
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$ApplianceId
    )

    if ($ApplianceId.Length -eq 12)
    {
        # Hardware
        $local:Bytes = ($ApplianceId -replace '^0x', '' -split "(?<=\G\w{2})(?=\w{2})" | ForEach-Object { [Convert]::ToByte( $_, 16 ) })
        $local:Bytes[0] = $local:Bytes[0] -bor 0x02
        $local:Bytes += $local:Bytes[4]
        $local:Bytes += $local:Bytes[5]
        $local:Bytes[5] = $local:Bytes[3]
        $local:Bytes[4] = 0xfe
        $local:Bytes[3] = 0xff
    }
    else
    {
        # VM
        $local:Bytes = ($ApplianceId.Substring(0,16) -replace '^0x', '' -split "(?<=\G\w{2})(?=\w{2})" | ForEach-Object { [Convert]::ToByte( $_, 16 ) })
        $local:Bytes[0] = $local:Bytes[0] -band 0xfd
    }

    ("fd70:616e:6761:6561:" + [System.BitConverter]::ToString($local:Bytes).Replace("-","").Insert(12,":").Insert(8,":").Insert(4,":")).ToLower()
}
