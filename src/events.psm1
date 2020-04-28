#Helper
function Resolve-SubscriptionEvent
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
        [object]$TypeOfEvent,
        [Parameter(Mandatory=$true,Position=1)]
        [string[]]$EventsToValidate
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    [string[]]$InvalidEvents = $null
    [object[]]$SubscriptionEvents = $null
    [string[]]$EventNames = Get-SafeguardEventName -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -TypeOfEvent $TypeOfEvent

    foreach ($IndividualEvent in $EventsToValidate)
    {
        if (-not $EventNames.Contains($IndividualEvent))
        {
            $InvalidEvents += $IndividualEvent
        }
        $local:SubscriptionEvent = @{
            Name = $IndividualEvent
        }
        $SubscriptionEvents += $local:SubscriptionEvent
    }

    if ($null -ne $InvalidEvents)
    {
        $InvalidEventsList = $InvalidEvents -join ","
        Write-Error -Message "The following are not valid $ObjectTypeToSubscribe events: $InvalidEventsList." -Category InvalidArgument -ErrorAction Stop
    }
    return $SubscriptionEvents
}

<#
.SYNOPSIS
Get events in Safeguard via the Web API.

.DESCRIPTION
Safeguard events are events that occur as a result of an administrative activity such as created and deletion of an asset or an account.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER EventToGet
A string containing the name of the event to get.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardEvent -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardEvent AssetCreated
#>
function Get-SafeguardEvent
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
        [object]$EventToGet
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSBoundParameters.ContainsKey("EventToGet"))
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "Events/$EventToGet"
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Events
    }
}

<#
.SYNOPSIS
Get the names of subscription events in Safeguard by their type via the Web API.

.DESCRIPTION
Get the list of names of subscription events in Safeguard.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER TypeofEvent
A string containing the type of events for which to return the names of the events that belong to this type.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardEventName -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardEventName AssetAccount
#>
function Get-SafeguardEventName
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false, Position=0)]
        [ValidateSet('Asset', 'AssetAccount', 'Directory', 'DirectoryAccount', 'IdentityProvider', 'User', 'UserGroup', 'AssetPartition', 'PartitionProfileAccountDiscoverySchedule',
        'PartitionAccountPasswordRule', 'PartitionProfileChangeSchedule', 'PartitionProfileCheckSchedule', 'PartitionProfile','AccessPolicy', 'AccountGroup', 'AssetGroup',
        'Role', 'ReasonCode', 'DirectoryAccountDiscoveryJob', 'DirectoryAccountPasswordRule', 'DirectoryProfileChangeSchedule', 'DirectoryProfileCheckSchedule', 'DirectoryProfile',
        'ArchiveServer', 'TicketSystem', 'PartitionTag', 'PartitionTaggingRule', 'DirectoryTag', 'DirectoryTaggingRule', 'DynamicGroupingRule', IgnoreCase=$true)]
        [object]$TypeofEvent
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    [object[]]$Names = $null
    $local:Events = Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET Events
    ForEach($IndividualEvent in $Events)
    {
        if ($PSBoundParameters.ContainsKey("TypeofEvent"))
        {
            if(($IndividualEvent).ObjectType -eq $TypeofEvent)
            {
                $Names += $(($local:IndividualEvent).Name)
            }
        }
        else
        {
            $Names += $(($local:IndividualEvent).Name)
        }
    }
    return $Names
}

<#
.SYNOPSIS
Get event subscription in Safeguard via the Web API.

.DESCRIPTION
Event subscription is a subscription to receive notifications when an event occurs.
Event subscription can be created for all type of users but can only be created by
an administrative user. One event subscriber can subscribe to multiple events.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER SubscriptionId
An integer containing ID of the event subscription to get.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardEventSubscription -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Get-SafeguardEventSubscription 123
#>
function Get-SafeguardEventSubscription
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false, Position=0)]
        [string]$SubscriptionId
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSBoundParameters.ContainsKey("SubscriptionId"))
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "EventSubscribers/$SubscriptionId"
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET EventSubscribers
    }

}

<#
.SYNOPSIS
Search for an event subscription in Safeguard via the Web API.

.DESCRIPTION
Search for an event subscription in Safeguard for any string fields containing
the SearchString.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER SearchString
A string to search for in the event subscription.

.PARAMETER QueryFilter
A string to pass to the -filter query parameter in the Safeguard Web API.

.PARAMETER Fields
An array of the event property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Find-SafeguardEventSubscription -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Find-SafeguardEventSubscription "test"

.EXAMPLE
Find-SafeguardEventSubscription -QueryFilter "PartitionOwnerIsSubscribed eq True" -Fields Id,Type,Description

.EXAMPLE
Find-SafeguardEventSubscription -QueryFilter "AdminRoles contains 'ApplianceAdmin'" -Fields Id,Type,Description
#>
function Find-SafeguardEventSubscription
{
    [CmdletBinding(DefaultParameterSetName="Search")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0,ParameterSetName="Search")]
        [string]$SearchString,
        [Parameter(Mandatory=$true,Position=0,ParameterSetName="Query")]
        [string]$QueryFilter,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSCmdlet.ParameterSetName -eq "Search")
    {
        $local:Parameters = @{ q = $SearchString }
        if ($Fields)
        {
            $local:Parameters["fields"] = ($Fields -join ",")
        }
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET EventSubscribers `
            -Parameters $local:Parameters
    }
    else
    {
        $local:Parameters = @{ filter = $QueryFilter }
        if ($Fields)
        {
            $local:Parameters["fields"] = ($Fields -join ",")
        }
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET EventSubscribers `
            -Parameters $local:Parameters
    }
}

<#
.SYNOPSIS
Create a new event subscription in Safeguard via the Web API.

.DESCRIPTION
Event subscription is a subscription to receive notifications when an event occurs.
Event subscription can be created for all type of users but can only be created by
an administrative user. One event subscriber can subscribe to multiple events.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER ObjectTypeToSubscribe
A string containing the type of object to be subscribed.

.PARAMETER ObjectIdToSubscribe
A string containing the Id or name of the object to be subscribed.

.PARAMETER SubscriptionEvent
Array of name of events to be subscribed.

.PARAMETER UserToSubscribe
A string containing the name or Id of the user to be subscribed to events in Safeguard.

.PARAMETER Description
A string containing the description of the event subscription.

.PARAMETER IsEmailEvent
A switch to specify if the type of subscription to create is Email subscription. Default subscription type is SignalR.

.PARAMETER EmailAddress
A string containing the email address if the user to be subscribed. If the type of subscription is Email subscription. Either an email address or UserId is to be provided.

.PARAMETER IsSnmpEvent
A switch to specify if the type of subscription to create is SNMP subscription. Default subscription type is SignalR.

.PARAMETER SnmpNetworkAddress
A string containing network address of the SNMP server. This parameter is mandatory if -IsSnmpEvent parameter is switched ON.

.PARAMETER SnmpPort
An integer containing port of the SNMP server. The default port is 162.

.PARAMETER SnmpCommunity
A string containing the Community name of the SNMP server. THe default name of the SNMP community is "public"

.PARAMETER SnmpVersion
An integer containing the version of SNMP protocol. The default version is 2.

.PARAMETER IsSyslogEvent
A switch to specify if the type of subscription to create is Syslog subscription. Default subscription type is SignalR.

.PARAMETER SyslogNetworkAddress
A string containing network address of the Syslog server. This parameter is mandatory if -IsSyslogEvent parameter is switched ON.

.PARAMETER SyslogPort
An integer containing port of the Syslog server. The default port is 514.

.PARAMETER SyslogFacility
A string containing the Facility name of the Syslog server. THe default name of the Syslog Facility is "User"

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
New-SafeguardEventSubscription  -ObjectTypeToSubscribe Asset -ObjectIdToSubscribe 123 -SubscriptionEvent AssetCreated

.EXAMPLE
New-SafeguardEventSubscription  -ObjectTypeToSubscribe Asset -ObjectIdToSubscribe 123 -SubscriptionEvent AssetCreated -IsEmailEvent -EmailAddress "name@company.com"

.EXAMPLE
New-SafeguardEventSubscription  -ObjectTypeToSubscribe AssetAccount -ObjectIdToSubscribe 123 -SubscriptionEvent AssetAccountCreated -IsSyslogEvent -syslognetworkaddress "11.22.33.44"

.EXAMPLE
New-SafeguardEventSubscription  -ObjectTypeToSubscribe DirectoryAccount -ObjectIdToSubscribe 123 -SubscriptionEvent DirectoryAccountCreated -IsSnmpEvent -snmpnetworkaddress "11.22.33.44"
#>
function New-SafeguardEventSubscription
{
    [CmdletBinding(DefaultParametersetName='Default')]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateSet('Asset','AssetAccount','DirectoryAccount',IgnoreCase=$true)]
        [string]$ObjectTypeToSubscribe,
        [Parameter(Mandatory=$true, Position=1)]
        [string]$ObjectIdToSubscribe,
        [Parameter(Mandatory=$true, Position=2)]
        [string[]]$SubscriptionEvent,
        [Parameter(Mandatory=$false)]
        [object]$UserToSubscribe,
        [Parameter(Mandatory=$false)]
        [string]$Description,
        [Parameter(Mandatory=$false)]
        [switch]$IsSignalrEvent,

        [Parameter(ParameterSetName='EmailEvent')][switch]$IsEmailEvent,
        [Parameter(ParameterSetName='EmailEvent', Mandatory=$false)][string]$EmailAddress,

        [Parameter(ParameterSetName='SnmpEvent')][switch]$IsSnmpEvent,
        [Parameter(ParameterSetName='SnmpEvent', Mandatory=$true)][string]$SnmpNetworkAddress,
        [Parameter(ParameterSetName='SnmpEvent', Mandatory=$false)][Int]$SnmpPort,
        [Parameter(ParameterSetName='SnmpEvent', Mandatory=$false)][string]$SnmpCommunity,
        [Parameter(ParameterSetName='SnmpEvent', Mandatory=$false)][Int]$SnmpVersion,

        [Parameter(ParameterSetName='SyslogEvent')][switch]$IsSyslogEvent,
        [Parameter(ParameterSetName='SyslogEvent', Mandatory=$true)][string]$SyslogNetworkAddress,
        [Parameter(ParameterSetName='SyslogEvent', Mandatory=$false)][Int]$SyslogPort,
        [ValidateSet('Kernel', 'User', 'Mail', 'Daemons', 'Authorization', 'Syslog', 'Printer', 'News', 'Uucp', 'Clock', 'Authorization2', 'Ftp',
        'Ntp', 'Audit','Alert', 'Clock2', 'Local0', 'Local1', 'Local2', 'Local3', 'Local4', 'Local5', 'Local6', 'Local7', IgnoreCase=$true)]
        [Parameter(ParameterSetName='SyslogEvent', Mandatory=$false)][object]$SyslogFacility
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    #Resolve events to be subscribed
    [object[]]$SubscriptionEvents = Resolve-SubscriptionEvent -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -TypeOfEvent $ObjectTypeToSubscribe -EventsToValidate $SubscriptionEvent

    #Resolve the object to be subscribed
    switch ($ObjectTypeToSubscribe)
    {
        "Asset"{ $ObjectIdToSubscribe = (Get-SafeguardAsset -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetToGet $ObjectIdToSubscribe).Id; break }
        "AssetAccount"{ $ObjectIdToSubscribe = (Get-SafeguardAssetAccount -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AccountToGet $ObjectIdToSubscribe).Id;  break }
        "DirectoryAccount"{ $ObjectIdToSubscribe = (Get-SafeguardDirectoryAccount -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AccountToGet $ObjectIdToSubscribe).Id; break }
    }

    #Initialize the body of the API call. Default type of subscription is set as SignalR
    $local:Body = @{
        Type = "SignalR";
        ObjectType = $ObjectTypeToSubscribe;
        ObjectId = $ObjectIdToSubscribe;
        Subscriptions = $SubscriptionEvents
    }

    #Common parameters
    if ($PSBoundParameters.ContainsKey("UserToSubscribe"))
    {
        $local:User = Get-SafeguardUser -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -UserToGet $UserToSubscribe
        $local:Body.UserId = $($local:User).Id
    }
    if ($PSBoundParameters.ContainsKey("Description")) {$local:Body.Description = $Description}
    if ($PSBoundParameters.ContainsKey("EmailAddress")) {$local:Body.EmailAddress = $EmailAddress}

    #If the type of subscription is SNMP
    if ($PSBoundParameters.ContainsKey("IsSnmpEvent")) {$local:Body.Type = "SNMP"}
    #SNMP properties
    if ($PSBoundParameters.ContainsKey("SnmpNetworkAddress")) {$local:Body.SnmpNetworkAddress = $SnmpNetworkAddress}
    if ($PSBoundParameters.ContainsKey("SnmpPort")) {$local:Body.SnmpPort = $SnmpPort}
    if ($PSBoundParameters.ContainsKey("SnmpCommunity")) {$local:Body.SnmpCommunity = $SnmpCommunity}
    if ($PSBoundParameters.ContainsKey("SnmpVersion")) {$local:Body.SnmpVersion = $SnmpVersion}

    #If the type of subscription is Syslog
    if ($PSBoundParameters.ContainsKey("IsSyslogEvent")) {$local:Body.Type = "Syslog"}
    #Syslog Properties
    $local:SyslogProperties = @{
        NetworkAddress = $null
    }
    if ($PSBoundParameters.ContainsKey("SyslogNetworkAddress")) {$local:SyslogProperties.NetworkAddress = $SyslogNetworkAddress}
    if ($PSBoundParameters.ContainsKey("SyslogPort")) {$local:SyslogProperties.Port = $SyslogPort}
    if ($PSBoundParameters.ContainsKey("SyslogFacility")) {$local:SyslogProperties.Facility = $SyslogFacility}
    $local:Body.SyslogProperties = $local:SyslogProperties

    #If the type of subscription is Email
    if ($PSBoundParameters.ContainsKey("IsEmailEvent"))
    {
        $local:Body.Type = "Email"
        if ($PSBoundParameters.ContainsKey("UserToSubscribe"))
        {
            If([string]::IsNullOrWhitespace($local:User.EmailAddress))
            {
                Write-Error -Message "An email address or a user with an email address must be specified." -Category InvalidArgument -ErrorAction Stop
            }
        }

        if($PSBoundParameters.ContainsKey("UserToSubscribe") -and $PSBoundParameters.ContainsKey("EmailAddress"))
        {
            Write-Error -Message "You cannot specify both the UserID and an EmailAddress properties simultaneously." -Category InvalidArgument -ErrorAction Stop
        }
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST EventSubscribers -Body $local:Body
}

<#
.SYNOPSIS
Update an existing event subscription in Safeguard via the Web API.

.DESCRIPTION
Event subscription is a subscription to receive notifications when an event occurs.
Event subscription can be created for all type of users but can only be created by
an administrative user. One event subscriber can subscribe to multiple events.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER SubscriptonId
An integer containg the ID of an event subscription to be updated.

.PARAMETER SubscriptionObject
An object containing the existing event subscription with desired properties set.

.PARAMETER ObjectTypeToSubscribe
A string containing the type of object to be subscribed.

.PARAMETER ObjectIdToSubscribe
A string containing the Id or name of the object to be subscribed.

.PARAMETER SubscriptionEvent
Array of name of events to be subscribed.

.PARAMETER UserToSubscribe
A string containing the name or Id of the user to be subscribed to events in Safeguard.

.PARAMETER Description
A string containing the description of the event subscription.

.PARAMETER IsSignalrEvent
A switch to update the type of subscription to Signal.

.PARAMETER IsEmailEvent
A switch to update the type of subscription to Email.

.PARAMETER EmailAddress
A string containing the email address if the user to be subscribed. If the type of subscription is Email subscription. Either an email address or UserId is to be provided.

.PARAMETER IsSnmpEvent
A switch to update the type of subscription to SNMP.

.PARAMETER SnmpNetworkAddress
A string containing network address of the SNMP server. This parameter is mandatory if -IsSnmpEvent parameter is switched ON.

.PARAMETER SnmpPort
An integer containing port of the SNMP server. The default port is 162.

.PARAMETER SnmpCommunity
A string containing the Community name of the SNMP server. THe default name of the SNMP community is "public"

.PARAMETER SnmpVersion
An integer containing the version of SNMP protocol. The default version is 2.

.PARAMETER IsSyslogEvent
A switch to update the type of subscription to Syslog.

.PARAMETER SyslogNetworkAddress
A string containing network address of the Syslog server. This parameter is mandatory if -IsSyslogEvent parameter is switched ON.

.PARAMETER SyslogPort
An integer containing port of the Syslog server. The default port is 514.

.PARAMETER SyslogFacility
A string containing the Facility name of the Syslog server. THe default name of the Syslog Facility is "User"

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Edit-SafeguardEventSubscription  -SubscriptionObject $obj

.EXAMPLE
Edit-SafeguardEventSubscription  -SubscriptionId 123 -IsEmailEvent -EmailAddress "name@company.com"

.EXAMPLE
Edit-SafeguardEventSubscription  -SubscriptionId 123 -ObjectType DirectoryAccount -SubscriptionEvent DirectoryAccountCreated
#>
function Edit-SafeguardEventSubscription
{
    [CmdletBinding(DefaultParametersetName='Default')]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false, Position=0)]
        [Int]$SubscriptionId,
        [Parameter(Mandatory=$false, Position=1)]
        [ValidateSet('Asset','AssetAccount','DirectoryAccount',IgnoreCase=$true)]
        [string]$ObjectTypeToSubscribe,
        [Parameter(Mandatory=$false, Position=2)]
        [string]$ObjectIdToSubscribe,
        [Parameter(Mandatory=$false, Position=3)]
        [object[]]$SubscriptionEvent,
        [Parameter(Mandatory=$false)]
        [object]$UserToSubscribe,
        [Parameter(Mandatory=$false)]
        [string]$Description,
        [Parameter(Mandatory=$false)]
        [switch]$IsSignalrEvent,

        [Parameter(ParameterSetName='Object', Mandatory=$false)]
        [object]$SubscriptionObject,

        [Parameter(ParameterSetName='EmailEvent')][switch]$IsEmailEvent,
        [Parameter(ParameterSetName='EmailEvent', Mandatory=$false)][string]$EmailAddress,

        [Parameter(ParameterSetName='SnmpEvent')][switch]$IsSnmpEvent,
        [Parameter(ParameterSetName='SnmpEvent', Mandatory=$true)][string]$SnmpNetworkAddress,
        [Parameter(ParameterSetName='SnmpEvent', Mandatory=$false)][Int]$SnmpPort,
        [Parameter(ParameterSetName='SnmpEvent', Mandatory=$false)][string]$SnmpCommunity,
        [Parameter(ParameterSetName='SnmpEvent', Mandatory=$false)][Int]$SnmpVersion,

        [Parameter(ParameterSetName='SyslogEvent')][switch]$IsSyslogEvent,
        [Parameter(ParameterSetName='SyslogEvent', Mandatory=$true)][string]$SyslogNetworkAddress,
        [Parameter(ParameterSetName='SyslogEvent', Mandatory=$false)][Int]$SyslogPort,
        [ValidateSet('Kernel', 'User', 'Mail', 'Daemons', 'Authorization', 'Syslog', 'Printer', 'News', 'Uucp', 'Clock', 'Authorization2', 'Ftp',
        'Ntp', 'Audit','Alert', 'Clock2', 'Local0', 'Local1', 'Local2', 'Local3', 'Local4', 'Local5', 'Local6', 'Local7', IgnoreCase=$true)]
        [Parameter(ParameterSetName='SyslogEvent', Mandatory=$false)][object]$SyslogFacility
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if($PSBoundParameters.ContainsKey("SubscriptionObject"))
    {
        #Resolve events contained in the SubscriptionObject
        ForEach($IndividualEvent in $SubscriptionObject.Subscriptions)
        {
            [string[]]$local:Events += $IndividualEvent.Name
        }
        [object[]]$SubscriptionEvents = Resolve-SubscriptionEvent -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -TypeOfEvent $SubscriptionObject.ObjectType -EventsToValidate $Events
        $SubscriptionObject.Subscriptions = $SubscriptionEvents

        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "EventSubscribers/$($SubscriptionObject.Id)" -Body $SubscriptionObject
        return
    }

    if(-not $PSBoundParameters.ContainsKey("SubscriptionId"))
    {
        $SubscriptionId = (Read-Host "SubscriptionId")
    }

    $local:Body = Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "EventSubscribers/$SubscriptionId"

    if($PSBoundParameters.ContainsKey("ObjectTypeToSubscribe")) {$local:Body.ObjectType = $ObjectTypeToSubscribe}

    #Resolve events to be subscribed
    if($PSBoundParameters.ContainsKey("SubscriptionEvent"))
    {
        [object[]]$SubscriptionEvents = Resolve-SubscriptionEvent -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -TypeOfEvent $local:Body.ObjectType -EventsToValidate $SubscriptionEvent
    }
    else
    {
        ForEach($IndividualEvent in $local:Body.Subscriptions)
        {
            [string[]]$local:Events += $IndividualEvent.Name
        }
        [object[]]$SubscriptionEvents = Resolve-SubscriptionEvent -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -TypeOfEvent $local:Body.ObjectType -EventsToValidate $Events
    }
    $local:Body.Subscriptions = $SubscriptionEvents

    #Resolve the object to be subscribed
    if($PSBoundParameters.ContainsKey("ObjectIdToSubscribe"))
    {
        switch ($local:Body.ObjectType)
        {
            "Asset"{ $ObjectIdToSubscribe = (Get-SafeguardAsset -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AssetToGet $ObjectIdToSubscribe).Id; break }
            "AssetAccount"{ $ObjectIdToSubscribe = (Get-SafeguardAssetAccount -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AccountToGet $ObjectIdToSubscribe).Id;  break }
            "DirectoryAccount"{ $ObjectIdToSubscribe = (Get-SafeguardDirectoryAccount -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -AccountToGet $ObjectIdToSubscribe).Id; break }
        }
    }

    if ($PSBoundParameters.ContainsKey("IsSignalrEvent")) {$local:Body.Type = "SignalR"}

    #Common parameters
    if ($PSBoundParameters.ContainsKey("UserToSubscribe"))
    {
        $local:User = Get-SafeguardUser -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -UserToGet $UserToSubscribe
        $local:Body.UserId = $($local:User).Id
    }
    if ($PSBoundParameters.ContainsKey("Description")) {$local:Body.Description = $Description}
    if ($PSBoundParameters.ContainsKey("EmailAddress")) {$local:Body.EmailAddress = $EmailAddress}

    #If the type of subscription is SNMP
    if ($PSBoundParameters.ContainsKey("IsSnmpEvent")) {$local:Body.Type = "SNMP"}
    #SNMP properties
    if ($PSBoundParameters.ContainsKey("SnmpNetworkAddress")) {$local:Body.SnmpNetworkAddress = $SnmpNetworkAddress}
    if ($PSBoundParameters.ContainsKey("SnmpPort")) {$local:Body.SnmpPort = $SnmpPort}
    if ($PSBoundParameters.ContainsKey("SnmpCommunity")) {$local:Body.SnmpCommunity = $SnmpCommunity}
    if ($PSBoundParameters.ContainsKey("SnmpVersion")) {$local:Body.SnmpVersion = $SnmpVersion}

    #If the type of subscription is Syslog
    if ($PSBoundParameters.ContainsKey("IsSyslogEvent")) {$local:Body.Type = "Syslog"}
    #Syslog Properties
    $local:SyslogProperties = @{
        NetworkAddress = $null
    }
    if ($PSBoundParameters.ContainsKey("SyslogNetworkAddress")) {$local:SyslogProperties.NetworkAddress = $SyslogNetworkAddress}
    if ($PSBoundParameters.ContainsKey("SyslogPort")) {$local:SyslogProperties.Port = $SyslogPort}
    if ($PSBoundParameters.ContainsKey("SyslogFacility")) {$local:SyslogProperties.Facility = $SyslogFacility}
    $local:Body.SyslogProperties = $local:SyslogProperties

    #If the type of subscription is Email
    if ($PSBoundParameters.ContainsKey("IsEmailEvent"))
    {
        $local:Body.Type = "Email"

        if($PSBoundParameters.ContainsKey("EmailAddress") -and (-Not $PSBoundParameters.ContainsKey("UserToSubscribe")))
        {
            $local:Body.UserId = $null
        }

        if ($local:Body.UserId -ne $null)
        {
            $local:UserEmailAddress = (Get-SafeguardUser -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -UserToGet $local:Body.UserId).EmailAddress
            If([string]::IsNullOrWhitespace($local:UserEmailAddress))
            {
                Write-Error -Message "An email address or a user with an email address must be specified." -Category InvalidArgument -ErrorAction Stop
            }
        }

        if(($local:Body.UserId -ne $null) -and $PSBoundParameters.ContainsKey("EmailAddress"))
        {
            Write-Error -Message "You cannot specify both the UserID and an EmailAddress properties simultaneously." -Category InvalidArgument -ErrorAction Stop
        }
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "EventSubscribers/$($local:Body.Id)" -Body $local:Body
}

<#
.SYNOPSIS
Remove an event subscription in Safeguard via the Web API.

.DESCRIPTION
Event subscription is a subscription to receive notifications when an event occurs.
Event subscription can be created for all type of users but can only be created by
an administrative user. One event subscriber can subscribe to multiple events.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER SubscriptionId
An integer containing ID of the event subscription to get.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardEventSubscription 123
#>
function Remove-SafeguardEventSubscription
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true, Position=0)]
        [string]$SubscriptionId
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "EventSubscribers/$SubscriptionId"

}