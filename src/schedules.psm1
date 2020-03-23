# Helper
function Copy-ScheduleToDto
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [HashTable]$Schedule,
        [Parameter(Mandatory=$true)]
        [object]$Dto
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($Schedule)
    {
        $Dto.TimeZoneId = $Schedule.TimeZoneId
        $Dto.ScheduleType = $Schedule.ScheduleType
        $Dto.RepeatInterval = $Schedule.RepeatInterval
        $Dto.TimeOfDayType = $Schedule.TimeOfDayType
        # Monthly-specific
        if ($Schedule.RepeatMonthlyScheduleType) { $Dto.RepeatMonthlyScheduleType = $Schedule.RepeatMonthlyScheduleType }
        if ($Schedule.RepeatWeekOfMonth) { $Dto.RepeatWeekOfMonth = $Schedule.RepeatWeekOfMonth }
        if ($Schedule.RepeatDayOfWeek) { $Dto.RepeatDayOfWeek = $Schedule.RepeatDayOfWeek }
        if ($Schedule.RepeatDayOfMonth) { $Dto.RepeatDayOfMonth = $Schedule.RepeatDayOfMonth }
        # Weekly-specific
        if ($Schedule.RepeatDaysOfWeek) { $Dto.RepeatDaysOfWeek = $Schedule.RepeatDaysOfWeek }
        # Times
        if ($null -ne $Schedule.StartHour) { $Dto.StartHour = $Schedule.StartHour }
        if ($null -ne $Schedule.StartMinute) { $Dto.StartMinute = $Schedule.StartMinute }
    }

    $Dto
}

<#
.SYNOPSIS
Create a new Safeguard schedule object for use with other cmdlets.

.DESCRIPTION
Create a new schedule that can be associated to create or update profile components.
This cmdlet creates a hashtable object that represents the desired schedule and can
be passed as a parameter to other Safeguard cmdlets.

.PARAMETER Never
Select the schedule type of Never, meaning don't ever run.  Actually, this just returns null.

.PARAMETER MonthsByDayOfWeek
Select the schedule type of MonthsByDayOfWeek, meaning run every X months (see ScheduleInterval)
on a particular day (Sun,Mon,Tue,Wed,Thu,Fri,Sat) of a particular week (1st,2nd,3rd,4th,Last).

.PARAMETER MonthsByDay
Select theschedule type of MonthsByDay, meaning runevery X months (see ScheduleInterval)
on a particular day of the month (1-31).

.PARAMETER Weeks
Select the schedule type of Weeks, meaning run every X weeks (see ScheduleInterval)
on one or more days of the week (Sun,Mon,Tue,Wed,Thu,Fri,Sat).

.PARAMETER Days
Select the schedule type of Days, meaning run every X days (see ScheduleInterval).

.PARAMETER Hours
Select the schedule type of Hours, meaning run every X hours (see ScheduleInterval).

.PARAMETER Minutes
Select the schedule type of Minutes, meaning run every X minutes (see ScheduleInterval).

.PARAMETER ScheduleInterval
The interval at which to run, for example every X months, weeks, days, hours, or minutes.  (default: 1),
In other words the default is monthly, weekly, daily, hourly, every minute.

.PARAMETER WeekOfMonth
Which week of the month to run MonthsByDayOfWeek schedule type.

.PARAMETER DayOfWeekOfMonth
Which day of the week to run for MonthsByDayOfWeek schedule type.

.PARAMETER DayOfMonth
Which day of the month to run for MonthsByDay schedule type.

.PARAMETER RepeatDaysOfWeek
Which day(s) of the week to run for Weeks schedule type.

.PARAMETER TimeZone
Which time zone to use for calculating schedule times.  The IDs returned by Get-SafeguardTimeZone can be used to
determine valid values that can be passed in for this parameter.  (default: time zone of this computer, e.g. Get-TimeZone)

.PARAMETER StartHour
The hour at which to start running the schedule (0-23, using 24-hour clock).

.PARAMETER StartMinute
The minute at which to start running the schedule (0-59).
#>
function New-SafeguardSchedule
{
    [CmdletBinding(DefaultParameterSetName="Never")]
    Param(
        [Parameter(Mandatory=$false,ParameterSetName="Never")]
        [bool]$Never = $true,
        [Parameter(Mandatory=$true,ParameterSetName="MonthsByDayOfWeek")]
        [switch]$MonthsByDayOfWeek,
        [Parameter(Mandatory=$true,ParameterSetName="MonthsByDay")]
        [switch]$MonthsByDay,
        [Parameter(Mandatory=$true,ParameterSetName="Weeks")]
        [switch]$Weeks,
        [Parameter(Mandatory=$true,ParameterSetName="Days")]
        [switch]$Days,
        [Parameter(Mandatory=$true,ParameterSetName="Hours")]
        [switch]$Hours,
        [Parameter(Mandatory=$true,ParameterSetName="Minutes")]
        [switch]$Minutes,
        [Parameter(Mandatory=$false,ParameterSetName="MonthsByDayOfWeek")]
        [Parameter(Mandatory=$false,ParameterSetName="MonthsByDay")]
        [Parameter(Mandatory=$false,ParameterSetName="Weeks")]
        [Parameter(Mandatory=$false,ParameterSetName="Days")]
        [Parameter(Mandatory=$false,ParameterSetName="Hours")]
        [Parameter(Mandatory=$false,ParameterSetName="Minutes")]
        [int]$ScheduleInterval = 1,
        [Parameter(Mandatory=$true,ParameterSetName="MonthsByDayOfWeek")]
        [ValidateSet("First","Second","Third","Fourth","Last",IgnoreCase=$true)]
        [string]$WeekOfMonth,
        [Parameter(Mandatory=$true,ParameterSetName="MonthsByDayOfWeek")]
        [ValidateSet("Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday",IgnoreCase=$true)]
        [string]$DayOfWeekOfMonth,
        [Parameter(Mandatory=$true,ParameterSetName="MonthsByDay")]
        [ValidateRange(1,31)]
        [int]$DayOfMonth,
        [Parameter(Mandatory=$true,ParameterSetName="Weeks")]
        [ValidateSet("Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday",IgnoreCase=$true)]
        [string[]]$RepeatDaysOfWeek,
        [Parameter(Mandatory=$false,ParameterSetName="MonthsByDayOfWeek")]
        [Parameter(Mandatory=$false,ParameterSetName="MonthsByDay")]
        [Parameter(Mandatory=$false,ParameterSetName="Weeks")]
        [Parameter(Mandatory=$false,ParameterSetName="Days")]
        [Parameter(Mandatory=$false,ParameterSetName="Hours")]
        [Parameter(Mandatory=$false,ParameterSetName="Minutes")]
        [string]$TimeZone = (Get-TimeZone).Id,
        [Parameter(Mandatory=$true,ParameterSetName="MonthsByDayOfWeek")]
        [Parameter(Mandatory=$true,ParameterSetName="MonthsByDay")]
        [Parameter(Mandatory=$true,ParameterSetName="Weeks")]
        [Parameter(Mandatory=$true,ParameterSetName="Days")]
        [ValidateRange(0,23)]
        [int]$StartHour,
        [Parameter(Mandatory=$true,ParameterSetName="MonthsByDayOfWeek")]
        [Parameter(Mandatory=$true,ParameterSetName="MonthsByDay")]
        [Parameter(Mandatory=$true,ParameterSetName="Weeks")]
        [Parameter(Mandatory=$true,ParameterSetName="Days")]
        [Parameter(Mandatory=$true,ParameterSetName="Hours")]
        [ValidateRange(0,59)]
        [int]$StartMinute
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Schedule = @{}

    if ($PSCmdlet.ParameterSetName -ne "Never")
    {
        $local:Schedule.TimeZoneId = $TimeZone
        $local:Schedule.RepeatInterval = $ScheduleInterval
        # since we don't support time windows for now
        $local:Schedule.TimeOfDayType = "Instant"
    }

    switch ($PsCmdlet.ParameterSetName)
    {
        "MonthsByDayOfWeek" {
            $local:Schedule.ScheduleType = "Monthly"
            $local:Schedule.RepeatMonthlyScheduleType = "DayOfWeekOfMonth"
            $local:Schedule.RepeatWeekOfMonth = $WeekOfMonth
            $local:Schedule.RepeatDayOfWeek = $DayOfWeekOfMonth
            break
        }
        "MonthsByDay" {
            $local:Schedule.ScheduleType = "Monthly"
            $local:Schedule.RepeatMonthlyScheduleType = "DayOfMonth"
            $local:Schedule.RepeatDayOfMonth = $DayOfMonth
            break
        }
        "Weeks" {
            $local:Schedule.ScheduleType = "Weekly"
            $local:Schedule.RepeatDaysOfWeek = $RepeatDaysOfWeek
            break
        }
        "Days" {
            $local:Schedule.ScheduleType = "Daily"
            break
        }
        "Hours" {
            $local:Schedule.ScheduleType = "Hourly"
            break
        }
        "Minutes" {
            $local:Schedule.ScheduleType = "Minute"
            break
        }
    }

    if ($PSCmdlet.ParameterSetName -ne "Never" -and $PSCmdlet.ParameterSetName -ne "Minutes" -and $PSCmdlet.ParameterSetName -ne "Hours")
    {
        $local:Schedule.StartHour = $StartHour
    }

    if ($PSCmdlet.ParameterSetName -ne "Never" -and $PSCmdlet.ParameterSetName -ne "Minutes")
    {
        $local:Schedule.StartMinute = $StartMinute
    }

    if ($PSCmdlet.ParameterSetName -eq "Never")
    {
        $null
    }
    else
    {
        $local:Schedule
    }
}

<#
.SYNOPSIS
Create a new once monthly (on a specified day of a specified week) Safeguard schedule
object for use with other cmdlets.

.DESCRIPTION
Create a new schedule that can be associated to create or update profile components.
This cmdlet creates a hashtable object that represents the desired schedule and can
be passed as a parameter to other Safeguard cmdlets.

.PARAMETER WeekOfMonth
Which week of the month to run.

.PARAMETER DayOfWeekOfMonth
Which day of the week to run.

.PARAMETER StartTime
A string represent the time to start running the schedule (hh:mm).

.PARAMETER StartHour
The hour at which to start running the schedule (0-23, using 24-hour clock).

.PARAMETER StartMinute
The minute at which to start running the schedule (0-59).

.PARAMETER TimeZone
Which time zone to use for calculating schedule times.  The IDs returned by Get-SafeguardTimeZone can be used to
determine valid values that can be passed in for this parameter.  (default: time zone of this computer, e.g. Get-TimeZone)
#>
function New-SafeguardScheduleMonthlyByDayOfWeek
{
    [CmdletBinding(DefaultParameterSetName="StartTime")]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("First","Second","Third","Fourth","Last",IgnoreCase=$true)]
        [string]$WeekOfMonth,
        [Parameter(Mandatory=$true)]
        [ValidateSet("Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday",IgnoreCase=$true)]
        [string]$DayOfWeekOfMonth,
        [Parameter(Mandatory=$true,Position=0,ParameterSetName="StartTime")]
        [string]$StartTime,
        [Parameter(Mandatory=$true,ParameterSetName="StartInt")]
        [int]$StartHour,
        [Parameter(Mandatory=$true,ParameterSetName="StartInt")]
        [int]$StartMinute,
        [Parameter(Mandatory=$false)]
        [string]$TimeZone = (Get-TimeZone).Id
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSCmdlet.ParameterSetName -eq "StartTime")
    {
        $local:Pair = ($StartTime -split ":")
        if ($local:Pair.Length -ne 2)
        {
            throw "Unable to parse '$($StartTime)' using expected format of 'hh:mm'."
        }
        $StartHour = $local:Pair[0]
        $StartMinute = $local:Pair[1]
    }

    New-SafeguardSchedule -MonthsByDayOfWeek -ScheduleInterval 1 -WeekOfMonth $WeekOfMonth -DayOfWeekOfMonth $DayOfWeekOfMonth `
        -StartHour $StartHour -StartMinute $StartMinute -TimeZone $TimeZone
}

<#
.SYNOPSIS
Create a new once monthly (on a specified day of the month) Safeguard schedule
object for use with other cmdlets.

.DESCRIPTION
Create a new schedule that can be associated to create or update profile components.
This cmdlet creates a hashtable object that represents the desired schedule and can
be passed as a parameter to other Safeguard cmdlets.

.PARAMETER DayOfMonth
Which day of the month to run.

.PARAMETER StartTime
A string represent the time to start running the schedule (hh:mm).

.PARAMETER StartHour
The hour at which to start running the schedule (0-23, using 24-hour clock).

.PARAMETER StartMinute
The minute at which to start running the schedule (0-59).

.PARAMETER TimeZone
Which time zone to use for calculating schedule times.  The IDs returned by Get-SafeguardTimeZone can be used to
determine valid values that can be passed in for this parameter.  (default: time zone of this computer, e.g. Get-TimeZone)
#>
function New-SafeguardScheduleMonthlyByDay
{
    [CmdletBinding(DefaultParameterSetName="StartTime")]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateRange(1,31)]
        [int]$DayOfMonth,
        [Parameter(Mandatory=$true,Position=0,ParameterSetName="StartTime")]
        [string]$StartTime,
        [Parameter(Mandatory=$true,ParameterSetName="StartInt")]
        [int]$StartHour,
        [Parameter(Mandatory=$true,ParameterSetName="StartInt")]
        [int]$StartMinute,
        [Parameter(Mandatory=$false)]
        [string]$TimeZone = (Get-TimeZone).Id
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSCmdlet.ParameterSetName -eq "StartTime")
    {
        $local:Pair = ($StartTime -split ":")
        if ($local:Pair.Length -ne 2)
        {
            throw "Unable to parse '$($StartTime)' using expected format of 'hh:mm'."
        }
        $StartHour = $local:Pair[0]
        $StartMinute = $local:Pair[1]
    }

    New-SafeguardSchedule -MonthsByDay -ScheduleInterval 1 -DayOfMonth $DayOfMonth `
        -StartHour $StartHour -StartMinute $StartMinute -TimeZone $TimeZone
}

<#
.SYNOPSIS
Create a new weekly Safeguard schedule object for use with other cmdlets.

.DESCRIPTION
Create a new schedule that can be associated to create or update profile components.
This cmdlet creates a hashtable object that represents the desired schedule and can
be passed as a parameter to other Safeguard cmdlets.

.PARAMETER RepeatDaysOfWeek
Which day(s) of the week to run.

.PARAMETER StartTime
A string represent the time to start running the schedule (hh:mm).

.PARAMETER StartHour
The hour at which to start running the schedule (0-23, using 24-hour clock).

.PARAMETER StartMinute
The minute at which to start running the schedule (0-59).

.PARAMETER TimeZone
Which time zone to use for calculating schedule times.  The IDs returned by Get-SafeguardTimeZone can be used to
determine valid values that can be passed in for this parameter.  (default: time zone of this computer, e.g. Get-TimeZone)
#>
function New-SafeguardScheduleWeekly
{
    [CmdletBinding(DefaultParameterSetName="StartTime")]
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday",IgnoreCase=$true)]
        [string[]]$RepeatDaysOfWeek,
        [Parameter(Mandatory=$true,Position=0,ParameterSetName="StartTime")]
        [string]$StartTime,
        [Parameter(Mandatory=$true,ParameterSetName="StartInt")]
        [int]$StartHour,
        [Parameter(Mandatory=$true,ParameterSetName="StartInt")]
        [int]$StartMinute,
        [Parameter(Mandatory=$false)]
        [string]$TimeZone = (Get-TimeZone).Id
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSCmdlet.ParameterSetName -eq "StartTime")
    {
        $local:Pair = ($StartTime -split ":")
        if ($local:Pair.Length -ne 2)
        {
            throw "Unable to parse '$($StartTime)' using expected format of 'hh:mm'."
        }
        $StartHour = $local:Pair[0]
        $StartMinute = $local:Pair[1]
    }

    New-SafeguardSchedule -Weeks -ScheduleInterval 1 -RepeatDaysOfWeek $RepeatDaysOfWeek -StartHour $StartHour -StartMinute $StartMinute -TimeZone $TimeZone
}

<#
.SYNOPSIS
Create a new once daily Safeguard schedule object for use with other cmdlets.

.DESCRIPTION
Create a new schedule that can be associated to create or update profile components.
This cmdlet creates a hashtable object that represents the desired schedule and can
be passed as a parameter to other Safeguard cmdlets.

.PARAMETER StartTime
A string represent the time to start running the schedule (hh:mm).

.PARAMETER StartHour
The hour at which to start running the schedule (0-23, using 24-hour clock).

.PARAMETER StartMinute
The minute at which to start running the schedule (0-59).

.PARAMETER TimeZone
Which time zone to use for calculating schedule times.  The IDs returned by Get-SafeguardTimeZone can be used to
determine valid values that can be passed in for this parameter.  (default: time zone of this computer, e.g. Get-TimeZone)
#>
function New-SafeguardScheduleDaily
{
    [CmdletBinding(DefaultParameterSetName="StartTime")]
    Param(
        [Parameter(Mandatory=$true,Position=0,ParameterSetName="StartTime")]
        [string]$StartTime,
        [Parameter(Mandatory=$true,ParameterSetName="StartInt")]
        [int]$StartHour,
        [Parameter(Mandatory=$true,ParameterSetName="StartInt")]
        [int]$StartMinute,
        [Parameter(Mandatory=$false)]
        [string]$TimeZone = (Get-TimeZone).Id
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSCmdlet.ParameterSetName -eq "StartTime")
    {
        $local:Pair = ($StartTime -split ":")
        if ($local:Pair.Length -ne 2)
        {
            throw "Unable to parse '$($StartTime)' using expected format of 'hh:mm'."
        }
        $StartHour = $local:Pair[0]
        $StartMinute = $local:Pair[1]
    }

    New-SafeguardSchedule -Days -ScheduleInterval 1 -StartHour $StartHour -StartMinute $StartMinute -TimeZone $TimeZone
}
