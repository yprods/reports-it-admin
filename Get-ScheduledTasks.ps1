<#
.SYNOPSIS
    Gets all scheduled tasks from servers.

.DESCRIPTION
    This script retrieves all scheduled tasks (Task Scheduler tasks) from remote servers.
    It provides detailed information about task configuration, status, and schedules.

.PARAMETER ComputerList
    Path to a text file containing computer names (one per line).

.PARAMETER ComputerName
    Single computer name or array of computer names to query.

.PARAMETER Domain
    Query all servers in the specified domain (requires Active Directory module).

.PARAMETER TaskName
    Filter by specific task name (supports wildcards).

.PARAMETER TaskState
    Filter by task state: All, Running, Ready, Disabled (default: All).

.PARAMETER OutputFile
    Path to CSV file where results will be exported. Default: ScheduledTasksReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication (optional).

.PARAMETER IncludeHidden
    Include hidden tasks (default: false).

.PARAMETER ShowDetails
    Show detailed task information including triggers and actions (default: true).

.EXAMPLE
    .\Get-ScheduledTasks.ps1 -ComputerList "servers.txt"
    
.EXAMPLE
    .\Get-ScheduledTasks.ps1 -ComputerName "SERVER01","SERVER02" -TaskState "Running"
    
.EXAMPLE
    .\Get-ScheduledTasks.ps1 -Domain "contoso.com" -TaskName "*Backup*"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ComputerName,
    
    [Parameter(Mandatory=$false)]
    [string]$Domain,
    
    [Parameter(Mandatory=$false)]
    [string]$TaskName = "*",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("All","Running","Ready","Disabled")]
    [string]$TaskState = "All",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "ScheduledTasksReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeHidden,
    
    [Parameter(Mandatory=$false)]
    [switch]$ShowDetails = $true
)

# Function to get scheduled tasks from a single computer
function Get-ScheduledTasks {
    param(
        [string]$Computer,
        [string]$NameFilter,
        [string]$StateFilter,
        [System.Management.Automation.PSCredential]$Cred,
        [bool]$IncludeHiddenTasks,
        [bool]$ShowTaskDetails
    )
    
    $scriptBlock = {
        param([string]$TaskName, [string]$State, [bool]$Hidden, [bool]$Details)
        
        $tasks = @()
        
        try {
            # Get all scheduled tasks
            $allTasks = Get-ScheduledTask -ErrorAction Stop
            
            foreach ($task in $allTasks) {
                # Filter by name
                if ($TaskName -ne "*" -and $task.TaskName -notlike $TaskName) {
                    continue
                }
                
                # Filter by state
                if ($State -ne "All") {
                    $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -ErrorAction SilentlyContinue
                    if ($taskInfo) {
                        $currentState = $taskInfo.State
                        if ($State -eq "Running" -and $currentState -ne "Running") {
                            continue
                        }
                        if ($State -eq "Ready" -and $currentState -ne "Ready") {
                            continue
                        }
                        if ($State -eq "Disabled" -and $task.Settings.Enabled -ne $false) {
                            continue
                        }
                    }
                }
                
                # Filter hidden tasks
                if (-not $Hidden -and $task.Settings.Hidden) {
                    continue
                }
                
                $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -ErrorAction SilentlyContinue
                $taskDetails = Get-ScheduledTask -TaskName $task.TaskName -ErrorAction SilentlyContinue
                
                $taskData = @{
                    TaskName = $task.TaskName
                    TaskPath = $task.TaskPath
                    State = if ($taskInfo) { $taskInfo.State.ToString() } else { "Unknown" }
                    Enabled = $task.Settings.Enabled
                    LastRunTime = if ($taskInfo) { $taskInfo.LastRunTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
                    NextRunTime = if ($taskInfo) { $taskInfo.NextRunTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
                    LastTaskResult = if ($taskInfo) { $taskInfo.LastTaskResult } else { "N/A" }
                    Author = if ($task.Principal) { $task.Principal.UserId } else { "N/A" }
                    RunLevel = if ($task.Principal) { $task.Principal.RunLevel.ToString() } else { "N/A" }
                    Description = if ($task.Description) { $task.Description } else { "N/A" }
                }
                
                if ($Details) {
                    # Get triggers
                    $triggers = @()
                    if ($taskDetails -and $taskDetails.Triggers) {
                        foreach ($trigger in $taskDetails.Triggers) {
                            $triggerInfo = $trigger.CimClass.CimClassName
                            if ($triggerInfo -like "*Daily*") {
                                $triggers += "Daily at $($trigger.StartBoundary)"
                            }
                            elseif ($triggerInfo -like "*Weekly*") {
                                $triggers += "Weekly on $($trigger.DaysOfWeek) at $($trigger.StartBoundary)"
                            }
                            elseif ($triggerInfo -like "*AtStartup*") {
                                $triggers += "At Startup"
                            }
                            elseif ($triggerInfo -like "*AtLogon*") {
                                $triggers += "At Logon"
                            }
                            elseif ($triggerInfo -like "*OnEvent*") {
                                $triggers += "On Event"
                            }
                            else {
                                $triggers += $triggerInfo
                            }
                        }
                    }
                    $taskData['Triggers'] = ($triggers -join "; ")
                    
                    # Get actions
                    $actions = @()
                    if ($taskDetails -and $taskDetails.Actions) {
                        foreach ($action in $taskDetails.Actions) {
                            if ($action.Execute) {
                                $actions += "$($action.Execute) $($action.Arguments)"
                            }
                            elseif ($action.WorkingDirectory) {
                                $actions += "Working Directory: $($action.WorkingDirectory)"
                            }
                        }
                    }
                    $taskData['Actions'] = ($actions -join "; ")
                    
                    # Additional settings
                    $taskData['AllowDemandStart'] = $task.Settings.AllowDemandStart
                    $taskData['StartWhenAvailable'] = $task.Settings.StartWhenAvailable
                    $taskData['RunOnlyIfNetworkAvailable'] = $task.Settings.RunOnlyIfNetworkAvailable
                    $taskData['WakeToRun'] = $task.Settings.WakeToRun
                    $taskData['MultipleInstances'] = $task.Settings.MultipleInstances.ToString()
                    $taskData['Priority'] = $task.Settings.Priority
                    $taskData['ExecutionTimeLimit'] = if ($task.Settings.ExecutionTimeLimit) { $task.Settings.ExecutionTimeLimit.ToString() } else { "N/A" }
                }
                
                $tasks += $taskData
            }
        }
        catch {
            $tasks += @{
                TaskName = "Error"
                TaskPath = "N/A"
                State = "Error"
                Error = $_.Exception.Message
            }
        }
        
        return $tasks
    }
    
    $results = @()
    
    try {
        # Test connectivity first
        if (-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            $result = [PSCustomObject]@{
                ComputerName = $Computer
                TaskName = "N/A"
                TaskPath = "N/A"
                State = "N/A"
                Enabled = $false
                LastRunTime = "N/A"
                NextRunTime = "N/A"
                Status = "Offline"
                Error = "Computer is not reachable"
            }
            $results += $result
            return $results
        }
        
        # Execute remotely
        $invokeParams = @{
            ComputerName = $Computer
            ScriptBlock = $scriptBlock
            ArgumentList = @($NameFilter, $StateFilter, $IncludeHiddenTasks, $ShowTaskDetails)
            ErrorAction = "Stop"
        }
        
        if ($Cred) {
            $invokeParams['Credential'] = $Cred
        }
        
        $taskData = Invoke-Command @invokeParams
        
        # Format results
        foreach ($task in $taskData) {
            $result = [PSCustomObject]@{
                ComputerName = $Computer
                TaskName = $task.TaskName
                TaskPath = $task.TaskPath
                State = $task.State
                Enabled = $task.Enabled
                LastRunTime = $task.LastRunTime
                NextRunTime = $task.NextRunTime
                LastTaskResult = $task.LastTaskResult
                Author = $task.Author
                RunLevel = $task.RunLevel
                Description = $task.Description
                Status = "Success"
                Error = if ($task.Error) { $task.Error } else { $null }
            }
            
            if ($ShowTaskDetails) {
                $result | Add-Member -MemberType NoteProperty -Name "Triggers" -Value $task.Triggers -Force
                $result | Add-Member -MemberType NoteProperty -Name "Actions" -Value $task.Actions -Force
                $result | Add-Member -MemberType NoteProperty -Name "AllowDemandStart" -Value $task.AllowDemandStart -Force
                $result | Add-Member -MemberType NoteProperty -Name "StartWhenAvailable" -Value $task.StartWhenAvailable -Force
                $result | Add-Member -MemberType NoteProperty -Name "RunOnlyIfNetworkAvailable" -Value $task.RunOnlyIfNetworkAvailable -Force
                $result | Add-Member -MemberType NoteProperty -Name "WakeToRun" -Value $task.WakeToRun -Force
                $result | Add-Member -MemberType NoteProperty -Name "MultipleInstances" -Value $task.MultipleInstances -Force
                $result | Add-Member -MemberType NoteProperty -Name "Priority" -Value $task.Priority -Force
                $result | Add-Member -MemberType NoteProperty -Name "ExecutionTimeLimit" -Value $task.ExecutionTimeLimit -Force
            }
            
            $results += $result
        }
    }
    catch {
        $result = [PSCustomObject]@{
            ComputerName = $Computer
            TaskName = "N/A"
            TaskPath = "N/A"
            State = "N/A"
            Enabled = $false
            LastRunTime = "N/A"
            NextRunTime = "N/A"
            Status = "Error"
            Error = $_.Exception.Message
        }
        $results += $result
    }
    
    # If no results, add a default entry
    if ($results.Count -eq 0) {
        $result = [PSCustomObject]@{
            ComputerName = $Computer
            TaskName = "N/A"
            TaskPath = "N/A"
            State = "N/A"
            Enabled = $false
            LastRunTime = "N/A"
            NextRunTime = "N/A"
            Status = "No Tasks Found"
            Error = "No scheduled tasks found or accessible"
        }
        $results += $result
    }
    
    return $results
}

# Main execution
Write-Host "Scheduled Tasks Query Tool" -ForegroundColor Cyan
Write-Host "=========================" -ForegroundColor Cyan
Write-Host ""

# Collect computer names
$computers = @()

if ($Domain) {
    try {
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            Write-Warning "Active Directory module not found. Install RSAT-AD-PowerShell feature."
        }
        else {
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
            Write-Host "Querying servers from domain: $Domain" -ForegroundColor Yellow
            
            try {
                $domainParams = @{
                    Filter = *
                    Properties = @("Name", "OperatingSystem")
                }
                if ($Credential) {
                    $domainParams['Credential'] = $Credential
                    $domainParams['Server'] = $Domain
                }
                
                $allComputers = Get-ADComputer @domainParams
                
                # Filter for servers only
                foreach ($computer in $allComputers) {
                    $os = $computer.OperatingSystem
                    if ($os -and ($os -like "*Server*" -or $os -like "*Windows Server*")) {
                        $computers += $computer.Name
                    }
                }
                
                Write-Host "Found $($computers.Count) server(s) in domain" -ForegroundColor Green
            }
            catch {
                Write-Warning "Could not query domain. Error: $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Warning "Active Directory query failed: $($_.Exception.Message)"
    }
}

if ($ComputerList) {
    if (Test-Path $ComputerList) {
        Write-Host "Reading computer list from: $ComputerList" -ForegroundColor Yellow
        $computers += Get-Content $ComputerList | Where-Object { $_.Trim() -ne "" } | ForEach-Object { $_.Trim() }
    }
    else {
        Write-Error "Computer list file not found: $ComputerList"
        exit 1
    }
}

if ($ComputerName) {
    $computers += $ComputerName
}

# Remove duplicates
$computers = $computers | Select-Object -Unique

if ($computers.Count -eq 0) {
    Write-Error "No computers specified. Use -ComputerList, -ComputerName, or -Domain parameter."
    exit 1
}

Write-Host "Task Name Filter: $TaskName" -ForegroundColor Yellow
Write-Host "Task State Filter: $TaskState" -ForegroundColor Yellow
Write-Host "Found $($computers.Count) unique computer(s) to query" -ForegroundColor Green
if ($IncludeHidden) {
    Write-Host "Including hidden tasks: ENABLED" -ForegroundColor Cyan
}
if ($ShowDetails) {
    Write-Host "Show details: ENABLED" -ForegroundColor Cyan
}
Write-Host ""

# Query each computer
$allResults = @()
$total = $computers.Count
$current = 0

foreach ($computer in $computers) {
    $current++
    Write-Progress -Activity "Querying Scheduled Tasks" -Status "Processing $computer ($current of $total)" -PercentComplete (($current / $total) * 100)
    
    Write-Host "[$current/$total] Querying $computer..." -NoNewline
    
    $results = Get-ScheduledTasks -Computer $computer -NameFilter $TaskName -StateFilter $TaskState -Cred $Credential -IncludeHiddenTasks $IncludeHidden.IsPresent -ShowTaskDetails $ShowDetails.IsPresent
    $allResults += $results
    
    $taskCount = ($results | Where-Object { $_.Status -eq "Success" -and $_.TaskName -ne "N/A" }).Count
    $runningCount = ($results | Where-Object { $_.State -eq "Running" }).Count
    $disabledCount = ($results | Where-Object { $_.Enabled -eq $false }).Count
    
    if ($taskCount -gt 0) {
        Write-Host " Found $taskCount task(s)" -ForegroundColor Green
        if ($runningCount -gt 0) {
            Write-Host "  Running: $runningCount" -ForegroundColor Yellow
        }
        if ($disabledCount -gt 0) {
            Write-Host "  Disabled: $disabledCount" -ForegroundColor Gray
        }
    }
    else {
        $statusColor = switch ($results[0].Status) {
            "Offline" { "Red" }
            "Error" { "Red" }
            "No Tasks Found" { "Yellow" }
            default { "Gray" }
        }
        Write-Host " $($results[0].Status)" -ForegroundColor $statusColor
        if ($results[0].Error) {
            Write-Host "  Error: $($results[0].Error)" -ForegroundColor Red
        }
    }
}

Write-Progress -Activity "Querying Scheduled Tasks" -Completed

# Display summary
Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "========" -ForegroundColor Cyan
$totalTasks = ($allResults | Where-Object { $_.Status -eq "Success" -and $_.TaskName -ne "N/A" }).Count
$runningTasks = ($allResults | Where-Object { $_.State -eq "Running" }).Count
$readyTasks = ($allResults | Where-Object { $_.State -eq "Ready" }).Count
$disabledTasks = ($allResults | Where-Object { $_.Enabled -eq $false }).Count
$offline = ($allResults | Where-Object { $_.Status -eq "Offline" }).Count
$errors = ($allResults | Where-Object { $_.Status -eq "Error" }).Count

Write-Host "Total Tasks:     $totalTasks" -ForegroundColor Green
Write-Host "Running:         $runningTasks" -ForegroundColor Yellow
Write-Host "Ready:           $readyTasks" -ForegroundColor Cyan
Write-Host "Disabled:        $disabledTasks" -ForegroundColor Gray
Write-Host "Offline:         $offline" -ForegroundColor Red
Write-Host "Errors:          $errors" -ForegroundColor Red
Write-Host ""

# Show tasks by computer
Write-Host "Tasks by Computer:" -ForegroundColor Cyan
$allResults | Where-Object { $_.Status -eq "Success" -and $_.TaskName -ne "N/A" } | Group-Object -Property ComputerName | Select-Object Count, Name | Sort-Object Count -Descending | Format-Table -AutoSize
Write-Host ""

# Export to CSV
try {
    $allResults | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
    Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
}
catch {
    Write-Error "Failed to export results: $($_.Exception.Message)"
}

# Display results table
Write-Host ""
Write-Host "Sample Results (first 20):" -ForegroundColor Cyan
Write-Host "==========================" -ForegroundColor Cyan
$allResults | Where-Object { $_.Status -eq "Success" -and $_.TaskName -ne "N/A" } | Select-Object -First 20 | Format-Table -AutoSize ComputerName, TaskName, State, Enabled, LastRunTime, NextRunTime

