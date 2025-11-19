<#
.SYNOPSIS
    Gets all processes from remote computers.

.DESCRIPTION
    This script retrieves all running processes from multiple remote computers
    with detailed information including CPU, memory usage, and process details.

.PARAMETER ComputerList
    Path to a text file containing computer names (one per line).

.PARAMETER ComputerName
    Single computer name or array of computer names to query.

.PARAMETER Domain
    Query all computers in the specified domain (requires Active Directory module).

.PARAMETER ProcessName
    Filter by specific process name (supports wildcards, e.g., "chrome*", "*sql*").

.PARAMETER OutputFile
    Path to CSV file where results will be exported. Default: AllProcessesReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication (optional).

.PARAMETER SortBy
    Sort results by: CPU, Memory, ProcessName, or None (default: None).

.PARAMETER TopN
    Show only top N processes per computer (default: all processes).

.EXAMPLE
    .\Get-AllProcesses.ps1 -ComputerList "computers.txt"
    
.EXAMPLE
    .\Get-AllProcesses.ps1 -ComputerName "PC01","PC02" -ProcessName "chrome*"
    
.EXAMPLE
    .\Get-AllProcesses.ps1 -Domain "contoso.com" -SortBy "Memory" -TopN 10
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
    [string]$ProcessName = "*",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "AllProcessesReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("CPU","Memory","ProcessName","None")]
    [string]$SortBy = "None",
    
    [Parameter(Mandatory=$false)]
    [int]$TopN = 0
)

# Function to get processes from a single computer
function Get-AllProcesses {
    param(
        [string]$Computer,
        [string]$NameFilter,
        [System.Management.Automation.PSCredential]$Cred
    )
    
    $scriptBlock = {
        param([string]$ProcessName)
        
        $processes = @()
        
        try {
            $allProcesses = Get-Process -ErrorAction Stop
            
            foreach ($proc in $allProcesses) {
                # Filter by name
                if ($ProcessName -ne "*" -and $proc.ProcessName -notlike $ProcessName) {
                    continue
                }
                
                # Get CPU usage (may require multiple samples for accuracy)
                $cpuUsage = $null
                try {
                    $cpuCounter = Get-Counter "\Process($($proc.ProcessName))\% Processor Time" -ErrorAction SilentlyContinue
                    if ($cpuCounter) {
                        $cpuUsage = $cpuCounter.CounterSamples[0].CookedValue
                    }
                }
                catch {
                    # CPU counter not available, continue
                }
                
                $processes += @{
                    ProcessName = $proc.ProcessName
                    ProcessID = $proc.Id
                    CPU = if ($cpuUsage) { [math]::Round($cpuUsage, 2) } else { 0 }
                    MemoryMB = [math]::Round($proc.WorkingSet64 / 1MB, 2)
                    VirtualMemoryMB = [math]::Round($proc.VirtualMemorySize64 / 1MB, 2)
                    StartTime = if ($proc.StartTime) { $proc.StartTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
                    Path = if ($proc.Path) { $proc.Path } else { "N/A" }
                    Company = if ($proc.Company) { $proc.Company } else { "N/A" }
                    Description = if ($proc.Description) { $proc.Description } else { "N/A" }
                    Threads = $proc.Threads.Count
                    Handles = $proc.HandleCount
                    Responding = $proc.Responding
                }
            }
        }
        catch {
            $processes += @{
                ProcessName = "Error"
                ProcessID = 0
                Error = $_.Exception.Message
            }
        }
        
        return $processes
    }
    
    $results = @()
    
    try {
        # Test connectivity first
        if (-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            return @([PSCustomObject]@{
                ComputerName = $Computer
                ProcessName = "N/A"
                ProcessID = $null
                CPU = $null
                MemoryMB = $null
                VirtualMemoryMB = $null
                StartTime = "N/A"
                Path = "N/A"
                Status = "Offline"
                Error = "Computer is not reachable"
            })
        }
        
        # Execute remotely
        $invokeParams = @{
            ComputerName = $Computer
            ScriptBlock = $scriptBlock
            ArgumentList = @($NameFilter)
            ErrorAction = "Stop"
        }
        
        if ($Cred) {
            $invokeParams['Credential'] = $Cred
        }
        
        $processData = Invoke-Command @invokeParams
        
        # Format results
        foreach ($proc in $processData) {
            if ($proc.Error) {
                $results += [PSCustomObject]@{
                    ComputerName = $Computer
                    ProcessName = "Error"
                    ProcessID = $null
                    CPU = $null
                    MemoryMB = $null
                    VirtualMemoryMB = $null
                    StartTime = "N/A"
                    Path = "N/A"
                    Company = "N/A"
                    Description = "N/A"
                    Threads = $null
                    Handles = $null
                    Responding = $null
                    Status = "Error"
                    Error = $proc.Error
                }
            }
            else {
                $results += [PSCustomObject]@{
                    ComputerName = $Computer
                    ProcessName = $proc.ProcessName
                    ProcessID = $proc.ProcessID
                    CPU = $proc.CPU
                    MemoryMB = $proc.MemoryMB
                    VirtualMemoryMB = $proc.VirtualMemoryMB
                    StartTime = $proc.StartTime
                    Path = $proc.Path
                    Company = $proc.Company
                    Description = $proc.Description
                    Threads = $proc.Threads
                    Handles = $proc.Handles
                    Responding = $proc.Responding
                    Status = "Success"
                    Error = $null
                }
            }
        }
    }
    catch {
        $results += [PSCustomObject]@{
            ComputerName = $Computer
            ProcessName = "N/A"
            ProcessID = $null
            CPU = $null
            MemoryMB = $null
            VirtualMemoryMB = $null
            StartTime = "N/A"
            Path = "N/A"
            Company = "N/A"
            Description = "N/A"
            Threads = $null
            Handles = $null
            Responding = $null
            Status = "Error"
            Error = $_.Exception.Message
        }
    }
    
    return $results
}

# Main execution
Write-Host "All Processes Query Tool" -ForegroundColor Cyan
Write-Host "=======================" -ForegroundColor Cyan
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
            Write-Host "Querying computers from domain: $Domain" -ForegroundColor Yellow
            
            try {
                $domainParams = @{
                    Filter = *
                    Properties = Name
                }
                if ($Credential) {
                    $domainParams['Credential'] = $Credential
                    $domainParams['Server'] = $Domain
                }
                $domainComputers = Get-ADComputer @domainParams | Select-Object -ExpandProperty Name
                $computers += $domainComputers
                Write-Host "Found $($domainComputers.Count) computer(s) in domain" -ForegroundColor Green
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

Write-Host "Process Name Filter: $ProcessName" -ForegroundColor Yellow
Write-Host "Found $($computers.Count) unique computer(s) to query" -ForegroundColor Green
if ($TopN -gt 0) {
    Write-Host "Top N: $TopN processes per computer" -ForegroundColor Cyan
}
Write-Host ""

# Query each computer
$allResults = @()
$total = $computers.Count
$current = 0

foreach ($computer in $computers) {
    $current++
    Write-Progress -Activity "Querying Processes" -Status "Processing $computer ($current of $total)" -PercentComplete (($current / $total) * 100)
    
    Write-Host "[$current/$total] Querying $computer..." -NoNewline
    
    $results = Get-AllProcesses -Computer $computer -NameFilter $ProcessName -Cred $Credential
    
    # Apply TopN filter if specified
    if ($TopN -gt 0) {
        switch ($SortBy) {
            "CPU" {
                $results = $results | Where-Object { $_.Status -eq "Success" } | Sort-Object CPU -Descending | Select-Object -First $TopN
            }
            "Memory" {
                $results = $results | Where-Object { $_.Status -eq "Success" } | Sort-Object MemoryMB -Descending | Select-Object -First $TopN
            }
            "ProcessName" {
                $results = $results | Where-Object { $_.Status -eq "Success" } | Sort-Object ProcessName | Select-Object -First $TopN
            }
            default {
                $results = $results | Where-Object { $_.Status -eq "Success" } | Select-Object -First $TopN
            }
        }
    }
    
    $allResults += $results
    
    $processCount = ($results | Where-Object { $_.Status -eq "Success" }).Count
    
    if ($processCount -gt 0) {
        Write-Host " Found $processCount process(es)" -ForegroundColor Green
        $totalMemory = ($results | Where-Object { $_.MemoryMB -ne $null } | Measure-Object -Property MemoryMB -Sum).Sum
        Write-Host "  Total Memory: $([math]::Round($totalMemory, 2)) MB" -ForegroundColor Gray
    }
    else {
        $statusColor = switch ($results[0].Status) {
            "Offline" { "Red" }
            "Error" { "Red" }
            default { "Gray" }
        }
        Write-Host " $($results[0].Status)" -ForegroundColor $statusColor
        if ($results[0].Error) {
            Write-Host "  Error: $($results[0].Error)" -ForegroundColor Red
        }
    }
}

Write-Progress -Activity "Querying Processes" -Completed

# Sort all results if specified
if ($SortBy -ne "None") {
    switch ($SortBy) {
        "CPU" {
            $allResults = $allResults | Sort-Object CPU -Descending
        }
        "Memory" {
            $allResults = $allResults | Sort-Object MemoryMB -Descending
        }
        "ProcessName" {
            $allResults = $allResults | Sort-Object ProcessName
        }
    }
}

# Display summary
Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "========" -ForegroundColor Cyan
$totalProcesses = ($allResults | Where-Object { $_.Status -eq "Success" }).Count
$totalMemory = ($allResults | Where-Object { $_.MemoryMB -ne $null } | Measure-Object -Property MemoryMB -Sum).Sum
$totalCPU = ($allResults | Where-Object { $_.CPU -ne $null } | Measure-Object -Property CPU -Sum).Sum
$uniqueProcesses = ($allResults | Where-Object { $_.Status -eq "Success" } | Select-Object -Unique ProcessName).Count
$offline = ($allResults | Where-Object { $_.Status -eq "Offline" }).Count
$errors = ($allResults | Where-Object { $_.Status -eq "Error" }).Count

Write-Host "Total Processes:  $totalProcesses" -ForegroundColor Green
Write-Host "Unique Processes: $uniqueProcesses" -ForegroundColor Cyan
Write-Host "Total Memory:     $([math]::Round($totalMemory, 2)) MB" -ForegroundColor Cyan
Write-Host "Total CPU:        $([math]::Round($totalCPU, 2))%" -ForegroundColor Cyan
Write-Host "Offline:          $offline" -ForegroundColor Red
Write-Host "Errors:           $errors" -ForegroundColor Red
Write-Host ""

# Show top processes by memory
Write-Host "Top 10 Processes by Memory:" -ForegroundColor Cyan
$allResults | Where-Object { $_.Status -eq "Success" } | Sort-Object MemoryMB -Descending | Select-Object -First 10 | Format-Table -AutoSize ComputerName, ProcessName, MemoryMB, CPU, ProcessID

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
$allResults | Where-Object { $_.Status -eq "Success" } | Select-Object -First 20 | Format-Table -AutoSize ComputerName, ProcessName, ProcessID, MemoryMB, CPU, StartTime

