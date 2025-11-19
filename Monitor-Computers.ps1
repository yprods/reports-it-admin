<#
.SYNOPSIS
    Monitors a list of computers for all IT needs (comprehensive monitoring).

.DESCRIPTION
    This script monitors multiple computers and collects comprehensive information
    including system status, disk space, memory, CPU, users, services, and more.

.PARAMETER ComputerList
    Path to text file with computer names.

.PARAMETER ComputerName
    Single or array of computer names.

.PARAMETER OutputFile
    Path to CSV file. Default: ComputerMonitorReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication.

.PARAMETER MonitorInterval
    Monitoring interval in seconds (default: 60, use 0 for single run).

.PARAMETER MonitorDuration
    Total monitoring duration in minutes (default: 0 for single run).

.EXAMPLE
    .\Monitor-Computers.ps1 -ComputerList "computers.txt"
    
.EXAMPLE
    .\Monitor-Computers.ps1 -ComputerName "PC01","PC02" -MonitorInterval 60 -MonitorDuration 60
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ComputerName,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "ComputerMonitorReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [int]$MonitorInterval = 0,
    
    [Parameter(Mandatory=$false)]
    [int]$MonitorDuration = 0
)

function Get-ComputerMonitor {
    param([string]$Computer, [System.Management.Automation.PSCredential]$Cred)
    
    $scriptBlock = {
        $info = @{}
        
        try {
            # System Info
            $cs = Get-CimInstance -ClassName Win32_ComputerSystem
            $info.ComputerName = $cs.Name
            $info.Manufacturer = $cs.Manufacturer
            $info.Model = $cs.Model
            $info.Domain = $cs.Domain
            $info.TotalPhysicalMemoryGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
            
            # OS Info
            $os = Get-CimInstance -ClassName Win32_OperatingSystem
            $info.OSName = $os.Caption
            $info.OSVersion = $os.Version
            $info.OSArchitecture = $os.OSArchitecture
            $info.LastBootTime = $os.LastBootUpTime
            $info.UptimeHours = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 2)
            
            # CPU Info
            $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
            $info.CPUName = $cpu.Name
            $info.CPUCores = $cpu.NumberOfCores
            $info.CPULogicalProcessors = $cpu.NumberOfLogicalProcessors
            $info.CPUUsagePercent = (Get-Counter '\Processor(_Total)\% Processor Time' -ErrorAction SilentlyContinue).CounterSamples[0].CookedValue
            
            # Memory Info
            $mem = Get-CimInstance -ClassName Win32_OperatingSystem
            $info.TotalMemoryGB = [math]::Round($mem.TotalVisibleMemorySize / 1MB, 2)
            $info.FreeMemoryGB = [math]::Round($mem.FreePhysicalMemory / 1MB, 2)
            $info.UsedMemoryGB = [math]::Round(($mem.TotalVisibleMemorySize - $mem.FreePhysicalMemory) / 1MB, 2)
            $info.MemoryUsagePercent = [math]::Round((($mem.TotalVisibleMemorySize - $mem.FreePhysicalMemory) / $mem.TotalVisibleMemorySize) * 100, 2)
            
            # Disk Info
            $disks = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
            $diskInfo = @()
            foreach ($disk in $disks) {
                $diskInfo += "$($disk.DeviceID) - Free: $([math]::Round($disk.FreeSpace / 1GB, 2))GB / Total: $([math]::Round($disk.Size / 1GB, 2))GB"
            }
            $info.DiskInfo = $diskInfo -join "; "
            
            # Network Info
            $adapters = Get-CimInstance -ClassName Win32_NetworkAdapter | Where-Object { $_.NetConnectionStatus -eq 2 }
            $info.NetworkAdapters = $adapters.Count
            $info.NetworkAdapterNames = ($adapters | Select-Object -ExpandProperty Name) -join "; "
            
            # User Sessions
            $sessions = query user 2>&1
            $userCount = ($sessions | Where-Object { $_ -match '^\s+\S+\s+\S+\s+\d+\s+' }).Count
            $info.LoggedOnUsers = $userCount
            
            # Services Status
            $services = Get-Service
            $info.TotalServices = $services.Count
            $info.RunningServices = ($services | Where-Object { $_.Status -eq 'Running' }).Count
            $info.StoppedServices = ($services | Where-Object { $_.Status -eq 'Stopped' }).Count
            
            # Processes
            $processes = Get-Process
            $info.TotalProcesses = $processes.Count
            $info.ProcessMemoryMB = [math]::Round(($processes | Measure-Object -Property WorkingSet -Sum).Sum / 1MB, 2)
            
            # Installed Software Count
            $software = Get-CimInstance -ClassName Win32_Product -ErrorAction SilentlyContinue
            $info.InstalledSoftwareCount = $software.Count
            
            # Battery Status (if applicable)
            $battery = Get-CimInstance -ClassName Win32_Battery | Select-Object -First 1
            if ($battery) {
                $info.BatteryPresent = $true
                $info.BatteryLevel = $battery.EstimatedChargeRemaining
            } else {
                $info.BatteryPresent = $false
                $info.BatteryLevel = $null
            }
            
            # Time Info
            $info.LocalTime = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            $info.TimeZone = [System.TimeZoneInfo]::Local.DisplayName
            
            $info.Status = "Success"
        }
        catch {
            $info.Status = "Error"
            $info.Error = $_.Exception.Message
        }
        
        return $info
    }
    
    $result = [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        ComputerName = $Computer
        Status = "Unknown"
    }
    
    try {
        if (-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            $result.Status = "Offline"
            return $result
        }
        
        $invokeParams = @{
            ComputerName = $Computer
            ScriptBlock = $scriptBlock
        }
        if ($Cred) { $invokeParams['Credential'] = $Cred }
        
        $monitorData = Invoke-Command @invokeParams
        
        # Add all monitor data to result
        foreach ($key in $monitorData.Keys) {
            $result | Add-Member -MemberType NoteProperty -Name $key -Value $monitorData[$key] -Force
        }
    }
    catch {
        $result.Status = "Error"
        $result.Error = $_.Exception.Message
    }
    
    return $result
}

# Main execution
Write-Host "Computer Monitoring Tool" -ForegroundColor Cyan
Write-Host "=======================" -ForegroundColor Cyan
Write-Host ""

$computers = @()
if ($ComputerList -and (Test-Path $ComputerList)) {
    $computers = Get-Content $ComputerList | Where-Object { $_.Trim() -ne "" }
}
if ($ComputerName) {
    $computers += $ComputerName
}
$computers = $computers | Select-Object -Unique

if ($computers.Count -eq 0) {
    Write-Error "No computers specified."
    exit 1
}

$allResults = @()
$startTime = Get-Date
$endTime = if ($MonitorDuration -gt 0) { $startTime.AddMinutes($MonitorDuration) } else { $startTime }

Write-Host "Monitoring $($computers.Count) computer(s)..." -ForegroundColor Yellow
if ($MonitorInterval -gt 0) {
    Write-Host "Interval: $MonitorInterval seconds" -ForegroundColor Yellow
    Write-Host "Duration: $MonitorDuration minutes" -ForegroundColor Yellow
}
Write-Host ""

do {
    $iterationResults = @()
    
    foreach ($computer in $computers) {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Monitoring $computer..." -NoNewline
        $result = Get-ComputerMonitor -Computer $computer -Cred $Credential
        $iterationResults += $result
        $allResults += $result
        
        $statusColor = switch ($result.Status) {
            "Success" { "Green" }
            "Offline" { "Red" }
            "Error" { "Red" }
            default { "Gray" }
        }
        Write-Host " $($result.Status)" -ForegroundColor $statusColor
        
        if ($result.Status -eq "Success") {
            Write-Host "  CPU: $($result.CPUUsagePercent)% | Memory: $($result.MemoryUsagePercent)% | Users: $($result.LoggedOnUsers)" -ForegroundColor Gray
        }
    }
    
    if ($MonitorInterval -gt 0 -and (Get-Date) -lt $endTime) {
        Write-Host ""
        Write-Host "Waiting $MonitorInterval seconds until next check..." -ForegroundColor Yellow
        Start-Sleep -Seconds $MonitorInterval
        Write-Host ""
    }
} while ($MonitorInterval -gt 0 -and (Get-Date) -lt $endTime)

$allResults | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host ""
Write-Host "Monitoring complete. Results exported to: $OutputFile" -ForegroundColor Green

# Summary
Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
$success = ($allResults | Where-Object { $_.Status -eq "Success" }).Count
$offline = ($allResults | Where-Object { $_.Status -eq "Offline" }).Count
$errors = ($allResults | Where-Object { $_.Status -eq "Error" }).Count
Write-Host "Successful: $success" -ForegroundColor Green
Write-Host "Offline: $offline" -ForegroundColor Red
Write-Host "Errors: $errors" -ForegroundColor Red

