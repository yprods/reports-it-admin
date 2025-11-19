<#
.SYNOPSIS
    Retrieves device information from remote computers using WMI.

.DESCRIPTION
    This script queries a list of computers to retrieve detailed device information
    including hardware components, drivers, and system devices.

.PARAMETER ComputerList
    Path to a text file containing computer names (one per line).

.PARAMETER ComputerName
    Single computer name or array of computer names to query.

.PARAMETER OutputFile
    Path to CSV file where results will be exported. Default: ComputerDevicesReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication (optional).

.PARAMETER DeviceType
    Filter by device type: All, CPU, Memory, Disk, Network, Video, Audio, USB, or Printer (default: All).

.EXAMPLE
    .\Get-ComputerDevices.ps1 -ComputerList "computers.txt"
    
.EXAMPLE
    .\Get-ComputerDevices.ps1 -ComputerName "PC01","PC02","PC03" -DeviceType "Network"
    
.EXAMPLE
    .\Get-ComputerDevices.ps1 -ComputerList "computers.txt" -DeviceType "USB"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ComputerName,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "ComputerDevicesReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("All","CPU","Memory","Disk","Network","Video","Audio","USB","Printer")]
    [string]$DeviceType = "All"
)

# Function to get devices from a single computer
function Get-ComputerDevices {
    param(
        [string]$Computer,
        [string]$Type,
        [System.Management.Automation.PSCredential]$Cred
    )
    
    $results = @()
    
    try {
        # Test connectivity first
        if (-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            $result = [PSCustomObject]@{
                ComputerName = $Computer
                DeviceType = "N/A"
                DeviceName = "N/A"
                Manufacturer = "N/A"
                Model = "N/A"
                Status = "Offline"
                Error = "Computer is not reachable"
            }
            $results += $result
            return $results
        }
        
        # Query different device types based on parameter
        $deviceQueries = @()
        
        if ($Type -eq "All" -or $Type -eq "CPU") {
            $deviceQueries += @{ Class = "Win32_Processor"; Type = "CPU" }
        }
        if ($Type -eq "All" -or $Type -eq "Memory") {
            $deviceQueries += @{ Class = "Win32_PhysicalMemory"; Type = "Memory" }
        }
        if ($Type -eq "All" -or $Type -eq "Disk") {
            $deviceQueries += @{ Class = "Win32_DiskDrive"; Type = "Disk" }
        }
        if ($Type -eq "All" -or $Type -eq "Network") {
            $deviceQueries += @{ Class = "Win32_NetworkAdapter"; Filter = "PhysicalAdapter = True"; Type = "Network" }
        }
        if ($Type -eq "All" -or $Type -eq "Video") {
            $deviceQueries += @{ Class = "Win32_VideoController"; Type = "Video" }
        }
        if ($Type -eq "All" -or $Type -eq "Audio") {
            $deviceQueries += @{ Class = "Win32_SoundDevice"; Type = "Audio" }
        }
        if ($Type -eq "All" -or $Type -eq "USB") {
            $deviceQueries += @{ Class = "Win32_USBController"; Type = "USB" }
        }
        if ($Type -eq "All" -or $Type -eq "Printer") {
            $deviceQueries += @{ Class = "Win32_Printer"; Type = "Printer" }
        }
        
        foreach ($query in $deviceQueries) {
            try {
                $wmiParams = @{
                    ComputerName = $Computer
                    Class = $query.Class
                    ErrorAction = "Stop"
                }
                
                if ($query.Filter) {
                    $wmiParams['Filter'] = $query.Filter
                }
                
                if ($Cred) {
                    $wmiParams['Credential'] = $Cred
                }
                
                $devices = Get-CimInstance @wmiParams
                
                foreach ($device in $devices) {
                    $deviceName = $null
                    $manufacturer = $null
                    $model = $null
                    $details = @()
                    
                    # Extract common properties based on device type
                    switch ($query.Type) {
                        "CPU" {
                            $deviceName = $device.Name
                            $manufacturer = $device.Manufacturer
                            $model = "$($device.Name) ($($device.NumberOfCores) cores)"
                            $details += "Speed: $($device.MaxClockSpeed) MHz"
                            $details += "Architecture: $($device.Architecture)"
                        }
                        "Memory" {
                            $deviceName = $device.Manufacturer
                            $manufacturer = $device.Manufacturer
                            $model = "$([math]::Round($device.Capacity / 1GB, 2)) GB"
                            $details += "Speed: $($device.Speed) MHz"
                            $details += "Type: $($device.MemoryType)"
                        }
                        "Disk" {
                            $deviceName = $device.Model
                            $manufacturer = $device.Manufacturer
                            $model = "$([math]::Round($device.Size / 1GB, 2)) GB"
                            $details += "Interface: $($device.InterfaceType)"
                            $details += "Serial: $($device.SerialNumber)"
                        }
                        "Network" {
                            $deviceName = $device.Name
                            $manufacturer = $device.Manufacturer
                            $model = $device.ProductName
                            $details += "MAC: $($device.MACAddress)"
                            $details += "Speed: $($device.Speed)"
                        }
                        "Video" {
                            $deviceName = $device.Name
                            $manufacturer = $device.AdapterCompatibility
                            $model = "$($device.Name) - $([math]::Round($device.AdapterRAM / 1MB, 2)) MB"
                            $details += "Driver: $($device.DriverVersion)"
                        }
                        "Audio" {
                            $deviceName = $device.Name
                            $manufacturer = $device.Manufacturer
                            $model = $device.ProductName
                        }
                        "USB" {
                            $deviceName = $device.Name
                            $manufacturer = $device.Manufacturer
                            $model = $device.Description
                        }
                        "Printer" {
                            $deviceName = $device.Name
                            $manufacturer = $device.Manufacturer
                            $model = $device.Model
                            $details += "Status: $($device.PrinterStatus)"
                            $details += "Default: $($device.Default)"
                        }
                    }
                    
                    $result = [PSCustomObject]@{
                        ComputerName = $Computer
                        DeviceType = $query.Type
                        DeviceName = if ($deviceName) { $deviceName } else { "N/A" }
                        Manufacturer = if ($manufacturer) { $manufacturer } else { "N/A" }
                        Model = if ($model) { $model } else { "N/A" }
                        Details = ($details -join "; ")
                        Status = "Success"
                        Error = $null
                    }
                    $results += $result
                }
            }
            catch {
                $result = [PSCustomObject]@{
                    ComputerName = $Computer
                    DeviceType = $query.Type
                    DeviceName = "N/A"
                    Manufacturer = "N/A"
                    Model = "N/A"
                    Details = "N/A"
                    Status = "Error"
                    Error = $_.Exception.Message
                }
                $results += $result
            }
        }
    }
    catch {
        $result = [PSCustomObject]@{
            ComputerName = $Computer
            DeviceType = "Error"
            DeviceName = "N/A"
            Manufacturer = "N/A"
            Model = "N/A"
            Details = "N/A"
            Status = "Error"
            Error = $_.Exception.Message
        }
        $results += $result
    }
    
    # If no results, add a default entry
    if ($results.Count -eq 0) {
        $result = [PSCustomObject]@{
            ComputerName = $Computer
            DeviceType = "N/A"
            DeviceName = "N/A"
            Manufacturer = "N/A"
            Model = "N/A"
            Details = "N/A"
            Status = "No Devices Found"
            Error = "No devices found or accessible"
        }
        $results += $result
    }
    
    return $results
}

# Main execution
Write-Host "Computer Devices Query Tool" -ForegroundColor Cyan
Write-Host "===========================" -ForegroundColor Cyan
Write-Host ""

# Collect computer names
$computers = @()

if ($ComputerList) {
    if (Test-Path $ComputerList) {
        Write-Host "Reading computer list from: $ComputerList" -ForegroundColor Yellow
        $computers = Get-Content $ComputerList | Where-Object { $_.Trim() -ne "" } | ForEach-Object { $_.Trim() }
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
    Write-Error "No computers specified. Use -ComputerList or -ComputerName parameter."
    exit 1
}

Write-Host "Device Type Filter: $DeviceType" -ForegroundColor Yellow
Write-Host "Found $($computers.Count) unique computer(s) to query" -ForegroundColor Green
Write-Host ""

# Query each computer
$allResults = @()
$total = $computers.Count
$current = 0

foreach ($computer in $computers) {
    $current++
    Write-Progress -Activity "Querying Computer Devices" -Status "Processing $computer ($current of $total)" -PercentComplete (($current / $total) * 100)
    
    Write-Host "[$current/$total] Querying $computer..." -NoNewline
    
    $results = Get-ComputerDevices -Computer $computer -Type $DeviceType -Cred $Credential
    $allResults += $results
    
    $deviceCount = ($results | Where-Object { $_.Status -eq "Success" }).Count
    
    if ($deviceCount -gt 0) {
        Write-Host " Found $deviceCount device(s)" -ForegroundColor Green
        $deviceTypes = ($results | Where-Object { $_.Status -eq "Success" } | Select-Object -Unique DeviceType).DeviceType
        Write-Host "  Types: $($deviceTypes -join ', ')" -ForegroundColor Gray
    }
    else {
        $statusColor = switch ($results[0].Status) {
            "Offline" { "Red" }
            "Error" { "Red" }
            "No Devices Found" { "Yellow" }
            default { "Gray" }
        }
        Write-Host " $($results[0].Status)" -ForegroundColor $statusColor
        if ($results[0].Error) {
            Write-Host "  Error: $($results[0].Error)" -ForegroundColor Red
        }
    }
}

Write-Progress -Activity "Querying Computer Devices" -Completed

# Display summary
Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "========" -ForegroundColor Cyan
$totalDevices = ($allResults | Where-Object { $_.Status -eq "Success" }).Count
$offline = ($allResults | Where-Object { $_.Status -eq "Offline" }).Count
$errors = ($allResults | Where-Object { $_.Status -eq "Error" }).Count
$notFound = ($allResults | Where-Object { $_.Status -eq "No Devices Found" }).Count

Write-Host "Total Devices:      $totalDevices" -ForegroundColor Green
Write-Host "Offline:            $offline" -ForegroundColor Red
Write-Host "Errors:             $errors" -ForegroundColor Red
Write-Host "Not Found:          $notFound" -ForegroundColor Yellow
Write-Host ""

# Show breakdown by device type
if ($DeviceType -eq "All") {
    Write-Host "Devices by Type:" -ForegroundColor Cyan
    $allResults | Where-Object { $_.Status -eq "Success" } | Group-Object -Property DeviceType | Select-Object Count, Name | Sort-Object Count -Descending | Format-Table -AutoSize
    Write-Host ""
}

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
$allResults | Where-Object { $_.Status -eq "Success" } | Select-Object -First 20 | Format-Table -AutoSize ComputerName, DeviceType, DeviceName, Manufacturer, Model

