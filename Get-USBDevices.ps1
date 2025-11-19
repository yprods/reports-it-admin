<#
.SYNOPSIS
    Finds all USB devices on remote computers.

.DESCRIPTION
    This script queries all computers to find connected USB devices
    including storage devices, keyboards, mice, and other USB peripherals.

.PARAMETER ComputerList
    Path to a text file containing computer names (one per line).

.PARAMETER ComputerName
    Single computer name or array of computer names to query.

.PARAMETER Domain
    Query all computers in the specified domain (requires Active Directory module).

.PARAMETER OutputFile
    Path to CSV file where results will be exported. Default: USBDevicesReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication (optional).

.PARAMETER DeviceType
    Filter by device type: All, Storage, Input, Audio, Video, Network, Printer, or Other (default: All).

.EXAMPLE
    .\Get-USBDevices.ps1 -ComputerList "computers.txt"
    
.EXAMPLE
    .\Get-USBDevices.ps1 -ComputerName "PC01","PC02","PC03" -DeviceType "Storage"
    
.EXAMPLE
    .\Get-USBDevices.ps1 -Domain "contoso.com" -DeviceType "All"
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
    [string]$OutputFile = "USBDevicesReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("All","Storage","Input","Audio","Video","Network","Printer","Other")]
    [string]$DeviceType = "All"
)

# Function to determine USB device type
function Get-USBDeviceType {
    param(
        [string]$Description,
        [string]$Class,
        [string]$Service
    )
    
    $descLower = $Description.ToLower()
    $classLower = $Class.ToLower()
    $serviceLower = $Service.ToLower()
    
    # Storage devices
    if ($descLower -like "*disk*" -or $descLower -like "*drive*" -or 
        $descLower -like "*usb storage*" -or $descLower -like "*flash*" -or
        $descLower -like "*thumb*" -or $classLower -like "*disk*") {
        return "Storage"
    }
    
    # Input devices
    if ($descLower -like "*keyboard*" -or $descLower -like "*mouse*" -or
        $descLower -like "*hid*" -or $classLower -like "*keyboard*" -or
        $classLower -like "*mouse*") {
        return "Input"
    }
    
    # Audio devices
    if ($descLower -like "*audio*" -or $descLower -like "*sound*" -or
        $descLower -like "*microphone*" -or $descLower -like "*headset*" -or
        $classLower -like "*audio*" -or $classLower -like "*sound*") {
        return "Audio"
    }
    
    # Video devices
    if ($descLower -like "*camera*" -or $descLower -like "*webcam*" -or
        $descLower -like "*video*" -or $classLower -like "*camera*" -or
        $classLower -like "*video*") {
        return "Video"
    }
    
    # Network devices
    if ($descLower -like "*network*" -or $descLower -like "*ethernet*" -or
        $descLower -like "*wifi*" -or $descLower -like "*wireless*" -or
        $classLower -like "*network*") {
        return "Network"
    }
    
    # Printers
    if ($descLower -like "*printer*" -or $classLower -like "*printer*") {
        return "Printer"
    }
    
    return "Other"
}

# Function to get USB devices from a single computer
function Get-USBDevices {
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
                DeviceName = "N/A"
                DeviceType = "N/A"
                Manufacturer = "N/A"
                Description = "N/A"
                SerialNumber = "N/A"
                Status = "Offline"
                Error = "Computer is not reachable"
            }
            $results += $result
            return $results
        }
        
        # Method 1: Query Win32_USBControllerDevice
        try {
            $usbParams = @{
                ComputerName = $Computer
                Class = "Win32_USBControllerDevice"
                ErrorAction = "Stop"
            }
            
            if ($Cred) {
                $usbParams['Credential'] = $Cred
            }
            
            $usbControllers = Get-CimInstance @usbParams
            
            foreach ($controller in $usbControllers) {
                try {
                    # Get the dependent device
                    $dependent = $controller.Dependent
                    $deviceId = $dependent -replace '.*DeviceID="([^"]+)".*', '$1'
                    
                    # Get device details from Win32_PnPEntity
                    $pnpParams = @{
                        ComputerName = $Computer
                        Class = "Win32_PnPEntity"
                        Filter = "DeviceID = '$deviceId'"
                        ErrorAction = "SilentlyContinue"
                    }
                    
                    if ($Cred) {
                        $pnpParams['Credential'] = $Cred
                    }
                    
                    $pnpDevice = Get-CimInstance @pnpParams
                    
                    if ($pnpDevice) {
                        $deviceType = Get-USBDeviceType -Description $pnpDevice.Description -Class $pnpDevice.Class -Service $pnpDevice.Service
                        
                        # Filter by device type if specified
                        if ($Type -ne "All" -and $deviceType -ne $Type) {
                            continue
                        }
                        
                        # Get additional info from Win32_LogicalDisk if it's a storage device
                        $serialNumber = "N/A"
                        $size = $null
                        
                        if ($deviceType -eq "Storage") {
                            try {
                                $diskParams = @{
                                    ComputerName = $Computer
                                    Class = "Win32_LogicalDisk"
                                    Filter = "DeviceID LIKE '%'"
                                    ErrorAction = "SilentlyContinue"
                                }
                                
                                if ($Cred) {
                                    $diskParams['Credential'] = $Cred
                                }
                                
                                $disks = Get-CimInstance @diskParams
                                foreach ($disk in $disks) {
                                    if ($disk.VolumeSerialNumber) {
                                        $serialNumber = $disk.VolumeSerialNumber
                                        $size = $disk.Size
                                        break
                                    }
                                }
                            }
                            catch {
                                # Continue without disk info
                            }
                        }
                        
                        $result = [PSCustomObject]@{
                            ComputerName = $Computer
                            DeviceName = if ($pnpDevice.Name) { $pnpDevice.Name } else { "N/A" }
                            DeviceType = $deviceType
                            Manufacturer = if ($pnpDevice.Manufacturer) { $pnpDevice.Manufacturer } else { "N/A" }
                            Description = if ($pnpDevice.Description) { $pnpDevice.Description } else { "N/A" }
                            SerialNumber = $serialNumber
                            DeviceID = $deviceId
                            Status = if ($pnpDevice.Status) { $pnpDevice.Status } else { "N/A" }
                            SizeGB = if ($size) { [math]::Round($size / 1GB, 2) } else { $null }
                            Error = $null
                        }
                        $results += $result
                    }
                }
                catch {
                    # Continue with next device
                }
            }
        }
        catch {
            # Method 2: Query Win32_PnPEntity directly for USB devices
            try {
                $pnpParams = @{
                    ComputerName = $Computer
                    Class = "Win32_PnPEntity"
                    Filter = "DeviceID LIKE 'USB%'"
                    ErrorAction = "Stop"
                }
                
                if ($Cred) {
                    $pnpParams['Credential'] = $Cred
                }
                
                $usbDevices = Get-CimInstance @pnpParams
                
                foreach ($device in $usbDevices) {
                    $deviceType = Get-USBDeviceType -Description $device.Description -Class $device.Class -Service $device.Service
                    
                    if ($Type -ne "All" -and $deviceType -ne $Type) {
                        continue
                    }
                    
                    $result = [PSCustomObject]@{
                        ComputerName = $Computer
                        DeviceName = if ($device.Name) { $device.Name } else { "N/A" }
                        DeviceType = $deviceType
                        Manufacturer = if ($device.Manufacturer) { $device.Manufacturer } else { "N/A" }
                        Description = if ($device.Description) { $device.Description } else { "N/A" }
                        SerialNumber = "N/A"
                        DeviceID = if ($device.DeviceID) { $device.DeviceID } else { "N/A" }
                        Status = if ($device.Status) { $device.Status } else { "N/A" }
                        SizeGB = $null
                        Error = $null
                    }
                    $results += $result
                }
            }
            catch {
                $result = [PSCustomObject]@{
                    ComputerName = $Computer
                    DeviceName = "N/A"
                    DeviceType = "N/A"
                    Manufacturer = "N/A"
                    Description = "N/A"
                    SerialNumber = "N/A"
                    DeviceID = "N/A"
                    Status = "Error"
                    SizeGB = $null
                    Error = $_.Exception.Message
                }
                $results += $result
            }
        }
    }
    catch {
        $result = [PSCustomObject]@{
            ComputerName = $Computer
            DeviceName = "N/A"
            DeviceType = "N/A"
            Manufacturer = "N/A"
            Description = "N/A"
            SerialNumber = "N/A"
            DeviceID = "N/A"
            Status = "Error"
            SizeGB = $null
            Error = $_.Exception.Message
        }
        $results += $result
    }
    
    # If no results, add a default entry
    if ($results.Count -eq 0) {
        $result = [PSCustomObject]@{
            ComputerName = $Computer
            DeviceName = "N/A"
            DeviceType = "N/A"
            Manufacturer = "N/A"
            Description = "N/A"
            SerialNumber = "N/A"
            DeviceID = "N/A"
            Status = "No USB Devices Found"
            SizeGB = $null
            Error = "No USB devices found or accessible"
        }
        $results += $result
    }
    
    return $results
}

# Main execution
Write-Host "USB Devices Query Tool" -ForegroundColor Cyan
Write-Host "=====================" -ForegroundColor Cyan
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

Write-Host "Device Type Filter: $DeviceType" -ForegroundColor Yellow
Write-Host "Found $($computers.Count) unique computer(s) to query" -ForegroundColor Green
Write-Host ""

# Query each computer
$allResults = @()
$total = $computers.Count
$current = 0

foreach ($computer in $computers) {
    $current++
    Write-Progress -Activity "Querying USB Devices" -Status "Processing $computer ($current of $total)" -PercentComplete (($current / $total) * 100)
    
    Write-Host "[$current/$total] Querying $computer..." -NoNewline
    
    $results = Get-USBDevices -Computer $computer -Type $DeviceType -Cred $Credential
    $allResults += $results
    
    $deviceCount = ($results | Where-Object { $_.Status -eq "OK" -or $_.DeviceName -ne "N/A" }).Count
    
    if ($deviceCount -gt 0) {
        Write-Host " Found $deviceCount device(s)" -ForegroundColor Green
        $deviceTypes = ($results | Where-Object { $_.DeviceType -ne "N/A" } | Select-Object -Unique DeviceType).DeviceType
        if ($deviceTypes) {
            Write-Host "  Types: $($deviceTypes -join ', ')" -ForegroundColor Gray
        }
    }
    else {
        $statusColor = switch ($results[0].Status) {
            "Offline" { "Red" }
            "Error" { "Red" }
            "No USB Devices Found" { "Yellow" }
            default { "Gray" }
        }
        Write-Host " $($results[0].Status)" -ForegroundColor $statusColor
        if ($results[0].Error) {
            Write-Host "  Error: $($results[0].Error)" -ForegroundColor Red
        }
    }
}

Write-Progress -Activity "Querying USB Devices" -Completed

# Display summary
Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "========" -ForegroundColor Cyan
$totalDevices = ($allResults | Where-Object { $_.DeviceName -ne "N/A" -and $_.Status -ne "Offline" -and $_.Status -ne "Error" }).Count
$storageDevices = ($allResults | Where-Object { $_.DeviceType -eq "Storage" }).Count
$inputDevices = ($allResults | Where-Object { $_.DeviceType -eq "Input" }).Count
$audioDevices = ($allResults | Where-Object { $_.DeviceType -eq "Audio" }).Count
$videoDevices = ($allResults | Where-Object { $_.DeviceType -eq "Video" }).Count
$otherDevices = ($allResults | Where-Object { $_.DeviceType -eq "Other" }).Count
$offline = ($allResults | Where-Object { $_.Status -eq "Offline" }).Count
$errors = ($allResults | Where-Object { $_.Status -eq "Error" }).Count

Write-Host "Total Devices:      $totalDevices" -ForegroundColor Green
Write-Host "Storage Devices:    $storageDevices" -ForegroundColor Cyan
Write-Host "Input Devices:      $inputDevices" -ForegroundColor Cyan
Write-Host "Audio Devices:      $audioDevices" -ForegroundColor Cyan
Write-Host "Video Devices:      $videoDevices" -ForegroundColor Cyan
Write-Host "Other Devices:      $otherDevices" -ForegroundColor Cyan
Write-Host "Offline:            $offline" -ForegroundColor Red
Write-Host "Errors:             $errors" -ForegroundColor Red
Write-Host ""

# Show breakdown by device type
if ($DeviceType -eq "All") {
    Write-Host "Devices by Type:" -ForegroundColor Cyan
    $allResults | Where-Object { $_.DeviceType -ne "N/A" } | Group-Object -Property DeviceType | Select-Object Count, Name | Sort-Object Count -Descending | Format-Table -AutoSize
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
$allResults | Where-Object { $_.DeviceName -ne "N/A" } | Select-Object -First 20 | Format-Table -AutoSize ComputerName, DeviceName, DeviceType, Manufacturer, Description

