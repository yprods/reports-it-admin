<#
.SYNOPSIS
    Queries monitor brand and information from a list of computers using WMI.

.DESCRIPTION
    This script reads a list of computer names and queries their monitor information
    remotely using WMI. It retrieves monitor brand, model, serial number, and other details.

.PARAMETER ComputerList
    Path to a text file containing computer names (one per line).

.PARAMETER ComputerName
    Single computer name or array of computer names to query.

.PARAMETER OutputFile
    Path to CSV file where results will be exported. Default: MonitorInfoReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication (optional).

.EXAMPLE
    .\Get-MonitorInfo.ps1 -ComputerList "computers.txt"
    
.EXAMPLE
    .\Get-MonitorInfo.ps1 -ComputerName "PC01","PC02","PC03"
    
.EXAMPLE
    .\Get-MonitorInfo.ps1 -ComputerList "computers.txt" -OutputFile "results.csv"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ComputerName,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "MonitorInfoReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential
)

# Function to get monitor information from a single computer
function Get-MonitorInfo {
    param(
        [string]$Computer,
        [System.Management.Automation.PSCredential]$Cred
    )
    
    $results = @()
    
    try {
        # Test connectivity first
        if (-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            $result = [PSCustomObject]@{
                ComputerName = $Computer
                MonitorIndex = "N/A"
                Manufacturer = "N/A"
                Model = "N/A"
                SerialNumber = "N/A"
                Name = "N/A"
                Status = "Offline"
                LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Error = "Computer is not reachable"
            }
            $results += $result
            return $results
        }
        
        # Method 1: Query WmiMonitorBasicDisplayParams (most detailed info)
        try {
            $wmiParams = @{
                ComputerName = $Computer
                Namespace = "root\wmi"
                Class = "WmiMonitorBasicDisplayParams"
                ErrorAction = "Stop"
            }
            
            if ($Cred) {
                $wmiParams['Credential'] = $Cred
            }
            
            $monitors = Get-CimInstance @wmiParams
            
            if ($monitors) {
                $index = 0
                foreach ($monitor in $monitors) {
                    $index++
                    $result = [PSCustomObject]@{
                        ComputerName = $Computer
                        MonitorIndex = $index
                        Manufacturer = "N/A"
                        Model = "N/A"
                        SerialNumber = "N/A"
                        Name = "N/A"
                        Status = "Success"
                        LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        Error = $null
                    }
                    
                    # Get additional info from WmiMonitorID
                    try {
                        $idParams = @{
                            ComputerName = $Computer
                            Namespace = "root\wmi"
                            Class = "WmiMonitorID"
                            ErrorAction = "Stop"
                        }
                        
                        if ($Cred) {
                            $idParams['Credential'] = $Cred
                        }
                        
                        $monitorIds = Get-CimInstance @idParams
                        if ($monitorIds -and $monitorIds.Count -ge $index) {
                            $monitorId = $monitorIds[$index - 1]
                            
                            # Convert byte arrays to strings
                            if ($monitorId.ManufacturerName) {
                                $result.Manufacturer = [System.Text.Encoding]::ASCII.GetString($monitorId.ManufacturerName).TrimEnd([char]0)
                            }
                            if ($monitorId.UserFriendlyName) {
                                $result.Name = [System.Text.Encoding]::ASCII.GetString($monitorId.UserFriendlyName).TrimEnd([char]0)
                            }
                            if ($monitorId.SerialNumberID) {
                                $result.SerialNumber = [System.Text.Encoding]::ASCII.GetString($monitorId.SerialNumberID).TrimEnd([char]0)
                            }
                            if ($monitorId.ProductCodeID) {
                                $result.Model = [System.Text.Encoding]::ASCII.GetString($monitorId.ProductCodeID).TrimEnd([char]0)
                            }
                        }
                    }
                    catch {
                        # Continue without ID info
                    }
                    
                    $results += $result
                }
            }
        }
        catch {
            # Method 2: Query Win32_DesktopMonitor (fallback)
            try {
                $desktopParams = @{
                    ComputerName = $Computer
                    Class = "Win32_DesktopMonitor"
                    ErrorAction = "Stop"
                }
                
                if ($Cred) {
                    $desktopParams['Credential'] = $Cred
                }
                
                $desktopMonitors = Get-CimInstance @desktopParams
                
                if ($desktopMonitors) {
                    $index = 0
                    foreach ($monitor in $desktopMonitors) {
                        $index++
                        $result = [PSCustomObject]@{
                            ComputerName = $Computer
                            MonitorIndex = $index
                            Manufacturer = if ($monitor.Manufacturer) { $monitor.Manufacturer } else { "N/A" }
                            Model = if ($monitor.Name) { $monitor.Name } else { "N/A" }
                            SerialNumber = if ($monitor.SerialNumber) { $monitor.SerialNumber } else { "N/A" }
                            Name = if ($monitor.Name) { $monitor.Name } else { "N/A" }
                            Status = "Success"
                            LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                            Error = $null
                        }
                        $results += $result
                    }
                }
                else {
                    throw "No monitors found"
                }
            }
            catch {
                # Method 3: Query Win32_PnPEntity for display devices
                try {
                    $pnpParams = @{
                        ComputerName = $Computer
                        Class = "Win32_PnPEntity"
                        Filter = "PNPClass='Monitor'"
                        ErrorAction = "Stop"
                    }
                    
                    if ($Cred) {
                        $pnpParams['Credential'] = $Cred
                    }
                    
                    $pnpMonitors = Get-CimInstance @pnpParams
                    
                    if ($pnpMonitors) {
                        $index = 0
                        foreach ($monitor in $pnpMonitors) {
                            $index++
                            $result = [PSCustomObject]@{
                                ComputerName = $Computer
                                MonitorIndex = $index
                                Manufacturer = if ($monitor.Manufacturer) { $monitor.Manufacturer } else { "N/A" }
                                Model = if ($monitor.Name) { $monitor.Name } else { "N/A" }
                                SerialNumber = "N/A"
                                Name = if ($monitor.Name) { $monitor.Name } else { "N/A" }
                                Status = "Success"
                                LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                                Error = "Retrieved via PnP (limited info)"
                            }
                            $results += $result
                        }
                    }
                    else {
                        throw "No monitors found via any method"
                    }
                }
                catch {
                    $result = [PSCustomObject]@{
                        ComputerName = $Computer
                        MonitorIndex = "N/A"
                        Manufacturer = "N/A"
                        Model = "N/A"
                        SerialNumber = "N/A"
                        Name = "N/A"
                        Status = "Error"
                        LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        Error = $_.Exception.Message
                    }
                    $results += $result
                }
            }
        }
    }
    catch {
        $result = [PSCustomObject]@{
            ComputerName = $Computer
            MonitorIndex = "N/A"
            Manufacturer = "N/A"
            Model = "N/A"
            SerialNumber = "N/A"
            Name = "N/A"
            Status = "Error"
            LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Error = $_.Exception.Message
        }
        $results += $result
    }
    
    # If no results, add a default entry
    if ($results.Count -eq 0) {
        $result = [PSCustomObject]@{
            ComputerName = $Computer
            MonitorIndex = "N/A"
            Manufacturer = "N/A"
            Model = "N/A"
            SerialNumber = "N/A"
            Name = "N/A"
            Status = "No Monitors Found"
            LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Error = "No monitor information could be retrieved"
        }
        $results += $result
    }
    
    return $results
}

# Main execution
Write-Host "Monitor Information Query Tool" -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor Cyan
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

if ($computers.Count -eq 0) {
    Write-Error "No computers specified. Use -ComputerList or -ComputerName parameter."
    exit 1
}

Write-Host "Found $($computers.Count) computer(s) to query" -ForegroundColor Green
Write-Host ""

# Query each computer
$allResults = @()
$total = $computers.Count
$current = 0

foreach ($computer in $computers) {
    $current++
    Write-Progress -Activity "Querying Monitor Information" -Status "Processing $computer ($current of $total)" -PercentComplete (($current / $total) * 100)
    
    Write-Host "[$current/$total] Querying $computer..." -NoNewline
    
    $results = Get-MonitorInfo -Computer $computer -Cred $Credential
    $allResults += $results
    
    $statusColor = switch ($results[0].Status) {
        "Success" { "Green" }
        "Offline" { "Red" }
        "Error" { "Red" }
        "No Monitors Found" { "Yellow" }
        default { "Gray" }
    }
    
    $monitorCount = ($results | Where-Object { $_.Status -eq "Success" }).Count
    if ($monitorCount -gt 0) {
        Write-Host " Found $monitorCount monitor(s)" -ForegroundColor $statusColor
        foreach ($monitor in $results) {
            if ($monitor.Status -eq "Success") {
                $monitorInfo = "$($monitor.Manufacturer) $($monitor.Model)"
                if ($monitorInfo.Trim() -eq "" -or $monitorInfo.Trim() -eq "N/A N/A") {
                    $monitorInfo = $monitor.Name
                }
                Write-Host "  - Monitor $($monitor.MonitorIndex): $monitorInfo" -ForegroundColor Gray
            }
        }
    }
    else {
        Write-Host " $($results[0].Status)" -ForegroundColor $statusColor
        if ($results[0].Error) {
            Write-Host "  Error: $($results[0].Error)" -ForegroundColor Red
        }
    }
}

Write-Progress -Activity "Querying Monitor Information" -Completed

# Display summary
Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "========" -ForegroundColor Cyan
$success = ($allResults | Where-Object { $_.Status -eq "Success" }).Count
$offline = ($allResults | Where-Object { $_.Status -eq "Offline" }).Count
$errors = ($allResults | Where-Object { $_.Status -eq "Error" }).Count
$notFound = ($allResults | Where-Object { $_.Status -eq "No Monitors Found" }).Count
$totalMonitors = ($allResults | Where-Object { $_.Status -eq "Success" }).Count

Write-Host "Monitors Found: $totalMonitors" -ForegroundColor Green
Write-Host "Offline:        $offline" -ForegroundColor Red
Write-Host "Errors:         $errors" -ForegroundColor Red
Write-Host "Not Found:      $notFound" -ForegroundColor Yellow
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
Write-Host "Detailed Results:" -ForegroundColor Cyan
Write-Host "================" -ForegroundColor Cyan
$allResults | Format-Table -AutoSize ComputerName, MonitorIndex, Manufacturer, Model, SerialNumber, Status

