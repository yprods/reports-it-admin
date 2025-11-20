<#
.SYNOPSIS
    Creates a live monitoring dashboard for pinging computers.

.DESCRIPTION
    This script provides a real-time ping monitoring dashboard that continuously
    pings computers and displays their status with color-coded results.

.PARAMETER ComputerList
    Path to text file with computer names (one per line) or array of computer names.

.PARAMETER Interval
    Ping interval in seconds (default: 5).

.PARAMETER Timeout
    Ping timeout in milliseconds (default: 1000).

.PARAMETER Count
    Number of pings per check (default: 1).

.PARAMETER OutputFile
    Path to CSV file for logging. Default: PingMonitorLog.csv

.PARAMETER AutoRefresh
    Automatically refresh the display (default: true).

.EXAMPLE
    .\Monitor-PingLive.ps1 -ComputerList "computers.txt" -Interval 3
    
.EXAMPLE
    .\Monitor-PingLive.ps1 -ComputerList @("PC01", "PC02", "PC03") -Interval 5 -Timeout 2000
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [object]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [int]$Interval = 5,
    
    [Parameter(Mandatory=$false)]
    [int]$Timeout = 1000,
    
    [Parameter(Mandatory=$false)]
    [int]$Count = 1,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "PingMonitorLog.csv",
    
    [Parameter(Mandatory=$false)]
    [switch]$AutoRefresh = $true
)

# Function to ping computer
function Test-ComputerPing {
    param(
        [string]$Computer,
        [int]$PingTimeout,
        [int]$PingCount
    )
    
    try {
        $ping = Test-Connection -ComputerName $Computer -Count $PingCount -TimeoutSeconds ($PingTimeout / 1000) -ErrorAction Stop -Quiet
        
        if ($ping) {
            $result = Test-Connection -ComputerName $Computer -Count 1 -ErrorAction Stop
            return @{
                Success = $true
                ResponseTime = $result.ResponseTime
                Status = "Online"
            }
        }
        else {
            return @{
                Success = $false
                ResponseTime = $null
                Status = "Offline"
            }
        }
    }
    catch {
        return @{
            Success = $false
            ResponseTime = $null
            Status = "Error"
            Error = $_.Exception.Message
        }
    }
}

# Main execution
Write-Host "Live Ping Monitor" -ForegroundColor Cyan
Write-Host "================" -ForegroundColor Cyan
Write-Host ""

# Get computer list
$computers = @()

if ($ComputerList -is [string]) {
    if (Test-Path $ComputerList) {
        $computers = Get-Content $ComputerList | Where-Object { $_.Trim() -ne "" }
    }
    else {
        $computers = @($ComputerList)
    }
}
elseif ($ComputerList -is [array]) {
    $computers = $ComputerList
}
else {
    Write-Error "ComputerList must be a file path (string) or array of computer names."
    exit 1
}

if ($computers.Count -eq 0) {
    Write-Error "No computers specified."
    exit 1
}

Write-Host "Monitoring $($computers.Count) computer(s)" -ForegroundColor Yellow
Write-Host "Interval: $Interval seconds" -ForegroundColor Yellow
Write-Host "Timeout: $Timeout ms" -ForegroundColor Yellow
Write-Host "Press Ctrl+C to stop" -ForegroundColor Yellow
Write-Host ""

# Initialize results
$results = @{}
foreach ($computer in $computers) {
    $results[$computer] = @{
        Status = "Unknown"
        ResponseTime = $null
        LastCheck = $null
        SuccessCount = 0
        FailureCount = 0
    }
}

$logEntries = @()
$iteration = 0

try {
    while ($true) {
        $iteration++
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        
        # Clear screen for live update
        if ($AutoRefresh) {
            Clear-Host
            Write-Host "Live Ping Monitor - Iteration $iteration - $timestamp" -ForegroundColor Cyan
            Write-Host "=" * 80 -ForegroundColor Cyan
            Write-Host ""
        }
        
        # Ping all computers
        foreach ($computer in $computers) {
            $pingResult = Test-ComputerPing -Computer $computer -PingTimeout $Timeout -PingCount $Count
            
            $results[$computer].Status = $pingResult.Status
            $results[$computer].ResponseTime = $pingResult.ResponseTime
            $results[$computer].LastCheck = $timestamp
            
            if ($pingResult.Success) {
                $results[$computer].SuccessCount++
                $color = "Green"
                $statusSymbol = "✓"
            }
            else {
                $results[$computer].FailureCount++
                $color = "Red"
                $statusSymbol = "✗"
            }
            
            # Display result
            $responseTime = if ($pingResult.ResponseTime) { "$($pingResult.ResponseTime) ms" } else { "N/A" }
            Write-Host "$statusSymbol $computer " -NoNewline -ForegroundColor $color
            Write-Host "- $($pingResult.Status) " -NoNewline -ForegroundColor $color
            Write-Host "($responseTime) " -NoNewline -ForegroundColor Gray
            Write-Host "[Success: $($results[$computer].SuccessCount) | Failed: $($results[$computer].FailureCount)]" -ForegroundColor Gray
            
            # Log entry
            $logEntries += [PSCustomObject]@{
                Timestamp = $timestamp
                Computer = $computer
                Status = $pingResult.Status
                ResponseTime = $pingResult.ResponseTime
                SuccessCount = $results[$computer].SuccessCount
                FailureCount = $results[$computer].FailureCount
            }
        }
        
        # Summary
        $online = ($results.Values | Where-Object { $_.Status -eq "Online" }).Count
        $offline = ($results.Values | Where-Object { $_.Status -eq "Offline" }).Count
        $errors = ($results.Values | Where-Object { $_.Status -eq "Error" }).Count
        
        Write-Host ""
        Write-Host "Summary: " -NoNewline -ForegroundColor Cyan
        Write-Host "Online: $online " -NoNewline -ForegroundColor Green
        Write-Host "Offline: $offline " -NoNewline -ForegroundColor Red
        Write-Host "Errors: $errors" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Next check in $Interval seconds... (Press Ctrl+C to stop)" -ForegroundColor Gray
        
        # Save log periodically
        if ($iteration % 10 -eq 0) {
            $logEntries | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8 -Append
            $logEntries = @()
        }
        
        Start-Sleep -Seconds $Interval
    }
}
catch {
    Write-Host ""
    Write-Host "Monitoring stopped." -ForegroundColor Yellow
}
finally {
    # Final log save
    if ($logEntries.Count -gt 0) {
        $logEntries | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8 -Append
    }
    
    Write-Host ""
    Write-Host "Final Summary:" -ForegroundColor Cyan
    foreach ($computer in $computers) {
        $result = $results[$computer]
        Write-Host "$computer : Success=$($result.SuccessCount) Failed=$($result.FailureCount)" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "Log saved to: $OutputFile" -ForegroundColor Green
}

