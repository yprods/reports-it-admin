<#
.SYNOPSIS
    Gets battery status from all computers.

.DESCRIPTION
    This script queries battery information from remote computers (laptops).

.PARAMETER ComputerList
    Path to text file with computer names.

.PARAMETER ComputerName
    Single or array of computer names.

.PARAMETER OutputFile
    Path to CSV file. Default: BatteryStatusReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication.

.EXAMPLE
    .\Get-BatteryStatus.ps1 -ComputerList "computers.txt"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ComputerName,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "BatteryStatusReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential
)

function Get-BatteryStatus {
    param([string]$Computer, [System.Management.Automation.PSCredential]$Cred)
    
    $result = [PSCustomObject]@{
        ComputerName = $Computer
        BatteryPresent = $false
        ChargeLevel = $null
        BatteryStatus = "N/A"
        EstimatedRuntime = "N/A"
        Status = "Unknown"
        Error = $null
    }
    
    try {
        if (-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            $result.Status = "Offline"
            return $result
        }
        
        $wmiParams = @{
            ComputerName = $Computer
            Class = "Win32_Battery"
            ErrorAction = "Stop"
        }
        if ($Cred) { $wmiParams['Credential'] = $Cred }
        
        $batteries = Get-CimInstance @wmiParams
        
        if ($batteries -and $batteries.Count -gt 0) {
            $battery = $batteries[0]
            $result.BatteryPresent = $true
            $result.ChargeLevel = $battery.EstimatedChargeRemaining
            $result.BatteryStatus = switch ($battery.BatteryStatus) {
                1 { "Other" }
                2 { "Unknown" }
                3 { "Fully Charged" }
                4 { "Low" }
                5 { "Critical" }
                6 { "Charging" }
                7 { "Charging and High" }
                8 { "Charging and Low" }
                9 { "Charging and Critical" }
                10 { "Undefined" }
                11 { "Partially Charged" }
                default { "Unknown" }
            }
            
            if ($battery.EstimatedRunTime -and $battery.EstimatedRunTime -ne 71582788) {
                $result.EstimatedRuntime = "$($battery.EstimatedRunTime) minutes"
            }
            
            $result.Status = "Success"
        } else {
            $result.Status = "No Battery"
            $result.BatteryStatus = "Desktop/No Battery"
        }
    }
    catch {
        $result.Status = "Error"
        $result.Error = $_.Exception.Message
    }
    
    return $result
}

# Main execution
Write-Host "Battery Status Query Tool" -ForegroundColor Cyan
Write-Host "========================" -ForegroundColor Cyan
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

Write-Host "Querying $($computers.Count) computer(s)..." -ForegroundColor Yellow

$results = @()
foreach ($computer in $computers) {
    $result = Get-BatteryStatus -Computer $computer -Cred $Credential
    $results += $result
    if ($result.BatteryPresent) {
        Write-Host "$computer - $($result.ChargeLevel)% ($($result.BatteryStatus))" -ForegroundColor Green
    } else {
        Write-Host "$computer - No Battery" -ForegroundColor Gray
    }
}

$results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
$results | Format-Table -AutoSize

