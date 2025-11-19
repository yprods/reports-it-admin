<#
.SYNOPSIS
    Gets time from all computers and time zone information.

.DESCRIPTION
    This script queries time and time zone from remote computers.

.PARAMETER ComputerList
    Path to text file with computer names.

.PARAMETER ComputerName
    Single or array of computer names.

.PARAMETER OutputFile
    Path to CSV file. Default: ComputerTimeReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication.

.EXAMPLE
    .\Get-ComputerTime.ps1 -ComputerList "computers.txt"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ComputerName,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "ComputerTimeReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential
)

function Get-ComputerTime {
    param([string]$Computer, [System.Management.Automation.PSCredential]$Cred)
    
    $scriptBlock = {
        $time = Get-Date
        $tz = [System.TimeZoneInfo]::Local
        
        return @{
            LocalTime = $time.ToString("yyyy-MM-dd HH:mm:ss")
            UTC = $time.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
            TimeZone = $tz.DisplayName
            TimeZoneOffset = $tz.BaseUtcOffset.TotalHours
        }
    }
    
    $result = [PSCustomObject]@{
        ComputerName = $Computer
        LocalTime = "N/A"
        UTC = "N/A"
        TimeZone = "N/A"
        TimeZoneOffset = $null
        Status = "Unknown"
        Error = $null
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
        
        $timeData = Invoke-Command @invokeParams
        
        $result.LocalTime = $timeData.LocalTime
        $result.UTC = $timeData.UTC
        $result.TimeZone = $timeData.TimeZone
        $result.TimeZoneOffset = $timeData.TimeZoneOffset
        $result.Status = "Success"
    }
    catch {
        $result.Status = "Error"
        $result.Error = $_.Exception.Message
    }
    
    return $result
}

# Main execution
Write-Host "Computer Time Query Tool" -ForegroundColor Cyan
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

Write-Host "Querying $($computers.Count) computer(s)..." -ForegroundColor Yellow

$results = @()
foreach ($computer in $computers) {
    $result = Get-ComputerTime -Computer $computer -Cred $Credential
    $results += $result
    Write-Host "$computer - $($result.LocalTime) ($($result.TimeZone))" -ForegroundColor Gray
}

$results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
$results | Format-Table -AutoSize

