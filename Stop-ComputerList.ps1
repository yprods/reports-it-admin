<#
.SYNOPSIS
    Shuts down a list of computers remotely.

.DESCRIPTION
    This script shuts down multiple computers remotely with optional delay and force options.

.PARAMETER ComputerList
    Path to text file with computer names.

.PARAMETER ComputerName
    Single or array of computer names.

.PARAMETER OutputFile
    Path to CSV file. Default: ShutdownReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication.

.PARAMETER Force
    Force shutdown even if users are logged on.

.PARAMETER Delay
    Delay in seconds before shutdown (default: 0).

.PARAMETER Message
    Message to display before shutdown.

.EXAMPLE
    .\Stop-ComputerList.ps1 -ComputerList "computers.txt" -Force
    
.EXAMPLE
    .\Stop-ComputerList.ps1 -ComputerName "PC01","PC02" -Delay 60 -Message "System maintenance"
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ComputerName,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "ShutdownReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force,
    
    [Parameter(Mandatory=$false)]
    [int]$Delay = 0,
    
    [Parameter(Mandatory=$false)]
    [string]$Message = "System shutdown"
)

function Stop-ComputerRemote {
    param([string]$Computer, [bool]$ForceShutdown, [int]$DelaySeconds, [string]$ShutdownMessage, [System.Management.Automation.PSCredential]$Cred)
    
    $result = [PSCustomObject]@{
        ComputerName = $Computer
        Status = "Unknown"
        Error = $null
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    try {
        if (-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            $result.Status = "Offline"
            return $result
        }
        
        $stopParams = @{
            ComputerName = $Computer
            Force = $ForceShutdown
            ErrorAction = "Stop"
        }
        
        if ($Cred) {
            $stopParams['Credential'] = $Cred
        }
        
        if ($DelaySeconds -gt 0) {
            $stopParams['Delay'] = $DelaySeconds
        }
        
        Stop-Computer @stopParams
        $result.Status = "Shutdown Initiated"
    }
    catch {
        $result.Status = "Error"
        $result.Error = $_.Exception.Message
    }
    
    return $result
}

# Main execution
Write-Host "Computer Shutdown Tool" -ForegroundColor Cyan
Write-Host "=====================" -ForegroundColor Cyan
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

Write-Host "Computers to shutdown: $($computers.Count)" -ForegroundColor Yellow
if ($Force) {
    Write-Host "Force shutdown: ENABLED" -ForegroundColor Red
}
if ($Delay -gt 0) {
    Write-Host "Delay: $Delay seconds" -ForegroundColor Yellow
}
Write-Host ""

if (-not $PSCmdlet.ShouldProcess("Shutdown $($computers.Count) computer(s)", "This will shutdown the computers. Continue?")) {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
    exit 0
}

$results = @()
foreach ($computer in $computers) {
    Write-Host "Shutting down $computer..." -NoNewline
    $result = Stop-ComputerRemote -Computer $computer -ForceShutdown $Force.IsPresent -DelaySeconds $Delay -ShutdownMessage $Message -Cred $Credential
    $results += $result
    Write-Host " $($result.Status)" -ForegroundColor $(if ($result.Status -eq "Shutdown Initiated") { "Green" } else { "Red" })
}

$results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
$results | Format-Table -AutoSize

