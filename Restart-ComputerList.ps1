<#
.SYNOPSIS
    Restarts a list of computers remotely.

.DESCRIPTION
    This script restarts multiple computers remotely with optional delay and force options.

.PARAMETER ComputerList
    Path to text file with computer names.

.PARAMETER ComputerName
    Single or array of computer names.

.PARAMETER OutputFile
    Path to CSV file. Default: RestartReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication.

.PARAMETER Force
    Force restart even if users are logged on.

.PARAMETER Delay
    Delay in seconds before restart (default: 0).

.PARAMETER Message
    Message to display before restart.

.EXAMPLE
    .\Restart-ComputerList.ps1 -ComputerList "computers.txt" -Force
    
.EXAMPLE
    .\Restart-ComputerList.ps1 -ComputerName "PC01","PC02" -Delay 60 -Message "System maintenance"
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ComputerName,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "RestartReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force,
    
    [Parameter(Mandatory=$false)]
    [int]$Delay = 0,
    
    [Parameter(Mandatory=$false)]
    [string]$Message = "System restart"
)

function Restart-ComputerRemote {
    param([string]$Computer, [bool]$ForceRestart, [int]$DelaySeconds, [string]$RestartMessage, [System.Management.Automation.PSCredential]$Cred)
    
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
        
        $restartParams = @{
            ComputerName = $Computer
            Force = $ForceRestart
            ErrorAction = "Stop"
        }
        
        if ($Cred) {
            $restartParams['Credential'] = $Cred
        }
        
        if ($DelaySeconds -gt 0) {
            $restartParams['Delay'] = $DelaySeconds
        }
        
        Restart-Computer @restartParams
        $result.Status = "Restart Initiated"
    }
    catch {
        $result.Status = "Error"
        $result.Error = $_.Exception.Message
    }
    
    return $result
}

# Main execution
Write-Host "Computer Restart Tool" -ForegroundColor Cyan
Write-Host "====================" -ForegroundColor Cyan
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

Write-Host "Computers to restart: $($computers.Count)" -ForegroundColor Yellow
if ($Force) {
    Write-Host "Force restart: ENABLED" -ForegroundColor Red
}
if ($Delay -gt 0) {
    Write-Host "Delay: $Delay seconds" -ForegroundColor Yellow
}
Write-Host ""

if (-not $PSCmdlet.ShouldProcess("Restart $($computers.Count) computer(s)", "This will restart the computers. Continue?")) {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
    exit 0
}

$results = @()
foreach ($computer in $computers) {
    Write-Host "Restarting $computer..." -NoNewline
    $result = Restart-ComputerRemote -Computer $computer -ForceRestart $Force.IsPresent -DelaySeconds $Delay -RestartMessage $Message -Cred $Credential
    $results += $result
    Write-Host " $($result.Status)" -ForegroundColor $(if ($result.Status -eq "Restart Initiated") { "Green" } else { "Red" })
}

$results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
$results | Format-Table -AutoSize

