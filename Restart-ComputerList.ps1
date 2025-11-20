<#
.SYNOPSIS
    Restarts a list of computers remotely.

.DESCRIPTION
    This script restarts computers from a list using various methods.
    Supports graceful shutdown, force restart, and scheduled restart.

.PARAMETER ComputerList
    Path to text file with computer names (one per line) or array of computer names.

.PARAMETER Force
    Force restart without waiting for applications to close (default: false).

.PARAMETER Delay
    Delay in seconds before restart (default: 30).

.PARAMETER Message
    Message to display to users before restart.

.PARAMETER Credential
    PSCredential object for remote authentication.

.PARAMETER OutputFile
    Path to CSV file. Default: RestartComputerReport.csv

.PARAMETER WhatIf
    Show what would be restarted without actually restarting.

.EXAMPLE
    .\Restart-ComputerList.ps1 -ComputerList "computers.txt"
    
.EXAMPLE
    .\Restart-ComputerList.ps1 -ComputerList @("PC01", "PC02") -Force -Delay 60 -Message "System maintenance in progress"
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$true)]
    [object]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force,
    
    [Parameter(Mandatory=$false)]
    [int]$Delay = 30,
    
    [Parameter(Mandatory=$false)]
    [string]$Message = "The computer will restart in $Delay seconds for maintenance.",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "RestartComputerReport.csv",
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

# Function to restart computer
function Restart-ComputerRemote {
    param(
        [string]$Computer,
        [bool]$ForceRestart,
        [int]$RestartDelay,
        [string]$RestartMessage,
        [System.Management.Automation.PSCredential]$Cred
    )
    
    try {
        $scriptBlock = {
            param($Force, $Delay, $Message)
            
            # Show message to users
            if ($Message) {
                msg * $Message
            }
            
            Start-Sleep -Seconds $Delay
            
            if ($Force) {
                Restart-Computer -Force
            }
            else {
                Restart-Computer
            }
        }
        
        if ($Computer -eq "." -or $Computer -eq "localhost" -or $Computer -eq $env:COMPUTERNAME) {
            if (-not $WhatIf) {
                & $scriptBlock -Force $ForceRestart -Delay $RestartDelay -Message $RestartMessage
            }
            return @{ Success = $true; Error = $null }
        }
        else {
            if ($Cred) {
                Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -ArgumentList $ForceRestart, $RestartDelay, $RestartMessage -Credential $Cred -ErrorAction Stop
            }
            else {
                Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -ArgumentList $ForceRestart, $RestartDelay, $RestartMessage -ErrorAction Stop
            }
            return @{ Success = $true; Error = $null }
        }
    }
    catch {
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

# Main execution
Write-Host "Restart Computer List Tool" -ForegroundColor Cyan
Write-Host "=========================" -ForegroundColor Cyan
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

Write-Host "Computers: $($computers.Count)" -ForegroundColor Yellow
Write-Host "Force: $Force" -ForegroundColor Yellow
Write-Host "Delay: $Delay seconds" -ForegroundColor Yellow
Write-Host "Message: $Message" -ForegroundColor Yellow
if ($WhatIf) {
    Write-Host "MODE: WHATIF (no computers will be restarted)" -ForegroundColor Yellow
}
Write-Host ""

if (-not $WhatIf -and -not $PSCmdlet.ShouldProcess("Restart $($computers.Count) computer(s)", "This will restart computers. Continue?")) {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
    exit 0
}

$results = @()

foreach ($computer in $computers) {
    Write-Host "Restarting: $computer" -NoNewline
    
    $result = [PSCustomObject]@{
        Computer = $computer
        Force = $Force
        Delay = $Delay
        Status = "Unknown"
        Error = $null
        LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    if (-not $WhatIf) {
        $restartResult = Restart-ComputerRemote -Computer $computer -ForceRestart $Force.IsPresent -RestartDelay $Delay -RestartMessage $Message -Cred $Credential
        
        if ($restartResult.Success) {
            $result.Status = "Restarted"
            Write-Host " - Success" -ForegroundColor Green
        }
        else {
            $result.Status = "Failed"
            $result.Error = $restartResult.Error
            Write-Host " - Failed: $($restartResult.Error)" -ForegroundColor Red
        }
    }
    else {
        $result.Status = "WhatIf - Would Restart"
        Write-Host " - WhatIf" -ForegroundColor Gray
    }
    
    $results += $result
}

Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
$restarted = ($results | Where-Object { $_.Status -like "*Restarted*" -or $_.Status -like "WhatIf*" }).Count
Write-Host "Restarted: $restarted" -ForegroundColor Green
Write-Host "Failed: $(($results | Where-Object { $_.Status -eq 'Failed' }).Count)" -ForegroundColor Red

$results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
$results | Format-Table -AutoSize
