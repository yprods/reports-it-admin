<#
.SYNOPSIS
    Clears the print spooler queue on local or remote computers.

.DESCRIPTION
    This script clears all print jobs from the spooler queue and optionally
    restarts the spooler service.

.PARAMETER ComputerList
    Path to text file with computer names (one per line) or array of computer names.
    Use "." or "localhost" for local computer.

.PARAMETER RestartSpooler
    Restart the spooler service after clearing (default: true).

.PARAMETER Credential
    PSCredential object for remote authentication.

.PARAMETER OutputFile
    Path to CSV file. Default: ClearSpoolerReport.csv

.PARAMETER WhatIf
    Show what would be cleared without actually clearing.

.EXAMPLE
    .\Clear-PrintSpooler.ps1 -ComputerList "computers.txt"
    
.EXAMPLE
    .\Clear-PrintSpooler.ps1 -ComputerList @("PC01", "PC02") -RestartSpooler
    
.EXAMPLE
    .\Clear-PrintSpooler.ps1 -ComputerList "." -RestartSpooler:$false
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$true)]
    [object]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [switch]$RestartSpooler = $true,
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "ClearSpoolerReport.csv",
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

# Function to clear spooler
function Clear-SpoolerQueue {
    param(
        [string]$Computer,
        [bool]$Restart,
        [System.Management.Automation.PSCredential]$Cred
    )
    
    try {
        $scriptBlock = {
            param($RestartService)
            
            $result = @{
                Success = $false
                JobsCleared = 0
                Error = $null
            }
            
            try {
                # Get print jobs count
                $jobs = Get-WmiObject -Class Win32_PrintJob -ErrorAction SilentlyContinue
                $jobCount = $jobs.Count
                
                # Stop spooler service
                $spooler = Get-Service -Name Spooler -ErrorAction Stop
                if ($spooler.Status -eq "Running") {
                    Stop-Service -Name Spooler -Force -ErrorAction Stop
                    Start-Sleep -Seconds 2
                }
                
                # Clear spooler directory
                $spoolPath = "$env:SystemRoot\System32\spool\PRINTERS"
                if (Test-Path $spoolPath) {
                    $files = Get-ChildItem -Path $spoolPath -File -ErrorAction SilentlyContinue
                    $fileCount = $files.Count
                    
                    foreach ($file in $files) {
                        try {
                            Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                        }
                        catch {
                            # Some files may be locked, continue
                        }
                    }
                    
                    $result.JobsCleared = $fileCount
                }
                
                # Restart spooler if requested
                if ($RestartService) {
                    Start-Service -Name Spooler -ErrorAction Stop
                    Start-Sleep -Seconds 2
                    
                    # Verify service started
                    $spooler = Get-Service -Name Spooler
                    if ($spooler.Status -ne "Running") {
                        $result.Error = "Spooler service did not start properly"
                        return $result
                    }
                }
                
                $result.Success = $true
            }
            catch {
                $result.Error = $_.Exception.Message
                
                # Try to start spooler if it was stopped
                if ($RestartService) {
                    try {
                        Start-Service -Name Spooler -ErrorAction SilentlyContinue
                    }
                    catch { }
                }
            }
            
            return $result
        }
        
        if ($Computer -eq "." -or $Computer -eq "localhost" -or $Computer -eq $env:COMPUTERNAME) {
            return & $scriptBlock -RestartService $Restart
        }
        else {
            if ($Cred) {
                return Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -ArgumentList $Restart -Credential $Cred -ErrorAction Stop
            }
            else {
                return Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -ArgumentList $Restart -ErrorAction Stop
            }
        }
    }
    catch {
        return @{ Success = $false; JobsCleared = 0; Error = $_.Exception.Message }
    }
}

# Main execution
Write-Host "Clear Print Spooler Tool" -ForegroundColor Cyan
Write-Host "========================" -ForegroundColor Cyan
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
Write-Host "Restart Spooler: $RestartSpooler" -ForegroundColor Yellow
if ($WhatIf) {
    Write-Host "MODE: WHATIF (no spooler will be cleared)" -ForegroundColor Yellow
}
Write-Host ""

if (-not $WhatIf -and -not $PSCmdlet.ShouldProcess("Clear spooler on $($computers.Count) computer(s)", "This will clear print spooler queues. Continue?")) {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
    exit 0
}

$results = @()

foreach ($computer in $computers) {
    Write-Host "Clearing spooler on: $computer" -NoNewline
    
    $result = [PSCustomObject]@{
        Computer = $computer
        JobsCleared = 0
        Status = "Unknown"
        Error = $null
        SpoolerRestarted = $RestartSpooler
        LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    if (-not $WhatIf) {
        $clearResult = Clear-SpoolerQueue -Computer $computer -Restart $RestartSpooler.IsPresent -Cred $Credential
        
        $result.JobsCleared = $clearResult.JobsCleared
        
        if ($clearResult.Success) {
            $result.Status = "Cleared"
            Write-Host " - Success ($($clearResult.JobsCleared) jobs cleared)" -ForegroundColor Green
        }
        else {
            $result.Status = "Failed"
            $result.Error = $clearResult.Error
            Write-Host " - Failed: $($clearResult.Error)" -ForegroundColor Red
        }
    }
    else {
        $result.Status = "WhatIf - Would Clear"
        Write-Host " - WhatIf" -ForegroundColor Gray
    }
    
    $results += $result
}

Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
$cleared = ($results | Where-Object { $_.Status -like "*Cleared*" -or $_.Status -like "WhatIf*" }).Count
$totalJobs = ($results | Measure-Object -Property JobsCleared -Sum).Sum
Write-Host "Cleared: $cleared" -ForegroundColor Green
Write-Host "Total Jobs Cleared: $totalJobs" -ForegroundColor Green
Write-Host "Failed: $(($results | Where-Object { $_.Status -eq 'Failed' }).Count)" -ForegroundColor Red

$results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
$results | Format-Table -AutoSize

