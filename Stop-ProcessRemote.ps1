<#
.SYNOPSIS
    Kills processes on remote computers.

.DESCRIPTION
    This script terminates processes on multiple remote computers.

.PARAMETER ComputerList
    Path to text file with computer names.

.PARAMETER ComputerName
    Single or array of computer names.

.PARAMETER ProcessName
    Process name to kill (e.g., "notepad", "chrome").

.PARAMETER ProcessID
    Process ID to kill (optional, overrides ProcessName).

.PARAMETER OutputFile
    Path to CSV file. Default: ProcessKillReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication.

.PARAMETER Force
    Force kill the process (default: true).

.PARAMETER WhatIf
    Show what would be killed without actually killing.

.EXAMPLE
    .\Stop-ProcessRemote.ps1 -ComputerList "computers.txt" -ProcessName "notepad"
    
.EXAMPLE
    .\Stop-ProcessRemote.ps1 -ComputerName "PC01","PC02" -ProcessID 1234 -Force
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ComputerName,
    
    [Parameter(Mandatory=$false)]
    [string]$ProcessName,
    
    [Parameter(Mandatory=$false)]
    [int]$ProcessID,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "ProcessKillReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

function Stop-ProcessRemote {
    param([string]$Computer, [string]$Name, [int]$PID, [bool]$ForceKill, [System.Management.Automation.PSCredential]$Cred, [bool]$WhatIfMode)
    
    $scriptBlock = {
        param([string]$ProcName, [int]$ProcID, [bool]$Force, [bool]$WhatIf)
        
        $results = @()
        
        try {
            $processes = @()
            
            if ($ProcID -gt 0) {
                $processes = Get-Process -Id $ProcID -ErrorAction SilentlyContinue
            }
            elseif ($ProcName) {
                $processes = Get-Process -Name $ProcName -ErrorAction SilentlyContinue
            }
            
            if ($processes.Count -eq 0) {
                return @(@{
                    ProcessName = if ($ProcName) { $ProcName } else { "N/A" }
                    ProcessID = $ProcID
                    Status = "Not Found"
                    Error = "Process not found"
                })
            }
            
            foreach ($proc in $processes) {
                if (-not $WhatIf) {
                    if ($Force) {
                        Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                    } else {
                        Stop-Process -Id $proc.Id -ErrorAction Stop
                    }
                    $results += @{
                        ProcessName = $proc.ProcessName
                        ProcessID = $proc.Id
                        Status = "Killed"
                    }
                } else {
                    $results += @{
                        ProcessName = $proc.ProcessName
                        ProcessID = $proc.Id
                        Status = "WhatIf - Would Kill"
                    }
                }
            }
        }
        catch {
            $results += @{
                ProcessName = if ($ProcName) { $ProcName } else { "N/A" }
                ProcessID = $ProcID
                Status = "Error"
                Error = $_.Exception.Message
            }
        }
        
        return $results
    }
    
    $allResults = @()
    
    try {
        if (-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            return @([PSCustomObject]@{
                ComputerName = $Computer
                ProcessName = if ($Name) { $Name } else { "N/A" }
                ProcessID = $PID
                Status = "Offline"
                Error = "Computer is not reachable"
            })
        }
        
        $invokeParams = @{
            ComputerName = $Computer
            ScriptBlock = $scriptBlock
            ArgumentList = @($Name, $PID, $ForceKill, $WhatIfMode)
        }
        if ($Cred) { $invokeParams['Credential'] = $Cred }
        
        $killResults = Invoke-Command @invokeParams
        
        foreach ($kill in $killResults) {
            $allResults += [PSCustomObject]@{
                ComputerName = $Computer
                ProcessName = $kill.ProcessName
                ProcessID = $kill.ProcessID
                Status = $kill.Status
                Error = if ($kill.Error) { $kill.Error } else { $null }
            }
        }
    }
    catch {
        $allResults += [PSCustomObject]@{
            ComputerName = $Computer
            ProcessName = if ($Name) { $Name } else { "N/A" }
            ProcessID = $PID
            Status = "Error"
            Error = $_.Exception.Message
        }
    }
    
    return $allResults
}

# Main execution
Write-Host "Remote Process Kill Tool" -ForegroundColor Cyan
Write-Host "=======================" -ForegroundColor Cyan
Write-Host ""

if (-not $ProcessName -and $ProcessID -eq 0) {
    Write-Error "Either ProcessName or ProcessID must be specified."
    exit 1
}

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

Write-Host "Target: " -NoNewline
if ($ProcessID -gt 0) {
    Write-Host "Process ID $ProcessID" -ForegroundColor Yellow
} else {
    Write-Host "Process Name: $ProcessName" -ForegroundColor Yellow
}
Write-Host "Force Kill: $Force" -ForegroundColor Yellow
Write-Host "Processing $($computers.Count) computer(s)..." -ForegroundColor Yellow
if ($WhatIf) {
    Write-Host "MODE: WHATIF (no processes will be killed)" -ForegroundColor Yellow
}
Write-Host ""

if (-not $WhatIf -and -not $PSCmdlet.ShouldProcess("Kill process on $($computers.Count) computer(s)", "This will terminate processes. Continue?")) {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
    exit 0
}

$allResults = @()
foreach ($computer in $computers) {
    Write-Host "Processing $computer..." -NoNewline
    $results = Stop-ProcessRemote -Computer $computer -Name $ProcessName -PID $ProcessID -ForceKill $Force.IsPresent -Cred $Credential -WhatIfMode $WhatIf.IsPresent
    $allResults += $results
    
    $killedCount = ($results | Where-Object { $_.Status -like "*Kill*" }).Count
    Write-Host " $killedCount process(es)" -ForegroundColor $(if ($killedCount -gt 0) { "Green" } else { "Gray" })
}

$allResults | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host ""
Write-Host "Results exported to: $OutputFile" -ForegroundColor Green

$totalKilled = ($allResults | Where-Object { $_.Status -like "*Kill*" -and $_.Status -notlike "WhatIf*" }).Count
Write-Host "Total processes killed: $totalKilled" -ForegroundColor Green

$allResults | Format-Table -AutoSize

