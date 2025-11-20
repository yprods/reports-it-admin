<#
.SYNOPSIS
    Kills processes on remote computers using taskkill.

.DESCRIPTION
    This script terminates processes on remote computers using taskkill command.
    Supports killing by process name, ID, or user.

.PARAMETER ComputerList
    Path to text file with computer names (one per line) or array of computer names.

.PARAMETER ProcessName
    Name of process to kill (e.g., "notepad", "chrome").

.PARAMETER ProcessID
    Process ID to kill.

.PARAMETER ProcessList
    Path to text file with process names (one per line).

.PARAMETER UserName
    Kill all processes for a specific user.

.PARAMETER Force
    Force kill processes (default: true).

.PARAMETER Tree
    Kill process tree (parent and all children).

.PARAMETER Credential
    PSCredential object for remote authentication.

.PARAMETER OutputFile
    Path to CSV file. Default: TaskKillReport.csv

.PARAMETER WhatIf
    Show what would be killed without actually killing.

.EXAMPLE
    .\Stop-ProcessRemote.ps1 -ComputerList "computers.txt" -ProcessName "notepad"
    
.EXAMPLE
    .\Stop-ProcessRemote.ps1 -ComputerList @("PC01", "PC02") -ProcessName "chrome" -Force -Tree
    
.EXAMPLE
    .\Stop-ProcessRemote.ps1 -ComputerList "computers.txt" -ProcessList "processes.txt" -User "john.doe"
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$true)]
    [object]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [string]$ProcessName,
    
    [Parameter(Mandatory=$false)]
    [int]$ProcessID,
    
    [Parameter(Mandatory=$false)]
    [string]$ProcessList,
    
    [Parameter(Mandatory=$false)]
    [string]$UserName,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$Tree,
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "TaskKillReport.csv",
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

# Function to kill process on remote computer
function Invoke-TaskKillRemote {
    param(
        [string]$Computer,
        [string]$ProcName,
        [int]$ProcID,
        [string]$User,
        [bool]$ForceKill,
        [bool]$KillTree,
        [System.Management.Automation.PSCredential]$Cred
    )
    
    try {
        $scriptBlock = {
            param($ProcessName, $ProcessID, $UserName, $Force, $Tree)
            
            $results = @()
            
            # Build taskkill command
            $taskkillArgs = @()
            
            if ($ProcessID -gt 0) {
                $taskkillArgs += "/PID"
                $taskkillArgs += $ProcessID
            }
            elseif ($ProcessName) {
                $taskkillArgs += "/IM"
                $taskkillArgs += $ProcessName
            }
            elseif ($UserName) {
                $taskkillArgs += "/FI"
                $taskkillArgs += "USERNAME eq $UserName"
            }
            else {
                return @{ Success = $false; Error = "No process specified" }
            }
            
            if ($Force) {
                $taskkillArgs += "/F"
            }
            
            if ($Tree) {
                $taskkillArgs += "/T"
            }
            
            # Execute taskkill
            $process = Start-Process -FilePath "taskkill.exe" -ArgumentList $taskkillArgs -Wait -PassThru -NoNewWindow -RedirectStandardOutput "taskkill_output.txt" -RedirectStandardError "taskkill_error.txt"
            
            $output = if (Test-Path "taskkill_output.txt") { Get-Content "taskkill_output.txt" -Raw } else { "" }
            $error = if (Test-Path "taskkill_error.txt") { Get-Content "taskkill_error.txt" -Raw } else { "" }
            
            # Cleanup
            if (Test-Path "taskkill_output.txt") { Remove-Item "taskkill_output.txt" -Force }
            if (Test-Path "taskkill_error.txt") { Remove-Item "taskkill_error.txt" -Force }
            
            return @{
                Success = ($process.ExitCode -eq 0)
                ExitCode = $process.ExitCode
                Output = $output
                Error = if ($process.ExitCode -ne 0) { $error } else { $null }
            }
        }
        
        if ($Computer -eq "." -or $Computer -eq "localhost" -or $Computer -eq $env:COMPUTERNAME) {
            return & $scriptBlock -ProcessName $ProcName -ProcessID $ProcID -UserName $User -Force $ForceKill -Tree $KillTree
        }
        else {
            if ($Cred) {
                return Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -ArgumentList $ProcName, $ProcID, $User, $ForceKill, $KillTree -Credential $Cred -ErrorAction Stop
            }
            else {
                return Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -ArgumentList $ProcName, $ProcID, $User, $ForceKill, $KillTree -ErrorAction Stop
            }
        }
    }
    catch {
        return @{ Success = $false; ExitCode = -1; Error = $_.Exception.Message; Output = $null }
    }
}

# Main execution
Write-Host "Remote TaskKill Tool" -ForegroundColor Cyan
Write-Host "===================" -ForegroundColor Cyan
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

# Get process list
$processes = @()

if ($ProcessList -and (Test-Path $ProcessList)) {
    $processes = Get-Content $ProcessList | Where-Object { $_.Trim() -ne "" }
}
elseif ($ProcessName) {
    $processes = @($ProcessName)
}
elseif ($ProcessID -gt 0) {
    $processes = @("PID:$ProcessID")
}
elseif ($UserName) {
    $processes = @("USER:$UserName")
}
else {
    Write-Error "Must specify either -ProcessName, -ProcessID, -ProcessList, or -UserName"
    exit 1
}

Write-Host "Computers: $($computers.Count)" -ForegroundColor Yellow
Write-Host "Processes: $($processes.Count)" -ForegroundColor Yellow
Write-Host "Force: $Force" -ForegroundColor Yellow
Write-Host "Tree: $Tree" -ForegroundColor Yellow
if ($WhatIf) {
    Write-Host "MODE: WHATIF (no processes will be killed)" -ForegroundColor Yellow
}
Write-Host ""

if (-not $WhatIf -and -not $PSCmdlet.ShouldProcess("Kill processes on $($computers.Count) computer(s)", "This will kill processes. Continue?")) {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
    exit 0
}

$results = @()

foreach ($computer in $computers) {
    foreach ($process in $processes) {
        $procName = $null
        $procID = 0
        $user = $null
        
        if ($process -like "PID:*") {
            $procID = [int]($process -replace "PID:", "")
        }
        elseif ($process -like "USER:*") {
            $user = $process -replace "USER:", ""
        }
        else {
            $procName = $process
        }
        
        Write-Host "Killing process on $computer : " -NoNewline
        if ($procID -gt 0) {
            Write-Host "PID $procID" -NoNewline
        }
        elseif ($user) {
            Write-Host "User $user" -NoNewline
        }
        else {
            Write-Host "$procName" -NoNewline
        }
        
        $result = [PSCustomObject]@{
            Computer = $computer
            ProcessName = if ($procName) { $procName } else { "N/A" }
            ProcessID = if ($procID -gt 0) { $procID } else { $null }
            UserName = if ($user) { $user } else { $null }
            Status = "Unknown"
            Error = $null
            LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        
        if (-not $WhatIf) {
            $killResult = Invoke-TaskKillRemote -Computer $computer -ProcName $procName -ProcID $procID -User $user -ForceKill $Force.IsPresent -KillTree $Tree.IsPresent -Cred $Credential
            
            if ($killResult.Success) {
                $result.Status = "Killed"
                Write-Host " - Success" -ForegroundColor Green
            }
            else {
                $result.Status = "Failed"
                $result.Error = $killResult.Error
                Write-Host " - Failed: $($killResult.Error)" -ForegroundColor Red
            }
        }
        else {
            $result.Status = "WhatIf - Would Kill"
            Write-Host " - WhatIf" -ForegroundColor Gray
        }
        
        $results += $result
    }
}

Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
$killed = ($results | Where-Object { $_.Status -like "*Killed*" -or $_.Status -like "WhatIf*" }).Count
Write-Host "Killed: $killed" -ForegroundColor Green
Write-Host "Failed: $(($results | Where-Object { $_.Status -eq 'Failed' }).Count)" -ForegroundColor Red

$results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
$results | Format-Table -AutoSize
