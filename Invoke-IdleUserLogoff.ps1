<#
.SYNOPSIS
    Logs off users that have been idle for a specified time.

.DESCRIPTION
    This script finds users who have been idle for a specified duration
    and logs them off from remote computers.

.PARAMETER ComputerList
    Path to text file with computer names.

.PARAMETER ComputerName
    Single or array of computer names.

.PARAMETER IdleTime
    Idle time threshold in hours (default: 2).

.PARAMETER OutputFile
    Path to CSV file. Default: IdleUserLogoffReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication.

.PARAMETER WhatIf
    Show what would be done without actually logging off.

.EXAMPLE
    .\Invoke-IdleUserLogoff.ps1 -ComputerList "computers.txt" -IdleTime 2
    
.EXAMPLE
    .\Invoke-IdleUserLogoff.ps1 -ComputerName "PC01","PC02" -IdleTime 1 -WhatIf
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ComputerName,
    
    [Parameter(Mandatory=$false)]
    [int]$IdleTime = 2,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "IdleUserLogoffReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

function Invoke-IdleUserLogoff {
    param([string]$Computer, [int]$IdleHours, [System.Management.Automation.PSCredential]$Cred, [bool]$WhatIfMode)
    
    $scriptBlock = {
        param([int]$IdleHours, [bool]$WhatIf)
        
        $results = @()
        $idleThreshold = (Get-Date).AddHours(-$IdleHours)
        
        try {
            $queryResult = query user 2>&1
            if ($LASTEXITCODE -eq 0) {
                $lines = $queryResult | Where-Object { $_ -match '^\s+\S+\s+\S+\s+\d+\s+' }
                foreach ($line in $lines) {
                    if ($line -match '^\s+(\S+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\S+.*)') {
                        $username = $matches[2]
                        $sessionId = $matches[3]
                        $idleTimeStr = $matches[5]
                        
                        # Parse idle time
                        $isIdle = $false
                        if ($idleTimeStr -match '(\d+):(\d+)') {
                            $hours = [int]$matches[1]
                            $minutes = [int]$matches[2]
                            $totalMinutes = ($hours * 60) + $minutes
                            if ($totalMinutes -ge ($IdleHours * 60)) {
                                $isIdle = $true
                            }
                        }
                        elseif ($idleTimeStr -eq "none" -or $idleTimeStr -eq "0") {
                            $isIdle = $false
                        }
                        else {
                            # Assume idle if format is unclear
                            $isIdle = $true
                        }
                        
                        if ($isIdle) {
                            if (-not $WhatIf) {
                                logoff $sessionId
                                $results += @{
                                    Username = $username
                                    SessionID = $sessionId
                                    IdleTime = $idleTimeStr
                                    Action = "Logged Off"
                                }
                            } else {
                                $results += @{
                                    Username = $username
                                    SessionID = $sessionId
                                    IdleTime = $idleTimeStr
                                    Action = "Would Log Off"
                                }
                            }
                        }
                    }
                }
            }
        }
        catch {
            $results += @{
                Username = "Error"
                SessionID = "N/A"
                IdleTime = "N/A"
                Action = "Error: $($_.Exception.Message)"
            }
        }
        
        return $results
    }
    
    $allResults = @()
    
    try {
        if (-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            return @([PSCustomObject]@{
                ComputerName = $Computer
                Username = "N/A"
                SessionID = "N/A"
                IdleTime = "N/A"
                Action = "Offline"
            })
        }
        
        $invokeParams = @{
            ComputerName = $Computer
            ScriptBlock = $scriptBlock
            ArgumentList = @($IdleHours, $WhatIfMode)
        }
        if ($Cred) { $invokeParams['Credential'] = $Cred }
        
        $logoffResults = Invoke-Command @invokeParams
        
        foreach ($logoff in $logoffResults) {
            $allResults += [PSCustomObject]@{
                ComputerName = $Computer
                Username = $logoff.Username
                SessionID = $logoff.SessionID
                IdleTime = $logoff.IdleTime
                Action = $logoff.Action
            }
        }
    }
    catch {
        $allResults += [PSCustomObject]@{
            ComputerName = $Computer
            Username = "N/A"
            SessionID = "N/A"
            IdleTime = "N/A"
            Action = "Error"
            Error = $_.Exception.Message
        }
    }
    
    return $allResults
}

# Main execution
Write-Host "Idle User Logoff Tool" -ForegroundColor Cyan
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

Write-Host "Idle Time Threshold: $IdleTime hour(s)" -ForegroundColor Yellow
Write-Host "Processing $($computers.Count) computer(s)..." -ForegroundColor Yellow
if ($WhatIf) {
    Write-Host "MODE: WHATIF (no users will be logged off)" -ForegroundColor Yellow
}
Write-Host ""

if (-not $WhatIf -and -not $PSCmdlet.ShouldProcess("Log off idle users from $($computers.Count) computer(s)", "This will log off users idle for $IdleTime hours. Continue?")) {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
    exit 0
}

$allResults = @()
foreach ($computer in $computers) {
    Write-Host "Processing $computer..." -NoNewline
    $results = Invoke-IdleUserLogoff -Computer $computer -IdleHours $IdleTime -Cred $Credential -WhatIfMode $WhatIf.IsPresent
    $allResults += $results
    
    $logoffCount = ($results | Where-Object { $_.Action -like "*Log*" }).Count
    Write-Host " $logoffCount user(s)" -ForegroundColor $(if ($logoffCount -gt 0) { "Green" } else { "Gray" })
}

$allResults | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "Results exported to: $OutputFile" -ForegroundColor Green

$totalLogoffs = ($allResults | Where-Object { $_.Action -like "*Log*" }).Count
Write-Host ""
Write-Host "Total users logged off: $totalLogoffs" -ForegroundColor Green

$allResults | Where-Object { $_.Action -like "*Log*" } | Format-Table -AutoSize

