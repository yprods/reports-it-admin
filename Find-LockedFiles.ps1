<#
.SYNOPSIS
    Finds locked files on servers.

.DESCRIPTION
    This script identifies files that are currently locked/in use on servers
    by checking open file handles.

.PARAMETER ComputerList
    Path to text file with computer names.

.PARAMETER ComputerName
    Single or array of computer names.

.PARAMETER Path
    Specific path to check (default: all drives).

.PARAMETER OutputFile
    Path to CSV file. Default: LockedFilesReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication.

.EXAMPLE
    .\Find-LockedFiles.ps1 -ComputerList "servers.txt" -Path "C:\Data"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ComputerName,
    
    [Parameter(Mandatory=$false)]
    [string]$Path = "*",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "LockedFilesReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential
)

function Find-LockedFiles {
    param([string]$Computer, [string]$SearchPath, [System.Management.Automation.PSCredential]$Cred)
    
    $scriptBlock = {
        param([string]$Path)
        
        $lockedFiles = @()
        
        try {
            # Use openfiles command to find locked files
            $openFiles = openfiles /query /fo csv 2>&1 | ConvertFrom-Csv -ErrorAction SilentlyContinue
            
            if ($openFiles) {
                foreach ($file in $openFiles) {
                    if ($file.'Accessed By' -and $file.'File ID') {
                        $lockedFiles += @{
                            FilePath = $file.'Accessed By'
                            Process = $file.'ID'
                            User = $file.'Accessed By'
                        }
                    }
                }
            }
            
            # Alternative: Check via Get-Process and file handles
            $processes = Get-Process | Where-Object { $_.Path }
            foreach ($proc in $processes) {
                try {
                    $handles = $proc | Select-Object -ExpandProperty Modules -ErrorAction SilentlyContinue
                    if ($handles) {
                        foreach ($module in $handles) {
                            if ($module.FileName -like "*$Path*") {
                                $lockedFiles += @{
                                    FilePath = $module.FileName
                                    Process = $proc.ProcessName
                                    PID = $proc.Id
                                    User = $proc.StartInfo.UserName
                                }
                            }
                        }
                    }
                } catch { }
            }
        }
        catch {
            return @(@{
                FilePath = "Error"
                Process = "N/A"
                Error = $_.Exception.Message
            })
        }
        
        return $lockedFiles
    }
    
    $results = @()
    
    try {
        if (-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            return @([PSCustomObject]@{
                ComputerName = $Computer
                FilePath = "N/A"
                Process = "N/A"
                PID = $null
                User = "N/A"
                Status = "Offline"
            })
        }
        
        $invokeParams = @{
            ComputerName = $Computer
            ScriptBlock = $scriptBlock
            ArgumentList = @($SearchPath)
        }
        if ($Cred) { $invokeParams['Credential'] = $Cred }
        
        $files = Invoke-Command @invokeParams
        
        foreach ($file in $files) {
            $results += [PSCustomObject]@{
                ComputerName = $Computer
                FilePath = $file.FilePath
                Process = $file.Process
                PID = if ($file.PID) { $file.PID } else { "N/A" }
                User = $file.User
                Status = "Locked"
            }
        }
    }
    catch {
        $results += [PSCustomObject]@{
            ComputerName = $Computer
            FilePath = "N/A"
            Process = "N/A"
            PID = $null
            User = "N/A"
            Status = "Error"
            Error = $_.Exception.Message
        }
    }
    
    return $results
}

# Main execution
Write-Host "Locked Files Finder" -ForegroundColor Cyan
Write-Host "===================" -ForegroundColor Cyan
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

Write-Host "Search Path: $Path" -ForegroundColor Yellow
Write-Host "Querying $($computers.Count) computer(s)..." -ForegroundColor Yellow

$allResults = @()
foreach ($computer in $computers) {
    $results = Find-LockedFiles -Computer $computer -SearchPath $Path -Cred $Credential
    $allResults += $results
    $lockedCount = ($results | Where-Object { $_.Status -eq "Locked" }).Count
    Write-Host "$computer - Found $lockedCount locked file(s)" -ForegroundColor Gray
}

$allResults | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "Results exported to: $OutputFile" -ForegroundColor Green

$locked = $allResults | Where-Object { $_.Status -eq "Locked" }
if ($locked) {
    Write-Host ""
    Write-Host "Locked Files:" -ForegroundColor Cyan
    $locked | Format-Table -AutoSize ComputerName, FilePath, Process, User
} else {
    Write-Host "No locked files found." -ForegroundColor Green
}

