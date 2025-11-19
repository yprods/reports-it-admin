<#
.SYNOPSIS
    Clears recycle bin from remote computers.

.DESCRIPTION
    This script empties the recycle bin on remote computers.

.PARAMETER ComputerList
    Path to text file with computer names.

.PARAMETER ComputerName
    Single or array of computer names.

.PARAMETER OutputFile
    Path to CSV file. Default: RecycleBinClearReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication.

.PARAMETER Drive
    Specific drive to clear (default: all drives).

.EXAMPLE
    .\Clear-RecycleBinRemote.ps1 -ComputerList "computers.txt"
    
.EXAMPLE
    .\Clear-RecycleBinRemote.ps1 -ComputerName "PC01","PC02" -Drive "C:"
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ComputerName,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "RecycleBinClearReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [string]$Drive = "*"
)

function Clear-RecycleBinRemote {
    param([string]$Computer, [string]$DriveFilter, [System.Management.Automation.PSCredential]$Cred)
    
    $scriptBlock = {
        param([string]$Drive)
        
        $results = @()
        $totalSize = 0
        
        try {
            # Get all drives
            $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Name -like $Drive }
            
            foreach ($driveObj in $drives) {
                $driveLetter = "$($driveObj.Name):"
                $recyclePath = "$driveLetter`$Recycle.Bin"
                
                if (Test-Path $recyclePath) {
                    $items = Get-ChildItem -Path $recyclePath -Recurse -Force -ErrorAction SilentlyContinue
                    $size = ($items | Measure-Object -Property Length -Sum).Sum
                    $totalSize += $size
                    
                    Remove-Item -Path "$recyclePath\*" -Recurse -Force -ErrorAction SilentlyContinue
                    
                    $results += @{
                        Drive = $driveLetter
                        ItemsCleared = $items.Count
                        SizeClearedMB = [math]::Round($size / 1MB, 2)
                    }
                }
            }
            
            return @{
                Success = $true
                TotalSizeMB = [math]::Round($totalSize / 1MB, 2)
                Drives = $results
            }
        }
        catch {
            return @{
                Success = $false
                Error = $_.Exception.Message
            }
        }
    }
    
    $result = [PSCustomObject]@{
        ComputerName = $Computer
        Status = "Unknown"
        TotalSizeMB = $null
        DrivesCleared = "N/A"
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
            ArgumentList = @($DriveFilter)
        }
        if ($Cred) { $invokeParams['Credential'] = $Cred }
        
        $clearResult = Invoke-Command @invokeParams
        
        if ($clearResult.Success) {
            $result.Status = "Success"
            $result.TotalSizeMB = $clearResult.TotalSizeMB
            $result.DrivesCleared = ($clearResult.Drives | ForEach-Object { "$($_.Drive) ($($_.ItemsCleared) items)" }) -join "; "
        } else {
            $result.Status = "Error"
            $result.Error = $clearResult.Error
        }
    }
    catch {
        $result.Status = "Error"
        $result.Error = $_.Exception.Message
    }
    
    return $result
}

# Main execution
Write-Host "Remote Recycle Bin Clear Tool" -ForegroundColor Cyan
Write-Host "=============================" -ForegroundColor Cyan
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

Write-Host "Drive Filter: $Drive" -ForegroundColor Yellow
Write-Host "Processing $($computers.Count) computer(s)..." -ForegroundColor Yellow
Write-Host ""

if (-not $PSCmdlet.ShouldProcess("Clear recycle bin on $($computers.Count) computer(s)", "This will empty recycle bins. Continue?")) {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
    exit 0
}

$results = @()
foreach ($computer in $computers) {
    Write-Host "Clearing recycle bin on $computer..." -NoNewline
    $result = Clear-RecycleBinRemote -Computer $computer -DriveFilter $Drive -Cred $Credential
    $results += $result
    Write-Host " $($result.Status)" -ForegroundColor $(if ($result.Status -eq "Success") { "Green" } else { "Red" })
    if ($result.TotalSizeMB) {
        Write-Host "  Freed: $($result.TotalSizeMB) MB" -ForegroundColor Gray
    }
}

$results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "Results exported to: $OutputFile" -ForegroundColor Green

$totalFreed = ($results | Where-Object { $_.TotalSizeMB -ne $null } | Measure-Object -Property TotalSizeMB -Sum).Sum
Write-Host ""
Write-Host "Total space freed: $([math]::Round($totalFreed, 2)) MB" -ForegroundColor Green

$results | Format-Table -AutoSize

