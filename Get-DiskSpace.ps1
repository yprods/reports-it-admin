<#
.SYNOPSIS
    Checks disk space on all computers in a list, domain, or OU.

.DESCRIPTION
    This script queries disk space information from remote computers
    using WMI, supporting lists, domains, and OUs.

.PARAMETER ComputerList
    Path to text file with computer names.

.PARAMETER ComputerName
    Single or array of computer names.

.PARAMETER Domain
    Query all computers in domain.

.PARAMETER OU
    Query all computers in specific OU.

.PARAMETER OutputFile
    Path to CSV file. Default: DiskSpaceReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication.

.PARAMETER Drive
    Specific drive to check (default: all drives).

.EXAMPLE
    .\Get-DiskSpace.ps1 -ComputerList "computers.txt"
    
.EXAMPLE
    .\Get-DiskSpace.ps1 -Domain "contoso.com" -Drive "C:"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ComputerName,
    
    [Parameter(Mandatory=$false)]
    [string]$Domain,
    
    [Parameter(Mandatory=$false)]
    [string]$OU,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "DiskSpaceReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [string]$Drive = "*"
)

function Get-DiskSpace {
    param([string]$Computer, [string]$DriveFilter, [System.Management.Automation.PSCredential]$Cred)
    
    $results = @()
    
    try {
        if (-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            return @([PSCustomObject]@{
                ComputerName = $Computer
                Drive = "N/A"
                FreeSpaceGB = $null
                TotalSizeGB = $null
                PercentFree = $null
                Status = "Offline"
            })
        }
        
        $wmiParams = @{
            ComputerName = $Computer
            Class = "Win32_LogicalDisk"
            Filter = "DriveType = 3"
            ErrorAction = "Stop"
        }
        if ($Cred) { $wmiParams['Credential'] = $Cred }
        
        $disks = Get-CimInstance @wmiParams
        
        foreach ($disk in $disks) {
            if ($disk.DeviceID -like $DriveFilter) {
                $freeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
                $totalGB = [math]::Round($disk.Size / 1GB, 2)
                $percentFree = [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 2)
                
                $results += [PSCustomObject]@{
                    ComputerName = $Computer
                    Drive = $disk.DeviceID
                    FreeSpaceGB = $freeGB
                    TotalSizeGB = $totalGB
                    UsedSpaceGB = [math]::Round($totalGB - $freeGB, 2)
                    PercentFree = $percentFree
                    Status = "Success"
                }
            }
        }
    }
    catch {
        $results += [PSCustomObject]@{
            ComputerName = $Computer
            Drive = "N/A"
            FreeSpaceGB = $null
            TotalSizeGB = $null
            PercentFree = $null
            Status = "Error"
            Error = $_.Exception.Message
        }
    }
    
    return $results
}

# Main execution
Write-Host "Disk Space Query Tool" -ForegroundColor Cyan
Write-Host "====================" -ForegroundColor Cyan
Write-Host ""

$computers = @()

if ($Domain) {
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        $adParams = @{ Filter = * }
        if ($Credential) { $adParams['Credential'] = $Credential; $adParams['Server'] = $Domain }
        $computers = (Get-ADComputer @adParams).Name
    }
}

if ($OU) {
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        $adParams = @{ SearchBase = $OU; Filter = * }
        if ($Credential) { $adParams['Credential'] = $Credential }
        $computers = (Get-ADComputer @adParams).Name
    }
}

if ($ComputerList -and (Test-Path $ComputerList)) {
    $computers += Get-Content $ComputerList | Where-Object { $_.Trim() -ne "" }
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

$allResults = @()
foreach ($computer in $computers) {
    $results = Get-DiskSpace -Computer $computer -DriveFilter $Drive -Cred $Credential
    $allResults += $results
    Write-Host "$computer - Found $($results.Count) drive(s)" -ForegroundColor Gray
}

$allResults | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "Results exported to: $OutputFile" -ForegroundColor Green

$lowSpace = $allResults | Where-Object { $_.PercentFree -lt 10 -and $_.Status -eq "Success" }
if ($lowSpace) {
    Write-Host ""
    Write-Host "WARNING: Low disk space detected:" -ForegroundColor Red
    $lowSpace | Format-Table -AutoSize ComputerName, Drive, FreeSpaceGB, PercentFree
}

$allResults | Format-Table -AutoSize

