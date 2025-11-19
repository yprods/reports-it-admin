<#
.SYNOPSIS
    Syncs folders from one source to many computers.

.DESCRIPTION
    This script synchronizes a source folder to multiple remote computers,
    ensuring all files match between source and destination.

.PARAMETER ComputerList
    Path to a text file containing computer names (one per line).

.PARAMETER ComputerName
    Single computer name or array of computer names to process.

.PARAMETER SourcePath
    Source folder path to sync from (can be local or network path).

.PARAMETER DestinationPath
    Destination folder path on remote computers.

.PARAMETER OutputFile
    Path to CSV file where results will be exported. Default: FolderSyncReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication (optional).

.PARAMETER DeleteExtraFiles
    Delete files in destination that don't exist in source (default: false).

.PARAMETER CompareBy
    Comparison method: Size, Date, Hash (default: Date).

.PARAMETER WhatIf
    Show what would be synced without actually syncing.

.EXAMPLE
    .\Sync-FoldersToComputers.ps1 -ComputerList "computers.txt" -SourcePath "C:\Source" -DestinationPath "C:\Destination"
    
.EXAMPLE
    .\Sync-FoldersToComputers.ps1 -ComputerName "PC01","PC02" -SourcePath "\\server\share" -DestinationPath "C:\Sync" -DeleteExtraFiles
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ComputerName,
    
    [Parameter(Mandatory=$true)]
    [string]$SourcePath,
    
    [Parameter(Mandatory=$true)]
    [string]$DestinationPath,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "FolderSyncReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [switch]$DeleteExtraFiles,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Size","Date","Hash")]
    [string]$CompareBy = "Date",
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

# Function to sync folder to a single computer
function Sync-FolderToComputer {
    param(
        [string]$Computer,
        [string]$Source,
        [string]$Destination,
        [System.Management.Automation.PSCredential]$Cred,
        [bool]$DeleteExtra,
        [string]$CompareMethod,
        [bool]$WhatIfMode
    )
    
    $scriptBlock = {
        param(
            [string]$SourcePath,
            [string]$DestPath,
            [bool]$DeleteExtra,
            [string]$CompareMethod,
            [bool]$WhatIf
        )
        
        $output = @{
            FilesAdded = 0
            FilesUpdated = 0
            FilesDeleted = 0
            FilesSkipped = 0
            SizeSyncedMB = 0
            Status = "Unknown"
            Error = $null
        }
        
        try {
            # Check if source exists
            if (-not (Test-Path $SourcePath)) {
                $output.Error = "Source path does not exist: $SourcePath"
                return $output
            }
            
            if (-not (Test-Path $SourcePath -PathType Container)) {
                $output.Error = "Source path is not a folder: $SourcePath"
                return $output
            }
            
            # Create destination if it doesn't exist
            if (-not (Test-Path $DestPath)) {
                if (-not $WhatIf) {
                    New-Item -Path $DestPath -ItemType Directory -Force | Out-Null
                }
            }
            
            # Get all files from source
            $sourceFiles = Get-ChildItem -Path $SourcePath -Recurse -File
            
            # Get all files from destination
            $destFiles = @()
            if (Test-Path $DestPath) {
                $destFiles = Get-ChildItem -Path $DestPath -Recurse -File
            }
            
            # Create hashtable for destination files (relative path as key)
            $destFileMap = @{}
            foreach ($file in $destFiles) {
                $relativePath = $file.FullName.Substring($DestPath.Length).TrimStart('\')
                $destFileMap[$relativePath] = $file
            }
            
            # Sync files from source to destination
            foreach ($sourceFile in $sourceFiles) {
                $relativePath = $sourceFile.FullName.Substring($SourcePath.Length).TrimStart('\')
                $destFilePath = Join-Path $DestPath $relativePath
                $destFile = $destFileMap[$relativePath]
                
                $needsCopy = $false
                
                if (-not $destFile) {
                    # File doesn't exist in destination
                    $needsCopy = $true
                    if (-not $WhatIf) {
                        $destDir = Split-Path $destFilePath -Parent
                        if (-not (Test-Path $destDir)) {
                            New-Item -Path $destDir -ItemType Directory -Force | Out-Null
                        }
                        Copy-Item -Path $sourceFile.FullName -Destination $destFilePath -Force
                        $output.FilesAdded++
                    } else {
                        $output.FilesAdded++
                    }
                }
                else {
                    # File exists, check if it needs updating
                    switch ($CompareMethod) {
                        "Size" {
                            if ($sourceFile.Length -ne $destFile.Length) {
                                $needsCopy = $true
                            }
                        }
                        "Date" {
                            if ($sourceFile.LastWriteTime -gt $destFile.LastWriteTime) {
                                $needsCopy = $true
                            }
                        }
                        "Hash" {
                            $sourceHash = (Get-FileHash -Path $sourceFile.FullName -Algorithm MD5).Hash
                            $destHash = (Get-FileHash -Path $destFile.FullName -Algorithm MD5).Hash
                            if ($sourceHash -ne $destHash) {
                                $needsCopy = $true
                            }
                        }
                    }
                    
                    if ($needsCopy) {
                        if (-not $WhatIf) {
                            Copy-Item -Path $sourceFile.FullName -Destination $destFilePath -Force
                            $output.FilesUpdated++
                        } else {
                            $output.FilesUpdated++
                        }
                    }
                    else {
                        $output.FilesSkipped++
                    }
                }
                
                if ($needsCopy -or -not $destFile) {
                    $output.SizeSyncedMB += [math]::Round($sourceFile.Length / 1MB, 2)
                }
            }
            
            # Delete extra files if requested
            if ($DeleteExtra) {
                foreach ($destFile in $destFiles) {
                    $relativePath = $destFile.FullName.Substring($DestPath.Length).TrimStart('\')
                    $sourceFilePath = Join-Path $SourcePath $relativePath
                    
                    if (-not (Test-Path $sourceFilePath)) {
                        if (-not $WhatIf) {
                            Remove-Item -Path $destFile.FullName -Force
                            $output.FilesDeleted++
                        } else {
                            $output.FilesDeleted++
                        }
                    }
                }
            }
            
            $output.Status = "Success"
            if ($WhatIf) {
                $output.Status = "WhatIf - Would Sync"
            }
        }
        catch {
            $output.Status = "Error"
            $output.Error = $_.Exception.Message
        }
        
        return $output
    }
    
    $result = [PSCustomObject]@{
        ComputerName = $Computer
        SourcePath = $Source
        DestinationPath = $Destination
        FilesAdded = 0
        FilesUpdated = 0
        FilesDeleted = 0
        FilesSkipped = 0
        SizeSyncedMB = $null
        Status = "Unknown"
        StartTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        EndTime = $null
        Duration = $null
        Error = $null
    }
    
    try {
        if (-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            $result.Status = "Offline"
            $result.Error = "Computer is not reachable"
            $result.EndTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            return $result
        }
        
        $invokeParams = @{
            ComputerName = $Computer
            ScriptBlock = $scriptBlock
            ArgumentList = @($Source, $Destination, $DeleteExtra, $CompareMethod, $WhatIfMode)
        }
        if ($Cred) { $invokeParams['Credential'] = $Cred }
        
        Write-Host "  Syncing to $Computer..." -ForegroundColor Gray
        
        $startTime = Get-Date
        $syncResult = Invoke-Command @invokeParams
        $endTime = Get-Date
        
        $result.FilesAdded = $syncResult.FilesAdded
        $result.FilesUpdated = $syncResult.FilesUpdated
        $result.FilesDeleted = $syncResult.FilesDeleted
        $result.FilesSkipped = $syncResult.FilesSkipped
        $result.SizeSyncedMB = $syncResult.SizeSyncedMB
        $result.Status = $syncResult.Status
        $result.Error = $syncResult.Error
        $result.EndTime = $endTime.ToString("yyyy-MM-dd HH:mm:ss")
        $result.Duration = [math]::Round(($endTime - $startTime).TotalSeconds, 2)
    }
    catch {
        $result.Status = "Error"
        $result.Error = $_.Exception.Message
        $result.EndTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    return $result
}

# Main execution
Write-Host "Folder Sync to Multiple Computers Tool" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

# Validate source path
if (-not (Test-Path $SourcePath)) {
    Write-Error "Source path does not exist: $SourcePath"
    exit 1
}

if (-not (Test-Path $SourcePath -PathType Container)) {
    Write-Error "Source path is not a folder: $SourcePath"
    exit 1
}

# Collect computer names
$computers = @()

if ($ComputerList) {
    if (Test-Path $ComputerList) {
        Write-Host "Reading computer list from: $ComputerList" -ForegroundColor Yellow
        $computers = Get-Content $ComputerList | Where-Object { $_.Trim() -ne "" } | ForEach-Object { $_.Trim() }
    }
    else {
        Write-Error "Computer list file not found: $ComputerList"
        exit 1
    }
}

if ($ComputerName) {
    $computers += $ComputerName
}

$computers = $computers | Select-Object -Unique

if ($computers.Count -eq 0) {
    Write-Error "No computers specified. Use -ComputerList or -ComputerName parameter."
    exit 1
}

Write-Host "Source: $SourcePath" -ForegroundColor Yellow
Write-Host "Destination: $DestinationPath" -ForegroundColor Yellow
Write-Host "Compare By: $CompareBy" -ForegroundColor Yellow
Write-Host "Found $($computers.Count) unique computer(s) to process" -ForegroundColor Green
if ($DeleteExtraFiles) {
    Write-Host "Delete Extra Files: ENABLED" -ForegroundColor Cyan
}
if ($WhatIf) {
    Write-Host "MODE: WHATIF (no files will be synced)" -ForegroundColor Yellow
}
Write-Host ""

if (-not $WhatIf -and -not $PSCmdlet.ShouldProcess("Sync folders to $($computers.Count) computer(s)", "This will sync folders to remote computers. Continue?")) {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
    exit 0
}

$results = @()
$total = $computers.Count
$current = 0

foreach ($computer in $computers) {
    $current++
    Write-Progress -Activity "Syncing Folders" -Status "Processing $computer ($current of $total)" -PercentComplete (($current / $total) * 100)
    
    Write-Host "[$current/$total] Processing $computer..." -NoNewline
    
    $result = Sync-FolderToComputer -Computer $computer -Source $SourcePath -Destination $DestinationPath -Cred $Credential -DeleteExtra $DeleteExtraFiles.IsPresent -CompareMethod $CompareBy -WhatIfMode $WhatIf.IsPresent
    
    $results += $result
    
    $statusColor = switch ($result.Status) {
        "Success" { "Green" }
        "WhatIf - Would Sync" { "Yellow" }
        "Offline" { "Red" }
        "Error" { "Red" }
        default { "Gray" }
    }
    
    Write-Host " $($result.Status)" -ForegroundColor $statusColor
    if ($result.Status -like "*Success*" -or $result.Status -like "WhatIf*") {
        Write-Host "  Added: $($result.FilesAdded), Updated: $($result.FilesUpdated), Deleted: $($result.FilesDeleted), Skipped: $($result.FilesSkipped)" -ForegroundColor Gray
        if ($result.SizeSyncedMB) {
            Write-Host "  Size: $($result.SizeSyncedMB) MB" -ForegroundColor Gray
        }
    }
    if ($result.Duration) {
        Write-Host "  Duration: $($result.Duration) seconds" -ForegroundColor Gray
    }
    if ($result.Error) {
        Write-Host "  Error: $($result.Error)" -ForegroundColor Red
    }
}

Write-Progress -Activity "Syncing Folders" -Completed

Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "========" -ForegroundColor Cyan
$success = ($results | Where-Object { $_.Status -eq "Success" -or $_.Status -like "WhatIf*" }).Count
$totalAdded = ($results | Measure-Object -Property FilesAdded -Sum).Sum
$totalUpdated = ($results | Measure-Object -Property FilesUpdated -Sum).Sum
$totalDeleted = ($results | Measure-Object -Property FilesDeleted -Sum).Sum
$totalSize = ($results | Where-Object { $_.SizeSyncedMB -ne $null } | Measure-Object -Property SizeSyncedMB -Sum).Sum

Write-Host "Success:      $success" -ForegroundColor Green
Write-Host "Files Added:  $totalAdded" -ForegroundColor Cyan
Write-Host "Files Updated: $totalUpdated" -ForegroundColor Cyan
Write-Host "Files Deleted: $totalDeleted" -ForegroundColor Yellow
Write-Host "Total Size:   $([math]::Round($totalSize, 2)) MB" -ForegroundColor Cyan
Write-Host ""

$results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "Results exported to: $OutputFile" -ForegroundColor Green

$results | Format-Table -AutoSize ComputerName, Status, FilesAdded, FilesUpdated, FilesDeleted, SizeSyncedMB, Duration

