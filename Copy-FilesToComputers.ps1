<#
.SYNOPSIS
    Copies files and folders to multiple computers in a list.

.DESCRIPTION
    This script copies files or folders from a source location to multiple
    remote computers, supporting network paths and local files.

.PARAMETER ComputerList
    Path to a text file containing computer names (one per line).

.PARAMETER ComputerName
    Single computer name or array of computer names to process.

.PARAMETER SourcePath
    Source file or folder path to copy (can be local or network path).

.PARAMETER DestinationPath
    Destination path on remote computers (e.g., "C:\Temp\Files").

.PARAMETER OutputFile
    Path to CSV file where results will be exported. Default: FileCopyReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication (optional).

.PARAMETER Overwrite
    Overwrite existing files (default: false).

.PARAMETER Recurse
    Copy subdirectories recursively (default: true for folders).

.PARAMETER WhatIf
    Show what would be copied without actually copying.

.EXAMPLE
    .\Copy-FilesToComputers.ps1 -ComputerList "computers.txt" -SourcePath "C:\Files" -DestinationPath "C:\Temp\Files"
    
.EXAMPLE
    .\Copy-FilesToComputers.ps1 -ComputerName "PC01","PC02" -SourcePath "\\server\share\file.txt" -DestinationPath "C:\Temp" -Overwrite
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
    [string]$OutputFile = "FileCopyReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [switch]$Overwrite,
    
    [Parameter(Mandatory=$false)]
    [switch]$Recurse = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

# Function to copy files to a single computer
function Copy-FilesToComputer {
    param(
        [string]$Computer,
        [string]$Source,
        [string]$Destination,
        [System.Management.Automation.PSCredential]$Cred,
        [bool]$OverwriteFiles,
        [bool]$Recursive,
        [bool]$WhatIfMode
    )
    
    $result = [PSCustomObject]@{
        ComputerName = $Computer
        SourcePath = $Source
        DestinationPath = $Destination
        FilesCopied = 0
        SizeCopiedMB = $null
        Status = "Unknown"
        StartTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        EndTime = $null
        Duration = $null
        Error = $null
    }
    
    try {
        # Test connectivity first
        if (-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            $result.Status = "Offline"
            $result.Error = "Computer is not reachable"
            $result.EndTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            return $result
        }
        
        # Build copy script block
        $copyScript = {
            param(
                [string]$SourcePath,
                [string]$DestPath,
                [bool]$Overwrite,
                [bool]$Recursive,
                [bool]$WhatIf
            )
            
            $output = @{
                FilesCopied = 0
                SizeCopied = 0
                Error = $null
            }
            
            try {
                # Check if source exists
                if (-not (Test-Path $SourcePath)) {
                    $output.Error = "Source path does not exist: $SourcePath"
                    return $output
                }
                
                # Create destination directory if it doesn't exist
                if (-not (Test-Path $DestPath)) {
                    if (-not $WhatIf) {
                        New-Item -Path $DestPath -ItemType Directory -Force | Out-Null
                    }
                }
                
                if ($WhatIf) {
                    # Count files that would be copied
                    if (Test-Path $SourcePath -PathType Container) {
                        $files = Get-ChildItem -Path $SourcePath -Recurse:$Recursive -File
                    } else {
                        $files = @(Get-Item -Path $SourcePath)
                    }
                    $output.FilesCopied = $files.Count
                    $output.SizeCopied = ($files | Measure-Object -Property Length -Sum).Sum
                    $output.Error = "WhatIf - Would copy"
                    return $output
                }
                
                # Perform copy
                $copyParams = @{
                    Path = $SourcePath
                    Destination = $DestPath
                    Force = $Overwrite
                    ErrorAction = "Stop"
                }
                
                if (Test-Path $SourcePath -PathType Container) {
                    $copyParams['Recurse'] = $Recursive
                }
                
                Copy-Item @copyParams
                
                # Count copied files
                if (Test-Path $DestPath) {
                    if (Test-Path $SourcePath -PathType Container) {
                        $copiedFiles = Get-ChildItem -Path $DestPath -Recurse -File
                    } else {
                        $copiedFiles = @(Get-Item -Path $DestPath)
                    }
                    $output.FilesCopied = $copiedFiles.Count
                    $output.SizeCopied = ($copiedFiles | Measure-Object -Property Length -Sum).Sum
                }
            }
            catch {
                $output.Error = $_.Exception.Message
            }
            
            return $output
        }
        
        # Execute copy remotely
        $invokeParams = @{
            ComputerName = $Computer
            ScriptBlock = $copyScript
            ArgumentList = @($Source, $Destination, $OverwriteFiles, $Recursive, $WhatIfMode)
            ErrorAction = "Stop"
        }
        
        if ($Cred) {
            $invokeParams['Credential'] = $Cred
        }
        
        Write-Host "  Copying to $Computer..." -ForegroundColor Gray
        
        $startTime = Get-Date
        $copyResult = Invoke-Command @invokeParams
        $endTime = Get-Date
        
        $result.FilesCopied = $copyResult.FilesCopied
        $result.SizeCopiedMB = if ($copyResult.SizeCopied) { [math]::Round($copyResult.SizeCopied / 1MB, 2) } else { $null }
        $result.Error = $copyResult.Error
        $result.EndTime = $endTime.ToString("yyyy-MM-dd HH:mm:ss")
        $result.Duration = [math]::Round(($endTime - $startTime).TotalSeconds, 2)
        
        # Determine status
        if ($copyResult.Error -like "WhatIf*") {
            $result.Status = "WhatIf - Would Copy"
        }
        elseif ($copyResult.Error) {
            $result.Status = "Error"
        }
        elseif ($result.FilesCopied -gt 0) {
            $result.Status = "Success"
        }
        else {
            $result.Status = "No Files Copied"
        }
    }
    catch {
        $result.Status = "Error"
        $result.Error = $_.Exception.Message
        $result.EndTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        
        if ($result.Duration -eq $null) {
            $start = [DateTime]::ParseExact($result.StartTime, "yyyy-MM-dd HH:mm:ss", $null)
            $end = [DateTime]::ParseExact($result.EndTime, "yyyy-MM-dd HH:mm:ss", $null)
            $result.Duration = [math]::Round(($end - $start).TotalSeconds, 2)
        }
    }
    
    return $result
}

# Main execution
Write-Host "File Copy to Multiple Computers Tool" -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan
Write-Host ""

# Validate source path
if (-not (Test-Path $SourcePath)) {
    Write-Error "Source path does not exist: $SourcePath"
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

# Remove duplicates
$computers = $computers | Select-Object -Unique

if ($computers.Count -eq 0) {
    Write-Error "No computers specified. Use -ComputerList or -ComputerName parameter."
    exit 1
}

$sourceType = if (Test-Path $SourcePath -PathType Container) { "Folder" } else { "File" }
Write-Host "Source: $SourcePath ($sourceType)" -ForegroundColor Yellow
Write-Host "Destination: $DestinationPath" -ForegroundColor Yellow
Write-Host "Found $($computers.Count) unique computer(s) to process" -ForegroundColor Green
if ($Overwrite) {
    Write-Host "Overwrite: ENABLED" -ForegroundColor Cyan
}
if ($Recurse -and $sourceType -eq "Folder") {
    Write-Host "Recursive: ENABLED" -ForegroundColor Cyan
}
if ($WhatIf) {
    Write-Host "MODE: WHATIF (no files will be copied)" -ForegroundColor Yellow
}
Write-Host ""

# Confirm action
if (-not $WhatIf -and -not $PSCmdlet.ShouldProcess("Copy files to $($computers.Count) computer(s)", "This will copy files to remote computers. Continue?")) {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
    exit 0
}

# Process each computer
$results = @()
$total = $computers.Count
$current = 0

foreach ($computer in $computers) {
    $current++
    Write-Progress -Activity "Copying Files" -Status "Processing $computer ($current of $total)" -PercentComplete (($current / $total) * 100)
    
    Write-Host "[$current/$total] Processing $computer..." -NoNewline
    
    $result = Copy-FilesToComputer -Computer $computer -Source $SourcePath -Destination $DestinationPath -Cred $Credential -OverwriteFiles $Overwrite.IsPresent -Recursive $Recurse.IsPresent -WhatIfMode $WhatIf.IsPresent
    
    $results += $result
    
    $statusColor = switch ($result.Status) {
        "Success" { "Green" }
        "WhatIf - Would Copy" { "Yellow" }
        "No Files Copied" { "Yellow" }
        "Offline" { "Red" }
        "Error" { "Red" }
        default { "Gray" }
    }
    
    Write-Host " $($result.Status)" -ForegroundColor $statusColor
    if ($result.FilesCopied -gt 0) {
        Write-Host "  Files: $($result.FilesCopied), Size: $($result.SizeCopiedMB) MB" -ForegroundColor Gray
    }
    if ($result.Duration) {
        Write-Host "  Duration: $($result.Duration) seconds" -ForegroundColor Gray
    }
    if ($result.Error) {
        Write-Host "  Error: $($result.Error)" -ForegroundColor Red
    }
}

Write-Progress -Activity "Copying Files" -Completed

# Display summary
Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "========" -ForegroundColor Cyan
$success = ($results | Where-Object { $_.Status -eq "Success" }).Count
$whatIf = ($results | Where-Object { $_.Status -like "WhatIf*" }).Count
$offline = ($results | Where-Object { $_.Status -eq "Offline" }).Count
$errors = ($results | Where-Object { $_.Status -eq "Error" }).Count
$totalFiles = ($results | Measure-Object -Property FilesCopied -Sum).Sum
$totalSize = ($results | Where-Object { $_.SizeCopiedMB -ne $null } | Measure-Object -Property SizeCopiedMB -Sum).Sum

Write-Host "Success:      $success" -ForegroundColor Green
Write-Host "WhatIf:       $whatIf" -ForegroundColor Yellow
Write-Host "Offline:      $offline" -ForegroundColor Red
Write-Host "Errors:       $errors" -ForegroundColor Red
Write-Host "Total Files:  $totalFiles" -ForegroundColor Cyan
Write-Host "Total Size:   $([math]::Round($totalSize, 2)) MB" -ForegroundColor Cyan
Write-Host ""

# Export to CSV
try {
    $results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
    Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
}
catch {
    Write-Error "Failed to export results: $($_.Exception.Message)"
}

# Display results table
Write-Host ""
Write-Host "Detailed Results:" -ForegroundColor Cyan
Write-Host "================" -ForegroundColor Cyan
$results | Format-Table -AutoSize ComputerName, Status, FilesCopied, SizeCopiedMB, Duration, Error

