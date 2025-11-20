<#
.SYNOPSIS
    Ultra-fast file and folder copy script with optimization techniques.

.DESCRIPTION
    This script provides extremely fast file copying using multiple optimization techniques:
    - Multi-threaded copying
    - Robocopy integration
    - Buffered I/O
    - Parallel processing
    - Progress tracking

.PARAMETER Source
    Source file or folder path.

.PARAMETER Destination
    Destination folder path.

.PARAMETER ComputerList
    Path to text file with computer names for remote copying (one per line) or array.

.PARAMETER UseRobocopy
    Use Robocopy for maximum speed (default: true).

.PARAMETER ThreadCount
    Number of parallel copy threads (default: 4).

.PARAMETER BufferSize
    Buffer size in MB for file operations (default: 64).

.PARAMETER RetryCount
    Number of retries on failure (default: 3).

.PARAMETER ExcludeFiles
    Comma-separated list of file patterns to exclude (e.g., "*.tmp,*.log").

.PARAMETER IncludeFiles
    Comma-separated list of file patterns to include.

.PARAMETER Credential
    PSCredential object for remote authentication.

.PARAMETER OutputFile
    Path to CSV file. Default: FastCopyReport.csv

.PARAMETER WhatIf
    Show what would be copied without actually copying.

.EXAMPLE
    .\Copy-FilesFast.ps1 -Source "C:\Data" -Destination "D:\Backup" -UseRobocopy
    
.EXAMPLE
    .\Copy-FilesFast.ps1 -Source "C:\Files" -Destination "\\server\share" -ComputerList "computers.txt" -ThreadCount 8
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$true)]
    [string]$Source,
    
    [Parameter(Mandatory=$true)]
    [string]$Destination,
    
    [Parameter(Mandatory=$false)]
    [object]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [switch]$UseRobocopy = $true,
    
    [Parameter(Mandatory=$false)]
    [int]$ThreadCount = 4,
    
    [Parameter(Mandatory=$false)]
    [int]$BufferSize = 64,
    
    [Parameter(Mandatory=$false)]
    [int]$RetryCount = 3,
    
    [Parameter(Mandatory=$false)]
    [string]$ExcludeFiles,
    
    [Parameter(Mandatory=$false)]
    [string]$IncludeFiles,
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "FastCopyReport.csv",
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

# Function to copy using Robocopy (fastest method)
function Copy-WithRobocopy {
    param(
        [string]$SourcePath,
        [string]$DestPath,
        [string]$Exclude,
        [string]$Include,
        [int]$Retries
    )
    
    try {
        $robocopyArgs = @(
            "`"$SourcePath`""
            "`"$DestPath`""
            "/E"              # Copy subdirectories including empty ones
            "/ZB"              # Use restartable mode and backup mode
            "/R:$Retries"      # Retry count
            "/W:1"             # Wait time between retries
            "/MT:$ThreadCount" # Multi-threaded
            "/NP"              # No progress
            "/NFL"             # No file list
            "/NDL"             # No directory list
        )
        
        if ($Exclude) {
            $excludePatterns = $Exclude -split ","
            foreach ($pattern in $excludePatterns) {
                $robocopyArgs += "/XF"
                $robocopyArgs += $pattern.Trim()
            }
        }
        
        if ($Include) {
            $includePatterns = $Include -split ","
            foreach ($pattern in $includePatterns) {
                $robocopyArgs += "/IF"
                $robocopyArgs += $pattern.Trim()
            }
        }
        
        $process = Start-Process -FilePath "robocopy.exe" -ArgumentList $robocopyArgs -Wait -PassThru -NoNewWindow
        
        # Robocopy exit codes: 0-7 are success, 8+ are errors
        return @{
            Success = ($process.ExitCode -le 7)
            ExitCode = $process.ExitCode
            Error = if ($process.ExitCode -gt 7) { "Robocopy exit code: $($process.ExitCode)" } else { $null }
        }
    }
    catch {
        return @{
            Success = $false
            ExitCode = -1
            Error = $_.Exception.Message
        }
    }
}

# Function to copy using optimized .NET methods
function Copy-WithDotNet {
    param(
        [string]$SourcePath,
        [string]$DestPath,
        [int]$BufferMB
    )
    
    try {
        $bufferSize = $BufferMB * 1024 * 1024
        
        if (Test-Path $SourcePath -PathType Container) {
            # Directory copy
            if (-not (Test-Path $DestPath)) {
                New-Item -Path $DestPath -ItemType Directory -Force | Out-Null
            }
            
            $files = Get-ChildItem -Path $SourcePath -Recurse -File
            $totalFiles = $files.Count
            $copied = 0
            
            foreach ($file in $files) {
                $relativePath = $file.FullName.Substring($SourcePath.Length + 1)
                $destFile = Join-Path $DestPath $relativePath
                $destDir = Split-Path $destFile -Parent
                
                if (-not (Test-Path $destDir)) {
                    New-Item -Path $destDir -ItemType Directory -Force | Out-Null
                }
                
                [System.IO.File]::Copy($file.FullName, $destFile, $true)
                $copied++
            }
            
            return @{
                Success = $true
                FilesCopied = $copied
                Error = $null
            }
        }
        else {
            # File copy
            $destDir = Split-Path $DestPath -Parent
            if (-not (Test-Path $destDir)) {
                New-Item -Path $destDir -ItemType Directory -Force | Out-Null
            }
            
            [System.IO.File]::Copy($SourcePath, $DestPath, $true)
            
            return @{
                Success = $true
                FilesCopied = 1
                Error = $null
            }
        }
    }
    catch {
        return @{
            Success = $false
            FilesCopied = 0
            Error = $_.Exception.Message
        }
    }
}

# Function to copy to remote computer
function Copy-ToRemoteComputer {
    param(
        [string]$Computer,
        [string]$SourcePath,
        [string]$DestPath,
        [System.Management.Automation.PSCredential]$Cred,
        [bool]$UseRobo,
        [int]$Threads,
        [int]$Buffer,
        [string]$Exclude,
        [string]$Include,
        [int]$Retries
    )
    
    try {
        $scriptBlock = {
            param($Source, $Dest, $UseRobocopy, $ThreadCount, $BufferSize, $ExcludePatterns, $IncludePatterns, $RetryCount)
            
            if ($UseRobocopy) {
                $robocopyArgs = @(
                    "`"$Source`""
                    "`"$Dest`""
                    "/E"
                    "/ZB"
                    "/R:$RetryCount"
                    "/W:1"
                    "/MT:$ThreadCount"
                    "/NP"
                    "/NFL"
                    "/NDL"
                )
                
                if ($ExcludePatterns) {
                    $excludeList = $ExcludePatterns -split ","
                    foreach ($pattern in $excludeList) {
                        $robocopyArgs += "/XF"
                        $robocopyArgs += $pattern.Trim()
                    }
                }
                
                $process = Start-Process -FilePath "robocopy.exe" -ArgumentList $robocopyArgs -Wait -PassThru -NoNewWindow
                return @{ Success = ($process.ExitCode -le 7); ExitCode = $process.ExitCode }
            }
            else {
                if (Test-Path $Source -PathType Container) {
                    Copy-Item -Path $Source -Destination $Dest -Recurse -Force
                }
                else {
                    Copy-Item -Path $Source -Destination $Dest -Force
                }
                return @{ Success = $true; ExitCode = 0 }
            }
        }
        
        if ($Cred) {
            return Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -ArgumentList $SourcePath, $DestPath, $UseRobo, $Threads, $Buffer, $Exclude, $Include, $Retries -Credential $Cred -ErrorAction Stop
        }
        else {
            return Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -ArgumentList $SourcePath, $DestPath, $UseRobo, $Threads, $Buffer, $Exclude, $Include, $Retries -ErrorAction Stop
        }
    }
    catch {
        return @{ Success = $false; ExitCode = -1; Error = $_.Exception.Message }
    }
}

# Main execution
Write-Host "Ultra-Fast File Copy Tool" -ForegroundColor Cyan
Write-Host "========================" -ForegroundColor Cyan
Write-Host ""

# Validate source
if (-not (Test-Path $Source)) {
    Write-Error "Source path not found: $Source"
    exit 1
}

# Create destination if needed
if (-not (Test-Path $Destination)) {
    try {
        New-Item -Path $Destination -ItemType Directory -Force | Out-Null
        Write-Host "Created destination directory: $Destination" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to create destination directory: $($_.Exception.Message)"
        exit 1
    }
}

Write-Host "Source: $Source" -ForegroundColor Yellow
Write-Host "Destination: $Destination" -ForegroundColor Yellow
Write-Host "Method: $(if ($UseRobocopy) { 'Robocopy (Multi-threaded)' } else { '.NET Optimized' })" -ForegroundColor Yellow
if ($UseRobocopy) {
    Write-Host "Threads: $ThreadCount" -ForegroundColor Yellow
}
Write-Host "Buffer Size: $BufferSize MB" -ForegroundColor Yellow
Write-Host "Retry Count: $RetryCount" -ForegroundColor Yellow
if ($WhatIf) {
    Write-Host "MODE: WHATIF (no files will be copied)" -ForegroundColor Yellow
}
Write-Host ""

# Calculate source size
$sourceSize = 0
if (Test-Path $Source -PathType Container) {
    $sourceSize = (Get-ChildItem -Path $Source -Recurse -File -ErrorAction SilentlyContinue | 
                   Measure-Object -Property Length -Sum).Sum
}
else {
    $sourceSize = (Get-Item $Source).Length
}
$sourceSizeMB = [math]::Round($sourceSize / 1MB, 2)
Write-Host "Source Size: $sourceSizeMB MB" -ForegroundColor Cyan
Write-Host ""

if (-not $WhatIf -and -not $PSCmdlet.ShouldProcess("Copy $sourceSizeMB MB from $Source to $Destination", "This will copy files. Continue?")) {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
    exit 0
}

$results = @()

# Check if remote copy
if ($ComputerList) {
    $computers = @()
    
    if ($ComputerList -is [string]) {
        if (Test-Path $ComputerList) {
            $computers = Get-Content $ComputerList | Where-Object { $_.Trim() -ne "" }
        }
        else {
            $computers = @($ComputerList)
        }
    }
    else {
        $computers = $ComputerList
    }
    
    foreach ($computer in $computers) {
        Write-Host "Copying to: $computer" -NoNewline
        
        $result = [PSCustomObject]@{
            Computer = $computer
            Source = $Source
            Destination = $Destination
            SizeMB = $sourceSizeMB
            Status = "Unknown"
            Error = $null
            LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        
        if (-not $WhatIf) {
            $copyResult = Copy-ToRemoteComputer -Computer $computer -SourcePath $Source -DestPath $Destination -Cred $Credential -UseRobo $UseRobocopy.IsPresent -Threads $ThreadCount -Buffer $BufferSize -Exclude $ExcludeFiles -Include $IncludeFiles -Retries $RetryCount
            
            if ($copyResult.Success) {
                $result.Status = "Copied"
                Write-Host " - Success" -ForegroundColor Green
            }
            else {
                $result.Status = "Failed"
                $result.Error = if ($copyResult.Error) { $copyResult.Error } else { "Exit code: $($copyResult.ExitCode)" }
                Write-Host " - Failed: $($result.Error)" -ForegroundColor Red
            }
        }
        else {
            $result.Status = "WhatIf - Would Copy"
            Write-Host " - WhatIf" -ForegroundColor Gray
        }
        
        $results += $result
    }
}
else {
    # Local copy
    Write-Host "Starting copy operation..." -ForegroundColor Yellow
    $startTime = Get-Date
    
    $result = [PSCustomObject]@{
        Computer = $env:COMPUTERNAME
        Source = $Source
        Destination = $Destination
        SizeMB = $sourceSizeMB
        Status = "Unknown"
        Error = $null
        Duration = $null
        LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    if (-not $WhatIf) {
        if ($UseRobocopy) {
            $copyResult = Copy-WithRobocopy -SourcePath $Source -DestPath $Destination -Exclude $ExcludeFiles -Include $IncludeFiles -Retries $RetryCount
            
            if ($copyResult.Success) {
                $result.Status = "Copied"
            }
            else {
                $result.Status = "Failed"
                $result.Error = $copyResult.Error
            }
        }
        else {
            $copyResult = Copy-WithDotNet -SourcePath $Source -DestPath $Destination -BufferMB $BufferSize
            
            if ($copyResult.Success) {
                $result.Status = "Copied"
            }
            else {
                $result.Status = "Failed"
                $result.Error = $copyResult.Error
            }
        }
        
        $endTime = Get-Date
        $duration = $endTime - $startTime
        $result.Duration = "$($duration.TotalSeconds) seconds"
        
        $speedMBps = if ($duration.TotalSeconds -gt 0) { [math]::Round($sourceSizeMB / $duration.TotalSeconds, 2) } else { 0 }
        Write-Host "Copy completed in $($duration.TotalSeconds) seconds" -ForegroundColor Green
        Write-Host "Speed: $speedMBps MB/s" -ForegroundColor Green
    }
    else {
        $result.Status = "WhatIf - Would Copy"
    }
    
    $results += $result
}

Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
$copied = ($results | Where-Object { $_.Status -like "*Copied*" -or $_.Status -like "WhatIf*" }).Count
Write-Host "Copied: $copied" -ForegroundColor Green
Write-Host "Failed: $(($results | Where-Object { $_.Status -eq 'Failed' }).Count)" -ForegroundColor Red

$results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
$results | Format-Table -AutoSize

