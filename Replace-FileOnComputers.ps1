<#
.SYNOPSIS
    Replaces a file on multiple computers with a new version.

.DESCRIPTION
    This script replaces files on remote computers with a new file from a source location.
    Supports backup of original files and rollback capability.

.PARAMETER ComputerList
    Path to text file with computer names (one per line) or array of computer names.

.PARAMETER SourceFile
    Path to source file that will replace the target file.

.PARAMETER TargetPath
    Destination path on remote computers (can include filename or just directory).

.PARAMETER Backup
    Create backup of original file before replacing (default: true).

.PARAMETER BackupPath
    Path where backups will be stored (default: same directory with .bak extension).

.PARAMETER Credential
    PSCredential object for remote authentication.

.PARAMETER OutputFile
    Path to CSV file. Default: ReplaceFileReport.csv

.PARAMETER WhatIf
    Show what would be replaced without actually replacing.

.EXAMPLE
    .\Replace-FileOnComputers.ps1 -ComputerList "computers.txt" -SourceFile "C:\NewFile.txt" -TargetPath "C:\Windows\File.txt"
    
.EXAMPLE
    .\Replace-FileOnComputers.ps1 -ComputerList @("PC01", "PC02") -SourceFile "config.ini" -TargetPath "C:\Program Files\App\" -Backup
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$true)]
    [object]$ComputerList,
    
    [Parameter(Mandatory=$true)]
    [string]$SourceFile,
    
    [Parameter(Mandatory=$true)]
    [string]$TargetPath,
    
    [Parameter(Mandatory=$false)]
    [switch]$Backup = $true,
    
    [Parameter(Mandatory=$false)]
    [string]$BackupPath,
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "ReplaceFileReport.csv",
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

# Function to replace file on remote computer
function Replace-FileRemote {
    param(
        [string]$Computer,
        [string]$Source,
        [string]$Target,
        [bool]$CreateBackup,
        [string]$BackupDir,
        [System.Management.Automation.PSCredential]$Cred
    )
    
    try {
        $scriptBlock = {
            param($SourceFilePath, $TargetFilePath, $Backup, $BackupDirectory)
            
            $result = @{
                Success = $false
                BackupCreated = $false
                BackupPath = $null
                Error = $null
            }
            
            try {
                # Determine target file path
                if (Test-Path $TargetFilePath -PathType Container) {
                    # Target is a directory, use source filename
                    $fileName = Split-Path $SourceFilePath -Leaf
                    $targetFile = Join-Path $TargetFilePath $fileName
                }
                else {
                    $targetFile = $TargetFilePath
                }
                
                # Create backup if needed
                if ($Backup -and (Test-Path $targetFile)) {
                    $backupName = (Split-Path $targetFile -Leaf) + ".bak." + (Get-Date -Format "yyyyMMddHHmmss")
                    
                    if ($BackupDirectory) {
                        if (-not (Test-Path $BackupDirectory)) {
                            New-Item -Path $BackupDirectory -ItemType Directory -Force | Out-Null
                        }
                        $backupPath = Join-Path $BackupDirectory $backupName
                    }
                    else {
                        $backupPath = Join-Path (Split-Path $targetFile -Parent) $backupName
                    }
                    
                    Copy-Item -Path $targetFile -Destination $backupPath -Force -ErrorAction Stop
                    $result.BackupCreated = $true
                    $result.BackupPath = $backupPath
                }
                
                # Ensure target directory exists
                $targetDir = Split-Path $targetFile -Parent
                if (-not (Test-Path $targetDir)) {
                    New-Item -Path $targetDir -ItemType Directory -Force | Out-Null
                }
                
                # Copy source file to target
                Copy-Item -Path $SourceFilePath -Destination $targetFile -Force -ErrorAction Stop
                
                $result.Success = $true
            }
            catch {
                $result.Error = $_.Exception.Message
            }
            
            return $result
        }
        
        if ($Computer -eq "." -or $Computer -eq "localhost" -or $Computer -eq $env:COMPUTERNAME) {
            return & $scriptBlock -SourceFilePath $Source -TargetFilePath $Target -Backup $CreateBackup -BackupDirectory $BackupDir
        }
        else {
            # Copy source file to remote computer first
            $remoteTemp = "\\$Computer\C$\Temp\ReplaceFile_$(Get-Date -Format 'yyyyMMddHHmmss')"
            $remoteTempDir = Split-Path $remoteTemp -Parent
            if (-not (Test-Path $remoteTempDir)) {
                New-Item -Path $remoteTempDir -ItemType Directory -Force | Out-Null
            }
            
            Copy-Item -Path $SourceFile -Destination $remoteTemp -Force -ErrorAction Stop
            
            try {
                if ($Cred) {
                    $result = Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -ArgumentList $remoteTemp, $Target, $CreateBackup, $BackupPath -Credential $Cred -ErrorAction Stop
                }
                else {
                    $result = Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -ArgumentList $remoteTemp, $Target, $CreateBackup, $BackupPath -ErrorAction Stop
                }
                
                # Cleanup temp file
                Remove-Item -Path $remoteTemp -Force -ErrorAction SilentlyContinue
                
                return $result
            }
            catch {
                # Cleanup on error
                Remove-Item -Path $remoteTemp -Force -ErrorAction SilentlyContinue
                throw
            }
        }
    }
    catch {
        return @{ Success = $false; BackupCreated = $false; BackupPath = $null; Error = $_.Exception.Message }
    }
}

# Main execution
Write-Host "Replace File on Computers Tool" -ForegroundColor Cyan
Write-Host "=============================" -ForegroundColor Cyan
Write-Host ""

# Validate source file
if (-not (Test-Path $SourceFile)) {
    Write-Error "Source file not found: $SourceFile"
    exit 1
}

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

Write-Host "Source File: $SourceFile" -ForegroundColor Yellow
Write-Host "Target Path: $TargetPath" -ForegroundColor Yellow
Write-Host "Computers: $($computers.Count)" -ForegroundColor Yellow
Write-Host "Backup: $Backup" -ForegroundColor Yellow
if ($WhatIf) {
    Write-Host "MODE: WHATIF (no files will be replaced)" -ForegroundColor Yellow
}
Write-Host ""

if (-not $WhatIf -and -not $PSCmdlet.ShouldProcess("Replace file on $($computers.Count) computer(s)", "This will replace files. Continue?")) {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
    exit 0
}

$results = @()

foreach ($computer in $computers) {
    Write-Host "Replacing file on: $computer" -NoNewline
    
    $result = [PSCustomObject]@{
        Computer = $computer
        SourceFile = $SourceFile
        TargetPath = $TargetPath
        BackupCreated = $false
        BackupPath = $null
        Status = "Unknown"
        Error = $null
        LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    if (-not $WhatIf) {
        $replaceResult = Replace-FileRemote -Computer $computer -Source $SourceFile -Target $TargetPath -CreateBackup $Backup.IsPresent -BackupDir $BackupPath -Cred $Credential
        
        $result.BackupCreated = $replaceResult.BackupCreated
        $result.BackupPath = $replaceResult.BackupPath
        
        if ($replaceResult.Success) {
            $result.Status = "Replaced"
            Write-Host " - Success" -ForegroundColor Green
            if ($replaceResult.BackupCreated) {
                Write-Host "    Backup: $($replaceResult.BackupPath)" -ForegroundColor Gray
            }
        }
        else {
            $result.Status = "Failed"
            $result.Error = $replaceResult.Error
            Write-Host " - Failed: $($replaceResult.Error)" -ForegroundColor Red
        }
    }
    else {
        $result.Status = "WhatIf - Would Replace"
        Write-Host " - WhatIf" -ForegroundColor Gray
    }
    
    $results += $result
}

Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
$replaced = ($results | Where-Object { $_.Status -like "*Replaced*" -or $_.Status -like "WhatIf*" }).Count
Write-Host "Replaced: $replaced" -ForegroundColor Green
Write-Host "Failed: $(($results | Where-Object { $_.Status -eq 'Failed' }).Count)" -ForegroundColor Red

$results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
$results | Format-Table -AutoSize

