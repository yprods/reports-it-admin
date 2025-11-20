<#
.SYNOPSIS
    Creates a backup of user profiles and then deletes them.

.DESCRIPTION
    This script backs up user profiles from local or remote computers,
    then deletes the original profiles. Supports backing up to network share
    or local directory.

.PARAMETER ComputerList
    Path to text file with computer names (one per line) or array of computer names.
    Use "." or "localhost" for local computer.

.PARAMETER ProfileName
    Specific profile name to backup and delete (e.g., "username" or "DOMAIN\username").

.PARAMETER ProfileList
    Path to text file with profile names (one per line).

.PARAMETER BackupPath
    Path where profiles will be backed up (local or UNC path).

.PARAMETER DeleteOnly
    Only delete profiles without backing up (default: false).

.PARAMETER BackupOnly
    Only backup profiles without deleting (default: false).

.PARAMETER Credential
    PSCredential object for remote authentication.

.PARAMETER OutputFile
    Path to CSV file. Default: ProfileBackupDeleteReport.csv

.PARAMETER CompressionLevel
    ZIP compression level: None, Fastest, Optimal, Maximum (default: Optimal).

.PARAMETER ExcludeFolders
    Folders to exclude from backup (comma-separated, e.g., "AppData\Local\Temp,AppData\Local\Cache").

.PARAMETER WhatIf
    Show what would be backed up/deleted without actually doing it.

.EXAMPLE
    .\Backup-DeleteUserProfile.ps1 -ComputerList "computers.txt" -ProfileName "john.doe" -BackupPath "\\server\backups"
    
.EXAMPLE
    .\Backup-DeleteUserProfile.ps1 -ComputerList @("PC01", "PC02") -ProfileList "profiles.txt" -BackupPath "C:\Backups"
    
.EXAMPLE
    .\Backup-DeleteUserProfile.ps1 -ComputerList "." -ProfileName "olduser" -DeleteOnly
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$true)]
    [object]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [string]$ProfileName,
    
    [Parameter(Mandatory=$false)]
    [string]$ProfileList,
    
    [Parameter(Mandatory=$false)]
    [string]$BackupPath,
    
    [Parameter(Mandatory=$false)]
    [switch]$DeleteOnly,
    
    [Parameter(Mandatory=$false)]
    [switch]$BackupOnly,
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "ProfileBackupDeleteReport.csv",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("None","Fastest","Optimal","Maximum")]
    [string]$CompressionLevel = "Optimal",
    
    [Parameter(Mandatory=$false)]
    [string]$ExcludeFolders,
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

# Function to get user profiles on a computer
function Get-UserProfiles {
    param(
        [string]$Computer,
        [System.Management.Automation.PSCredential]$Cred
    )
    
    try {
        $profiles = @()
        
        if ($Computer -eq "." -or $Computer -eq "localhost" -or $Computer -eq $env:COMPUTERNAME) {
            # Local computer
            $profilePaths = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue | Where-Object {
                $_.Name -notin @("Public", "Default", "Default User", "All Users")
            }
            
            foreach ($profile in $profilePaths) {
                $profiles += [PSCustomObject]@{
                    Name = $profile.Name
                    Path = $profile.FullName
                    LastWriteTime = $profile.LastWriteTime
                    Size = (Get-ChildItem -Path $profile.FullName -Recurse -ErrorAction SilentlyContinue | 
                           Measure-Object -Property Length -Sum).Sum
                }
            }
        }
        else {
            # Remote computer
            $scriptBlock = {
                $profiles = @()
                $profilePaths = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue | Where-Object {
                    $_.Name -notin @("Public", "Default", "Default User", "All Users")
                }
                
                foreach ($profile in $profilePaths) {
                    $profiles += [PSCustomObject]@{
                        Name = $profile.Name
                        Path = $profile.FullName
                        LastWriteTime = $profile.LastWriteTime
                        Size = (Get-ChildItem -Path $profile.FullName -Recurse -ErrorAction SilentlyContinue | 
                               Measure-Object -Property Length -Sum).Sum
                    }
                }
                return $profiles
            }
            
            if ($Cred) {
                $profiles = Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -Credential $Cred -ErrorAction Stop
            }
            else {
                $profiles = Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -ErrorAction Stop
            }
        }
        
        return $profiles
    }
    catch {
        Write-Warning "Failed to get profiles from $Computer : $($_.Exception.Message)"
        return @()
    }
}

# Function to backup profile
function Backup-Profile {
    param(
        [string]$Computer,
        [string]$ProfileName,
        [string]$ProfilePath,
        [string]$BackupDir,
        [string]$CompressLevel,
        [string]$Exclude,
        [System.Management.Automation.PSCredential]$Cred
    )
    
    try {
        $backupFileName = "$($Computer)_$ProfileName_$(Get-Date -Format 'yyyyMMdd_HHmmss').zip"
        $backupFilePath = Join-Path $BackupDir $backupFileName
        
        if ($Computer -eq "." -or $Computer -eq "localhost" -or $Computer -eq $env:COMPUTERNAME) {
            # Local backup
            Write-Host "  Backing up profile locally..." -ForegroundColor Gray
            
            # Create temp directory for staging
            $tempDir = Join-Path $env:TEMP "ProfileBackup_$(Get-Date -Format 'yyyyMMddHHmmss')"
            New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
            
            try {
                # Copy profile to temp directory (excluding specified folders)
                $excludePaths = @()
                if ($Exclude) {
                    $excludePaths = $Exclude -split "," | ForEach-Object { $_.Trim() }
                }
                
                $items = Get-ChildItem -Path $ProfilePath -ErrorAction SilentlyContinue
                foreach ($item in $items) {
                    $shouldExclude = $false
                    foreach ($excludePath in $excludePaths) {
                        if ($item.Name -like "*$excludePath*") {
                            $shouldExclude = $true
                            break
                        }
                    }
                    
                    if (-not $shouldExclude) {
                        Copy-Item -Path $item.FullName -Destination (Join-Path $tempDir $item.Name) -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }
                
                # Compress to ZIP
                Add-Type -AssemblyName System.IO.Compression.FileSystem
                [System.IO.Compression.ZipFile]::CreateFromDirectory($tempDir, $backupFilePath, $CompressLevel, $false)
                
                $size = (Get-Item $backupFilePath).Length
                return @{
                    Success = $true
                    BackupFile = $backupFilePath
                    Size = $size
                    Error = $null
                }
            }
            finally {
                # Cleanup temp directory
                if (Test-Path $tempDir) {
                    Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
        else {
            # Remote backup - copy files first, then compress
            Write-Host "  Backing up profile from remote computer..." -ForegroundColor Gray
            
            $scriptBlock = {
                param($ProfilePath, $TempDir, $ExcludePaths)
                
                New-Item -Path $TempDir -ItemType Directory -Force | Out-Null
                
                $items = Get-ChildItem -Path $ProfilePath -ErrorAction SilentlyContinue
                foreach ($item in $items) {
                    $shouldExclude = $false
                    foreach ($excludePath in $ExcludePaths) {
                        if ($item.Name -like "*$excludePath*") {
                            $shouldExclude = $true
                            break
                        }
                    }
                    
                    if (-not $shouldExclude) {
                        Copy-Item -Path $item.FullName -Destination (Join-Path $TempDir $item.Name) -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }
            }
            
            $tempDir = Join-Path $env:TEMP "ProfileBackup_$(Get-Date -Format 'yyyyMMddHHmmss')"
            $excludePaths = @()
            if ($Exclude) {
                $excludePaths = $Exclude -split "," | ForEach-Object { $_.Trim() }
            }
            
            try {
                if ($Cred) {
                    Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -ArgumentList $ProfilePath, $tempDir, $excludePaths -Credential $Cred -ErrorAction Stop
                }
                else {
                    Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -ArgumentList $ProfilePath, $tempDir, $excludePaths -ErrorAction Stop
                }
                
                # Copy from remote temp to local, then compress
                $localTemp = Join-Path $env:TEMP "ProfileBackup_Local_$(Get-Date -Format 'yyyyMMddHHmmss')"
                New-Item -Path $localTemp -ItemType Directory -Force | Out-Null
                
                try {
                    Copy-Item -Path "\\$Computer\C$\Users\$ProfileName\*" -Destination $localTemp -Recurse -Force -ErrorAction SilentlyContinue
                    
                    Add-Type -AssemblyName System.IO.Compression.FileSystem
                    [System.IO.Compression.ZipFile]::CreateFromDirectory($localTemp, $backupFilePath, $CompressLevel, $false)
                    
                    $size = (Get-Item $backupFilePath).Length
                    return @{
                        Success = $true
                        BackupFile = $backupFilePath
                        Size = $size
                        Error = $null
                    }
                }
                finally {
                    if (Test-Path $localTemp) {
                        Remove-Item -Path $localTemp -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }
            }
            catch {
                return @{
                    Success = $false
                    BackupFile = $null
                    Size = $null
                    Error = $_.Exception.Message
                }
            }
        }
    }
    catch {
        return @{
            Success = $false
            BackupFile = $null
            Size = $null
            Error = $_.Exception.Message
        }
    }
}

# Function to delete profile
function Remove-Profile {
    param(
        [string]$Computer,
        [string]$ProfileName,
        [string]$ProfilePath,
        [System.Management.Automation.PSCredential]$Cred
    )
    
    try {
        if ($Computer -eq "." -or $Computer -eq "localhost" -or $Computer -eq $env:COMPUTERNAME) {
            # Local delete
            Write-Host "  Deleting profile locally..." -ForegroundColor Gray
            
            # Remove from registry first
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
            $profiles = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue | Where-Object {
                (Get-ItemProperty $_.PSPath).ProfileImagePath -like "*$ProfileName*"
            }
            
            foreach ($profile in $profiles) {
                Remove-Item -Path $profile.PSPath -Recurse -Force -ErrorAction SilentlyContinue
            }
            
            # Remove profile directory
            if (Test-Path $ProfilePath) {
                Remove-Item -Path $ProfilePath -Recurse -Force -ErrorAction Stop
            }
            
            return @{ Success = $true; Error = $null }
        }
        else {
            # Remote delete
            Write-Host "  Deleting profile from remote computer..." -ForegroundColor Gray
            
            $scriptBlock = {
                param($ProfilePath, $ProfileName)
                
                # Remove from registry
                $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
                $profiles = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue | Where-Object {
                    (Get-ItemProperty $_.PSPath).ProfileImagePath -like "*$ProfileName*"
                }
                
                foreach ($profile in $profiles) {
                    Remove-Item -Path $profile.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                }
                
                # Remove profile directory
                if (Test-Path $ProfilePath) {
                    Remove-Item -Path $ProfilePath -Recurse -Force -ErrorAction Stop
                }
            }
            
            if ($Cred) {
                Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -ArgumentList $ProfilePath, $ProfileName -Credential $Cred -ErrorAction Stop
            }
            else {
                Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -ArgumentList $ProfilePath, $ProfileName -ErrorAction Stop
            }
            
            return @{ Success = $true; Error = $null }
        }
    }
    catch {
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

# Main execution
Write-Host "Backup and Delete User Profile Tool" -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan
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

# Get profile list
$profileNames = @()

if ($ProfileName) {
    $profileNames = @($ProfileName)
}
elseif ($ProfileList -and (Test-Path $ProfileList)) {
    $profileNames = Get-Content $ProfileList | Where-Object { $_.Trim() -ne "" }
}
else {
    Write-Error "Must specify either -ProfileName or -ProfileList"
    exit 1
}

if ($profileNames.Count -eq 0) {
    Write-Error "No profiles specified."
    exit 1
}

# Validate backup path
if (-not $DeleteOnly) {
    if (-not $BackupPath) {
        Write-Error "BackupPath is required when not using -DeleteOnly"
        exit 1
    }
    
    if (-not (Test-Path $BackupPath)) {
        try {
            New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null
            Write-Host "Created backup directory: $BackupPath" -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to create backup directory: $($_.Exception.Message)"
            exit 1
        }
    }
}

Write-Host "Computers: $($computers.Count)" -ForegroundColor Yellow
Write-Host "Profiles: $($profileNames.Count)" -ForegroundColor Yellow
if (-not $DeleteOnly) {
    Write-Host "Backup Path: $BackupPath" -ForegroundColor Yellow
}
Write-Host "Delete Only: $DeleteOnly" -ForegroundColor Yellow
Write-Host "Backup Only: $BackupOnly" -ForegroundColor Yellow
if ($WhatIf) {
    Write-Host "MODE: WHATIF (no profiles will be backed up or deleted)" -ForegroundColor Yellow
}
Write-Host ""

if (-not $WhatIf -and -not $PSCmdlet.ShouldProcess("Backup/delete profiles on $($computers.Count) computer(s)", "This will backup and/or delete user profiles. Continue?")) {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
    exit 0
}

$results = @()

foreach ($computer in $computers) {
    Write-Host "Processing: $computer" -ForegroundColor Cyan
    
    # Get all profiles on computer
    $allProfiles = Get-UserProfiles -Computer $computer -Cred $Credential
    
    foreach ($profileName in $profileNames) {
        $profile = $allProfiles | Where-Object { $_.Name -eq $profileName -or $_.Name -like "*$profileName*" }
        
        if (-not $profile) {
            Write-Host "  Profile '$profileName' not found on $computer" -ForegroundColor Yellow
            $results += [PSCustomObject]@{
                Computer = $computer
                ProfileName = $profileName
                ProfilePath = "N/A"
                ProfileSizeMB = $null
                BackupFile = $null
                BackupSizeMB = $null
                BackupStatus = "Not Found"
                DeleteStatus = "Skipped"
                Error = "Profile not found"
                LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
            continue
        }
        
        $profile = $profile | Select-Object -First 1
        $profilePath = $profile.Path
        $profileSizeMB = [math]::Round($profile.Size / 1MB, 2)
        
        Write-Host "  Profile: $($profile.Name) ($profileSizeMB MB)" -ForegroundColor Yellow
        
        $result = [PSCustomObject]@{
            Computer = $computer
            ProfileName = $profile.Name
            ProfilePath = $profilePath
            ProfileSizeMB = $profileSizeMB
            BackupFile = $null
            BackupSizeMB = $null
            BackupStatus = "Skipped"
            DeleteStatus = "Skipped"
            Error = $null
            LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        
        # Backup
        if (-not $DeleteOnly) {
            if (-not $WhatIf) {
                $backupResult = Backup-Profile -Computer $computer -ProfileName $profile.Name -ProfilePath $profilePath -BackupDir $BackupPath -CompressLevel $CompressionLevel -Exclude $ExcludeFolders -Cred $Credential
                
                if ($backupResult.Success) {
                    $result.BackupFile = $backupResult.BackupFile
                    $result.BackupSizeMB = [math]::Round($backupResult.Size / 1MB, 2)
                    $result.BackupStatus = "Success"
                    Write-Host "    Backup: Success ($($result.BackupSizeMB) MB)" -ForegroundColor Green
                }
                else {
                    $result.BackupStatus = "Failed"
                    $result.Error = $backupResult.Error
                    Write-Host "    Backup: Failed - $($backupResult.Error)" -ForegroundColor Red
                }
            }
            else {
                $result.BackupStatus = "WhatIf - Would Backup"
                Write-Host "    Backup: WhatIf" -ForegroundColor Gray
            }
        }
        
        # Delete
        if (-not $BackupOnly -and $result.BackupStatus -ne "Failed") {
            if (-not $WhatIf) {
                $deleteResult = Remove-Profile -Computer $computer -ProfileName $profile.Name -ProfilePath $profilePath -Cred $Credential
                
                if ($deleteResult.Success) {
                    $result.DeleteStatus = "Success"
                    Write-Host "    Delete: Success" -ForegroundColor Green
                }
                else {
                    $result.DeleteStatus = "Failed"
                    if ($result.Error) {
                        $result.Error += "; Delete: $($deleteResult.Error)"
                    }
                    else {
                        $result.Error = "Delete: $($deleteResult.Error)"
                    }
                    Write-Host "    Delete: Failed - $($deleteResult.Error)" -ForegroundColor Red
                }
            }
            else {
                $result.DeleteStatus = "WhatIf - Would Delete"
                Write-Host "    Delete: WhatIf" -ForegroundColor Gray
            }
        }
        
        $results += $result
    }
}

Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
$backedUp = ($results | Where-Object { $_.BackupStatus -like "*Success*" -or $_.BackupStatus -like "WhatIf*" }).Count
$deleted = ($results | Where-Object { $_.DeleteStatus -like "*Success*" -or $_.DeleteStatus -like "WhatIf*" }).Count
Write-Host "Backed Up: $backedUp" -ForegroundColor Green
Write-Host "Deleted: $deleted" -ForegroundColor Green
Write-Host "Errors: $(($results | Where-Object { $_.Error }).Count)" -ForegroundColor Red

$results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
$results | Format-Table -AutoSize

