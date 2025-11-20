<#
.SYNOPSIS
    Deletes user profiles from local or remote computers.

.DESCRIPTION
    This script deletes user profiles from Windows computers.
    Supports deleting from registry and file system.

.PARAMETER ComputerList
    Path to text file with computer names (one per line) or array of computer names.
    Use "." or "localhost" for local computer.

.PARAMETER ProfileName
    Specific profile name to delete (e.g., "username" or "DOMAIN\username").

.PARAMETER ProfileList
    Path to text file with profile names (one per line).

.PARAMETER AllProfiles
    Delete all user profiles (except default profiles).

.PARAMETER ExcludeProfiles
    Comma-separated list of profile names to exclude from deletion.

.PARAMETER Credential
    PSCredential object for remote authentication.

.PARAMETER OutputFile
    Path to CSV file. Default: DeleteProfileReport.csv

.PARAMETER Force
    Force deletion even if profile is in use.

.PARAMETER WhatIf
    Show what would be deleted without actually deleting.

.EXAMPLE
    .\Remove-UserProfile.ps1 -ComputerList "computers.txt" -ProfileName "john.doe"
    
.EXAMPLE
    .\Remove-UserProfile.ps1 -ComputerList @("PC01", "PC02") -ProfileList "profiles.txt"
    
.EXAMPLE
    .\Remove-UserProfile.ps1 -ComputerList "." -AllProfiles -ExcludeProfiles "admin,service"
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
    [switch]$AllProfiles,
    
    [Parameter(Mandatory=$false)]
    [string]$ExcludeProfiles,
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "DeleteProfileReport.csv",
    
    [Parameter(Mandatory=$false)]
    [switch]$Force,
    
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
        $scriptBlock = {
            $profiles = @()
            
            # Get profiles from registry
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
            if (Test-Path $regPath) {
                $regProfiles = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue
                
                foreach ($regProfile in $regProfiles) {
                    $profileData = Get-ItemProperty $regProfile.PSPath -ErrorAction SilentlyContinue
                    if ($profileData.ProfileImagePath) {
                        $profilePath = $profileData.ProfileImagePath
                        if (Test-Path $profilePath) {
                            $profiles += [PSCustomObject]@{
                                SID = $regProfile.PSChildName
                                Name = Split-Path $profilePath -Leaf
                                Path = $profilePath
                                RegistryPath = $regProfile.PSPath
                                LastUseTime = if ($profileData.LastUseTime) { [DateTime]::FromFileTime($profileData.LastUseTime) } else { $null }
                                Size = (Get-ChildItem -Path $profilePath -Recurse -ErrorAction SilentlyContinue | 
                                       Measure-Object -Property Length -Sum).Sum
                            }
                        }
                    }
                }
            }
            
            return $profiles
        }
        
        if ($Computer -eq "." -or $Computer -eq "localhost" -or $Computer -eq $env:COMPUTERNAME) {
            return & $scriptBlock
        }
        else {
            if ($Cred) {
                return Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -Credential $Cred -ErrorAction Stop
            }
            else {
                return Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -ErrorAction Stop
            }
        }
    }
    catch {
        Write-Warning "Failed to get profiles from $Computer : $($_.Exception.Message)"
        return @()
    }
}

# Function to delete profile
function Remove-UserProfile {
    param(
        [string]$Computer,
        [object]$Profile,
        [System.Management.Automation.PSCredential]$Cred,
        [bool]$ForceDelete
    )
    
    try {
        $scriptBlock = {
            param($ProfileSID, $ProfilePath, $ProfileName, $Force)
            
            $result = @{
                Success = $false
                Error = $null
            }
            
            try {
                # Check if profile is in use
                $processes = Get-Process -ErrorAction SilentlyContinue | Where-Object {
                    $_.Path -like "$ProfilePath*"
                }
                
                if ($processes -and -not $Force) {
                    $result.Error = "Profile is in use by processes: $($processes.ProcessName -join ', ')"
                    return $result
                }
                
                # Kill processes if forced
                if ($processes -and $Force) {
                    $processes | Stop-Process -Force -ErrorAction SilentlyContinue
                    Start-Sleep -Seconds 2
                }
                
                # Remove from registry
                $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$ProfileSID"
                if (Test-Path $regPath) {
                    Remove-Item -Path $regPath -Recurse -Force -ErrorAction Stop
                }
                
                # Remove profile directory
                if (Test-Path $ProfilePath) {
                    Remove-Item -Path $ProfilePath -Recurse -Force -ErrorAction Stop
                }
                
                $result.Success = $true
            }
            catch {
                $result.Error = $_.Exception.Message
            }
            
            return $result
        }
        
        if ($Computer -eq "." -or $Computer -eq "localhost" -or $Computer -eq $env:COMPUTERNAME) {
            return & $scriptBlock -ProfileSID $Profile.SID -ProfilePath $Profile.Path -ProfileName $Profile.Name -Force $ForceDelete
        }
        else {
            if ($Cred) {
                return Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -ArgumentList $Profile.SID, $Profile.Path, $Profile.Name, $ForceDelete -Credential $Cred -ErrorAction Stop
            }
            else {
                return Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -ArgumentList $Profile.SID, $Profile.Path, $Profile.Name, $ForceDelete -ErrorAction Stop
            }
        }
    }
    catch {
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

# Main execution
Write-Host "Delete User Profile Tool" -ForegroundColor Cyan
Write-Host "========================" -ForegroundColor Cyan
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

# Get profile names to delete
$profileNamesToDelete = @()
$excludeList = @()

if ($ExcludeProfiles) {
    $excludeList = $ExcludeProfiles -split "," | ForEach-Object { $_.Trim() }
}

if ($AllProfiles) {
    Write-Host "Mode: Delete all profiles (except excluded)" -ForegroundColor Yellow
}
elseif ($ProfileName) {
    $profileNamesToDelete = @($ProfileName)
}
elseif ($ProfileList -and (Test-Path $ProfileList)) {
    $profileNamesToDelete = Get-Content $ProfileList | Where-Object { $_.Trim() -ne "" }
}
else {
    Write-Error "Must specify either -ProfileName, -ProfileList, or -AllProfiles"
    exit 1
}

Write-Host "Computers: $($computers.Count)" -ForegroundColor Yellow
if (-not $AllProfiles) {
    Write-Host "Profiles to delete: $($profileNamesToDelete.Count)" -ForegroundColor Yellow
}
if ($excludeList.Count -gt 0) {
    Write-Host "Excluded profiles: $($excludeList -join ', ')" -ForegroundColor Yellow
}
Write-Host "Force: $Force" -ForegroundColor Yellow
if ($WhatIf) {
    Write-Host "MODE: WHATIF (no profiles will be deleted)" -ForegroundColor Yellow
}
Write-Host ""

if (-not $WhatIf -and -not $PSCmdlet.ShouldProcess("Delete profiles on $($computers.Count) computer(s)", "This will delete user profiles. Continue?")) {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
    exit 0
}

$results = @()

foreach ($computer in $computers) {
    Write-Host "Processing: $computer" -ForegroundColor Cyan
    
    # Get all profiles
    $allProfiles = Get-UserProfiles -Computer $computer -Cred $Credential
    
    # Determine which profiles to delete
    $profilesToDelete = @()
    
    if ($AllProfiles) {
        $profilesToDelete = $allProfiles | Where-Object {
            $_.Name -notin @("Public", "Default", "Default User", "All Users") -and
            $_.Name -notin $excludeList
        }
    }
    else {
        foreach ($profileName in $profileNamesToDelete) {
            $matchingProfiles = $allProfiles | Where-Object {
                $_.Name -eq $profileName -or 
                $_.Name -like "*$profileName*" -or
                $_.Path -like "*$profileName*"
            }
            $profilesToDelete += $matchingProfiles
        }
    }
    
    $profilesToDelete = $profilesToDelete | Select-Object -Unique
    
    if ($profilesToDelete.Count -eq 0) {
        Write-Host "  No matching profiles found" -ForegroundColor Yellow
        continue
    }
    
    Write-Host "  Found $($profilesToDelete.Count) profile(s) to delete" -ForegroundColor Yellow
    
    foreach ($profile in $profilesToDelete) {
        $profileSizeMB = [math]::Round($profile.Size / 1MB, 2)
        Write-Host "    Deleting: $($profile.Name) ($profileSizeMB MB)" -NoNewline
        
        $result = [PSCustomObject]@{
            Computer = $computer
            ProfileName = $profile.Name
            ProfileSID = $profile.SID
            ProfilePath = $profile.Path
            ProfileSizeMB = $profileSizeMB
            LastUseTime = if ($profile.LastUseTime) { $profile.LastUseTime.ToString() } else { "Unknown" }
            Status = "Unknown"
            Error = $null
            LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        
        if (-not $WhatIf) {
            $deleteResult = Remove-UserProfile -Computer $computer -Profile $profile -Cred $Credential -ForceDelete $Force.IsPresent
            
            if ($deleteResult.Success) {
                $result.Status = "Deleted"
                Write-Host " - Success" -ForegroundColor Green
            }
            else {
                $result.Status = "Failed"
                $result.Error = $deleteResult.Error
                Write-Host " - Failed: $($deleteResult.Error)" -ForegroundColor Red
            }
        }
        else {
            $result.Status = "WhatIf - Would Delete"
            Write-Host " - WhatIf" -ForegroundColor Gray
        }
        
        $results += $result
    }
}

Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
$deleted = ($results | Where-Object { $_.Status -like "*Deleted*" -or $_.Status -like "WhatIf*" }).Count
Write-Host "Deleted: $deleted" -ForegroundColor Green
Write-Host "Failed: $(($results | Where-Object { $_.Status -eq 'Failed' }).Count)" -ForegroundColor Red

$results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
$results | Format-Table -AutoSize

