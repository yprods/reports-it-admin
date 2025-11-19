<#
.SYNOPSIS
    Creates file shares on remote computers with group permissions.

.DESCRIPTION
    This script creates file shares on remote computers and configures
    permissions for specified groups with different access levels.

.PARAMETER ComputerList
    Path to a text file containing computer names (one per line).

.PARAMETER ComputerName
    Single computer name or array of computer names to process.

.PARAMETER SharePath
    Local path on the computer to share (e.g., "C:\SharedFolder").

.PARAMETER ShareName
    Name of the share (e.g., "DataShare").

.PARAMETER Description
    Description for the share (optional).

.PARAMETER Groups
    Array of groups with permissions in format: "GroupName:Permission"
    Permissions: Read, Change, FullControl
    Example: @("Domain Users:Read", "IT Admins:FullControl")

.PARAMETER GroupList
    Path to text file with groups and permissions (one per line, format: GroupName:Permission).

.PARAMETER OutputFile
    Path to CSV file where results will be exported. Default: FileShareReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication (optional).

.PARAMETER CreateFolder
    Create the folder if it doesn't exist (default: false).

.PARAMETER WhatIf
    Show what would be done without actually creating the share.

.EXAMPLE
    .\New-FileShare.ps1 -ComputerList "computers.txt" -SharePath "C:\SharedData" -ShareName "DataShare" -Groups @("Domain Users:Read", "IT Admins:FullControl")
    
.EXAMPLE
    .\New-FileShare.ps1 -ComputerName "PC01","PC02" -SharePath "C:\Projects" -ShareName "Projects" -GroupList "groups.txt" -CreateFolder
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ComputerName,
    
    [Parameter(Mandatory=$true)]
    [string]$SharePath,
    
    [Parameter(Mandatory=$true)]
    [string]$ShareName,
    
    [Parameter(Mandatory=$false)]
    [string]$Description = "",
    
    [Parameter(Mandatory=$false)]
    [string[]]$Groups,
    
    [Parameter(Mandatory=$false)]
    [string]$GroupList,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "FileShareReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [switch]$CreateFolder,
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

# Function to create file share on a single computer
function New-FileShare {
    param(
        [string]$Computer,
        [string]$Path,
        [string]$Name,
        [string]$Desc,
        [string[]]$GroupPermissions,
        [System.Management.Automation.PSCredential]$Cred,
        [bool]$CreateDir,
        [bool]$WhatIfMode
    )
    
    $result = [PSCustomObject]@{
        ComputerName = $Computer
        ShareName = $Name
        SharePath = $Path
        Status = "Unknown"
        Permissions = "N/A"
        Error = $null
        LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    try {
        # Test connectivity first
        if (-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            $result.Status = "Offline"
            $result.Error = "Computer is not reachable"
            return $result
        }
        
        # Build script block
        $scriptBlock = {
            param(
                [string]$SharePath,
                [string]$ShareName,
                [string]$ShareDescription,
                [string[]]$Groups,
                [bool]$CreateFolder,
                [bool]$WhatIf
            )
            
            $output = @{
                Status = "Unknown"
                Permissions = @()
                Error = $null
            }
            
            try {
                # Create folder if needed
                if ($CreateFolder -and -not (Test-Path $SharePath)) {
                    if (-not $WhatIf) {
                        New-Item -Path $SharePath -ItemType Directory -Force | Out-Null
                        $output.Status = "Folder Created"
                    } else {
                        $output.Status = "WhatIf - Would Create Folder"
                    }
                }
                
                if (-not (Test-Path $SharePath)) {
                    $output.Status = "Error"
                    $output.Error = "Path does not exist: $SharePath"
                    return $output
                }
                
                # Check if share already exists
                $existingShare = Get-SmbShare -Name $ShareName -ErrorAction SilentlyContinue
                if ($existingShare) {
                    $output.Status = "Share Exists"
                    $output.Error = "Share already exists"
                    return $output
                }
                
                if (-not $WhatIf) {
                    # Create the share
                    $shareParams = @{
                        Name = $ShareName
                        Path = $SharePath
                        FullAccess = @()
                        ChangeAccess = @()
                        ReadAccess = @()
                    }
                    
                    if ($ShareDescription) {
                        $shareParams['Description'] = $ShareDescription
                    }
                    
                    # Parse group permissions
                    foreach ($groupPerm in $Groups) {
                        if ($groupPerm -match '^(.+?):(.+)$') {
                            $groupName = $matches[1].Trim()
                            $permission = $matches[2].Trim()
                            
                            switch ($permission.ToLower()) {
                                "read" {
                                    $shareParams['ReadAccess'] += $groupName
                                }
                                "change" {
                                    $shareParams['ChangeAccess'] += $groupName
                                }
                                "fullcontrol" {
                                    $shareParams['FullAccess'] += $groupName
                                }
                                default {
                                    $shareParams['ReadAccess'] += $groupName
                                }
                            }
                            
                            $output.Permissions += "$groupName : $permission"
                        }
                    }
                    
                    # Create share with permissions
                    New-SmbShare @shareParams -ErrorAction Stop
                    
                    # Set additional NTFS permissions if needed
                    $acl = Get-Acl -Path $SharePath
                    $permissionsSet = $false
                    
                    foreach ($groupPerm in $Groups) {
                        if ($groupPerm -match '^(.+?):(.+)$') {
                            $groupName = $matches[1].Trim()
                            $permission = $matches[2].Trim()
                            
                            try {
                                $group = New-Object System.Security.Principal.NTAccount($groupName)
                                $accessRule = $null
                                
                                switch ($permission.ToLower()) {
                                    "read" {
                                        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                                            $group, "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow"
                                        )
                                    }
                                    "change" {
                                        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                                            $group, "Modify", "ContainerInherit,ObjectInherit", "None", "Allow"
                                        )
                                    }
                                    "fullcontrol" {
                                        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                                            $group, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
                                        )
                                    }
                                }
                                
                                if ($accessRule) {
                                    $acl.SetAccessRule($accessRule)
                                    $permissionsSet = $true
                                }
                            }
                            catch {
                                # Continue with next group
                            }
                        }
                    }
                    
                    if ($permissionsSet) {
                        Set-Acl -Path $SharePath -AclObject $acl
                    }
                    
                    $output.Status = "Success"
                } else {
                    $output.Status = "WhatIf - Would Create Share"
                    foreach ($groupPerm in $Groups) {
                        if ($groupPerm -match '^(.+?):(.+)$') {
                            $output.Permissions += "$($matches[1].Trim()) : $($matches[2].Trim())"
                        }
                    }
                }
            }
            catch {
                $output.Status = "Error"
                $output.Error = $_.Exception.Message
            }
            
            return $output
        }
        
        # Execute remotely
        $invokeParams = @{
            ComputerName = $Computer
            ScriptBlock = $scriptBlock
            ArgumentList = @($Path, $Name, $Desc, $GroupPermissions, $CreateDir, $WhatIfMode)
            ErrorAction = "Stop"
        }
        
        if ($Cred) {
            $invokeParams['Credential'] = $Cred
        }
        
        $shareResult = Invoke-Command @invokeParams
        
        $result.Status = $shareResult.Status
        $result.Permissions = ($shareResult.Permissions -join "; ")
        $result.Error = $shareResult.Error
    }
    catch {
        $result.Status = "Error"
        $result.Error = $_.Exception.Message
    }
    
    return $result
}

# Main execution
Write-Host "File Share Creation Tool" -ForegroundColor Cyan
Write-Host "=======================" -ForegroundColor Cyan
Write-Host ""

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

# Collect group permissions
$groupPermissions = @()

if ($GroupList) {
    if (Test-Path $GroupList) {
        Write-Host "Reading group permissions from: $GroupList" -ForegroundColor Yellow
        $groupPermissions = Get-Content $GroupList | Where-Object { $_.Trim() -ne "" } | ForEach-Object { $_.Trim() }
    }
    else {
        Write-Error "Group list file not found: $GroupList"
        exit 1
    }
}

if ($Groups) {
    $groupPermissions += $Groups
}

# Remove duplicates
$groupPermissions = $groupPermissions | Select-Object -Unique

if ($groupPermissions.Count -eq 0) {
    Write-Warning "No group permissions specified. Share will be created with default permissions."
}

Write-Host "Share Name: $ShareName" -ForegroundColor Yellow
Write-Host "Share Path: $SharePath" -ForegroundColor Yellow
Write-Host "Description: $Description" -ForegroundColor Yellow
Write-Host "Groups/Permissions: $($groupPermissions.Count)" -ForegroundColor Yellow
if ($groupPermissions.Count -gt 0) {
    foreach ($gp in $groupPermissions) {
        Write-Host "  - $gp" -ForegroundColor Gray
    }
}
Write-Host "Found $($computers.Count) unique computer(s) to process" -ForegroundColor Green
if ($CreateFolder) {
    Write-Host "Create Folder: ENABLED" -ForegroundColor Cyan
}
if ($WhatIf) {
    Write-Host "MODE: WHATIF (no shares will be created)" -ForegroundColor Yellow
}
Write-Host ""

# Confirm action
if (-not $WhatIf -and -not $PSCmdlet.ShouldProcess("Create file share on $($computers.Count) computer(s)", "This will create file shares. Continue?")) {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
    exit 0
}

# Process each computer
$results = @()
$total = $computers.Count
$current = 0

foreach ($computer in $computers) {
    $current++
    Write-Progress -Activity "Creating File Shares" -Status "Processing $computer ($current of $total)" -PercentComplete (($current / $total) * 100)
    
    Write-Host "[$current/$total] Processing $computer..." -NoNewline
    
    $result = New-FileShare -Computer $computer -Path $SharePath -Name $ShareName -Desc $Description -GroupPermissions $groupPermissions -Cred $Credential -CreateDir $CreateFolder.IsPresent -WhatIfMode $WhatIf.IsPresent
    
    $results += $result
    
    $statusColor = switch ($result.Status) {
        "Success" { "Green" }
        "WhatIf - Would Create Share" { "Yellow" }
        "Share Exists" { "Yellow" }
        "Offline" { "Red" }
        "Error" { "Red" }
        default { "Gray" }
    }
    
    Write-Host " $($result.Status)" -ForegroundColor $statusColor
    if ($result.Permissions -ne "N/A" -and $result.Permissions) {
        Write-Host "  Permissions: $($result.Permissions)" -ForegroundColor Gray
    }
    if ($result.Error) {
        Write-Host "  Error: $($result.Error)" -ForegroundColor Red
    }
}

Write-Progress -Activity "Creating File Shares" -Completed

# Display summary
Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "========" -ForegroundColor Cyan
$success = ($results | Where-Object { $_.Status -eq "Success" }).Count
$whatIf = ($results | Where-Object { $_.Status -like "WhatIf*" }).Count
$exists = ($results | Where-Object { $_.Status -eq "Share Exists" }).Count
$offline = ($results | Where-Object { $_.Status -eq "Offline" }).Count
$errors = ($results | Where-Object { $_.Status -eq "Error" }).Count

Write-Host "Success:      $success" -ForegroundColor Green
Write-Host "WhatIf:       $whatIf" -ForegroundColor Yellow
Write-Host "Already Exists: $exists" -ForegroundColor Yellow
Write-Host "Offline:      $offline" -ForegroundColor Red
Write-Host "Errors:       $errors" -ForegroundColor Red
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
$results | Format-Table -AutoSize ComputerName, ShareName, Status, Permissions, Error

