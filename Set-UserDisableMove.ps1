<#
.SYNOPSIS
    Disables users and moves them to another OU, or creates a new OU for computers.

.DESCRIPTION
    This script disables a list of users and optionally moves them to another OU.
    It can also create OUs for organizing disabled users or computers.

.PARAMETER UserList
    Path to a text file containing usernames (one per line).

.PARAMETER Username
    Single username or array of usernames to process.

.PARAMETER TargetOU
    Target OU to move users to (e.g., "OU=Disabled,DC=contoso,DC=com").

.PARAMETER CreateOU
    Create a new OU if it doesn't exist (default: false).

.PARAMETER OUName
    Name for new OU to create (used with CreateOU).

.PARAMETER Domain
    Domain to operate on (default: current domain).

.PARAMETER OutputFile
    Path to CSV file where results will be exported. Default: UserDisableMoveReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication (optional).

.PARAMETER DisableOnly
    Only disable users without moving them (default: false).

.PARAMETER WhatIf
    Show what would be done without actually making changes.

.EXAMPLE
    .\Set-UserDisableMove.ps1 -UserList "users.txt" -TargetOU "OU=Disabled,DC=contoso,DC=com"
    
.EXAMPLE
    .\Set-UserDisableMove.ps1 -Username "jdoe" -CreateOU -OUName "DisabledUsers" -TargetOU "OU=DisabledUsers,DC=contoso,DC=com"
    
.EXAMPLE
    .\Set-UserDisableMove.ps1 -UserList "users.txt" -DisableOnly
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false)]
    [string]$UserList,
    
    [Parameter(Mandatory=$false)]
    [string[]]$Username,
    
    [Parameter(Mandatory=$false)]
    [string]$TargetOU,
    
    [Parameter(Mandatory=$false)]
    [switch]$CreateOU,
    
    [Parameter(Mandatory=$false)]
    [string]$OUName,
    
    [Parameter(Mandatory=$false)]
    [string]$Domain,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "UserDisableMoveReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [switch]$DisableOnly,
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

# Main execution
Write-Host "User Disable and Move Tool" -ForegroundColor Cyan
Write-Host "==========================" -ForegroundColor Cyan
Write-Host ""

# Check for Active Directory module
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "Active Directory PowerShell module is required. Install RSAT-AD-PowerShell feature."
    exit 1
}

Import-Module ActiveDirectory -ErrorAction Stop

try {
    # Collect usernames
    $users = @()
    
    if ($UserList) {
        if (Test-Path $UserList) {
            Write-Host "Reading user list from: $UserList" -ForegroundColor Yellow
            $users = Get-Content $UserList | Where-Object { $_.Trim() -ne "" } | ForEach-Object { $_.Trim() }
        }
        else {
            Write-Error "User list file not found: $UserList"
            exit 1
        }
    }
    
    if ($Username) {
        $users += $Username
    }
    
    $users = $users | Select-Object -Unique
    
    if ($users.Count -eq 0) {
        Write-Error "No users specified. Use -UserList or -Username parameter."
        exit 1
    }
    
    # Build AD parameters
    $adParams = @{
        ErrorAction = "Stop"
    }
    
    if ($Domain) {
        $adParams['Server'] = $Domain
    }
    
    if ($Credential) {
        $adParams['Credential'] = $Credential
    }
    
    # Create OU if requested
    if ($CreateOU -and $OUName -and $TargetOU) {
        Write-Host "Creating OU: $OUName" -ForegroundColor Yellow
        try {
            if (-not $WhatIf) {
                $ouParams = @{
                    Name = $OUName
                    Path = $TargetOU -replace "OU=$OUName,", ""
                    ErrorAction = "Stop"
                }
                if ($Domain) {
                    $ouParams['Server'] = $Domain
                }
                if ($Credential) {
                    $ouParams['Credential'] = $Credential
                }
                New-ADOrganizationalUnit @ouParams
                Write-Host "OU created successfully" -ForegroundColor Green
            }
            else {
                Write-Host "WhatIf: Would create OU: $OUName" -ForegroundColor Yellow
            }
        }
        catch {
            if ($_.Exception.Message -notlike "*already exists*") {
                Write-Warning "Could not create OU: $($_.Exception.Message)"
            }
        }
    }
    
    Write-Host "Processing $($users.Count) user(s)..." -ForegroundColor Yellow
    Write-Host ""
    
    $results = @()
    $total = $users.Count
    $current = 0
    
    foreach ($userName in $users) {
        $current++
        Write-Progress -Activity "Disabling and Moving Users" -Status "Processing $userName ($current of $total)" -PercentComplete (($current / $total) * 100)
        
        $result = [PSCustomObject]@{
            Username = $userName
            DisplayName = "N/A"
            Enabled = "N/A"
            OriginalOU = "N/A"
            TargetOU = if ($TargetOU) { $TargetOU } else { "N/A" }
            Moved = $false
            Disabled = $false
            Status = "Unknown"
            Error = $null
        }
        
        try {
            $user = Get-ADUser -Identity $userName @adParams -Properties Enabled, DistinguishedName
            
            $result.Username = $user.SamAccountName
            $result.DisplayName = $user.Name
            $result.Enabled = $user.Enabled
            $result.OriginalOU = $user.DistinguishedName
            
            # Disable user
            if (-not $WhatIf) {
                Disable-ADAccount -Identity $user @adParams -ErrorAction Stop
                $result.Disabled = $true
            }
            else {
                $result.Disabled = "WhatIf"
            }
            
            # Move user if target OU specified
            if ($TargetOU -and -not $DisableOnly) {
                if (-not $WhatIf) {
                    Move-ADObject -Identity $user @adParams -TargetPath $TargetOU -ErrorAction Stop
                    $result.Moved = $true
                }
                else {
                    $result.Moved = "WhatIf"
                }
            }
            
            $result.Status = "Success"
        }
        catch {
            $result.Status = "Error"
            $result.Error = $_.Exception.Message
        }
        
        $results += $result
        
        Write-Host "[$current/$total] $userName - $($result.Status)" -ForegroundColor $(if ($result.Status -eq "Success") { "Green" } else { "Red" })
    }
    
    Write-Progress -Activity "Disabling and Moving Users" -Completed
    
    # Display summary
    Write-Host ""
    Write-Host "Summary:" -ForegroundColor Cyan
    Write-Host "========" -ForegroundColor Cyan
    $success = ($results | Where-Object { $_.Status -eq "Success" }).Count
    $disabled = ($results | Where-Object { $_.Disabled -eq $true -or $_.Disabled -eq "WhatIf" }).Count
    $moved = ($results | Where-Object { $_.Moved -eq $true -or $_.Moved -eq "WhatIf" }).Count
    $errors = ($results | Where-Object { $_.Status -eq "Error" }).Count
    
    Write-Host "Success:  $success" -ForegroundColor Green
    Write-Host "Disabled: $disabled" -ForegroundColor Yellow
    Write-Host "Moved:    $moved" -ForegroundColor Cyan
    Write-Host "Errors:   $errors" -ForegroundColor Red
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
    Write-Host "Results:" -ForegroundColor Cyan
    Write-Host "========" -ForegroundColor Cyan
    $results | Format-Table -AutoSize Username, DisplayName, Disabled, Moved, Status, Error
}
catch {
    Write-Error "Failed to process users: $($_.Exception.Message)"
    exit 1
}

