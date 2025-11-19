<#
.SYNOPSIS
    Adds or removes users from groups in Active Directory.

.DESCRIPTION
    This script adds or removes users from specified groups in Active Directory.
    Supports bulk operations on multiple users and groups.

.PARAMETER UserList
    Path to a text file containing usernames (one per line).

.PARAMETER Username
    Single username or array of usernames to process.

.PARAMETER GroupList
    Path to a text file containing group names (one per line).

.PARAMETER GroupName
    Single group name or array of group names to process.

.PARAMETER Action
    Action to perform: Add or Remove (default: Add).

.PARAMETER Domain
    Domain to operate on (default: current domain).

.PARAMETER OutputFile
    Path to CSV file where results will be exported. Default: GroupMembershipReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication (optional).

.PARAMETER WhatIf
    Show what would be done without actually making changes.

.EXAMPLE
    .\Set-GroupMembership.ps1 -UserList "users.txt" -GroupName "Domain Admins" -Action Add
    
.EXAMPLE
    .\Set-GroupMembership.ps1 -Username "jdoe" -GroupList "groups.txt" -Action Remove
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false)]
    [string]$UserList,
    
    [Parameter(Mandatory=$false)]
    [string[]]$Username,
    
    [Parameter(Mandatory=$false)]
    [string]$GroupList,
    
    [Parameter(Mandatory=$false)]
    [string[]]$GroupName,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Add","Remove")]
    [string]$Action = "Add",
    
    [Parameter(Mandatory=$false)]
    [string]$Domain,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "GroupMembershipReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

# Main execution
Write-Host "Group Membership Management Tool" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

# Check for Active Directory module
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "Active Directory PowerShell module is required. Install RSAT-AD-PowerShell feature."
    exit 1
}

Import-Module ActiveDirectory -ErrorAction Stop

try {
    # Collect users
    $users = @()
    if ($UserList) {
        if (Test-Path $UserList) {
            $users = Get-Content $UserList | Where-Object { $_.Trim() -ne "" } | ForEach-Object { $_.Trim() }
        }
    }
    if ($Username) {
        $users += $Username
    }
    $users = $users | Select-Object -Unique
    
    # Collect groups
    $groups = @()
    if ($GroupList) {
        if (Test-Path $GroupList) {
            $groups = Get-Content $GroupList | Where-Object { $_.Trim() -ne "" } | ForEach-Object { $_.Trim() }
        }
    }
    if ($GroupName) {
        $groups += $GroupName
    }
    $groups = $groups | Select-Object -Unique
    
    if ($users.Count -eq 0 -or $groups.Count -eq 0) {
        Write-Error "Both users and groups must be specified."
        exit 1
    }
    
    $adParams = @{ ErrorAction = "Stop" }
    if ($Domain) { $adParams['Server'] = $Domain }
    if ($Credential) { $adParams['Credential'] = $Credential }
    
    Write-Host "Action: $Action" -ForegroundColor Yellow
    Write-Host "Users: $($users.Count)" -ForegroundColor Yellow
    Write-Host "Groups: $($groups.Count)" -ForegroundColor Yellow
    Write-Host ""
    
    $results = @()
    
    foreach ($userName in $users) {
        foreach ($groupName in $groups) {
            $result = [PSCustomObject]@{
                Username = $userName
                GroupName = $groupName
                Action = $Action
                Status = "Unknown"
                Error = $null
            }
            
            try {
                $user = Get-ADUser -Identity $userName @adParams
                $group = Get-ADGroup -Identity $groupName @adParams
                
                if ($Action -eq "Add") {
                    if (-not $WhatIf) {
                        Add-ADGroupMember -Identity $group -Members $user @adParams -ErrorAction Stop
                        $result.Status = "Added"
                    } else {
                        $result.Status = "WhatIf - Would Add"
                    }
                } else {
                    if (-not $WhatIf) {
                        Remove-ADGroupMember -Identity $group -Members $user @adParams -ErrorAction Stop
                        $result.Status = "Removed"
                    } else {
                        $result.Status = "WhatIf - Would Remove"
                    }
                }
            }
            catch {
                $result.Status = "Error"
                $result.Error = $_.Exception.Message
            }
            
            $results += $result
        }
    }
    
    Write-Host "Summary:" -ForegroundColor Cyan
    $success = ($results | Where-Object { $_.Status -like "*Added*" -or $_.Status -like "*Removed*" -or $_.Status -like "WhatIf*" }).Count
    Write-Host "Success: $success" -ForegroundColor Green
    Write-Host "Errors: $(($results | Where-Object { $_.Status -eq 'Error' }).Count)" -ForegroundColor Red
    
    $results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
    Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
    $results | Format-Table -AutoSize
}
catch {
    Write-Error "Failed: $($_.Exception.Message)"
    exit 1
}

