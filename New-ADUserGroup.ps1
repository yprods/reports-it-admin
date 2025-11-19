<#
.SYNOPSIS
    Creates users or groups in Active Directory.

.DESCRIPTION
    This script creates single or multiple users and groups in Active Directory
    with configurable properties.

.PARAMETER UserList
    Path to CSV file with user details (Name, SamAccountName, UserPrincipalName, etc.).

.PARAMETER GroupList
    Path to text file containing group names (one per line).

.PARAMETER GroupName
    Single group name or array of group names to create.

.PARAMETER Domain
    Domain to operate on (default: current domain).

.PARAMETER OutputFile
    Path to CSV file for results. Default: ADCreationReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication (optional).

.PARAMETER OU
    Organizational Unit to create objects in.

.PARAMETER WhatIf
    Show what would be created without actually creating.

.EXAMPLE
    .\New-ADUserGroup.ps1 -GroupName "Sales Team","IT Team"
    
.EXAMPLE
    .\New-ADUserGroup.ps1 -UserList "users.csv" -OU "OU=Users,DC=contoso,DC=com"
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false)]
    [string]$UserList,
    
    [Parameter(Mandatory=$false)]
    [string]$GroupList,
    
    [Parameter(Mandatory=$false)]
    [string[]]$GroupName,
    
    [Parameter(Mandatory=$false)]
    [string]$Domain,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "ADCreationReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [string]$OU,
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

# Main execution
Write-Host "AD User/Group Creation Tool" -ForegroundColor Cyan
Write-Host "==========================" -ForegroundColor Cyan
Write-Host ""

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "Active Directory PowerShell module is required."
    exit 1
}

Import-Module ActiveDirectory -ErrorAction Stop

$adParams = @{ ErrorAction = "Stop" }
if ($Domain) { $adParams['Server'] = $Domain }
if ($Credential) { $adParams['Credential'] = $Credential }

$results = @()

# Create groups
if ($GroupList -or $GroupName) {
    $groups = @()
    if ($GroupList -and (Test-Path $GroupList)) {
        $groups = Get-Content $GroupList | Where-Object { $_.Trim() -ne "" }
    }
    if ($GroupName) {
        $groups += $GroupName
    }
    $groups = $groups | Select-Object -Unique
    
    Write-Host "Creating $($groups.Count) group(s)..." -ForegroundColor Yellow
    
    foreach ($group in $groups) {
        $result = [PSCustomObject]@{
            Type = "Group"
            Name = $group
            Status = "Unknown"
            Error = $null
        }
        
        try {
            if (-not $WhatIf) {
                $groupParams = @{
                    Name = $group
                    GroupScope = "Global"
                    GroupCategory = "Security"
                }
                if ($OU) { $groupParams['Path'] = $OU }
                New-ADGroup @groupParams @adParams
                $result.Status = "Created"
            } else {
                $result.Status = "WhatIf - Would Create"
            }
        }
        catch {
            $result.Status = "Error"
            $result.Error = $_.Exception.Message
        }
        
        $results += $result
    }
}

# Create users
if ($UserList -and (Test-Path $UserList)) {
    Write-Host "Creating users from CSV..." -ForegroundColor Yellow
    $users = Import-Csv -Path $UserList
    
    foreach ($userData in $users) {
        $result = [PSCustomObject]@{
            Type = "User"
            Name = $userData.Name
            SamAccountName = $userData.SamAccountName
            Status = "Unknown"
            Error = $null
        }
        
        try {
            if (-not $WhatIf) {
                $userParams = @{
                    Name = $userData.Name
                    SamAccountName = $userData.SamAccountName
                    UserPrincipalName = $userData.UserPrincipalName
                    Enabled = $true
                }
                if ($OU) { $userParams['Path'] = $OU }
                if ($userData.Password) {
                    $userParams['AccountPassword'] = ConvertTo-SecureString -String $userData.Password -AsPlainText -Force
                }
                New-ADUser @userParams @adParams
                $result.Status = "Created"
            } else {
                $result.Status = "WhatIf - Would Create"
            }
        }
        catch {
            $result.Status = "Error"
            $result.Error = $_.Exception.Message
        }
        
        $results += $result
    }
}

Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
$success = ($results | Where-Object { $_.Status -like "*Created*" -or $_.Status -like "WhatIf*" }).Count
Write-Host "Success: $success" -ForegroundColor Green
Write-Host "Errors: $(($results | Where-Object { $_.Status -eq 'Error' }).Count)" -ForegroundColor Red

$results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
$results | Format-Table -AutoSize

