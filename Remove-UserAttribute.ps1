<#
.SYNOPSIS
    Removes an attribute from all users in a group, OU, or all active users.

.DESCRIPTION
    This script removes a specified attribute from users in Active Directory
    based on group membership, OU location, or all active users.

.PARAMETER AttributeName
    Name of the attribute to remove (e.g., "Department", "Title", "Office").

.PARAMETER GroupName
    Remove attribute from users in this group.

.PARAMETER OU
    Remove attribute from users in this OU (e.g., "OU=Users,DC=contoso,DC=com").

.PARAMETER AllActive
    Remove attribute from all active users in domain.

.PARAMETER Domain
    Domain to operate on (default: current domain).

.PARAMETER OutputFile
    Path to CSV file. Default: RemoveAttributeReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication.

.PARAMETER WhatIf
    Show what would be removed without actually removing.

.EXAMPLE
    .\Remove-UserAttribute.ps1 -AttributeName "Department" -GroupName "Sales Team"
    
.EXAMPLE
    .\Remove-UserAttribute.ps1 -AttributeName "Office" -OU "OU=Users,DC=contoso,DC=com"
    
.EXAMPLE
    .\Remove-UserAttribute.ps1 -AttributeName "Title" -AllActive
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$true)]
    [string]$AttributeName,
    
    [Parameter(Mandatory=$false)]
    [string]$GroupName,
    
    [Parameter(Mandatory=$false)]
    [string]$OU,
    
    [Parameter(Mandatory=$false)]
    [switch]$AllActive,
    
    [Parameter(Mandatory=$false)]
    [string]$Domain,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "RemoveAttributeReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

# Main execution
Write-Host "Remove User Attribute Tool" -ForegroundColor Cyan
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

$users = @()

# Get users based on criteria
if ($GroupName) {
    Write-Host "Getting users from group: $GroupName" -ForegroundColor Yellow
    try {
        $group = Get-ADGroup -Identity $GroupName @adParams
        $members = Get-ADGroupMember -Identity $group @adParams -Recursive
        $users = $members | Where-Object { $_.objectClass -eq "user" } | Get-ADUser -Properties $AttributeName @adParams
        Write-Host "Found $($users.Count) user(s) in group" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to get group members: $($_.Exception.Message)"
        exit 1
    }
}
elseif ($OU) {
    Write-Host "Getting users from OU: $OU" -ForegroundColor Yellow
    try {
        $userParams = @{
            SearchBase = $OU
            Filter = "*"
            Properties = $AttributeName
        }
        if ($Domain) { $userParams['Server'] = $Domain }
        if ($Credential) { $userParams['Credential'] = $Credential }
        
        $users = Get-ADUser @userParams
        Write-Host "Found $($users.Count) user(s) in OU" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to get users from OU: $($_.Exception.Message)"
        exit 1
    }
}
elseif ($AllActive) {
    Write-Host "Getting all active users from domain..." -ForegroundColor Yellow
    try {
        $userParams = @{
            Filter = "Enabled -eq 'True'"
            Properties = $AttributeName
        }
        if ($Domain) { $userParams['Server'] = $Domain }
        if ($Credential) { $userParams['Credential'] = $Credential }
        
        $users = Get-ADUser @userParams
        Write-Host "Found $($users.Count) active user(s)" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to get users: $($_.Exception.Message)"
        exit 1
    }
}
else {
    Write-Error "Must specify -GroupName, -OU, or -AllActive"
    exit 1
}

if ($users.Count -eq 0) {
    Write-Error "No users found."
    exit 1
}

Write-Host "Attribute to remove: $AttributeName" -ForegroundColor Yellow
Write-Host "Processing $($users.Count) user(s)..." -ForegroundColor Yellow
if ($WhatIf) {
    Write-Host "MODE: WHATIF (no attributes will be removed)" -ForegroundColor Yellow
}
Write-Host ""

if (-not $WhatIf -and -not $PSCmdlet.ShouldProcess("Remove attribute from $($users.Count) user(s)", "This will remove the attribute. Continue?")) {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
    exit 0
}

$results = @()
foreach ($user in $users) {
    $result = [PSCustomObject]@{
        Username = $user.SamAccountName
        DisplayName = $user.Name
        AttributeName = $AttributeName
        OldValue = if ($user.$AttributeName) { $user.$AttributeName.ToString() } else { "N/A" }
        Status = "Unknown"
        Error = $null
    }
    
    try {
        if ($user.$AttributeName) {
            if (-not $WhatIf) {
                Set-ADUser -Identity $user -Clear $AttributeName @adParams -ErrorAction Stop
                $result.Status = "Removed"
            }
            else {
                $result.Status = "WhatIf - Would Remove"
            }
        }
        else {
            $result.Status = "Already Empty"
        }
    }
    catch {
        $result.Status = "Error"
        $result.Error = $_.Exception.Message
    }
    
    $results += $result
    Write-Host "$($user.SamAccountName) - $($result.Status)" -ForegroundColor $(if ($result.Status -like "*Removed*" -or $result.Status -like "WhatIf*") { "Green" } else { "Gray" })
}

Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
$removed = ($results | Where-Object { $_.Status -like "*Removed*" -or $_.Status -like "WhatIf*" }).Count
Write-Host "Removed: $removed" -ForegroundColor Green
Write-Host "Already Empty: $(($results | Where-Object { $_.Status -eq 'Already Empty' }).Count)" -ForegroundColor Gray
Write-Host "Errors: $(($results | Where-Object { $_.Status -eq 'Error' }).Count)" -ForegroundColor Red

$results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
$results | Format-Table -AutoSize

