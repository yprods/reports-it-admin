<#
.SYNOPSIS
    Adds an attribute to all users in the domain.

.DESCRIPTION
    This script sets a specified attribute value for all users in Active Directory domain.

.PARAMETER AttributeName
    Name of the attribute to set (e.g., "Department", "Title", "Office").

.PARAMETER AttributeValue
    Value to set for the attribute.

.PARAMETER UserList
    Path to text file with specific usernames (optional, sets for all if not specified).

.PARAMETER Filter
    LDAP filter to select specific users (e.g., "Department -eq 'IT'").

.PARAMETER Domain
    Domain to operate on (default: current domain).

.PARAMETER OutputFile
    Path to CSV file. Default: SetAttributeReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication.

.PARAMETER Overwrite
    Overwrite existing attribute values (default: false, only sets if empty).

.PARAMETER WhatIf
    Show what would be set without actually setting.

.EXAMPLE
    .\Set-UserAttribute.ps1 -AttributeName "Department" -AttributeValue "IT"
    
.EXAMPLE
    .\Set-UserAttribute.ps1 -AttributeName "Office" -AttributeValue "Building A" -UserList "users.txt"
    
.EXAMPLE
    .\Set-UserAttribute.ps1 -AttributeName "Title" -AttributeValue "Employee" -Filter "Enabled -eq 'True'" -Overwrite
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$true)]
    [string]$AttributeName,
    
    [Parameter(Mandatory=$true)]
    [string]$AttributeValue,
    
    [Parameter(Mandatory=$false)]
    [string]$UserList,
    
    [Parameter(Mandatory=$false)]
    [string]$Filter,
    
    [Parameter(Mandatory=$false)]
    [string]$Domain,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "SetAttributeReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [switch]$Overwrite,
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

# Main execution
Write-Host "Set User Attribute Tool" -ForegroundColor Cyan
Write-Host "======================" -ForegroundColor Cyan
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

# Get users
if ($UserList -and (Test-Path $UserList)) {
    Write-Host "Reading user list from: $UserList" -ForegroundColor Yellow
    $userNames = Get-Content $UserList | Where-Object { $_.Trim() -ne "" }
    foreach ($userName in $userNames) {
        try {
            $user = Get-ADUser -Identity $userName -Properties $AttributeName @adParams
            $users += $user
        }
        catch {
            Write-Warning "User not found: $userName"
        }
    }
    Write-Host "Found $($users.Count) user(s)" -ForegroundColor Green
}
else {
    Write-Host "Getting users from domain..." -ForegroundColor Yellow
    try {
        $userParams = @{
            Filter = if ($Filter) { $Filter } else { "*" }
            Properties = $AttributeName
        }
        if ($Domain) { $userParams['Server'] = $Domain }
        if ($Credential) { $userParams['Credential'] = $Credential }
        
        $users = Get-ADUser @userParams
        Write-Host "Found $($users.Count) user(s)" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to get users: $($_.Exception.Message)"
        exit 1
    }
}

if ($users.Count -eq 0) {
    Write-Error "No users found."
    exit 1
}

Write-Host "Attribute: $AttributeName" -ForegroundColor Yellow
Write-Host "Value: $AttributeValue" -ForegroundColor Yellow
Write-Host "Processing $($users.Count) user(s)..." -ForegroundColor Yellow
if ($Overwrite) {
    Write-Host "Overwrite: ENABLED" -ForegroundColor Cyan
}
if ($WhatIf) {
    Write-Host "MODE: WHATIF (no attributes will be set)" -ForegroundColor Yellow
}
Write-Host ""

if (-not $WhatIf -and -not $PSCmdlet.ShouldProcess("Set attribute on $($users.Count) user(s)", "This will set the attribute. Continue?")) {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
    exit 0
}

$results = @()
foreach ($user in $users) {
    $result = [PSCustomObject]@{
        Username = $user.SamAccountName
        DisplayName = $user.Name
        AttributeName = $AttributeName
        OldValue = if ($user.$AttributeName) { $user.$AttributeName.ToString() } else { "Empty" }
        NewValue = $AttributeValue
        Status = "Unknown"
        Error = $null
    }
    
    try {
        # Check if attribute already has a value
        if ($user.$AttributeName -and -not $Overwrite) {
            $result.Status = "Skipped (Has Value)"
        }
        else {
            if (-not $WhatIf) {
                $setParams = @{
                    Identity = $user
                }
                $setParams[$AttributeName] = $AttributeValue
                Set-ADUser @setParams @adParams -ErrorAction Stop
                $result.Status = "Set"
            }
            else {
                $result.Status = "WhatIf - Would Set"
            }
        }
    }
    catch {
        $result.Status = "Error"
        $result.Error = $_.Exception.Message
    }
    
    $results += $result
}

Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
$set = ($results | Where-Object { $_.Status -like "*Set*" -or $_.Status -like "WhatIf*" }).Count
Write-Host "Set: $set" -ForegroundColor Green
Write-Host "Skipped: $(($results | Where-Object { $_.Status -like "*Skipped*" }).Count)" -ForegroundColor Gray
Write-Host "Errors: $(($results | Where-Object { $_.Status -eq 'Error' }).Count)" -ForegroundColor Red

$results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
$results | Format-Table -AutoSize

