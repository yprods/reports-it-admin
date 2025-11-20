<#
.SYNOPSIS
    Resets passwords for multiple users in Active Directory.

.DESCRIPTION
    This script resets passwords for a list of users in Active Directory.
    Can generate secure random passwords or use a specified password.
    Supports forcing password change on next logon.

.PARAMETER UserList
    Path to text file with usernames (one per line) or array of usernames.

.PARAMETER Password
    Specific password to set for all users (optional, generates random if not specified).

.PARAMETER PasswordLength
    Length of generated password (default: 16).

.PARAMETER ForceChangeOnLogon
    Force users to change password on next logon (default: false).

.PARAMETER Domain
    Domain to operate on (default: current domain).

.PARAMETER OutputFile
    Path to CSV file. Default: ResetPasswordReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication.

.PARAMETER WhatIf
    Show what would be reset without actually resetting.

.EXAMPLE
    .\Reset-UserPasswords.ps1 -UserList "users.txt"
    
.EXAMPLE
    .\Reset-UserPasswords.ps1 -UserList @("user1", "user2") -Password "TempPass123!"
    
.EXAMPLE
    .\Reset-UserPasswords.ps1 -UserList "users.txt" -PasswordLength 20 -ForceChangeOnLogon
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$true)]
    [object]$UserList,
    
    [Parameter(Mandatory=$false)]
    [string]$Password,
    
    [Parameter(Mandatory=$false)]
    [int]$PasswordLength = 16,
    
    [Parameter(Mandatory=$false)]
    [switch]$ForceChangeOnLogon,
    
    [Parameter(Mandatory=$false)]
    [string]$Domain,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "ResetPasswordReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

# Function to generate secure random password
function New-SecurePassword {
    param([int]$Length = 16)
    
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
    $password = ""
    
    # Ensure at least one of each required character type
    $password += [char]((65..90) | Get-Random)  # Uppercase
    $password += [char]((97..122) | Get-Random)   # Lowercase
    $password += [char]((48..57) | Get-Random)    # Number
    $password += @('!','@','#','$','%','^','&','*') | Get-Random  # Special
    
    # Fill the rest randomly
    for ($i = $password.Length; $i -lt $Length; $i++) {
        $password += $chars[(Get-Random -Maximum $chars.Length)]
    }
    
    # Shuffle the password
    $passwordArray = $password.ToCharArray()
    $shuffled = $passwordArray | Sort-Object { Get-Random }
    return -join $shuffled
}

# Main execution
Write-Host "Reset User Passwords Tool" -ForegroundColor Cyan
Write-Host "=========================" -ForegroundColor Cyan
Write-Host ""

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "Active Directory PowerShell module is required."
    exit 1
}

Import-Module ActiveDirectory -ErrorAction Stop

$adParams = @{ ErrorAction = "Stop" }
if ($Domain) { $adParams['Server'] = $Domain }
if ($Credential) { $adParams['Credential'] = $Credential }

# Get user list
$users = @()

if ($UserList -is [string]) {
    # File path
    if (Test-Path $UserList) {
        Write-Host "Reading user list from: $UserList" -ForegroundColor Yellow
        $userNames = Get-Content $UserList | Where-Object { $_.Trim() -ne "" }
        foreach ($userName in $userNames) {
            try {
                $user = Get-ADUser -Identity $userName.Trim() @adParams -Properties Enabled, PasswordLastSet
                $users += $user
            }
            catch {
                Write-Warning "User not found: $userName"
            }
        }
    }
    else {
        Write-Error "User list file not found: $UserList"
        exit 1
    }
}
elseif ($UserList -is [array]) {
    # Array of usernames
    Write-Host "Processing user array..." -ForegroundColor Yellow
    foreach ($userName in $UserList) {
        try {
            $user = Get-ADUser -Identity $userName.Trim() @adParams -Properties Enabled, PasswordLastSet
            $users += $user
        }
        catch {
            Write-Warning "User not found: $userName"
        }
    }
}
else {
    Write-Error "UserList must be a file path (string) or array of usernames."
    exit 1
}

if ($users.Count -eq 0) {
    Write-Error "No valid users found."
    exit 1
}

Write-Host "Found $($users.Count) user(s) to process" -ForegroundColor Green
Write-Host ""

# Determine password
$passwordToSet = $Password
if (-not $passwordToSet) {
    Write-Host "Generating secure random passwords..." -ForegroundColor Yellow
    $passwordToSet = New-SecurePassword -Length $PasswordLength
    Write-Host "Generated password length: $PasswordLength" -ForegroundColor Gray
}
else {
    Write-Host "Using specified password" -ForegroundColor Yellow
}

Write-Host "Force change on logon: $ForceChangeOnLogon" -ForegroundColor Yellow
if ($WhatIf) {
    Write-Host "MODE: WHATIF (no passwords will be reset)" -ForegroundColor Yellow
}
Write-Host ""

if (-not $WhatIf -and -not $PSCmdlet.ShouldProcess("Reset passwords for $($users.Count) user(s)", "This will reset passwords. Continue?")) {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
    exit 0
}

# Convert password to secure string
$securePassword = ConvertTo-SecureString -String $passwordToSet -AsPlainText -Force

$results = @()
$passwordFile = $OutputFile -replace "\.csv$", "_Passwords.txt"
$passwordEntries = @()

foreach ($user in $users) {
    $result = [PSCustomObject]@{
        Username = $user.SamAccountName
        DisplayName = $user.Name
        Enabled = $user.Enabled
        PasswordLastSet = if ($user.PasswordLastSet) { $user.PasswordLastSet.ToString() } else { "Never" }
        NewPassword = if (-not $Password) { "Generated" } else { "Specified" }
        Status = "Unknown"
        Error = $null
        LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    try {
        if (-not $WhatIf) {
            # Reset password
            Set-ADAccountPassword -Identity $user -NewPassword $securePassword -Reset @adParams -ErrorAction Stop
            
            # Set password change flag if needed
            if ($ForceChangeOnLogon) {
                Set-ADUser -Identity $user -ChangePasswordAtLogon $true @adParams -ErrorAction Stop
            }
            
            $result.Status = "Reset"
            
            # Store password for this user (if using generated passwords)
            if (-not $Password) {
                $userPassword = New-SecurePassword -Length $PasswordLength
                $passwordEntries += "$($user.SamAccountName) : $userPassword"
            }
        }
        else {
            $result.Status = "WhatIf - Would Reset"
            if (-not $Password) {
                $userPassword = New-SecurePassword -Length $PasswordLength
                $passwordEntries += "$($user.SamAccountName) : $userPassword (WhatIf)"
            }
        }
    }
    catch {
        $result.Status = "Error"
        $result.Error = $_.Exception.Message
    }
    
    $results += $result
    Write-Host "$($user.SamAccountName) - $($result.Status)" -ForegroundColor $(if ($result.Status -like "*Reset*" -or $result.Status -like "WhatIf*") { "Green" } else { "Red" })
}

Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
$reset = ($results | Where-Object { $_.Status -like "*Reset*" -or $_.Status -like "WhatIf*" }).Count
Write-Host "Reset: $reset" -ForegroundColor Green
Write-Host "Errors: $(($results | Where-Object { $_.Status -eq 'Error' }).Count)" -ForegroundColor Red

# Export results
$results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "Results exported to: $OutputFile" -ForegroundColor Green

# Export passwords if generated
if (-not $Password -and $passwordEntries.Count -gt 0) {
    $passwordEntries | Out-File -FilePath $passwordFile -Encoding UTF8
    Write-Host "Generated passwords exported to: $passwordFile" -ForegroundColor Yellow
    Write-Host "WARNING: Keep this file secure and delete it after distributing passwords!" -ForegroundColor Red
}
elseif ($Password) {
    Write-Host ""
    Write-Host "Password used for all users: $Password" -ForegroundColor Yellow
    Write-Host "WARNING: This password was used for all users. Ensure it meets complexity requirements!" -ForegroundColor Red
}

$results | Format-Table -AutoSize

