<#
.SYNOPSIS
    Generates and sets passwords for a list of users in Active Directory.

.DESCRIPTION
    This script generates secure passwords and sets them for users in Active Directory.
    It supports custom password policies and can generate passwords based on requirements.

.PARAMETER UserList
    Path to a text file containing usernames (one per line).

.PARAMETER Username
    Single username or array of usernames to process.

.PARAMETER Domain
    Domain to operate on (default: current domain).

.PARAMETER OutputFile
    Path to CSV file where results will be exported. Default: UserPasswordReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication (optional).

.PARAMETER PasswordLength
    Length of generated password (default: 16).

.PARAMETER IncludeSpecialChars
    Include special characters in password (default: true).

.PARAMETER IncludeNumbers
    Include numbers in password (default: true).

.PARAMETER IncludeUppercase
    Include uppercase letters in password (default: true).

.PARAMETER IncludeLowercase
    Include lowercase letters in password (default: true).

.PARAMETER ForceChangeAtLogon
    Force user to change password at next logon (default: false).

.PARAMETER PasswordNeverExpires
    Set password to never expire (default: false).

.PARAMETER WhatIf
    Show what would be done without actually changing passwords.

.EXAMPLE
    .\Set-UserPassword.ps1 -UserList "users.txt"
    
.EXAMPLE
    .\Set-UserPassword.ps1 -Username "jdoe","jsmith" -PasswordLength 20
    
.EXAMPLE
    .\Set-UserPassword.ps1 -UserList "users.txt" -ForceChangeAtLogon -WhatIf
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false)]
    [string]$UserList,
    
    [Parameter(Mandatory=$false)]
    [string[]]$Username,
    
    [Parameter(Mandatory=$false)]
    [string]$Domain,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "UserPasswordReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [int]$PasswordLength = 16,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeSpecialChars = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeNumbers = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeUppercase = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeLowercase = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$ForceChangeAtLogon,
    
    [Parameter(Mandatory=$false)]
    [switch]$PasswordNeverExpires,
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

# Function to generate secure password
function New-SecurePassword {
    param(
        [int]$Length,
        [bool]$SpecialChars,
        [bool]$Numbers,
        [bool]$Uppercase,
        [bool]$Lowercase
    )
    
    $chars = @()
    
    if ($Lowercase) {
        $chars += "abcdefghijklmnopqrstuvwxyz"
    }
    if ($Uppercase) {
        $chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    }
    if ($Numbers) {
        $chars += "0123456789"
    }
    if ($SpecialChars) {
        $chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    }
    
    if ($chars.Count -eq 0) {
        throw "At least one character type must be enabled"
    }
    
    $allChars = $chars -join ""
    $password = ""
    
    # Ensure at least one character from each enabled type
    if ($Lowercase) {
        $password += "abcdefghijklmnopqrstuvwxyz"[(Get-Random -Maximum 26)]
    }
    if ($Uppercase) {
        $password += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[(Get-Random -Maximum 26)]
    }
    if ($Numbers) {
        $password += "0123456789"[(Get-Random -Maximum 10)]
    }
    if ($SpecialChars) {
        $password += "!@#$%^&*()_+-=[]{}|;:,.<>?"[(Get-Random -Maximum 25)]
    }
    
    # Fill remaining length with random characters
    for ($i = $password.Length; $i -lt $Length; $i++) {
        $password += $allChars[(Get-Random -Maximum $allChars.Length)]
    }
    
    # Shuffle the password
    $passwordArray = $password.ToCharArray()
    $shuffled = $passwordArray | Get-Random -Count $passwordArray.Length
    $password = -join $shuffled
    
    return $password
}

# Function to set password for a single user
function Set-UserPassword {
    param(
        [string]$User,
        [string]$DomainName,
        [System.Management.Automation.PSCredential]$Cred,
        [int]$Length,
        [bool]$SpecialChars,
        [bool]$Numbers,
        [bool]$Uppercase,
        [bool]$Lowercase,
        [bool]$ForceChange,
        [bool]$NeverExpires,
        [bool]$WhatIfMode
    )
    
    $result = [PSCustomObject]@{
        Username = $User
        UserPrincipalName = "N/A"
        DisplayName = "N/A"
        Password = "N/A"
        PasswordLength = $Length
        Status = "Unknown"
        ForceChangeAtLogon = $ForceChange
        PasswordNeverExpires = $NeverExpires
        LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Error = $null
    }
    
    try {
        # Import Active Directory module if available
        if (-not (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
            if (Get-Module -ListAvailable -Name ActiveDirectory) {
                Import-Module ActiveDirectory -ErrorAction Stop
            }
            else {
                throw "Active Directory PowerShell module not found. Install RSAT-AD-PowerShell."
            }
        }
        
        # Find user
        $adParams = @{
            Filter = { SamAccountName -eq $User }
            Properties = @("Name", "UserPrincipalName", "Enabled")
            ErrorAction = "Stop"
        }
        
        if ($DomainName) {
            $adParams['Server'] = $DomainName
        }
        
        if ($Cred) {
            $adParams['Credential'] = $Cred
        }
        
        $adUser = Get-ADUser @adParams
        
        if ($adUser) {
            $result.Username = $adUser.SamAccountName
            $result.UserPrincipalName = if ($adUser.UserPrincipalName) { $adUser.UserPrincipalName } else { "N/A" }
            $result.DisplayName = $adUser.Name
            
            # Generate password
            $password = New-SecurePassword -Length $Length -SpecialChars $SpecialChars -Numbers $Numbers -Uppercase $Uppercase -Lowercase $Lowercase
            $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
            
            if (-not $WhatIfMode) {
                # Set password
                Set-ADAccountPassword -Identity $adUser -NewPassword $securePassword -Reset -ErrorAction Stop
                
                # Set additional properties
                if ($ForceChange) {
                    Set-ADUser -Identity $adUser -ChangePasswordAtLogon $true -ErrorAction SilentlyContinue
                }
                
                if ($NeverExpires) {
                    Set-ADUser -Identity $adUser -PasswordNeverExpires $true -ErrorAction SilentlyContinue
                }
                
                $result.Password = $password
                $result.Status = "Success"
            }
            else {
                $result.Password = "***GENERATED*** (WhatIf mode)"
                $result.Status = "WhatIf - Would Set Password"
            }
        }
        else {
            $result.Status = "User Not Found"
            $result.Error = "User not found in Active Directory"
        }
    }
    catch {
        $result.Status = "Error"
        $result.Error = $_.Exception.Message
    }
    
    return $result
}

# Main execution
Write-Host "User Password Generator Tool" -ForegroundColor Cyan
Write-Host "============================" -ForegroundColor Cyan
Write-Host ""

# Check for Active Directory module
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "Active Directory PowerShell module is required. Install RSAT-AD-PowerShell feature."
    exit 1
}

Import-Module ActiveDirectory -ErrorAction Stop

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

# Remove duplicates
$users = $users | Select-Object -Unique

if ($users.Count -eq 0) {
    Write-Error "No users specified. Use -UserList or -Username parameter."
    exit 1
}

Write-Host "Password Settings:" -ForegroundColor Yellow
Write-Host "  Length: $PasswordLength" -ForegroundColor Gray
Write-Host "  Special Characters: $IncludeSpecialChars" -ForegroundColor Gray
Write-Host "  Numbers: $IncludeNumbers" -ForegroundColor Gray
Write-Host "  Uppercase: $IncludeUppercase" -ForegroundColor Gray
Write-Host "  Lowercase: $IncludeLowercase" -ForegroundColor Gray
Write-Host "  Force Change at Logon: $ForceChangeAtLogon" -ForegroundColor Gray
Write-Host "  Password Never Expires: $PasswordNeverExpires" -ForegroundColor Gray
if ($WhatIf) {
    Write-Host "  MODE: WHATIF (no changes will be made)" -ForegroundColor Yellow
}
Write-Host ""
Write-Host "Found $($users.Count) unique user(s) to process" -ForegroundColor Green
Write-Host ""

# Confirm action
if (-not $WhatIf -and -not $PSCmdlet.ShouldProcess("Set passwords for $($users.Count) user(s)", "This will generate and set new passwords. Continue?")) {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
    exit 0
}

# Process each user
$results = @()
$total = $users.Count
$current = 0

foreach ($user in $users) {
    $current++
    Write-Progress -Activity "Generating Passwords" -Status "Processing $user ($current of $total)" -PercentComplete (($current / $total) * 100)
    
    Write-Host "[$current/$total] Processing $user..." -NoNewline
    
    $result = Set-UserPassword -User $user -DomainName $Domain -Cred $Credential -Length $PasswordLength -SpecialChars $IncludeSpecialChars.IsPresent -Numbers $IncludeNumbers.IsPresent -Uppercase $IncludeUppercase.IsPresent -Lowercase $IncludeLowercase.IsPresent -ForceChange $ForceChangeAtLogon.IsPresent -NeverExpires $PasswordNeverExpires.IsPresent -WhatIfMode $WhatIf.IsPresent
    
    $results += $result
    
    $statusColor = switch ($result.Status) {
        "Success" { "Green" }
        "WhatIf - Would Set Password" { "Yellow" }
        "User Not Found" { "Red" }
        "Error" { "Red" }
        default { "Gray" }
    }
    
    Write-Host " $($result.Status)" -ForegroundColor $statusColor
    if ($result.Error) {
        Write-Host "  Error: $($result.Error)" -ForegroundColor Red
    }
}

Write-Progress -Activity "Generating Passwords" -Completed

# Display summary
Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "========" -ForegroundColor Cyan
$success = ($results | Where-Object { $_.Status -eq "Success" -or $_.Status -like "WhatIf*" }).Count
$notFound = ($results | Where-Object { $_.Status -eq "User Not Found" }).Count
$errors = ($results | Where-Object { $_.Status -eq "Error" }).Count

Write-Host "Success:     $success" -ForegroundColor Green
Write-Host "Not Found:   $notFound" -ForegroundColor Red
Write-Host "Errors:      $errors" -ForegroundColor Red
Write-Host ""

# Export to CSV
try {
    $results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
    Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
    if (-not $WhatIf) {
        Write-Host "WARNING: This file contains passwords. Secure it appropriately!" -ForegroundColor Red
    }
}
catch {
    Write-Error "Failed to export results: $($_.Exception.Message)"
}

# Display results table (passwords shown for verification)
Write-Host ""
Write-Host "Results:" -ForegroundColor Cyan
Write-Host "========" -ForegroundColor Cyan
$results | Format-Table -AutoSize Username, DisplayName, Status, Password, ForceChangeAtLogon

