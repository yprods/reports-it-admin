<#
.SYNOPSIS
    Finds all locked user accounts in Active Directory domain.

.DESCRIPTION
    This script queries Active Directory to find all user accounts that are currently
    locked out or have been locked out recently.

.PARAMETER Domain
    Domain to search (default: current domain).

.PARAMETER OutputFile
    Path to CSV file where results will be exported. Default: LockedUsersReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication (optional).

.PARAMETER SearchBase
    Specific OU or container to search (default: entire domain).

.PARAMETER IncludeRecentlyUnlocked
    Include users that were recently unlocked (within last 24 hours).

.PARAMETER LockoutThreshold
    Number of failed attempts before lockout (default: query from domain policy).

.EXAMPLE
    .\Get-LockedUsers.ps1
    
.EXAMPLE
    .\Get-LockedUsers.ps1 -Domain "contoso.com" -IncludeRecentlyUnlocked
    
.EXAMPLE
    .\Get-LockedUsers.ps1 -SearchBase "OU=Users,DC=contoso,DC=com"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Domain,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "LockedUsersReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [string]$SearchBase,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeRecentlyUnlocked,
    
    [Parameter(Mandatory=$false)]
    [int]$LockoutThreshold = 0
)

# Function to get domain lockout policy
function Get-DomainLockoutPolicy {
    param(
        [string]$DomainName,
        [System.Management.Automation.PSCredential]$Cred
    )
    
    try {
        $policyParams = @{
            Identity = "Default Domain Policy"
            ErrorAction = "SilentlyContinue"
        }
        
        if ($DomainName) {
            $policyParams['Domain'] = $DomainName
        }
        
        if ($Cred) {
            $policyParams['Credential'] = $Cred
        }
        
        $policy = Get-GPO @policyParams
        
        if ($policy) {
            $lockoutThreshold = (Get-GPRegistryValue -Name "Default Domain Policy" -Key "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -ValueName "LockoutThreshold" -ErrorAction SilentlyContinue).Value
            if ($lockoutThreshold) {
                return $lockoutThreshold
            }
        }
    }
    catch {
        # Continue with default
    }
    
    return 5  # Default threshold
}

# Main execution
Write-Host "Locked Users Query Tool" -ForegroundColor Cyan
Write-Host "=======================" -ForegroundColor Cyan
Write-Host ""

# Check for Active Directory module
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "Active Directory PowerShell module is required. Install RSAT-AD-PowerShell feature."
    exit 1
}

Import-Module ActiveDirectory -ErrorAction Stop

try {
    # Get domain lockout threshold if not specified
    if ($LockoutThreshold -eq 0) {
        Write-Host "Querying domain lockout policy..." -ForegroundColor Yellow
        $LockoutThreshold = Get-DomainLockoutPolicy -DomainName $Domain -Cred $Credential
        Write-Host "Domain lockout threshold: $LockoutThreshold failed attempts" -ForegroundColor Green
    }
    
    # Build AD query parameters
    $adParams = @{
        Filter = "*"
        Properties = @("Name", "SamAccountName", "UserPrincipalName", "LockedOut", "BadPwdCount", "LastBadPasswordAttempt", "AccountLockoutTime", "Enabled", "LastLogonDate", "DistinguishedName", "Description", "Department", "Title", "Manager", "CanonicalName")
        ErrorAction = "Stop"
    }
    
    if ($Domain) {
        $adParams['Server'] = $Domain
    }
    
    if ($SearchBase) {
        $adParams['SearchBase'] = $SearchBase
    }
    
    if ($Credential) {
        $adParams['Credential'] = $Credential
    }
    
    Write-Host "Querying Active Directory for users..." -ForegroundColor Yellow
    
    # Get all users
    $allUsers = Get-ADUser @adParams
    
    Write-Host "Found $($allUsers.Count) total user(s)" -ForegroundColor Green
    Write-Host "Filtering for locked users..." -ForegroundColor Yellow
    Write-Host ""
    
    # Filter for locked users
    $results = @()
    $cutoffDate = (Get-Date).AddHours(-24)
    
    foreach ($user in $allUsers) {
        $isLocked = $false
        $lockReason = @()
        
        # Check if currently locked
        if ($user.LockedOut -eq $true) {
            $isLocked = $true
            $lockReason += "Currently Locked"
        }
        
        # Check bad password count
        if ($user.BadPwdCount -ge $LockoutThreshold) {
            $isLocked = $true
            $lockReason += "Bad password count: $($user.BadPwdCount) (Threshold: $LockoutThreshold)"
        }
        
        # Check account lockout time
        if ($user.AccountLockoutTime -and $user.AccountLockoutTime -gt (Get-Date).AddDays(-1)) {
            $isLocked = $true
            if ($IncludeRecentlyUnlocked -or $user.LockedOut) {
                $lockReason += "Locked at: $($user.AccountLockoutTime)"
            }
        }
        
        # Check last bad password attempt (recent)
        if ($user.LastBadPasswordAttempt -and $user.LastBadPasswordAttempt -gt $cutoffDate) {
            $isLocked = $true
            $lockReason += "Recent failed login: $($user.LastBadPasswordAttempt)"
        }
        
        if ($isLocked) {
            $result = [PSCustomObject]@{
                Username = $user.SamAccountName
                UserPrincipalName = if ($user.UserPrincipalName) { $user.UserPrincipalName } else { "N/A" }
                DisplayName = $user.Name
                Enabled = $user.Enabled
                LockedOut = $user.LockedOut
                BadPwdCount = $user.BadPwdCount
                AccountLockoutTime = if ($user.AccountLockoutTime) { $user.AccountLockoutTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
                LastBadPasswordAttempt = if ($user.LastBadPasswordAttempt) { $user.LastBadPasswordAttempt.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
                LastLogonDate = if ($user.LastLogonDate) { $user.LastLogonDate.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
                DistinguishedName = $user.DistinguishedName
                CanonicalName = if ($user.CanonicalName) { $user.CanonicalName } else { "N/A" }
                Description = if ($user.Description) { $user.Description } else { "N/A" }
                Department = if ($user.Department) { $user.Department } else { "N/A" }
                Title = if ($user.Title) { $user.Title } else { "N/A" }
                Manager = if ($user.Manager) { $user.Manager } else { "N/A" }
                LockReason = ($lockReason -join "; ")
                Status = if ($user.LockedOut) { "Currently Locked" } else { "Recently Locked/At Risk" }
            }
            $results += $result
        }
    }
    
    Write-Host "Found $($results.Count) locked or at-risk user(s)" -ForegroundColor Green
    Write-Host ""
    
    # Display summary
    Write-Host "Summary:" -ForegroundColor Cyan
    Write-Host "========" -ForegroundColor Cyan
    $currentlyLocked = ($results | Where-Object { $_.LockedOut -eq $true }).Count
    $atRisk = ($results | Where-Object { $_.LockedOut -eq $false -and $_.BadPwdCount -ge $LockoutThreshold }).Count
    $recentLockouts = ($results | Where-Object { $_.AccountLockoutTime -ne "N/A" }).Count
    $recentBadAttempts = ($results | Where-Object { $_.LastBadPasswordAttempt -ne "N/A" }).Count
    $disabled = ($results | Where-Object { $_.Enabled -eq $false }).Count
    
    Write-Host "Currently Locked:   $currentlyLocked" -ForegroundColor Red
    Write-Host "At Risk (Bad Pwd):  $atRisk" -ForegroundColor Yellow
    Write-Host "Recent Lockouts:    $recentLockouts" -ForegroundColor Yellow
    Write-Host "Recent Bad Attempts: $recentBadAttempts" -ForegroundColor Yellow
    Write-Host "Disabled Accounts:  $disabled" -ForegroundColor Gray
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
    Write-Host "Locked Users:" -ForegroundColor Cyan
    Write-Host "=============" -ForegroundColor Cyan
    $results | Format-Table -AutoSize Username, DisplayName, LockedOut, BadPwdCount, AccountLockoutTime, Status
    
    # Show by department
    if (($results | Where-Object { $_.Department -ne "N/A" }).Count -gt 0) {
        Write-Host ""
        Write-Host "Locked Users by Department:" -ForegroundColor Cyan
        Write-Host "===========================" -ForegroundColor Cyan
        $results | Where-Object { $_.Department -ne "N/A" } | Group-Object -Property Department | Select-Object Count, Name | Sort-Object Count -Descending | Format-Table -AutoSize
    }
}
catch {
    Write-Error "Failed to query Active Directory: $($_.Exception.Message)"
    exit 1
}

