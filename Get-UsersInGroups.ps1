<#
.SYNOPSIS
    Finds all users in groups and OUs in Active Directory.

.DESCRIPTION
    This script queries Active Directory to find users and their group memberships,
    OU locations, and provides comprehensive reporting on user organization.

.PARAMETER Domain
    Domain to search (default: current domain).

.PARAMETER OutputFile
    Path to CSV file where results will be exported. Default: UsersInGroupsReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication (optional).

.PARAMETER SearchBase
    Specific OU or container to search (default: entire domain).

.PARAMETER GroupName
    Filter by specific group name (supports wildcards).

.PARAMETER OUName
    Filter by specific OU name (supports wildcards).

.PARAMETER IncludeNestedGroups
    Include nested group memberships (default: true).

.PARAMETER IncludeDisabled
    Include disabled user accounts (default: false).

.EXAMPLE
    .\Get-UsersInGroups.ps1
    
.EXAMPLE
    .\Get-UsersInGroups.ps1 -GroupName "Domain Admins"
    
.EXAMPLE
    .\Get-UsersInGroups.ps1 -OUName "*Sales*" -IncludeNestedGroups
    
.EXAMPLE
    .\Get-UsersInGroups.ps1 -SearchBase "OU=Users,DC=contoso,DC=com"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Domain,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "UsersInGroupsReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [string]$SearchBase,
    
    [Parameter(Mandatory=$false)]
    [string]$GroupName = "*",
    
    [Parameter(Mandatory=$false)]
    [string]$OUName = "*",
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeNestedGroups = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeDisabled
)

# Main execution
Write-Host "Users in Groups/OU Query Tool" -ForegroundColor Cyan
Write-Host "=============================" -ForegroundColor Cyan
Write-Host ""

# Check for Active Directory module
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "Active Directory PowerShell module is required. Install RSAT-AD-PowerShell feature."
    exit 1
}

Import-Module ActiveDirectory -ErrorAction Stop

try {
    Write-Host "Querying Active Directory..." -ForegroundColor Yellow
    Write-Host ""
    
    $results = @()
    
    # Build user query parameters
    $userParams = @{
        Filter = "*"
        Properties = @("Name", "SamAccountName", "UserPrincipalName", "Enabled", "DistinguishedName", "CanonicalName", "MemberOf", "Department", "Title", "Manager", "LastLogonDate", "Created")
        ErrorAction = "Stop"
    }
    
    if ($Domain) {
        $userParams['Server'] = $Domain
    }
    
    if ($SearchBase) {
        $userParams['SearchBase'] = $SearchBase
    }
    
    if ($Credential) {
        $userParams['Credential'] = $Credential
    }
    
    if (-not $IncludeDisabled) {
        $userParams['Filter'] = "Enabled -eq 'True'"
    }
    
    # Get all users
    Write-Host "Retrieving users..." -ForegroundColor Yellow
    $allUsers = Get-ADUser @userParams
    
    Write-Host "Found $($allUsers.Count) user(s)" -ForegroundColor Green
    
    # Build group query parameters
    $groupParams = @{
        Filter = "*"
        Properties = @("Name", "DistinguishedName", "CanonicalName", "Members", "MemberOf", "Description")
        ErrorAction = "Stop"
    }
    
    if ($Domain) {
        $groupParams['Server'] = $Domain
    }
    
    if ($SearchBase) {
        $groupParams['SearchBase'] = $SearchBase
    }
    
    if ($Credential) {
        $groupParams['Credential'] = $Credential
    }
    
    if ($GroupName -ne "*") {
        $groupParams['Filter'] = "Name -like '$GroupName'"
    }
    
    # Get groups
    Write-Host "Retrieving groups..." -ForegroundColor Yellow
    $allGroups = Get-ADGroup @groupParams
    
    Write-Host "Found $($allGroups.Count) group(s)" -ForegroundColor Green
    Write-Host ""
    
    # Process each user
    Write-Host "Processing user memberships..." -ForegroundColor Yellow
    $total = $allUsers.Count
    $current = 0
    
    foreach ($user in $allUsers) {
        $current++
        Write-Progress -Activity "Processing Users" -Status "Processing $($user.SamAccountName) ($current of $total)" -PercentComplete (($current / $total) * 100)
        
        # Get user's OU
        $ouPath = $user.CanonicalName
        if ($ouPath) {
            $ouParts = $ouPath -split "/"
            $ouName = $ouParts[-2]  # Parent OU
            $domainName = $ouParts[0]
        }
        else {
            $ouName = "N/A"
            $domainName = "N/A"
        }
        
        # Check OU filter
        if ($OUName -ne "*" -and $ouName -notlike $OUName) {
            continue
        }
        
        # Get direct group memberships
        $directGroups = @()
        if ($user.MemberOf) {
            foreach ($groupDN in $user.MemberOf) {
                $group = $allGroups | Where-Object { $_.DistinguishedName -eq $groupDN }
                if ($group) {
                    $directGroups += $group
                }
            }
        }
        
        # Get all group memberships (including nested)
        $allUserGroups = @()
        if ($IncludeNestedGroups) {
            $allUserGroups = Get-ADPrincipalGroupMembership -Identity $user -ErrorAction SilentlyContinue
        }
        else {
            $allUserGroups = $directGroups
        }
        
        # Create entry for user with OU info
        if ($allUserGroups.Count -eq 0) {
            $result = [PSCustomObject]@{
                Username = $user.SamAccountName
                UserPrincipalName = if ($user.UserPrincipalName) { $user.UserPrincipalName } else { "N/A" }
                DisplayName = $user.Name
                Enabled = $user.Enabled
                OU = if ($ouName) { $ouName } else { "N/A" }
                OUDistinguishedName = $user.DistinguishedName
                GroupName = "No Groups"
                GroupDistinguishedName = "N/A"
                GroupType = "N/A"
                IsNested = $false
                Department = if ($user.Department) { $user.Department } else { "N/A" }
                Title = if ($user.Title) { $user.Title } else { "N/A" }
                LastLogonDate = if ($user.LastLogonDate) { $user.LastLogonDate.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
            }
            $results += $result
        }
        else {
            foreach ($group in $allUserGroups) {
                $isNested = $directGroups -notcontains $group
                
                $result = [PSCustomObject]@{
                    Username = $user.SamAccountName
                    UserPrincipalName = if ($user.UserPrincipalName) { $user.UserPrincipalName } else { "N/A" }
                    DisplayName = $user.Name
                    Enabled = $user.Enabled
                    OU = if ($ouName) { $ouName } else { "N/A" }
                    OUDistinguishedName = $user.DistinguishedName
                    GroupName = $group.Name
                    GroupDistinguishedName = $group.DistinguishedName
                    GroupType = if ($group.GroupCategory) { $group.GroupCategory } else { "N/A" }
                    IsNested = $isNested
                    Department = if ($user.Department) { $user.Department } else { "N/A" }
                    Title = if ($user.Title) { $user.Title } else { "N/A" }
                    LastLogonDate = if ($user.LastLogonDate) { $user.LastLogonDate.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
                }
                $results += $result
            }
        }
    }
    
    Write-Progress -Activity "Processing Users" -Completed
    
    Write-Host "Found $($results.Count) user-group relationship(s)" -ForegroundColor Green
    Write-Host ""
    
    # Display summary
    Write-Host "Summary:" -ForegroundColor Cyan
    Write-Host "========" -ForegroundColor Cyan
    $totalUsers = ($results | Select-Object -Unique Username).Count
    $totalGroups = ($results | Where-Object { $_.GroupName -ne "No Groups" } | Select-Object -Unique GroupName).Count
    $usersInGroups = ($results | Where-Object { $_.GroupName -ne "No Groups" } | Select-Object -Unique Username).Count
    $usersNoGroups = ($results | Where-Object { $_.GroupName -eq "No Groups" } | Select-Object -Unique Username).Count
    $nestedMemberships = ($results | Where-Object { $_.IsNested -eq $true }).Count
    $uniqueOUs = ($results | Select-Object -Unique OU).Count
    
    Write-Host "Total Users:        $totalUsers" -ForegroundColor Green
    Write-Host "Total Groups:       $totalGroups" -ForegroundColor Cyan
    Write-Host "Users in Groups:    $usersInGroups" -ForegroundColor Green
    Write-Host "Users with No Groups: $usersNoGroups" -ForegroundColor Yellow
    Write-Host "Nested Memberships: $nestedMemberships" -ForegroundColor Cyan
    Write-Host "Unique OUs:         $uniqueOUs" -ForegroundColor Cyan
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
    Write-Host "Sample Results (first 20):" -ForegroundColor Cyan
    Write-Host "==========================" -ForegroundColor Cyan
    $results | Select-Object -First 20 | Format-Table -AutoSize Username, DisplayName, OU, GroupName, IsNested, Enabled
    
    # Show top groups
    Write-Host ""
    Write-Host "Top 10 Groups by Membership:" -ForegroundColor Cyan
    Write-Host "============================" -ForegroundColor Cyan
    $results | Where-Object { $_.GroupName -ne "No Groups" } | Group-Object -Property GroupName | Select-Object Count, Name | Sort-Object Count -Descending | Select-Object -First 10 | Format-Table -AutoSize
    
    # Show users by OU
    Write-Host ""
    Write-Host "Users by OU:" -ForegroundColor Cyan
    Write-Host "===========" -ForegroundColor Cyan
    $results | Group-Object -Property OU | Select-Object Count, Name | Sort-Object Count -Descending | Format-Table -AutoSize
}
catch {
    Write-Error "Failed to query Active Directory: $($_.Exception.Message)"
    exit 1
}

