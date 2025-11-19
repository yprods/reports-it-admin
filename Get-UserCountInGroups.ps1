<#
.SYNOPSIS
    Gets the count of users in groups, OUs, and lists of groups.

.DESCRIPTION
    This script queries Active Directory to count users in specified groups,
    OUs, or a list of groups, providing comprehensive statistics.

.PARAMETER GroupList
    Path to a text file containing group names (one per line).

.PARAMETER GroupName
    Single group name or array of group names to query.

.PARAMETER OUList
    Path to a text file containing OU paths (one per line).

.PARAMETER OUName
    Single OU name or array of OU names to query.

.PARAMETER Domain
    Domain to search (default: current domain).

.PARAMETER OutputFile
    Path to CSV file where results will be exported. Default: UserCountReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication (optional).

.PARAMETER IncludeNested
    Include nested group members in counts (default: true).

.PARAMETER IncludeDisabled
    Include disabled users in counts (default: false).

.EXAMPLE
    .\Get-UserCountInGroups.ps1 -GroupList "groups.txt"
    
.EXAMPLE
    .\Get-UserCountInGroups.ps1 -GroupName "Domain Admins","Enterprise Admins"
    
.EXAMPLE
    .\Get-UserCountInGroups.ps1 -OUName "OU=Sales,DC=contoso,DC=com"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$GroupList,
    
    [Parameter(Mandatory=$false)]
    [string[]]$GroupName,
    
    [Parameter(Mandatory=$false)]
    [string]$OUList,
    
    [Parameter(Mandatory=$false)]
    [string[]]$OUName,
    
    [Parameter(Mandatory=$false)]
    [string]$Domain,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "UserCountReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeNested = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeDisabled
)

# Main execution
Write-Host "User Count in Groups/OU Tool" -ForegroundColor Cyan
Write-Host "===========================" -ForegroundColor Cyan
Write-Host ""

# Check for Active Directory module
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "Active Directory PowerShell module is required. Install RSAT-AD-PowerShell feature."
    exit 1
}

Import-Module ActiveDirectory -ErrorAction Stop

try {
    $results = @()
    
    # Collect groups
    $groups = @()
    if ($GroupList) {
        if (Test-Path $GroupList) {
            Write-Host "Reading group list from: $GroupList" -ForegroundColor Yellow
            $groups = Get-Content $GroupList | Where-Object { $_.Trim() -ne "" } | ForEach-Object { $_.Trim() }
        }
    }
    if ($GroupName) {
        $groups += $GroupName
    }
    $groups = $groups | Select-Object -Unique
    
    # Collect OUs
    $ous = @()
    if ($OUList) {
        if (Test-Path $OUList) {
            Write-Host "Reading OU list from: $OUList" -ForegroundColor Yellow
            $ous = Get-Content $OUList | Where-Object { $_.Trim() -ne "" } | ForEach-Object { $_.Trim() }
        }
    }
    if ($OUName) {
        $ous += $OUName
    }
    $ous = $ous | Select-Object -Unique
    
    if ($groups.Count -eq 0 -and $ous.Count -eq 0) {
        Write-Error "No groups or OUs specified. Use -GroupList, -GroupName, -OUList, or -OUName parameter."
        exit 1
    }
    
    # Build AD query parameters
    $adParams = @{
        ErrorAction = "Stop"
    }
    
    if ($Domain) {
        $adParams['Server'] = $Domain
    }
    
    if ($Credential) {
        $adParams['Credential'] = $Credential
    }
    
    # Process groups
    if ($groups.Count -gt 0) {
        Write-Host "Processing $($groups.Count) group(s)..." -ForegroundColor Yellow
        
        foreach ($groupName in $groups) {
            try {
                $group = Get-ADGroup -Identity $groupName @adParams -ErrorAction Stop
                
                # Get members
                if ($IncludeNested) {
                    $members = Get-ADGroupMember -Identity $group @adParams -Recursive -ErrorAction SilentlyContinue
                }
                else {
                    $members = Get-ADGroupMember -Identity $group @adParams -ErrorAction SilentlyContinue
                }
                
                # Filter users only
                $users = $members | Where-Object { $_.objectClass -eq "user" }
                
                # Filter disabled if needed
                if (-not $IncludeDisabled) {
                    $userObjects = $users | Get-ADUser -Properties Enabled @adParams -ErrorAction SilentlyContinue
                    $users = $userObjects | Where-Object { $_.Enabled -eq $true }
                }
                
                $result = [PSCustomObject]@{
                    Type = "Group"
                    Name = $group.Name
                    DistinguishedName = $group.DistinguishedName
                    UserCount = $users.Count
                    TotalMembers = $members.Count
                    EnabledUsers = ($users | Where-Object { $_.Enabled -ne $false }).Count
                    DisabledUsers = ($users | Where-Object { $_.Enabled -eq $false }).Count
                    IncludesNested = $IncludeNested
                    Status = "Success"
                    Error = $null
                }
                $results += $result
            }
            catch {
                $result = [PSCustomObject]@{
                    Type = "Group"
                    Name = $groupName
                    DistinguishedName = "N/A"
                    UserCount = 0
                    TotalMembers = 0
                    EnabledUsers = 0
                    DisabledUsers = 0
                    IncludesNested = $IncludeNested
                    Status = "Error"
                    Error = $_.Exception.Message
                }
                $results += $result
            }
        }
    }
    
    # Process OUs
    if ($ous.Count -gt 0) {
        Write-Host "Processing $($ous.Count) OU(s)..." -ForegroundColor Yellow
        
        foreach ($ouPath in $ous) {
            try {
                $ou = Get-ADOrganizationalUnit -Identity $ouPath @adParams -ErrorAction Stop
                
                # Get users in OU
                $userParams = @{
                    SearchBase = $ou.DistinguishedName
                    Filter = "*"
                    Properties = "Enabled"
                    ErrorAction = "Stop"
                }
                
                if ($Domain) {
                    $userParams['Server'] = $Domain
                }
                
                if ($Credential) {
                    $userParams['Credential'] = $Credential
                }
                
                if (-not $IncludeDisabled) {
                    $userParams['Filter'] = "Enabled -eq 'True'"
                }
                
                $users = Get-ADUser @userParams
                
                $result = [PSCustomObject]@{
                    Type = "OU"
                    Name = $ou.Name
                    DistinguishedName = $ou.DistinguishedName
                    UserCount = $users.Count
                    TotalMembers = $users.Count
                    EnabledUsers = ($users | Where-Object { $_.Enabled -ne $false }).Count
                    DisabledUsers = ($users | Where-Object { $_.Enabled -eq $false }).Count
                    IncludesNested = $false
                    Status = "Success"
                    Error = $null
                }
                $results += $result
            }
            catch {
                $result = [PSCustomObject]@{
                    Type = "OU"
                    Name = $ouPath
                    DistinguishedName = "N/A"
                    UserCount = 0
                    TotalMembers = 0
                    EnabledUsers = 0
                    DisabledUsers = 0
                    IncludesNested = $false
                    Status = "Error"
                    Error = $_.Exception.Message
                }
                $results += $result
            }
        }
    }
    
    Write-Host ""
    Write-Host "Summary:" -ForegroundColor Cyan
    Write-Host "========" -ForegroundColor Cyan
    $totalUsers = ($results | Measure-Object -Property UserCount -Sum).Sum
    $totalGroups = ($results | Where-Object { $_.Type -eq "Group" }).Count
    $totalOUs = ($results | Where-Object { $_.Type -eq "OU" }).Count
    $success = ($results | Where-Object { $_.Status -eq "Success" }).Count
    $errors = ($results | Where-Object { $_.Status -eq "Error" }).Count
    
    Write-Host "Total Users:  $totalUsers" -ForegroundColor Green
    Write-Host "Groups:        $totalGroups" -ForegroundColor Cyan
    Write-Host "OUs:           $totalOUs" -ForegroundColor Cyan
    Write-Host "Success:      $success" -ForegroundColor Green
    Write-Host "Errors:        $errors" -ForegroundColor Red
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
    $results | Format-Table -AutoSize Type, Name, UserCount, EnabledUsers, DisabledUsers, Status
    
    # Show top groups/OUs by user count
    Write-Host ""
    Write-Host "Top 10 by User Count:" -ForegroundColor Cyan
    Write-Host "=====================" -ForegroundColor Cyan
    $results | Where-Object { $_.Status -eq "Success" } | Sort-Object UserCount -Descending | Select-Object -First 10 | Format-Table -AutoSize Type, Name, UserCount
}
catch {
    Write-Error "Failed to query Active Directory: $($_.Exception.Message)"
    exit 1
}

