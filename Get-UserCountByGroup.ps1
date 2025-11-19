<#
.SYNOPSIS
    Counts all users from specific groups in Active Directory.

.DESCRIPTION
    This script counts users in specified groups, including nested group memberships.

.PARAMETER GroupList
    Path to text file with group names.

.PARAMETER GroupName
    Single or array of group names.

.PARAMETER Domain
    Domain to search (default: current domain).

.PARAMETER OutputFile
    Path to CSV file. Default: UserCountByGroupReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication.

.PARAMETER IncludeNested
    Include nested group members (default: true).

.PARAMETER IncludeDisabled
    Include disabled users (default: false).

.EXAMPLE
    .\Get-UserCountByGroup.ps1 -GroupName "Domain Admins","Enterprise Admins"
    
.EXAMPLE
    .\Get-UserCountByGroup.ps1 -GroupList "groups.txt" -IncludeNested
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$GroupList,
    
    [Parameter(Mandatory=$false)]
    [string[]]$GroupName,
    
    [Parameter(Mandatory=$false)]
    [string]$Domain,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "UserCountByGroupReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeNested = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeDisabled
)

# Main execution
Write-Host "User Count by Group Tool" -ForegroundColor Cyan
Write-Host "========================" -ForegroundColor Cyan
Write-Host ""

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "Active Directory PowerShell module is required."
    exit 1
}

Import-Module ActiveDirectory -ErrorAction Stop

$groups = @()
if ($GroupList -and (Test-Path $GroupList)) {
    $groups = Get-Content $GroupList | Where-Object { $_.Trim() -ne "" }
}
if ($GroupName) {
    $groups += $GroupName
}
$groups = $groups | Select-Object -Unique

if ($groups.Count -eq 0) {
    Write-Error "No groups specified."
    exit 1
}

$adParams = @{ ErrorAction = "Stop" }
if ($Domain) { $adParams['Server'] = $Domain }
if ($Credential) { $adParams['Credential'] = $Credential }

$results = @()

foreach ($groupName in $groups) {
    try {
        $group = Get-ADGroup -Identity $groupName @adParams
        
        if ($IncludeNested) {
            $members = Get-ADGroupMember -Identity $group @adParams -Recursive
        } else {
            $members = Get-ADGroupMember -Identity $group @adParams
        }
        
        $users = $members | Where-Object { $_.objectClass -eq "user" }
        
        if (-not $IncludeDisabled) {
            $userObjects = $users | Get-ADUser -Properties Enabled @adParams
            $users = $userObjects | Where-Object { $_.Enabled -eq $true }
        }
        
        $results += [PSCustomObject]@{
            GroupName = $group.Name
            TotalUsers = $users.Count
            EnabledUsers = ($users | Where-Object { $_.Enabled -ne $false }).Count
            DisabledUsers = ($users | Where-Object { $_.Enabled -eq $false }).Count
            IncludesNested = $IncludeNested
            Status = "Success"
        }
    }
    catch {
        $results += [PSCustomObject]@{
            GroupName = $groupName
            TotalUsers = 0
            EnabledUsers = 0
            DisabledUsers = 0
            IncludesNested = $IncludeNested
            Status = "Error"
            Error = $_.Exception.Message
        }
    }
}

$results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
$results | Format-Table -AutoSize

