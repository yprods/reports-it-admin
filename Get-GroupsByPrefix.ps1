<#
.SYNOPSIS
    Gets all groups that start with a specific prefix.

.DESCRIPTION
    This script queries Active Directory to find all groups whose names
    start with a specified prefix.

.PARAMETER Prefix
    Prefix to search for (e.g., "Sales", "IT").

.PARAMETER Domain
    Domain to search (default: current domain).

.PARAMETER OutputFile
    Path to CSV file. Default: GroupsByPrefixReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication (optional).

.EXAMPLE
    .\Get-GroupsByPrefix.ps1 -Prefix "Sales"
    
.EXAMPLE
    .\Get-GroupsByPrefix.ps1 -Prefix "IT" -Domain "contoso.com"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Prefix,
    
    [Parameter(Mandatory=$false)]
    [string]$Domain,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "GroupsByPrefixReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential
)

# Main execution
Write-Host "Groups by Prefix Query Tool" -ForegroundColor Cyan
Write-Host "===========================" -ForegroundColor Cyan
Write-Host ""

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "Active Directory PowerShell module is required."
    exit 1
}

Import-Module ActiveDirectory -ErrorAction Stop

try {
    $adParams = @{
        Filter = "Name -like '$Prefix*'"
        Properties = @("Name", "DistinguishedName", "GroupCategory", "GroupScope", "Members", "Description")
        ErrorAction = "Stop"
    }
    
    if ($Domain) { $adParams['Server'] = $Domain }
    if ($Credential) { $adParams['Credential'] = $Credential }
    
    Write-Host "Searching for groups starting with: $Prefix" -ForegroundColor Yellow
    $groups = Get-ADGroup @adParams
    
    Write-Host "Found $($groups.Count) group(s)" -ForegroundColor Green
    
    $results = @()
    foreach ($group in $groups) {
        $memberCount = (Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue).Count
        
        $results += [PSCustomObject]@{
            GroupName = $group.Name
            DistinguishedName = $group.DistinguishedName
            GroupCategory = $group.GroupCategory
            GroupScope = $group.GroupScope
            MemberCount = $memberCount
            Description = if ($group.Description) { $group.Description } else { "N/A" }
        }
    }
    
    $results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
    Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
    $results | Format-Table -AutoSize
}
catch {
    Write-Error "Failed: $($_.Exception.Message)"
    exit 1
}

