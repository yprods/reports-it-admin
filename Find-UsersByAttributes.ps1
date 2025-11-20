<#
.SYNOPSIS
    Finds all users in Active Directory based on specific attribute values.

.DESCRIPTION
    This script searches for users in Active Directory based on attribute values.
    Supports multiple attributes and various search operators.

.PARAMETER AttributeName
    Name of the attribute to search (e.g., "Department", "Title", "Office").

.PARAMETER AttributeValue
    Value to search for (supports wildcards with *).

.PARAMETER SearchOperator
    Search operator: Equals, Contains, StartsWith, EndsWith, NotEquals (default: Contains).

.PARAMETER AttributeList
    Path to CSV file with columns: AttributeName, AttributeValue, Operator (for multiple searches).

.PARAMETER OU
    Search only in specific OU (e.g., "OU=Users,DC=contoso,DC=com").

.PARAMETER Domain
    Domain to search (default: current domain).

.PARAMETER OutputFile
    Path to CSV file. Default: UsersByAttributesReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication.

.PARAMETER IncludeDisabled
    Include disabled user accounts (default: false).

.EXAMPLE
    .\Find-UsersByAttributes.ps1 -AttributeName "Department" -AttributeValue "IT"
    
.EXAMPLE
    .\Find-UsersByAttributes.ps1 -AttributeName "Title" -AttributeValue "Manager*" -SearchOperator "StartsWith"
    
.EXAMPLE
    .\Find-UsersByAttributes.ps1 -AttributeList "attributes.csv" -OU "OU=Users,DC=contoso,DC=com"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$AttributeName,
    
    [Parameter(Mandatory=$false)]
    [string]$AttributeValue,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Equals","Contains","StartsWith","EndsWith","NotEquals")]
    [string]$SearchOperator = "Contains",
    
    [Parameter(Mandatory=$false)]
    [string]$AttributeList,
    
    [Parameter(Mandatory=$false)]
    [string]$OU,
    
    [Parameter(Mandatory=$false)]
    [string]$Domain,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "UsersByAttributesReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeDisabled
)

# Main execution
Write-Host "Find Users by Attributes Tool" -ForegroundColor Cyan
Write-Host "=============================" -ForegroundColor Cyan
Write-Host ""

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "Active Directory PowerShell module is required."
    exit 1
}

Import-Module ActiveDirectory -ErrorAction Stop

$adParams = @{ ErrorAction = "Stop" }
if ($Domain) { $adParams['Server'] = $Domain }
if ($Credential) { $adParams['Credential'] = $Credential }

# Build search criteria
$searchCriteria = @()

if ($AttributeList -and (Test-Path $AttributeList)) {
    Write-Host "Loading search criteria from: $AttributeList" -ForegroundColor Yellow
    $criteriaList = Import-Csv -Path $AttributeList
    
    foreach ($criteria in $criteriaList) {
        if ($criteria.AttributeName -and $criteria.AttributeValue) {
            $operator = if ($criteria.Operator) { $criteria.Operator } else { "Contains" }
            $searchCriteria += @{
                AttributeName = $criteria.AttributeName
                AttributeValue = $criteria.AttributeValue
                Operator = $operator
            }
        }
    }
}
elseif ($AttributeName -and $AttributeValue) {
    $searchCriteria += @{
        AttributeName = $AttributeName
        AttributeValue = $AttributeValue
        Operator = $SearchOperator
    }
}
else {
    Write-Error "Must specify either -AttributeName and -AttributeValue, or -AttributeList"
    exit 1
}

Write-Host "Search Criteria:" -ForegroundColor Yellow
foreach ($criteria in $searchCriteria) {
    Write-Host "  $($criteria.AttributeName) $($criteria.Operator) '$($criteria.AttributeValue)'" -ForegroundColor Gray
}
Write-Host ""

# Build LDAP filter
$filterParts = @()

if (-not $IncludeDisabled) {
    $filterParts += "(Enabled -eq 'True')"
}

foreach ($criteria in $searchCriteria) {
    $attrName = $criteria.AttributeName
    $attrValue = $criteria.AttributeValue
    $operator = $criteria.Operator
    
    switch ($operator) {
        "Equals" {
            $filterParts += "($attrName -eq '$attrValue')"
        }
        "Contains" {
            $filterParts += "($attrName -like '*$attrValue*')"
        }
        "StartsWith" {
            $filterParts += "($attrName -like '$attrValue*')"
        }
        "EndsWith" {
            $filterParts += "($attrName -like '*$attrValue')"
        }
        "NotEquals" {
            $filterParts += "($attrName -ne '$attrValue')"
        }
    }
}

$ldapFilter = "(&" + ($filterParts -join "") + ")"

Write-Host "LDAP Filter: $ldapFilter" -ForegroundColor Gray
Write-Host ""

# Search for users
$searchParams = @{
    Filter = $ldapFilter
    Properties = "*"
}

if ($OU) {
    $searchParams['SearchBase'] = $OU
}

if ($Domain) {
    $searchParams['Server'] = $Domain
}

if ($Credential) {
    $searchParams['Credential'] = $Credential
}

Write-Host "Searching for users..." -ForegroundColor Yellow

try {
    $users = Get-ADUser @searchParams
    Write-Host "Found $($users.Count) user(s)" -ForegroundColor Green
}
catch {
    Write-Error "Search failed: $($_.Exception.Message)"
    exit 1
}

if ($users.Count -eq 0) {
    Write-Host "No users found matching the criteria." -ForegroundColor Yellow
    exit 0
}

# Build results
$results = @()

foreach ($user in $users) {
    $result = [PSCustomObject]@{
        Username = $user.SamAccountName
        DisplayName = $user.Name
        Enabled = $user.Enabled
        Email = $user.EmailAddress
        Department = $user.Department
        Title = $user.Title
        Office = $user.Office
        Phone = $user.telephoneNumber
        Manager = $user.Manager
        OU = $user.DistinguishedName -replace "CN=$($user.Name),"
        LastLogon = if ($user.LastLogonDate) { $user.LastLogonDate.ToString() } else { "Never" }
        PasswordLastSet = if ($user.PasswordLastSet) { $user.PasswordLastSet.ToString() } else { "Never" }
        AccountLockedOut = $user.LockedOut
        LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    # Add all search attributes
    foreach ($criteria in $searchCriteria) {
        $attrName = $criteria.AttributeName
        $attrValue = $user.$attrName
        $result | Add-Member -MemberType NoteProperty -Name $attrName -Value $(if ($attrValue) { $attrValue.ToString() } else { "Empty" })
    }
    
    $results += $result
}

Write-Host ""
Write-Host "Results:" -ForegroundColor Cyan
$results | Format-Table -AutoSize

$results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "Results exported to: $OutputFile" -ForegroundColor Green

