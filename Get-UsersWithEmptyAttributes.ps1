<#
.SYNOPSIS
    Finds all users with empty attributes in Active Directory.

.DESCRIPTION
    This script searches for users with missing or empty attribute values.

.PARAMETER Domain
    Domain to search (default: current domain).

.PARAMETER OutputFile
    Path to CSV file. Default: EmptyAttributesReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication.

.PARAMETER Attributes
    Specific attributes to check (default: common important attributes).

.PARAMETER SearchBase
    Specific OU to search (default: entire domain).

.EXAMPLE
    .\Get-UsersWithEmptyAttributes.ps1
    
.EXAMPLE
    .\Get-UsersWithEmptyAttributes.ps1 -Attributes "Department","Title","Manager"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Domain,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "EmptyAttributesReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [string[]]$Attributes = @("Department", "Title", "Manager", "Office", "TelephoneNumber", "EmailAddress", "Description"),
    
    [Parameter(Mandatory=$false)]
    [string]$SearchBase
)

# Main execution
Write-Host "Empty Attributes Finder" -ForegroundColor Cyan
Write-Host "======================" -ForegroundColor Cyan
Write-Host ""

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "Active Directory PowerShell module is required."
    exit 1
}

Import-Module ActiveDirectory -ErrorAction Stop

try {
    $adParams = @{
        Filter = "*"
        Properties = $Attributes
        ErrorAction = "Stop"
    }
    
    if ($Domain) { $adParams['Server'] = $Domain }
    if ($Credential) { $adParams['Credential'] = $Credential }
    if ($SearchBase) { $adParams['SearchBase'] = $SearchBase }
    
    Write-Host "Querying users..." -ForegroundColor Yellow
    $users = Get-ADUser @adParams
    
    Write-Host "Found $($users.Count) users" -ForegroundColor Green
    Write-Host "Checking attributes: $($Attributes -join ', ')" -ForegroundColor Yellow
    Write-Host ""
    
    $results = @()
    
    foreach ($user in $users) {
        $emptyAttrs = @()
        
        foreach ($attr in $Attributes) {
            $value = $user.$attr
            if ([string]::IsNullOrEmpty($value)) {
                $emptyAttrs += $attr
            }
        }
        
        if ($emptyAttrs.Count -gt 0) {
            $results += [PSCustomObject]@{
                Username = $user.SamAccountName
                DisplayName = $user.Name
                UserPrincipalName = if ($user.UserPrincipalName) { $user.UserPrincipalName } else { "N/A" }
                EmptyAttributes = ($emptyAttrs -join "; ")
                EmptyCount = $emptyAttrs.Count
                Enabled = $user.Enabled
                DistinguishedName = $user.DistinguishedName
            }
        }
    }
    
    Write-Host "Found $($results.Count) users with empty attributes" -ForegroundColor Green
    Write-Host ""
    
    # Summary by attribute
    Write-Host "Summary by Attribute:" -ForegroundColor Cyan
    $attrSummary = @{}
    foreach ($result in $results) {
        foreach ($attr in ($result.EmptyAttributes -split "; ")) {
            if (-not $attrSummary.ContainsKey($attr)) {
                $attrSummary[$attr] = 0
            }
            $attrSummary[$attr]++
        }
    }
    
    foreach ($attr in ($attrSummary.Keys | Sort-Object)) {
        Write-Host "  $attr : $($attrSummary[$attr]) users" -ForegroundColor Yellow
    }
    Write-Host ""
    
    $results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
    Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
    
    $results | Format-Table -AutoSize Username, DisplayName, EmptyCount, EmptyAttributes
}
catch {
    Write-Error "Failed: $($_.Exception.Message)"
    exit 1
}

