<#
.SYNOPSIS
    Gets all users and lists specified attributes from a list.

.DESCRIPTION
    This script retrieves users from Active Directory and exports
    only the attributes specified in a list file.

.PARAMETER AttributeList
    Path to text file containing attribute names (one per line).

.PARAMETER Domain
    Domain to search (default: current domain).

.PARAMETER OutputFile
    Path to CSV file. Default: UsersWithAttributesReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication.

.PARAMETER SearchBase
    Specific OU to search (default: entire domain).

.EXAMPLE
    .\Get-UsersWithAttributes.ps1 -AttributeList "attributes.txt"
    
.EXAMPLE
    .\Get-UsersWithAttributes.ps1 -AttributeList "attributes.txt" -SearchBase "OU=Users,DC=contoso,DC=com"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$AttributeList,
    
    [Parameter(Mandatory=$false)]
    [string]$Domain,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "UsersWithAttributesReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [string]$SearchBase
)

# Main execution
Write-Host "Users with Attributes Query Tool" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan
Write-Host ""

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "Active Directory PowerShell module is required."
    exit 1
}

Import-Module ActiveDirectory -ErrorAction Stop

if (-not (Test-Path $AttributeList)) {
    Write-Error "Attribute list file not found: $AttributeList"
    exit 1
}

$attributes = Get-Content $AttributeList | Where-Object { $_.Trim() -ne "" } | ForEach-Object { $_.Trim() }

if ($attributes.Count -eq 0) {
    Write-Error "No attributes found in list file."
    exit 1
}

Write-Host "Attributes to retrieve: $($attributes.Count)" -ForegroundColor Yellow
Write-Host "Attributes: $($attributes -join ', ')" -ForegroundColor Gray
Write-Host ""

try {
    $adParams = @{
        Filter = "*"
        Properties = $attributes
        ErrorAction = "Stop"
    }
    
    if ($Domain) { $adParams['Server'] = $Domain }
    if ($Credential) { $adParams['Credential'] = $Credential }
    if ($SearchBase) { $adParams['SearchBase'] = $SearchBase }
    
    Write-Host "Querying users..." -ForegroundColor Yellow
    $users = Get-ADUser @adParams
    
    Write-Host "Found $($users.Count) users" -ForegroundColor Green
    Write-Host ""
    
    $results = @()
    
    foreach ($user in $users) {
        $userData = @{
            Username = $user.SamAccountName
            DisplayName = $user.Name
        }
        
        foreach ($attr in $attributes) {
            $value = $user.$attr
            if ($value -is [System.Array]) {
                $userData[$attr] = $value -join "; "
            }
            elseif ($value -is [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]) {
                $userData[$attr] = ($value | ForEach-Object { $_.ToString() }) -join "; "
            }
            else {
                $userData[$attr] = if ($value) { $value.ToString() } else { "N/A" }
            }
        }
        
        $results += [PSCustomObject]$userData
    }
    
    $results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
    Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
    
    Write-Host ""
    Write-Host "Sample Results (first 5):" -ForegroundColor Cyan
    $results | Select-Object -First 5 | Format-Table -AutoSize
}
catch {
    Write-Error "Failed: $($_.Exception.Message)"
    exit 1
}

