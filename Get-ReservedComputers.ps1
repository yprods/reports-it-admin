<#
.SYNOPSIS
    Finds all reserved computers in Active Directory (computers with reserved names or special attributes).

.DESCRIPTION
    This script queries Active Directory to find computers that are reserved, typically
    those with specific naming conventions, in specific OUs, or with reserved attributes.

.PARAMETER Domain
    Domain to search (default: current domain).

.PARAMETER OutputFile
    Path to CSV file where results will be exported. Default: ReservedComputersReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication (optional).

.PARAMETER SearchBase
    Specific OU or container to search (default: entire domain).

.PARAMETER ReservedPattern
    Pattern to match reserved computer names (e.g., "RESERVED-*", "*RESERVED*").

.EXAMPLE
    .\Get-ReservedComputers.ps1
    
.EXAMPLE
    .\Get-ReservedComputers.ps1 -Domain "contoso.com" -ReservedPattern "RESERVED-*"
    
.EXAMPLE
    .\Get-ReservedComputers.ps1 -SearchBase "OU=Reserved,DC=contoso,DC=com"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Domain,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "ReservedComputersReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [string]$SearchBase,
    
    [Parameter(Mandatory=$false)]
    [string]$ReservedPattern = "*RESERVED*"
)

# Main execution
Write-Host "Reserved Computers Query Tool" -ForegroundColor Cyan
Write-Host "=============================" -ForegroundColor Cyan
Write-Host ""

# Check for Active Directory module
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "Active Directory PowerShell module is required. Install RSAT-AD-PowerShell feature."
    exit 1
}

Import-Module ActiveDirectory -ErrorAction Stop

try {
    # Build AD query parameters
    $adParams = @{
        Filter = "*"
        Properties = @("Name", "DistinguishedName", "Description", "OperatingSystem", "OperatingSystemVersion", "LastLogonDate", "Created", "Modified", "ManagedBy", "Location", "CanonicalName")
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
    
    Write-Host "Querying Active Directory for computers..." -ForegroundColor Yellow
    
    # Get all computers
    $allComputers = Get-ADComputer @adParams
    
    Write-Host "Found $($allComputers.Count) total computer(s)" -ForegroundColor Green
    Write-Host "Filtering for reserved computers..." -ForegroundColor Yellow
    Write-Host ""
    
    # Filter for reserved computers
    $results = @()
    
    foreach ($computer in $allComputers) {
        $isReserved = $false
        $reservationReason = @()
        
        # Check name pattern
        if ($computer.Name -like $ReservedPattern) {
            $isReserved = $true
            $reservationReason += "Name matches pattern: $ReservedPattern"
        }
        
        # Check for reserved keywords in name
        $reservedKeywords = @("RESERVED", "RESERVE", "SPARE", "BACKUP", "STANDBY", "TEMP", "TEST", "DEMO")
        foreach ($keyword in $reservedKeywords) {
            if ($computer.Name -like "*$keyword*") {
                $isReserved = $true
                if (-not ($reservationReason -like "*keyword*")) {
                    $reservationReason += "Contains reserved keyword: $keyword"
                }
            }
        }
        
        # Check description for reserved indicators
        if ($computer.Description -and ($computer.Description -like "*RESERVED*" -or $computer.Description -like "*RESERVE*" -or $computer.Description -like "*SPARE*")) {
            $isReserved = $true
            $reservationReason += "Description indicates reserved"
        }
        
        # Check if computer account is disabled
        if ($computer.Enabled -eq $false) {
            $isReserved = $true
            $reservationReason += "Account is disabled"
        }
        
        # Check if never logged on (older than 90 days without logon)
        if ($computer.LastLogonDate -eq $null -or $computer.LastLogonDate -lt (Get-Date).AddDays(-90)) {
            $isReserved = $true
            if ($computer.LastLogonDate) {
                $reservationReason += "No logon in 90+ days (Last: $($computer.LastLogonDate))"
            } else {
                $reservationReason += "Never logged on"
            }
        }
        
        # Check OU for reserved indicators
        if ($computer.DistinguishedName -like "*RESERVED*" -or $computer.DistinguishedName -like "*RESERVE*" -or $computer.DistinguishedName -like "*SPARE*") {
            $isReserved = $true
            $reservationReason += "In reserved OU"
        }
        
        if ($isReserved) {
            $result = [PSCustomObject]@{
                ComputerName = $computer.Name
                DistinguishedName = $computer.DistinguishedName
                CanonicalName = if ($computer.CanonicalName) { $computer.CanonicalName } else { "N/A" }
                Description = if ($computer.Description) { $computer.Description } else { "N/A" }
                OperatingSystem = if ($computer.OperatingSystem) { $computer.OperatingSystem } else { "N/A" }
                OperatingSystemVersion = if ($computer.OperatingSystemVersion) { $computer.OperatingSystemVersion } else { "N/A" }
                Enabled = $computer.Enabled
                LastLogonDate = if ($computer.LastLogonDate) { $computer.LastLogonDate.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
                Created = if ($computer.Created) { $computer.Created.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
                Modified = if ($computer.Modified) { $computer.Modified.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
                ManagedBy = if ($computer.ManagedBy) { $computer.ManagedBy } else { "N/A" }
                Location = if ($computer.Location) { $computer.Location } else { "N/A" }
                ReservationReason = ($reservationReason -join "; ")
                Status = "Reserved"
            }
            $results += $result
        }
    }
    
    Write-Host "Found $($results.Count) reserved computer(s)" -ForegroundColor Green
    Write-Host ""
    
    # Display summary
    Write-Host "Summary:" -ForegroundColor Cyan
    Write-Host "========" -ForegroundColor Cyan
    $byPattern = ($results | Where-Object { $_.ReservationReason -like "*pattern*" }).Count
    $byKeyword = ($results | Where-Object { $_.ReservationReason -like "*keyword*" }).Count
    $byDescription = ($results | Where-Object { $_.ReservationReason -like "*Description*" }).Count
    $disabled = ($results | Where-Object { $_.Enabled -eq $false }).Count
    $noLogon = ($results | Where-Object { $_.LastLogonDate -eq "Never" -or $_.ReservationReason -like "*No logon*" }).Count
    $inReservedOU = ($results | Where-Object { $_.ReservationReason -like "*reserved OU*" }).Count
    
    Write-Host "By Name Pattern:    $byPattern" -ForegroundColor Cyan
    Write-Host "By Keyword:         $byKeyword" -ForegroundColor Cyan
    Write-Host "By Description:     $byDescription" -ForegroundColor Cyan
    Write-Host "Disabled:           $disabled" -ForegroundColor Yellow
    Write-Host "No Recent Logon:    $noLogon" -ForegroundColor Yellow
    Write-Host "In Reserved OU:     $inReservedOU" -ForegroundColor Cyan
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
    Write-Host "Reserved Computers:" -ForegroundColor Cyan
    Write-Host "===================" -ForegroundColor Cyan
    $results | Format-Table -AutoSize ComputerName, Enabled, LastLogonDate, ReservationReason
    
    # Show computers by OU
    Write-Host ""
    Write-Host "Reserved Computers by OU:" -ForegroundColor Cyan
    Write-Host "========================" -ForegroundColor Cyan
    $results | Group-Object -Property CanonicalName | Select-Object Count, Name | Sort-Object Count -Descending | Format-Table -AutoSize
}
catch {
    Write-Error "Failed to query Active Directory: $($_.Exception.Message)"
    exit 1
}

