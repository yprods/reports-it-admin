<#
.SYNOPSIS
    Queries Secure Boot status using SCCM WMI namespace.

.DESCRIPTION
    This script uses SCCM's WMI namespace to query Secure Boot status from
    computers managed by System Center Configuration Manager.

.PARAMETER SiteCode
    SCCM Site Code (e.g., "ABC")

.PARAMETER SiteServer
    SCCM Site Server FQDN (e.g., "SCCM01.contoso.com")

.PARAMETER CollectionName
    Name of SCCM collection to query (optional)

.PARAMETER ComputerList
    Path to text file with computer names (alternative to CollectionName)

.PARAMETER OutputFile
    Path to CSV file for results. Default: SecureBootReport_SCCM.csv

.EXAMPLE
    .\Get-SecureBootStatus-SCCM.ps1 -SiteCode "ABC" -SiteServer "SCCM01.contoso.com" -CollectionName "All Workstations"
    
.EXAMPLE
    .\Get-SecureBootStatus-SCCM.ps1 -SiteCode "ABC" -SiteServer "SCCM01.contoso.com" -ComputerList "computers.txt"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$SiteCode,
    
    [Parameter(Mandatory=$true)]
    [string]$SiteServer,
    
    [Parameter(Mandatory=$false)]
    [string]$CollectionName,
    
    [Parameter(Mandatory=$false)]
    [string]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "SecureBootReport_SCCM.csv"
)

# Function to get computers from SCCM collection
function Get-SCCMCollectionComputers {
    param(
        [string]$SiteCode,
        [string]$SiteServer,
        [string]$CollectionName
    )
    
    try {
        $namespace = "root\SMS\site_$SiteCode"
        $computers = Get-CimInstance -ComputerName $SiteServer -Namespace $namespace -ClassName "SMS_Collection" -Filter "Name='$CollectionName'" | 
            Get-CimAssociatedInstance -ResultClassName "SMS_CM_RES_COLL_$SiteCode" |
            Get-CimAssociatedInstance -ResultClassName "SMS_R_System" |
            Select-Object -ExpandProperty Name
        
        return $computers
    }
    catch {
        Write-Error "Failed to query SCCM collection: $($_.Exception.Message)"
        return @()
    }
}

# Function to get Secure Boot status (same as main script)
function Get-SecureBootStatus {
    param(
        [string]$Computer
    )
    
    $result = [PSCustomObject]@{
        ComputerName = $Computer
        SecureBootEnabled = "Unknown"
        Status = "Unknown"
        LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Error = $null
    }
    
    try {
        if (-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            $result.Status = "Offline"
            $result.Error = "Computer is not reachable"
            return $result
        }
        
        # Try SecureBootUEFI WMI class
        try {
            $secureBoot = Get-CimInstance -ComputerName $Computer -Namespace "root\Microsoft\Windows\SecureBoot" -ClassName "SecureBootUEFI" -ErrorAction Stop
            
            if ($secureBoot) {
                $result.SecureBootEnabled = $secureBoot.SecureBootEnabled
                $result.Status = if ($secureBoot.SecureBootEnabled) { "Enabled" } else { "Disabled" }
            }
        }
        catch {
            # Fallback to registry query
            try {
                $reg = Get-CimInstance -ComputerName $Computer -Namespace "root\default" -ClassName "StdRegProv" -ErrorAction Stop
                $hklm = 2147483650
                $keyPath = "SYSTEM\CurrentControlSet\Control\SecureBoot\State"
                $valueName = "UEFISecureBootEnabled"
                
                $value = $reg.GetDWORDValue($hklm, $keyPath, $valueName)
                
                if ($value.ReturnValue -eq 0) {
                    $result.SecureBootEnabled = [bool]$value.uValue
                    $result.Status = if ($value.uValue -eq 1) { "Enabled" } else { "Disabled" }
                }
                else {
                    throw "Could not read Secure Boot registry value"
                }
            }
            catch {
                $result.Error = $_.Exception.Message
                $result.Status = "Not Available"
            }
        }
    }
    catch {
        $result.Status = "Error"
        $result.Error = $_.Exception.Message
    }
    
    return $result
}

# Main execution
Write-Host "SCCM Secure Boot Status Query Tool" -ForegroundColor Cyan
Write-Host "===================================" -ForegroundColor Cyan
Write-Host ""

# Get computer list
$computers = @()

if ($CollectionName) {
    Write-Host "Querying SCCM collection: $CollectionName" -ForegroundColor Yellow
    $computers = Get-SCCMCollectionComputers -SiteCode $SiteCode -SiteServer $SiteServer -CollectionName $CollectionName
    
    if ($computers.Count -eq 0) {
        Write-Warning "No computers found in collection or collection does not exist."
    }
}

if ($ComputerList) {
    if (Test-Path $ComputerList) {
        Write-Host "Reading computer list from: $ComputerList" -ForegroundColor Yellow
        $computers += Get-Content $ComputerList | Where-Object { $_.Trim() -ne "" -and $_.Trim() -notlike "#*" } | ForEach-Object { $_.Trim() }
    }
    else {
        Write-Error "Computer list file not found: $ComputerList"
        exit 1
    }
}

if ($computers.Count -eq 0) {
    Write-Error "No computers specified. Use -CollectionName or -ComputerList parameter."
    exit 1
}

# Remove duplicates
$computers = $computers | Select-Object -Unique

Write-Host "Found $($computers.Count) unique computer(s) to query" -ForegroundColor Green
Write-Host ""

# Query each computer
$results = @()
$total = $computers.Count
$current = 0

foreach ($computer in $computers) {
    $current++
    Write-Progress -Activity "Querying Secure Boot Status" -Status "Processing $computer ($current of $total)" -PercentComplete (($current / $total) * 100)
    
    Write-Host "[$current/$total] Querying $computer..." -NoNewline
    
    $result = Get-SecureBootStatus -Computer $computer
    
    $results += $result
    
    $statusColor = switch ($result.Status) {
        "Enabled" { "Green" }
        "Disabled" { "Yellow" }
        "Offline" { "Red" }
        "Error" { "Red" }
        default { "Gray" }
    }
    
    Write-Host " $($result.Status)" -ForegroundColor $statusColor
    if ($result.Error) {
        Write-Host "  Error: $($result.Error)" -ForegroundColor Red
    }
}

Write-Progress -Activity "Querying Secure Boot Status" -Completed

# Display summary
Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "========" -ForegroundColor Cyan
$enabled = ($results | Where-Object { $_.Status -eq "Enabled" }).Count
$disabled = ($results | Where-Object { $_.Status -eq "Disabled" }).Count
$offline = ($results | Where-Object { $_.Status -eq "Offline" }).Count
$errors = ($results | Where-Object { $_.Status -eq "Error" }).Count
$unknown = ($results | Where-Object { $_.Status -eq "Unknown" -or $_.Status -eq "Not Available" }).Count

Write-Host "Enabled:  $enabled" -ForegroundColor Green
Write-Host "Disabled: $disabled" -ForegroundColor Yellow
Write-Host "Offline:  $offline" -ForegroundColor Red
Write-Host "Errors:   $errors" -ForegroundColor Red
Write-Host "Unknown:  $unknown" -ForegroundColor Gray
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
Write-Host "Detailed Results:" -ForegroundColor Cyan
Write-Host "================" -ForegroundColor Cyan
$results | Format-Table -AutoSize

