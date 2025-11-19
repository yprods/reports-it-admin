<#
.SYNOPSIS
    Queries Secure Boot status from a list of computers using WMI.

.DESCRIPTION
    This script reads a list of computer names and queries their Secure Boot status
    remotely using WMI. It supports both SCCM and direct WMI queries.

.PARAMETER ComputerList
    Path to a text file containing computer names (one per line).

.PARAMETER ComputerName
    Single computer name or array of computer names to query.

.PARAMETER OutputFile
    Path to CSV file where results will be exported. Default: SecureBootReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication (optional).

.EXAMPLE
    .\Get-SecureBootStatus.ps1 -ComputerList "computers.txt"
    
.EXAMPLE
    .\Get-SecureBootStatus.ps1 -ComputerName "PC01","PC02","PC03"
    
.EXAMPLE
    .\Get-SecureBootStatus.ps1 -ComputerList "computers.txt" -OutputFile "results.csv"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ComputerName,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "SecureBootReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential
)

# Function to get Secure Boot status from a single computer
function Get-SecureBootStatus {
    param(
        [string]$Computer,
        [System.Management.Automation.PSCredential]$Cred
    )
    
    $result = [PSCustomObject]@{
        ComputerName = $Computer
        SecureBootEnabled = "Unknown"
        Status = "Unknown"
        LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Error = $null
    }
    
    try {
        # Test connectivity first
        if (-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            $result.Status = "Offline"
            $result.Error = "Computer is not reachable"
            return $result
        }
        
        # Method 1: Query SecureBootUEFI WMI class (Windows 8/Server 2012+)
        try {
            $wmiParams = @{
                ComputerName = $Computer
                Namespace = "root\Microsoft\Windows\SecureBoot"
                Class = "SecureBootUEFI"
                ErrorAction = "Stop"
            }
            
            if ($Cred) {
                $wmiParams['Credential'] = $Cred
            }
            
            $secureBoot = Get-CimInstance @wmiParams
            
            if ($secureBoot) {
                $result.SecureBootEnabled = $secureBoot.SecureBootEnabled
                $result.Status = if ($secureBoot.SecureBootEnabled) { "Enabled" } else { "Disabled" }
            }
        }
        catch {
            # Method 2: Query registry via WMI (fallback method)
            try {
                $regParams = @{
                    ComputerName = $Computer
                    Namespace = "root\default"
                    Class = "StdRegProv"
                    ErrorAction = "Stop"
                }
                
                if ($Cred) {
                    $regParams['Credential'] = $Cred
                }
                
                $reg = Get-CimInstance @regParams
                
                # Registry path: HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State
                # Value: UEFISecureBootEnabled (DWORD)
                $hklm = 2147483650  # HKEY_LOCAL_MACHINE
                $keyPath = "SYSTEM\CurrentControlSet\Control\SecureBoot\State"
                $valueName = "UEFISecureBootEnabled"
                
                $value = $reg.GetDWORDValue($hklm, $keyPath, $valueName)
                
                if ($value.ReturnValue -eq 0) {
                    $result.SecureBootEnabled = [bool]$value.uValue
                    $result.Status = if ($value.uValue -eq 1) { "Enabled" } else { "Disabled" }
                }
                else {
                    # Method 3: Try alternative registry path
                    $keyPath2 = "SYSTEM\CurrentControlSet\Control\SecureBoot"
                    $value2 = $reg.GetDWORDValue($hklm, $keyPath2, $valueName)
                    
                    if ($value2.ReturnValue -eq 0) {
                        $result.SecureBootEnabled = [bool]$value2.uValue
                        $result.Status = if ($value2.uValue -eq 1) { "Enabled" } else { "Disabled" }
                    }
                    else {
                        throw "Could not read Secure Boot registry value"
                    }
                }
            }
            catch {
                # Method 4: Try Win32_ComputerSystem for basic info
                try {
                    $csParams = @{
                        ComputerName = $Computer
                        Class = "Win32_ComputerSystem"
                        ErrorAction = "Stop"
                    }
                    
                    if ($Cred) {
                        $csParams['Credential'] = $Cred
                    }
                    
                    $cs = Get-CimInstance @csParams
                    $result.Error = "Secure Boot status not available via WMI. System: $($cs.Manufacturer) $($cs.Model)"
                    $result.Status = "Not Available"
                }
                catch {
                    throw $_.Exception.Message
                }
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
Write-Host "Secure Boot Status Query Tool" -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor Cyan
Write-Host ""

# Collect computer names
$computers = @()

if ($ComputerList) {
    if (Test-Path $ComputerList) {
        Write-Host "Reading computer list from: $ComputerList" -ForegroundColor Yellow
        $computers = Get-Content $ComputerList | Where-Object { $_.Trim() -ne "" } | ForEach-Object { $_.Trim() }
    }
    else {
        Write-Error "Computer list file not found: $ComputerList"
        exit 1
    }
}

if ($ComputerName) {
    $computers += $ComputerName
}

if ($computers.Count -eq 0) {
    Write-Error "No computers specified. Use -ComputerList or -ComputerName parameter."
    exit 1
}

Write-Host "Found $($computers.Count) computer(s) to query" -ForegroundColor Green
Write-Host ""

# Query each computer
$results = @()
$total = $computers.Count
$current = 0

foreach ($computer in $computers) {
    $current++
    Write-Progress -Activity "Querying Secure Boot Status" -Status "Processing $computer ($current of $total)" -PercentComplete (($current / $total) * 100)
    
    Write-Host "[$current/$total] Querying $computer..." -NoNewline
    
    $result = Get-SecureBootStatus -Computer $computer -Cred $Credential
    
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

