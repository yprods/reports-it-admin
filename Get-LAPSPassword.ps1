<#
.SYNOPSIS
    Retrieves LAPS (Local Administrator Password Solution) passwords for computers in the domain.

.DESCRIPTION
    This script queries Active Directory to retrieve LAPS passwords for computers.
    It requires appropriate permissions to read the ms-Mcs-AdmPwd attribute.

.PARAMETER ComputerList
    Path to a text file containing computer names (one per line).

.PARAMETER ComputerName
    Single computer name or array of computer names to query.

.PARAMETER Domain
    Query all computers in the specified domain (default: current domain).

.PARAMETER OutputFile
    Path to CSV file where results will be exported. Default: LAPSPasswordReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication (optional).

.PARAMETER IncludeExpired
    Include computers with expired LAPS passwords.

.EXAMPLE
    .\Get-LAPSPassword.ps1 -ComputerList "computers.txt"
    
.EXAMPLE
    .\Get-LAPSPassword.ps1 -ComputerName "PC01","PC02","PC03"
    
.EXAMPLE
    .\Get-LAPSPassword.ps1 -Domain "contoso.com"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ComputerName,
    
    [Parameter(Mandatory=$false)]
    [string]$Domain,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "LAPSPasswordReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeExpired
)

# Function to get LAPS password for a single computer
function Get-LAPSPassword {
    param(
        [string]$Computer,
        [string]$DomainName,
        [System.Management.Automation.PSCredential]$Cred
    )
    
    $result = [PSCustomObject]@{
        ComputerName = $Computer
        LAPSPassword = "N/A"
        PasswordExpired = $false
        ExpirationDate = "N/A"
        Status = "Unknown"
        LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Error = $null
    }
    
    try {
        # Import Active Directory module if available
        if (-not (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
            if (Get-Module -ListAvailable -Name ActiveDirectory) {
                Import-Module ActiveDirectory -ErrorAction Stop
            }
            else {
                throw "Active Directory PowerShell module not found. Install RSAT-AD-PowerShell."
            }
        }
        
        # Build AD query parameters
        $adParams = @{
            Filter = { Name -eq $Computer }
            Properties = @("ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime")
            ErrorAction = "Stop"
        }
        
        if ($DomainName) {
            $adParams['Server'] = $DomainName
        }
        
        if ($Cred) {
            $adParams['Credential'] = $Cred
        }
        
        # Query Active Directory
        $adComputer = Get-ADComputer @adParams
        
        if ($adComputer) {
            # Check if LAPS is configured
            if ($adComputer.'ms-Mcs-AdmPwd') {
                $result.LAPSPassword = $adComputer.'ms-Mcs-AdmPwd'
                $result.Status = "Success"
                
                # Check expiration
                if ($adComputer.'ms-Mcs-AdmPwdExpirationTime') {
                    $expirationDate = [DateTime]::FromFileTime($adComputer.'ms-Mcs-AdmPwdExpirationTime')
                    $result.ExpirationDate = $expirationDate.ToString("yyyy-MM-dd HH:mm:ss")
                    $result.PasswordExpired = $expirationDate -lt (Get-Date)
                    
                    if ($result.PasswordExpired -and -not $IncludeExpired) {
                        $result.Status = "Expired"
                    }
                }
            }
            else {
                $result.Status = "No LAPS Password"
                $result.Error = "LAPS password not found. Computer may not have LAPS configured."
            }
        }
        else {
            $result.Status = "Computer Not Found"
            $result.Error = "Computer not found in Active Directory"
        }
    }
    catch {
        $result.Status = "Error"
        $result.Error = $_.Exception.Message
    }
    
    return $result
}

# Main execution
Write-Host "LAPS Password Retrieval Tool" -ForegroundColor Cyan
Write-Host "============================" -ForegroundColor Cyan
Write-Host ""

# Check for Active Directory module
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "Active Directory PowerShell module is required. Install RSAT-AD-PowerShell feature."
    exit 1
}

Import-Module ActiveDirectory -ErrorAction Stop

# Collect computer names
$computers = @()

if ($Domain) {
    Write-Host "Querying computers from domain: $Domain" -ForegroundColor Yellow
    try {
        $domainParams = @{
            Filter = *
            Properties = Name
        }
        if ($Credential) {
            $domainParams['Credential'] = $Credential
            $domainParams['Server'] = $Domain
        }
        $domainComputers = Get-ADComputer @domainParams | Select-Object -ExpandProperty Name
        $computers += $domainComputers
        Write-Host "Found $($domainComputers.Count) computer(s) in domain" -ForegroundColor Green
    }
    catch {
        Write-Warning "Could not query domain. Error: $($_.Exception.Message)"
    }
}

if ($ComputerList) {
    if (Test-Path $ComputerList) {
        Write-Host "Reading computer list from: $ComputerList" -ForegroundColor Yellow
        $computers += Get-Content $ComputerList | Where-Object { $_.Trim() -ne "" } | ForEach-Object { $_.Trim() }
    }
    else {
        Write-Error "Computer list file not found: $ComputerList"
        exit 1
    }
}

if ($ComputerName) {
    $computers += $ComputerName
}

# Remove duplicates
$computers = $computers | Select-Object -Unique

if ($computers.Count -eq 0) {
    Write-Error "No computers specified. Use -ComputerList, -ComputerName, or -Domain parameter."
    exit 1
}

Write-Host "Found $($computers.Count) unique computer(s) to query" -ForegroundColor Green
Write-Host ""

# Query each computer
$results = @()
$total = $computers.Count
$current = 0

foreach ($computer in $computers) {
    $current++
    Write-Progress -Activity "Retrieving LAPS Passwords" -Status "Processing $computer ($current of $total)" -PercentComplete (($current / $total) * 100)
    
    Write-Host "[$current/$total] Querying $computer..." -NoNewline
    
    $result = Get-LAPSPassword -Computer $computer -DomainName $Domain -Cred $Credential
    
    # Filter expired if not requested
    if ($result.PasswordExpired -and -not $IncludeExpired) {
        $result.LAPSPassword = "***EXPIRED***"
    }
    
    $results += $result
    
    $statusColor = switch ($result.Status) {
        "Success" { "Green" }
        "Expired" { "Yellow" }
        "No LAPS Password" { "Gray" }
        "Computer Not Found" { "Red" }
        "Error" { "Red" }
        default { "Gray" }
    }
    
    Write-Host " $($result.Status)" -ForegroundColor $statusColor
    if ($result.ExpirationDate -ne "N/A") {
        $expColor = if ($result.PasswordExpired) { "Red" } else { "Green" }
        Write-Host "  Expires: $($result.ExpirationDate)" -ForegroundColor $expColor
    }
    if ($result.Error) {
        Write-Host "  Error: $($result.Error)" -ForegroundColor Red
    }
}

Write-Progress -Activity "Retrieving LAPS Passwords" -Completed

# Display summary
Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "========" -ForegroundColor Cyan
$success = ($results | Where-Object { $_.Status -eq "Success" }).Count
$expired = ($results | Where-Object { $_.Status -eq "Expired" -or $_.PasswordExpired -eq $true }).Count
$noLAPS = ($results | Where-Object { $_.Status -eq "No LAPS Password" }).Count
$notFound = ($results | Where-Object { $_.Status -eq "Computer Not Found" }).Count
$errors = ($results | Where-Object { $_.Status -eq "Error" }).Count

Write-Host "Success:           $success" -ForegroundColor Green
Write-Host "Expired:           $expired" -ForegroundColor Yellow
Write-Host "No LAPS Config:    $noLAPS" -ForegroundColor Gray
Write-Host "Not Found:         $notFound" -ForegroundColor Red
Write-Host "Errors:            $errors" -ForegroundColor Red
Write-Host ""

# Export to CSV
try {
    $results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
    Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
    Write-Host "WARNING: This file contains sensitive passwords. Secure it appropriately!" -ForegroundColor Red
}
catch {
    Write-Error "Failed to export results: $($_.Exception.Message)"
}

# Display results table (without passwords for security)
Write-Host ""
Write-Host "Results Summary (passwords hidden):" -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan
$results | Format-Table -AutoSize ComputerName, Status, ExpirationDate, PasswordExpired

