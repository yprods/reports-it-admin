<#
.SYNOPSIS
    Queries network adapter speeds (LAN/WiFi) from a list of computers using WMI.

.DESCRIPTION
    This script reads a list of computer names and queries their network adapter information
    remotely using WMI. It retrieves link speed, connection type (LAN/WiFi), adapter name,
    and connection status for all active network adapters.

.PARAMETER ComputerList
    Path to a text file containing computer names (one per line).

.PARAMETER ComputerName
    Single computer name or array of computer names to query.

.PARAMETER Domain
    Query all computers in the specified domain (requires Active Directory module).

.PARAMETER OutputFile
    Path to CSV file where results will be exported. Default: NetworkSpeedReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication (optional).

.PARAMETER IncludeDisabled
    Include disabled network adapters in the results (default: false, only active adapters).

.EXAMPLE
    .\Get-NetworkSpeed.ps1 -ComputerList "computers.txt"
    
.EXAMPLE
    .\Get-NetworkSpeed.ps1 -ComputerName "PC01","PC02","PC03"
    
.EXAMPLE
    .\Get-NetworkSpeed.ps1 -Domain "contoso.com"
    
.EXAMPLE
    .\Get-NetworkSpeed.ps1 -ComputerList "computers.txt" -IncludeDisabled
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
    [string]$OutputFile = "NetworkSpeedReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeDisabled
)

# Function to convert speed from bits to readable format
function Format-NetworkSpeed {
    param([long]$SpeedBits)
    
    if ($SpeedBits -eq $null -or $SpeedBits -eq 0) {
        return "N/A"
    }
    
    if ($SpeedBits -ge 1000000000) {
        return "$([math]::Round($SpeedBits / 1000000000, 2)) Gbps"
    }
    elseif ($SpeedBits -ge 1000000) {
        return "$([math]::Round($SpeedBits / 1000000, 2)) Mbps"
    }
    elseif ($SpeedBits -ge 1000) {
        return "$([math]::Round($SpeedBits / 1000, 2)) Kbps"
    }
    else {
        return "$SpeedBits bps"
    }
}

# Function to determine connection type (LAN/WiFi)
function Get-ConnectionType {
    param(
        [string]$AdapterType,
        [string]$Name,
        [string]$Description
    )
    
    $adapterLower = $AdapterType.ToLower()
    $nameLower = $Name.ToLower()
    $descLower = $Description.ToLower()
    
    # Check for WiFi/Wireless indicators
    if ($adapterLower -like "*wireless*" -or 
        $adapterLower -like "*wifi*" -or 
        $adapterLower -like "*802.11*" -or
        $nameLower -like "*wireless*" -or 
        $nameLower -like "*wifi*" -or 
        $nameLower -like "*wlan*" -or
        $descLower -like "*wireless*" -or 
        $descLower -like "*wifi*" -or 
        $descLower -like "*802.11*") {
        return "WiFi"
    }
    
    # Check for Ethernet/LAN indicators
    if ($adapterLower -like "*ethernet*" -or 
        $adapterLower -like "*lan*" -or
        $nameLower -like "*ethernet*" -or 
        $nameLower -like "*lan*" -or
        $descLower -like "*ethernet*" -or 
        $descLower -like "*lan*") {
        return "LAN"
    }
    
    # Default based on adapter type
    if ($adapterLower -eq "ethernet 802.3") {
        return "LAN"
    }
    
    return "Unknown"
}

# Function to get network adapter information from a single computer
function Get-NetworkSpeed {
    param(
        [string]$Computer,
        [System.Management.Automation.PSCredential]$Cred,
        [bool]$IncludeDisabledAdapters
    )
    
    $results = @()
    
    try {
        # Test connectivity first
        if (-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            $result = [PSCustomObject]@{
                ComputerName = $Computer
                AdapterName = "N/A"
                ConnectionType = "N/A"
                LinkSpeed = "N/A"
                LinkSpeedMbps = $null
                Status = "Offline"
                MACAddress = "N/A"
                IPAddress = "N/A"
                LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Error = "Computer is not reachable"
            }
            $results += $result
            return $results
        }
        
        # Method 1: Query Win32_NetworkAdapter (basic adapter info)
        try {
            $adapterParams = @{
                ComputerName = $Computer
                Class = "Win32_NetworkAdapter"
                Filter = "PhysicalAdapter = True"
                ErrorAction = "Stop"
            }
            
            if ($Cred) {
                $adapterParams['Credential'] = $Cred
            }
            
            $adapters = Get-CimInstance @adapterParams
            
            if ($adapters) {
                foreach ($adapter in $adapters) {
                    # Skip disabled adapters unless requested
                    if (-not $IncludeDisabledAdapters -and $adapter.NetConnectionStatus -ne 2) {
                        continue
                    }
                    
                    # Get connection status
                    $connectionStatus = switch ($adapter.NetConnectionStatus) {
                        0 { "Disconnected" }
                        1 { "Connecting" }
                        2 { "Connected" }
                        3 { "Disconnecting" }
                        4 { "Hardware Not Present" }
                        5 { "Hardware Disabled" }
                        6 { "Hardware Malfunction" }
                        7 { "Media Disconnected" }
                        8 { "Authenticating" }
                        9 { "Authentication Succeeded" }
                        10 { "Authentication Failed" }
                        11 { "Invalid Address" }
                        12 { "Credentials Required" }
                        default { "Unknown" }
                    }
                    
                    # Get adapter configuration for IP and MAC
                    $ipAddress = "N/A"
                    $macAddress = if ($adapter.MACAddress) { $adapter.MACAddress } else { "N/A" }
                    
                    try {
                        $configParams = @{
                            ComputerName = $Computer
                            Class = "Win32_NetworkAdapterConfiguration"
                            Filter = "Index = $($adapter.Index)"
                            ErrorAction = "SilentlyContinue"
                        }
                        
                        if ($Cred) {
                            $configParams['Credential'] = $Cred
                        }
                        
                        $config = Get-CimInstance @configParams
                        if ($config -and $config.IPAddress) {
                            # Get IPv4 address (skip IPv6)
                            $ipv4 = $config.IPAddress | Where-Object { $_ -notlike "*:*" } | Select-Object -First 1
                            if ($ipv4) {
                                $ipAddress = $ipv4
                            }
                        }
                    }
                    catch {
                        # Continue without IP info
                    }
                    
                    # Get link speed from Win32_NetworkAdapter
                    $linkSpeed = $null
                    $linkSpeedMbps = $null
                    
                    if ($adapter.Speed) {
                        $linkSpeed = Format-NetworkSpeed -SpeedBits $adapter.Speed
                        $linkSpeedMbps = [math]::Round($adapter.Speed / 1000000, 2)
                    }
                    
                    # Determine connection type
                    $connectionType = Get-ConnectionType -AdapterType $adapter.AdapterTypeID -Name $adapter.Name -Description $adapter.Description
                    
                    $result = [PSCustomObject]@{
                        ComputerName = $Computer
                        AdapterName = if ($adapter.Name) { $adapter.Name } else { "N/A" }
                        ConnectionType = $connectionType
                        LinkSpeed = if ($linkSpeed) { $linkSpeed } else { "N/A" }
                        LinkSpeedMbps = $linkSpeedMbps
                        Status = $connectionStatus
                        MACAddress = $macAddress
                        IPAddress = $ipAddress
                        LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        Error = $null
                    }
                    
                    $results += $result
                }
            }
        }
        catch {
            # Method 2: Try alternative approach with MSFT_NetAdapter
            try {
                $netAdapterParams = @{
                    ComputerName = $Computer
                    Class = "MSFT_NetAdapter"
                    Filter = "PhysicalMediaType -ne 'Unknown'"
                    ErrorAction = "Stop"
                }
                
                if ($Cred) {
                    $netAdapterParams['Credential'] = $Cred
                }
                
                $netAdapters = Get-CimInstance @netAdapterParams -Namespace "root\StandardCimv2"
                
                if ($netAdapters) {
                    foreach ($netAdapter in $netAdapters) {
                        if (-not $IncludeDisabledAdapters -and $netAdapter.Status -ne "Up") {
                            continue
                        }
                        
                        $linkSpeed = $null
                        $linkSpeedMbps = $null
                        
                        if ($netAdapter.LinkSpeed) {
                            $linkSpeedMbps = $netAdapter.LinkSpeed
                            $linkSpeed = Format-NetworkSpeed -SpeedBits ($netAdapter.LinkSpeed * 1000000)
                        }
                        
                        $connectionType = Get-ConnectionType -AdapterType "" -Name $netAdapter.Name -Description $netAdapter.InterfaceDescription
                        
                        $result = [PSCustomObject]@{
                            ComputerName = $Computer
                            AdapterName = if ($netAdapter.Name) { $netAdapter.Name } else { "N/A" }
                            ConnectionType = $connectionType
                            LinkSpeed = if ($linkSpeed) { $linkSpeed } else { "N/A" }
                            LinkSpeedMbps = $linkSpeedMbps
                            Status = if ($netAdapter.Status) { $netAdapter.Status } else { "Unknown" }
                            MACAddress = if ($netAdapter.MacAddress) { $netAdapter.MacAddress } else { "N/A" }
                            IPAddress = "N/A"
                            LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                            Error = $null
                        }
                        
                        $results += $result
                    }
                }
            }
            catch {
                $result = [PSCustomObject]@{
                    ComputerName = $Computer
                    AdapterName = "N/A"
                    ConnectionType = "N/A"
                    LinkSpeed = "N/A"
                    LinkSpeedMbps = $null
                    Status = "Error"
                    MACAddress = "N/A"
                    IPAddress = "N/A"
                    LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    Error = $_.Exception.Message
                }
                $results += $result
            }
        }
    }
    catch {
        $result = [PSCustomObject]@{
            ComputerName = $Computer
            AdapterName = "N/A"
            ConnectionType = "N/A"
            LinkSpeed = "N/A"
            LinkSpeedMbps = $null
            Status = "Error"
            MACAddress = "N/A"
            IPAddress = "N/A"
            LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Error = $_.Exception.Message
        }
        $results += $result
    }
    
    # If no results, add a default entry
    if ($results.Count -eq 0) {
        $result = [PSCustomObject]@{
            ComputerName = $Computer
            AdapterName = "N/A"
            ConnectionType = "N/A"
            LinkSpeed = "N/A"
            LinkSpeedMbps = $null
            Status = "No Adapters Found"
            MACAddress = "N/A"
            IPAddress = "N/A"
            LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Error = "No network adapters found or accessible"
        }
        $results += $result
    }
    
    return $results
}

# Main execution
Write-Host "Network Speed Query Tool" -ForegroundColor Cyan
Write-Host "========================" -ForegroundColor Cyan
Write-Host ""

# Collect computer names
$computers = @()

if ($Domain) {
    try {
        # Try to import Active Directory module
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            Write-Warning "Active Directory module not found. Install RSAT-AD-PowerShell feature."
            Write-Host "Falling back to other methods..." -ForegroundColor Yellow
        }
        else {
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
            Write-Host "Querying computers from domain: $Domain" -ForegroundColor Yellow
            
            try {
                $domainComputers = Get-ADComputer -Filter * -Properties Name | Select-Object -ExpandProperty Name
                $computers += $domainComputers
                Write-Host "Found $($domainComputers.Count) computer(s) in domain" -ForegroundColor Green
            }
            catch {
                Write-Warning "Could not query domain. Error: $($_.Exception.Message)"
                Write-Host "Please use -ComputerList or -ComputerName instead." -ForegroundColor Yellow
            }
        }
    }
    catch {
        Write-Warning "Active Directory query failed: $($_.Exception.Message)"
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
if ($IncludeDisabled) {
    Write-Host "Including disabled adapters: ENABLED" -ForegroundColor Cyan
}
Write-Host ""

# Query each computer
$allResults = @()
$total = $computers.Count
$current = 0

foreach ($computer in $computers) {
    $current++
    Write-Progress -Activity "Querying Network Speeds" -Status "Processing $computer ($current of $total)" -PercentComplete (($current / $total) * 100)
    
    Write-Host "[$current/$total] Querying $computer..." -NoNewline
    
    $results = Get-NetworkSpeed -Computer $computer -Cred $Credential -IncludeDisabledAdapters $IncludeDisabled.IsPresent
    $allResults += $results
    
    $successCount = ($results | Where-Object { $_.Status -eq "Connected" -or $_.Status -eq "Up" }).Count
    $lanCount = ($results | Where-Object { $_.ConnectionType -eq "LAN" -and ($_.Status -eq "Connected" -or $_.Status -eq "Up") }).Count
    $wifiCount = ($results | Where-Object { $_.ConnectionType -eq "WiFi" -and ($_.Status -eq "Connected" -or $_.Status -eq "Up") }).Count
    
    if ($successCount -gt 0) {
        Write-Host " Found $successCount active adapter(s)" -ForegroundColor Green
        foreach ($adapter in $results) {
            if ($adapter.Status -eq "Connected" -or $adapter.Status -eq "Up") {
                $typeColor = if ($adapter.ConnectionType -eq "LAN") { "Cyan" } elseif ($adapter.ConnectionType -eq "WiFi") { "Yellow" } else { "Gray" }
                Write-Host "  - $($adapter.AdapterName) ($($adapter.ConnectionType)): $($adapter.LinkSpeed)" -ForegroundColor $typeColor
            }
        }
    }
    else {
        $statusColor = switch ($results[0].Status) {
            "Offline" { "Red" }
            "Error" { "Red" }
            "No Adapters Found" { "Yellow" }
            default { "Gray" }
        }
        Write-Host " $($results[0].Status)" -ForegroundColor $statusColor
        if ($results[0].Error) {
            Write-Host "  Error: $($results[0].Error)" -ForegroundColor Red
        }
    }
}

Write-Progress -Activity "Querying Network Speeds" -Completed

# Display summary
Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "========" -ForegroundColor Cyan
$totalAdapters = ($allResults | Where-Object { $_.Status -eq "Connected" -or $_.Status -eq "Up" }).Count
$lanAdapters = ($allResults | Where-Object { $_.ConnectionType -eq "LAN" -and ($_.Status -eq "Connected" -or $_.Status -eq "Up") }).Count
$wifiAdapters = ($allResults | Where-Object { $_.ConnectionType -eq "WiFi" -and ($_.Status -eq "Connected" -or $_.Status -eq "Up") }).Count
$offline = ($allResults | Where-Object { $_.Status -eq "Offline" }).Count
$errors = ($allResults | Where-Object { $_.Status -eq "Error" }).Count

Write-Host "Active Adapters: $totalAdapters" -ForegroundColor Green
Write-Host "LAN Adapters:     $lanAdapters" -ForegroundColor Cyan
Write-Host "WiFi Adapters:   $wifiAdapters" -ForegroundColor Yellow
Write-Host "Offline:         $offline" -ForegroundColor Red
Write-Host "Errors:          $errors" -ForegroundColor Red
Write-Host ""

# Calculate average speeds
$avgLanSpeed = ($allResults | Where-Object { $_.ConnectionType -eq "LAN" -and $_.LinkSpeedMbps -ne $null } | Measure-Object -Property LinkSpeedMbps -Average).Average
$avgWifiSpeed = ($allResults | Where-Object { $_.ConnectionType -eq "WiFi" -and $_.LinkSpeedMbps -ne $null } | Measure-Object -Property LinkSpeedMbps -Average).Average

if ($avgLanSpeed) {
    Write-Host "Average LAN Speed:  $([math]::Round($avgLanSpeed, 2)) Mbps" -ForegroundColor Cyan
}
if ($avgWifiSpeed) {
    Write-Host "Average WiFi Speed: $([math]::Round($avgWifiSpeed, 2)) Mbps" -ForegroundColor Yellow
}
Write-Host ""

# Export to CSV
try {
    $allResults | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
    Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
}
catch {
    Write-Error "Failed to export results: $($_.Exception.Message)"
}

# Display results table
Write-Host ""
Write-Host "Detailed Results:" -ForegroundColor Cyan
Write-Host "================" -ForegroundColor Cyan
$allResults | Where-Object { $_.Status -eq "Connected" -or $_.Status -eq "Up" } | Format-Table -AutoSize ComputerName, AdapterName, ConnectionType, LinkSpeed, Status, IPAddress

