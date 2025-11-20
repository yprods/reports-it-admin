<#
.SYNOPSIS
    Wakes up computers using Wake-on-LAN (WOL) magic packets.

.DESCRIPTION
    This script sends Wake-on-LAN magic packets to wake up computers.
    Supports waking up computers from a list or all computers in the domain.

.PARAMETER ComputerList
    Path to text file with computer names (one per line) or array of computer names.

.PARAMETER AllDomainComputers
    Wake up all computers in the domain.

.PARAMETER MACAddressList
    Path to CSV file with columns: ComputerName, MACAddress (for direct MAC address targeting).

.PARAMETER Domain
    Domain to get computers from (default: current domain).

.PARAMETER OutputFile
    Path to CSV file. Default: WakeOnLANReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication.

.PARAMETER Port
    UDP port for WOL packet (default: 9).

.PARAMETER RetryCount
    Number of times to send WOL packet (default: 3).

.EXAMPLE
    .\Invoke-WakeOnLAN.ps1 -ComputerList "computers.txt"
    
.EXAMPLE
    .\Invoke-WakeOnLAN.ps1 -AllDomainComputers -Domain "contoso.com"
    
.EXAMPLE
    .\Invoke-WakeOnLAN.ps1 -MACAddressList "macs.csv" -RetryCount 5
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [object]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [switch]$AllDomainComputers,
    
    [Parameter(Mandatory=$false)]
    [string]$MACAddressList,
    
    [Parameter(Mandatory=$false)]
    [string]$Domain,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "WakeOnLANReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [int]$Port = 9,
    
    [Parameter(Mandatory=$false)]
    [int]$RetryCount = 3
)

# Function to get MAC address from computer
function Get-ComputerMACAddress {
    param(
        [string]$Computer,
        [System.Management.Automation.PSCredential]$Cred
    )
    
    try {
        $scriptBlock = {
            $macs = @()
            $adapters = Get-WmiObject -Class Win32_NetworkAdapter -Filter "NetConnectionStatus = 2" -ErrorAction SilentlyContinue
            
            foreach ($adapter in $adapters) {
                if ($adapter.MACAddress) {
                    $macs += $adapter.MACAddress
                }
            }
            
            return $macs
        }
        
        if ($Computer -eq "." -or $Computer -eq "localhost" -or $Computer -eq $env:COMPUTERNAME) {
            return & $scriptBlock
        }
        else {
            if ($Cred) {
                return Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -Credential $Cred -ErrorAction Stop
            }
            else {
                return Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -ErrorAction Stop
            }
        }
    }
    catch {
        Write-Warning "Failed to get MAC address for $Computer : $($_.Exception.Message)"
        return @()
    }
}

# Function to convert MAC address to byte array
function Convert-MACToBytes {
    param([string]$MACAddress)
    
    $mac = $MACAddress -replace "[:-]", ""
    if ($mac.Length -ne 12) {
        return $null
    }
    
    $bytes = @()
    for ($i = 0; $i -lt 12; $i += 2) {
        $bytes += [Convert]::ToByte($mac.Substring($i, 2), 16)
    }
    
    return $bytes
}

# Function to send Wake-on-LAN packet
function Send-WOLPacket {
    param(
        [string]$MACAddress,
        [string]$BroadcastIP = "255.255.255.255",
        [int]$UDPPort = 9
    )
    
    try {
        $macBytes = Convert-MACToBytes -MACAddress $MACAddress
        if (-not $macBytes) {
            return @{ Success = $false; Error = "Invalid MAC address format" }
        }
        
        # Create magic packet: 6 bytes of 0xFF + 16 repetitions of MAC address
        $magicPacket = @()
        for ($i = 0; $i -lt 6; $i++) {
            $magicPacket += 0xFF
        }
        
        for ($i = 0; $i -lt 16; $i++) {
            $magicPacket += $macBytes
        }
        
        # Send packet
        $udpClient = New-Object System.Net.Sockets.UdpClient
        $udpClient.Connect($BroadcastIP, $UDPPort)
        $bytesSent = $udpClient.Send($magicPacket, $magicPacket.Length)
        $udpClient.Close()
        
        return @{ Success = $true; BytesSent = $bytesSent }
    }
    catch {
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

# Main execution
Write-Host "Wake-on-LAN Tool" -ForegroundColor Cyan
Write-Host "================" -ForegroundColor Cyan
Write-Host ""

# Get computers and MAC addresses
$targets = @{}

if ($MACAddressList -and (Test-Path $MACAddressList)) {
    Write-Host "Loading MAC addresses from: $MACAddressList" -ForegroundColor Yellow
    $macList = Import-Csv -Path $MACAddressList
    
    foreach ($entry in $macList) {
        if ($entry.ComputerName -and $entry.MACAddress) {
            $targets[$entry.ComputerName] = $entry.MACAddress
        }
    }
}
elseif ($AllDomainComputers) {
    Write-Host "Getting all computers from domain..." -ForegroundColor Yellow
    
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Error "Active Directory PowerShell module is required."
        exit 1
    }
    
    Import-Module ActiveDirectory -ErrorAction Stop
    
    $adParams = @{ Filter = "*" }
    if ($Domain) { $adParams['Server'] = $Domain }
    if ($Credential) { $adParams['Credential'] = $Credential }
    
    try {
        $computers = Get-ADComputer @adParams | Select-Object -ExpandProperty Name
        Write-Host "Found $($computers.Count) computer(s) in domain" -ForegroundColor Green
        
        foreach ($computer in $computers) {
            Write-Host "Getting MAC address for: $computer" -NoNewline
            $macs = Get-ComputerMACAddress -Computer $computer -Cred $Credential
            if ($macs.Count -gt 0) {
                $targets[$computer] = $macs[0]  # Use first MAC address
                Write-Host " - $($macs[0])" -ForegroundColor Green
            }
            else {
                Write-Host " - Not found" -ForegroundColor Yellow
            }
        }
    }
    catch {
        Write-Error "Failed to get domain computers: $($_.Exception.Message)"
        exit 1
    }
}
elseif ($ComputerList) {
    $computers = @()
    
    if ($ComputerList -is [string]) {
        if (Test-Path $ComputerList) {
            $computers = Get-Content $ComputerList | Where-Object { $_.Trim() -ne "" }
        }
        else {
            $computers = @($ComputerList)
        }
    }
    else {
        $computers = $ComputerList
    }
    
    foreach ($computer in $computers) {
        Write-Host "Getting MAC address for: $computer" -NoNewline
        $macs = Get-ComputerMACAddress -Computer $computer -Cred $Credential
        if ($macs.Count -gt 0) {
            $targets[$computer] = $macs[0]
            Write-Host " - $($macs[0])" -ForegroundColor Green
        }
        else {
            Write-Host " - Not found" -ForegroundColor Yellow
        }
    }
}
else {
    Write-Error "Must specify either -ComputerList, -AllDomainComputers, or -MACAddressList"
    exit 1
}

if ($targets.Count -eq 0) {
    Write-Error "No MAC addresses found."
    exit 1
}

Write-Host ""
Write-Host "Targets: $($targets.Count)" -ForegroundColor Yellow
Write-Host "Port: $Port" -ForegroundColor Yellow
Write-Host "Retry Count: $RetryCount" -ForegroundColor Yellow
Write-Host ""

$results = @()

foreach ($computer in $targets.Keys) {
    $macAddress = $targets[$computer]
    Write-Host "Waking up: $computer ($macAddress)" -NoNewline
    
    $result = [PSCustomObject]@{
        Computer = $computer
        MACAddress = $macAddress
        Port = $Port
        PacketsSent = 0
        Status = "Unknown"
        Error = $null
        LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    $successCount = 0
    for ($i = 1; $i -le $RetryCount; $i++) {
        $wolResult = Send-WOLPacket -MACAddress $macAddress -UDPPort $Port
        
        if ($wolResult.Success) {
            $successCount++
            $result.PacketsSent = $wolResult.BytesSent
        }
        else {
            $result.Error = $wolResult.Error
        }
        
        Start-Sleep -Milliseconds 100
    }
    
    if ($successCount -gt 0) {
        $result.Status = "Sent"
        Write-Host " - Success ($successCount/$RetryCount packets)" -ForegroundColor Green
    }
    else {
        $result.Status = "Failed"
        Write-Host " - Failed: $($result.Error)" -ForegroundColor Red
    }
    
    $results += $result
}

Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
$sent = ($results | Where-Object { $_.Status -eq "Sent" }).Count
Write-Host "WOL Packets Sent: $sent" -ForegroundColor Green
Write-Host "Failed: $(($results | Where-Object { $_.Status -eq 'Failed' }).Count)" -ForegroundColor Red

$results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
$results | Format-Table -AutoSize

