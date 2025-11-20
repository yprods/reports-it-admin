<#
.SYNOPSIS
    Shows network routing information and what destinations computers are pointing to.

.DESCRIPTION
    This script analyzes network routing, traceroute, and network path information
    to show where computers are pointing and what routes they're taking.

.PARAMETER ComputerList
    Path to text file with computer names (one per line) or array of computer names.

.PARAMETER Destination
    Destination to trace route to (IP or hostname).

.PARAMETER ShowRoutes
    Show routing table (default: true).

.PARAMETER TraceRoute
    Perform traceroute to destination (default: true).

.PARAMETER ShowConnections
    Show active network connections (default: true).

.PARAMETER Credential
    PSCredential object for remote authentication.

.PARAMETER OutputFile
    Path to CSV file. Default: NetworkRouteReport.csv

.EXAMPLE
    .\Get-NetworkRoute.ps1 -ComputerList "computers.txt" -Destination "8.8.8.8"
    
.EXAMPLE
    .\Get-NetworkRoute.ps1 -ComputerList @("PC01", "PC02") -ShowRoutes -TraceRoute
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [object]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [string]$Destination,
    
    [Parameter(Mandatory=$false)]
    [switch]$ShowRoutes = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$TraceRoute = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$ShowConnections = $true,
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "NetworkRouteReport.csv"
)

# Function to get network information
function Get-NetworkInfo {
    param(
        [string]$Computer,
        [string]$Dest,
        [bool]$Routes,
        [bool]$Trace,
        [bool]$Connections,
        [System.Management.Automation.PSCredential]$Cred
    )
    
    try {
        $scriptBlock = {
            param($Destination, $ShowRoutes, $TraceRoute, $ShowConnections)
            
            $info = @{
                Computer = $env:COMPUTERNAME
                RoutingTable = @()
                Traceroute = @()
                Connections = @()
                DefaultGateway = $null
                DNS = @()
            }
            
            # Get routing table
            if ($ShowRoutes) {
                $routes = Get-NetRoute -ErrorAction SilentlyContinue | Where-Object {
                    $_.DestinationPrefix -ne "0.0.0.0/0" -or $_.NextHop
                } | Select-Object -First 20
                
                foreach ($route in $routes) {
                    $info.RoutingTable += [PSCustomObject]@{
                        Destination = $route.DestinationPrefix
                        NextHop = $route.NextHop
                        Interface = $route.InterfaceAlias
                        Metric = $route.RouteMetric
                    }
                }
                
                # Get default gateway
                $defaultRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($defaultRoute) {
                    $info.DefaultGateway = $defaultRoute.NextHop
                }
            }
            
            # Get DNS servers
            $dns = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue
            $info.DNS = $dns | Select-Object -ExpandProperty ServerAddresses -Unique
            
            # Traceroute
            if ($TraceRoute -and $Destination) {
                try {
                    $trace = Test-NetConnection -ComputerName $Destination -TraceRoute -InformationLevel Detailed -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
                    if ($trace) {
                        $info.Traceroute = $trace.TraceRoute
                    }
                }
                catch {
                    # Fallback to tracert command
                    $tracert = tracert -d -h 15 $Destination 2>&1
                    $hops = @()
                    foreach ($line in $tracert) {
                        if ($line -match "^\s+(\d+)\s+(\d+)\s+ms\s+(\d+)\s+ms\s+(\d+)\s+ms\s+(.+)$") {
                            $hops += $matches[5].Trim()
                        }
                    }
                    $info.Traceroute = $hops
                }
            }
            
            # Get active connections
            if ($ShowConnections) {
                $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | 
                         Select-Object -First 20 | 
                         Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
                
                $info.Connections = $conns
            }
            
            return $info
        }
        
        if ($Computer -eq "." -or $Computer -eq "localhost" -or $Computer -eq $env:COMPUTERNAME) {
            return & $scriptBlock -Destination $Dest -ShowRoutes $Routes -TraceRoute $Trace -ShowConnections $Connections
        }
        else {
            if ($Cred) {
                return Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -ArgumentList $Dest, $Routes, $Trace, $Connections -Credential $Cred -ErrorAction Stop
            }
            else {
                return Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -ArgumentList $Dest, $Routes, $Trace, $Connections -ErrorAction Stop
            }
        }
    }
    catch {
        Write-Warning "Failed to get network info for $Computer : $($_.Exception.Message)"
        return $null
    }
}

# Main execution
Write-Host "Network Route Analysis Tool" -ForegroundColor Cyan
Write-Host "===========================" -ForegroundColor Cyan
Write-Host ""

# Get computer list
$computers = @()

if ($ComputerList -is [string]) {
    if (Test-Path $ComputerList) {
        $computers = Get-Content $ComputerList | Where-Object { $_.Trim() -ne "" }
    }
    else {
        $computers = @($ComputerList)
    }
}
elseif ($ComputerList -is [array]) {
    $computers = $ComputerList
}
else {
    Write-Error "ComputerList must be a file path (string) or array of computer names."
    exit 1
}

if ($computers.Count -eq 0) {
    Write-Error "No computers specified."
    exit 1
}

Write-Host "Computers: $($computers.Count)" -ForegroundColor Yellow
if ($Destination) {
    Write-Host "Destination: $Destination" -ForegroundColor Yellow
}
Write-Host "Show Routes: $ShowRoutes" -ForegroundColor Yellow
Write-Host "Trace Route: $TraceRoute" -ForegroundColor Yellow
Write-Host "Show Connections: $ShowConnections" -ForegroundColor Yellow
Write-Host ""

$results = @()

foreach ($computer in $computers) {
    Write-Host "Analyzing: $computer" -ForegroundColor Cyan
    
    $networkInfo = Get-NetworkInfo -Computer $computer -Dest $Destination -Routes $ShowRoutes.IsPresent -Trace $TraceRoute.IsPresent -Connections $ShowConnections.IsPresent -Cred $Credential
    
    if ($networkInfo) {
        Write-Host "  Default Gateway: $($networkInfo.DefaultGateway)" -ForegroundColor Green
        Write-Host "  DNS Servers: $($networkInfo.DNS -join ', ')" -ForegroundColor Green
        Write-Host "  Routes: $($networkInfo.RoutingTable.Count)" -ForegroundColor Green
        Write-Host "  Connections: $($networkInfo.Connections.Count)" -ForegroundColor Green
        
        if ($networkInfo.Traceroute.Count -gt 0) {
            Write-Host "  Traceroute Hops: $($networkInfo.Traceroute.Count)" -ForegroundColor Green
            foreach ($hop in $networkInfo.Traceroute) {
                Write-Host "    -> $hop" -ForegroundColor Gray
            }
        }
        
        # Create result entries
        $result = [PSCustomObject]@{
            Computer = $networkInfo.Computer
            DefaultGateway = $networkInfo.DefaultGateway
            DNSServers = $networkInfo.DNS -join "; "
            RouteCount = $networkInfo.RoutingTable.Count
            ConnectionCount = $networkInfo.Connections.Count
            TracerouteHops = $networkInfo.Traceroute.Count
            TraceroutePath = $networkInfo.Traceroute -join " -> "
            LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        
        $results += $result
    }
    else {
        Write-Host "  Failed to get network information" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
$results | Format-Table -AutoSize

$results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "Results exported to: $OutputFile" -ForegroundColor Green

