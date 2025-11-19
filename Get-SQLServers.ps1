<#
.SYNOPSIS
    Gets all servers with SQL Server installed and exports to CSV.

.DESCRIPTION
    This script finds all servers in the domain that have SQL Server installed
    and exports detailed information to a CSV file.

.PARAMETER Domain
    Domain to search (default: current domain).

.PARAMETER OutputFile
    Path to CSV file. Default: SQLServersReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication.

.PARAMETER SQLVersion
    Filter by SQL Server version (e.g., "2019", "2017", "2016") or "All" (default: All).

.EXAMPLE
    .\Get-SQLServers.ps1 -Domain "contoso.com"
    
.EXAMPLE
    .\Get-SQLServers.ps1 -SQLVersion "2019" -OutputFile "SQL2019Servers.csv"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Domain,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "SQLServersReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [string]$SQLVersion = "All"
)

# Function to get SQL Server information from a server
function Get-SQLServerInfo {
    param(
        [string]$Server,
        [string]$Version,
        [System.Management.Automation.PSCredential]$Cred
    )
    
    $scriptBlock = {
        param([string]$SQLVersion)
        
        $sqlInfo = @()
        
        try {
            # Method 1: Check for SQL Server services
            $sqlServices = Get-Service | Where-Object {
                $_.Name -like "*MSSQL*" -or
                $_.Name -like "*SQL Server*" -or
                $_.DisplayName -like "*SQL Server*"
            }
            
            foreach ($service in $sqlServices) {
                $instanceName = "MSSQLSERVER"
                if ($service.Name -match 'MSSQL\$(\w+)') {
                    $instanceName = $matches[1]
                }
                
                $sqlInfo += @{
                    InstanceName = $instanceName
                    ServiceName = $service.Name
                    ServiceDisplayName = $service.DisplayName
                    ServiceStatus = $service.Status
                    Source = "Service"
                }
            }
            
            # Method 2: Check registry for SQL Server instances
            try {
                $instanceNames = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL" -ErrorAction SilentlyContinue
                if ($instanceNames) {
                    foreach ($prop in $instanceNames.PSObject.Properties) {
                        if ($prop.Name -ne "PSPath" -and $prop.Name -ne "PSParentPath") {
                            $instanceName = $prop.Name
                            $instanceValue = $prop.Value
                            
                            # Get instance details
                            $instanceKey = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$instanceValue"
                            $instanceDetails = Get-ItemProperty $instanceKey -ErrorAction SilentlyContinue
                            
                            $version = if ($instanceDetails) { $instanceDetails.Version } else { "Unknown" }
                            
                            # Filter by version if specified
                            if ($SQLVersion -ne "All" -and $version -notlike "*$SQLVersion*") {
                                continue
                            }
                            
                            $sqlInfo += @{
                                InstanceName = $instanceName
                                ServiceName = "MSSQL`$$instanceName"
                                ServiceDisplayName = "SQL Server ($instanceName)"
                                ServiceStatus = "N/A"
                                Version = $version
                                Source = "Registry"
                            }
                        }
                    }
                }
            }
            catch {
                # Continue
            }
            
            # Method 3: Check installed SQL Server software
            $regPaths = @(
                "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
                "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
            )
            
            foreach ($regPath in $regPaths) {
                $sqlApps = Get-ItemProperty $regPath -ErrorAction SilentlyContinue | Where-Object {
                    $_.DisplayName -like "*SQL Server*" -and
                    $_.DisplayName -notlike "*Management*" -and
                    $_.DisplayName -notlike "*Tools*"
                }
                
                foreach ($app in $sqlApps) {
                    $version = if ($app.DisplayVersion) { $app.DisplayVersion } else { "Unknown" }
                    
                    # Filter by version if specified
                    if ($SQLVersion -ne "All" -and $version -notlike "*$SQLVersion*") {
                        continue
                    }
                    
                    $sqlInfo += @{
                        InstanceName = "From Registry"
                        ServiceName = "N/A"
                        ServiceDisplayName = $app.DisplayName
                        ServiceStatus = "N/A"
                        Version = $version
                        Publisher = if ($app.Publisher) { $app.Publisher } else { "N/A" }
                        InstallDate = if ($app.InstallDate) { $app.InstallDate } else { "N/A" }
                        Source = "Installed Software"
                    }
                }
            }
            
            # Method 4: Check for running SQL Server processes
            $sqlProcesses = Get-Process | Where-Object {
                $_.ProcessName -like "*sqlservr*"
            }
            
            foreach ($proc in $sqlProcesses) {
                $sqlInfo += @{
                    InstanceName = "Running Process"
                    ServiceName = $proc.ProcessName
                    ServiceDisplayName = "SQL Server Process (PID: $($proc.Id))"
                    ServiceStatus = "Running"
                    Version = "Unknown"
                    Source = "Process"
                }
            }
        }
        catch {
            $sqlInfo += @{
                InstanceName = "Error"
                ServiceName = "N/A"
                ServiceDisplayName = "Error"
                ServiceStatus = "Error"
                Version = "N/A"
                Source = "Error"
                Error = $_.Exception.Message
            }
        }
        
        return $sqlInfo
    }
    
    $results = @()
    
    try {
        if (-not (Test-Connection -ComputerName $Server -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            return @([PSCustomObject]@{
                ServerName = $Server
                InstanceName = "N/A"
                ServiceName = "N/A"
                ServiceDisplayName = "N/A"
                ServiceStatus = "N/A"
                SQLVersion = "N/A"
                Publisher = "N/A"
                InstallDate = "N/A"
                Source = "N/A"
                Status = "Offline"
                Error = "Computer is not reachable"
            })
        }
        
        $invokeParams = @{
            ComputerName = $Server
            ScriptBlock = $scriptBlock
            ArgumentList = @($Version)
        }
        if ($Cred) { $invokeParams['Credential'] = $Cred }
        
        $sqlData = Invoke-Command @invokeParams
        
        if ($sqlData.Count -eq 0) {
            return @([PSCustomObject]@{
                ServerName = $Server
                InstanceName = "N/A"
                ServiceName = "N/A"
                ServiceDisplayName = "N/A"
                ServiceStatus = "N/A"
                SQLVersion = "N/A"
                Publisher = "N/A"
                InstallDate = "N/A"
                Source = "N/A"
                Status = "No SQL Found"
                Error = "No SQL Server found on this server"
            })
        }
        
        foreach ($sql in $sqlData) {
            $results += [PSCustomObject]@{
                ServerName = $Server
                InstanceName = $sql.InstanceName
                ServiceName = $sql.ServiceName
                ServiceDisplayName = $sql.ServiceDisplayName
                ServiceStatus = $sql.ServiceStatus
                SQLVersion = if ($sql.Version) { $sql.Version } else { "Unknown" }
                Publisher = if ($sql.Publisher) { $sql.Publisher } else { "N/A" }
                InstallDate = if ($sql.InstallDate) { $sql.InstallDate } else { "N/A" }
                Source = $sql.Source
                Status = "Success"
                Error = if ($sql.Error) { $sql.Error } else { $null }
            }
        }
    }
    catch {
        $results += [PSCustomObject]@{
            ServerName = $Server
            InstanceName = "N/A"
            ServiceName = "N/A"
            ServiceDisplayName = "N/A"
            ServiceStatus = "N/A"
            SQLVersion = "N/A"
            Publisher = "N/A"
            InstallDate = "N/A"
            Source = "N/A"
            Status = "Error"
            Error = $_.Exception.Message
        }
    }
    
    return $results
}

# Main execution
Write-Host "SQL Server Finder" -ForegroundColor Cyan
Write-Host "=================" -ForegroundColor Cyan
Write-Host ""

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "Active Directory PowerShell module is required."
    exit 1
}

Import-Module ActiveDirectory -ErrorAction Stop

try {
    $adParams = @{
        Filter = *
        Properties = @("Name", "OperatingSystem")
        ErrorAction = "Stop"
    }
    
    if ($Domain) {
        $adParams['Server'] = $Domain
    }
    
    if ($Credential) {
        $adParams['Credential'] = $Credential
    }
    
    Write-Host "Querying servers from domain..." -ForegroundColor Yellow
    $allComputers = Get-ADComputer @adParams
    
    # Filter for servers only
    $servers = @()
    foreach ($computer in $allComputers) {
        $os = $computer.OperatingSystem
        if ($os -and ($os -like "*Server*" -or $os -like "*Windows Server*")) {
            $servers += $computer.Name
        }
    }
    
    Write-Host "Found $($servers.Count) server(s)" -ForegroundColor Green
    Write-Host "SQL Version Filter: $SQLVersion" -ForegroundColor Yellow
    Write-Host ""
    
    $allResults = @()
    $total = $servers.Count
    $current = 0
    
    foreach ($server in $servers) {
        $current++
        Write-Progress -Activity "Searching for SQL Server" -Status "Processing $server ($current of $total)" -PercentComplete (($current / $total) * 100)
        
        Write-Host "[$current/$total] Checking $server..." -NoNewline
        
        $results = Get-SQLServerInfo -Server $server -Version $SQLVersion -Cred $Credential
        $allResults += $results
        
        $sqlCount = ($results | Where-Object { $_.Status -eq "Success" }).Count
        
        if ($sqlCount -gt 0) {
            Write-Host " Found $sqlCount SQL instance(s)" -ForegroundColor Green
            foreach ($sql in ($results | Where-Object { $_.Status -eq "Success" } | Select-Object -First 2)) {
                Write-Host "  - $($sql.InstanceName) ($($sql.SQLVersion))" -ForegroundColor Gray
            }
        }
        else {
            Write-Host " No SQL Server found" -ForegroundColor Gray
        }
    }
    
    Write-Progress -Activity "Searching for SQL Server" -Completed
    
    Write-Host ""
    Write-Host "Summary:" -ForegroundColor Cyan
    Write-Host "========" -ForegroundColor Cyan
    $totalSQL = ($allResults | Where-Object { $_.Status -eq "Success" }).Count
    $serversWithSQL = ($allResults | Where-Object { $_.Status -eq "Success" } | Select-Object -Unique ServerName).Count
    
    Write-Host "Total SQL Instances: $totalSQL" -ForegroundColor Green
    Write-Host "Servers with SQL:    $serversWithSQL" -ForegroundColor Cyan
    Write-Host ""
    
    # Export to CSV
    $allResults | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
    Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
    
    Write-Host ""
    Write-Host "SQL Servers Summary:" -ForegroundColor Cyan
    $allResults | Where-Object { $_.Status -eq "Success" } | Group-Object -Property ServerName | Select-Object Count, Name | Sort-Object Count -Descending | Format-Table -AutoSize
    
    Write-Host ""
    Write-Host "Sample Results:" -ForegroundColor Cyan
    $allResults | Where-Object { $_.Status -eq "Success" } | Select-Object -First 10 | Format-Table -AutoSize ServerName, InstanceName, SQLVersion, ServiceStatus, Source
}
catch {
    Write-Error "Failed: $($_.Exception.Message)"
    exit 1
}

