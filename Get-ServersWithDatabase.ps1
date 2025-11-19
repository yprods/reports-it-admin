<#
.SYNOPSIS
    Finds all servers with database installations in the domain.

.DESCRIPTION
    This script searches for servers that have database software installed,
    including SQL Server, MySQL, Oracle, PostgreSQL, and other database systems.

.PARAMETER Domain
    Domain to search (default: current domain).

.PARAMETER OutputFile
    Path to CSV file. Default: DatabaseServersReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication.

.PARAMETER DatabaseType
    Filter by database type: All, SQLServer, MySQL, Oracle, PostgreSQL, MongoDB, Other (default: All).

.PARAMETER SearchServices
    Search for database services (default: true).

.PARAMETER SearchInstalled
    Search for installed database software (default: true).

.EXAMPLE
    .\Get-ServersWithDatabase.ps1 -Domain "contoso.com"
    
.EXAMPLE
    .\Get-ServersWithDatabase.ps1 -DatabaseType "SQLServer" -SearchServices
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Domain,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "DatabaseServersReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("All","SQLServer","MySQL","Oracle","PostgreSQL","MongoDB","Other")]
    [string]$DatabaseType = "All",
    
    [Parameter(Mandatory=$false)]
    [switch]$SearchServices = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$SearchInstalled = $true
)

# Function to detect database type
function Get-DatabaseType {
    param(
        [string]$ServiceName,
        [string]$DisplayName,
        [string]$ProcessName
    )
    
    $combined = "$ServiceName $DisplayName $ProcessName".ToLower()
    
    if ($combined -match "sql server|mssql|microsoft sql|sqlservr") {
        return "SQLServer"
    }
    elseif ($combined -match "mysql|mysqld") {
        return "MySQL"
    }
    elseif ($combined -match "oracle|oracle.*service|oracle.*database") {
        return "Oracle"
    }
    elseif ($combined -match "postgresql|postgres") {
        return "PostgreSQL"
    }
    elseif ($combined -match "mongodb|mongo") {
        return "MongoDB"
    }
    elseif ($combined -match "database|db|sql") {
        return "Other"
    }
    
    return "Unknown"
}

# Function to find databases on a server
function Get-ServerDatabase {
    param(
        [string]$Server,
        [string]$Type,
        [bool]$SearchServices,
        [bool]$SearchInstalled,
        [System.Management.Automation.PSCredential]$Cred
    )
    
    $scriptBlock = {
        param([bool]$SearchServices, [bool]$SearchInstalled)
        
        $databases = @()
        
        # Search for database services
        if ($SearchServices) {
            $services = Get-Service | Where-Object {
                $_.Name -like "*SQL*" -or
                $_.Name -like "*MySQL*" -or
                $_.Name -like "*Oracle*" -or
                $_.Name -like "*PostgreSQL*" -or
                $_.Name -like "*MongoDB*" -or
                $_.DisplayName -like "*Database*" -or
                $_.DisplayName -like "*SQL*"
            }
            
            foreach ($service in $services) {
                $dbType = Get-DatabaseType -ServiceName $service.Name -DisplayName $service.DisplayName -ProcessName ""
                
                $databases += @{
                    Type = "Service"
                    DatabaseType = $dbType
                    Name = $service.Name
                    DisplayName = $service.DisplayName
                    Status = $service.Status
                    Description = "Service: $($service.DisplayName)"
                }
            }
        }
        
        # Search for installed database software
        if ($SearchInstalled) {
            $regPaths = @(
                "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
                "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
            )
            
            foreach ($regPath in $regPaths) {
                $apps = Get-ItemProperty $regPath -ErrorAction SilentlyContinue | Where-Object {
                    $_.DisplayName -like "*SQL Server*" -or
                    $_.DisplayName -like "*MySQL*" -or
                    $_.DisplayName -like "*Oracle*" -or
                    $_.DisplayName -like "*PostgreSQL*" -or
                    $_.DisplayName -like "*MongoDB*" -or
                    $_.DisplayName -like "*Database*"
                }
                
                foreach ($app in $apps) {
                    $dbType = Get-DatabaseType -ServiceName "" -DisplayName $app.DisplayName -ProcessName ""
                    
                    $databases += @{
                        Type = "Installed"
                        DatabaseType = $dbType
                        Name = $app.DisplayName
                        DisplayName = $app.DisplayName
                        Status = "N/A"
                        Description = "Installed Software: $($app.DisplayName) - Version: $($app.DisplayVersion)"
                    }
                }
            }
            
            # Check for SQL Server instances
            try {
                $sqlInstances = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL" -ErrorAction SilentlyContinue
                if ($sqlInstances) {
                    foreach ($instance in $sqlInstances.PSObject.Properties) {
                        if ($instance.Name -ne "PSPath" -and $instance.Name -ne "PSParentPath") {
                            $databases += @{
                                Type = "SQLInstance"
                                DatabaseType = "SQLServer"
                                Name = $instance.Name
                                DisplayName = "SQL Server Instance: $($instance.Name)"
                                Status = "N/A"
                                Description = "SQL Server Instance: $($instance.Name) = $($instance.Value)"
                            }
                        }
                    }
                }
            }
            catch {
                # Continue
            }
        }
        
        # Search for running database processes
        $processes = Get-Process | Where-Object {
            $_.ProcessName -like "*sqlservr*" -or
            $_.ProcessName -like "*mysqld*" -or
            $_.ProcessName -like "*oracle*" -or
            $_.ProcessName -like "*postgres*" -or
            $_.ProcessName -like "*mongod*"
        }
        
        foreach ($proc in $processes) {
            $dbType = Get-DatabaseType -ServiceName "" -DisplayName "" -ProcessName $proc.ProcessName
            
            $databases += @{
                Type = "Process"
                DatabaseType = $dbType
                Name = $proc.ProcessName
                DisplayName = $proc.ProcessName
                Status = "Running"
                Description = "Running Process: $($proc.ProcessName) (PID: $($proc.Id))"
            }
        }
        
        return $databases
    }
    
    $results = @()
    
    try {
        if (-not (Test-Connection -ComputerName $Server -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            return @([PSCustomObject]@{
                ServerName = $Server
                DatabaseType = "N/A"
                DatabaseName = "N/A"
                Type = "N/A"
                Status = "Offline"
                Description = "N/A"
                Error = "Computer is not reachable"
            })
        }
        
        $invokeParams = @{
            ComputerName = $Server
            ScriptBlock = $scriptBlock
            ArgumentList = @($SearchServices, $SearchInstalled)
        }
        if ($Cred) { $invokeParams['Credential'] = $Cred }
        
        $databases = Invoke-Command @invokeParams
        
        if ($databases.Count -eq 0) {
            return @([PSCustomObject]@{
                ServerName = $Server
                DatabaseType = "N/A"
                DatabaseName = "N/A"
                Type = "N/A"
                Status = "No Database Found"
                Description = "No database software found"
                Error = $null
            })
        }
        
        foreach ($db in $databases) {
            # Filter by database type if specified
            if ($Type -ne "All" -and $db.DatabaseType -ne $Type) {
                continue
            }
            
            $results += [PSCustomObject]@{
                ServerName = $Server
                DatabaseType = $db.DatabaseType
                DatabaseName = $db.Name
                Type = $db.Type
                Status = $db.Status
                Description = $db.Description
                Error = $null
            }
        }
    }
    catch {
        $results += [PSCustomObject]@{
            ServerName = $Server
            DatabaseType = "N/A"
            DatabaseName = "N/A"
            Type = "N/A"
            Status = "Error"
            Description = "N/A"
            Error = $_.Exception.Message
        }
    }
    
    return $results
}

# Main execution
Write-Host "Database Server Finder" -ForegroundColor Cyan
Write-Host "=====================" -ForegroundColor Cyan
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
    Write-Host "Database Type Filter: $DatabaseType" -ForegroundColor Yellow
    Write-Host "Search Services: $SearchServices" -ForegroundColor Yellow
    Write-Host "Search Installed: $SearchInstalled" -ForegroundColor Yellow
    Write-Host ""
    
    $allResults = @()
    $total = $servers.Count
    $current = 0
    
    foreach ($server in $servers) {
        $current++
        Write-Progress -Activity "Searching for Databases" -Status "Processing $server ($current of $total)" -PercentComplete (($current / $total) * 100)
        
        Write-Host "[$current/$total] Checking $server..." -NoNewline
        
        $results = Get-ServerDatabase -Server $server -Type $DatabaseType -SearchServices $SearchServices.IsPresent -SearchInstalled $SearchInstalled.IsPresent -Cred $Credential
        $allResults += $results
        
        $dbCount = ($results | Where-Object { $_.DatabaseType -ne "N/A" }).Count
        
        if ($dbCount -gt 0) {
            Write-Host " Found $dbCount database(s)" -ForegroundColor Green
            foreach ($db in ($results | Where-Object { $_.DatabaseType -ne "N/A" } | Select-Object -First 3)) {
                Write-Host "  - $($db.DatabaseType): $($db.DatabaseName)" -ForegroundColor Gray
            }
        }
        else {
            Write-Host " No databases found" -ForegroundColor Gray
        }
    }
    
    Write-Progress -Activity "Searching for Databases" -Completed
    
    Write-Host ""
    Write-Host "Summary:" -ForegroundColor Cyan
    Write-Host "========" -ForegroundColor Cyan
    $totalDatabases = ($allResults | Where-Object { $_.DatabaseType -ne "N/A" }).Count
    $serversWithDB = ($allResults | Where-Object { $_.DatabaseType -ne "N/A" } | Select-Object -Unique ServerName).Count
    $sqlServers = ($allResults | Where-Object { $_.DatabaseType -eq "SQLServer" }).Count
    $mysqlServers = ($allResults | Where-Object { $_.DatabaseType -eq "MySQL" }).Count
    $oracleServers = ($allResults | Where-Object { $_.DatabaseType -eq "Oracle" }).Count
    $otherDBs = ($allResults | Where-Object { $_.DatabaseType -eq "Other" }).Count
    
    Write-Host "Total Databases Found: $totalDatabases" -ForegroundColor Green
    Write-Host "Servers with Databases: $serversWithDB" -ForegroundColor Cyan
    Write-Host "SQL Server:            $sqlServers" -ForegroundColor Yellow
    Write-Host "MySQL:                 $mysqlServers" -ForegroundColor Yellow
    Write-Host "Oracle:                $oracleServers" -ForegroundColor Yellow
    Write-Host "Other Databases:       $otherDBs" -ForegroundColor Yellow
    Write-Host ""
    
    $allResults | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
    Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
    
    Write-Host ""
    Write-Host "Servers with Databases:" -ForegroundColor Cyan
    $allResults | Where-Object { $_.DatabaseType -ne "N/A" } | Group-Object -Property ServerName | Select-Object Count, Name | Sort-Object Count -Descending | Format-Table -AutoSize
    
    Write-Host ""
    Write-Host "Detailed Results:" -ForegroundColor Cyan
    $allResults | Where-Object { $_.DatabaseType -ne "N/A" } | Format-Table -AutoSize ServerName, DatabaseType, DatabaseName, Type, Status, Description
}
catch {
    Write-Error "Failed: $($_.Exception.Message)"
    exit 1
}

