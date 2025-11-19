<#
.SYNOPSIS
    Shuts down all servers in the domain.

.DESCRIPTION
    This script shuts down all servers (Windows Server OS) in the specified domain.
    Use with extreme caution!

.PARAMETER Domain
    Domain to query for servers (default: current domain).

.PARAMETER ExcludeList
    Path to text file with server names to exclude.

.PARAMETER Force
    Force shutdown even if users are logged on.

.PARAMETER Delay
    Delay in seconds before shutdown (default: 0).

.PARAMETER Message
    Message to display before shutdown.

.PARAMETER OutputFile
    Path to CSV file. Default: DomainServersShutdownReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication.

.PARAMETER WhatIf
    Show what would be shut down without actually shutting down.

.EXAMPLE
    .\Stop-AllDomainServers.ps1 -Domain "contoso.com" -WhatIf
    
.EXAMPLE
    .\Stop-AllDomainServers.ps1 -Domain "contoso.com" -Delay 600 -Message "Server maintenance"
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false)]
    [string]$Domain,
    
    [Parameter(Mandatory=$false)]
    [string]$ExcludeList,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force,
    
    [Parameter(Mandatory=$false)]
    [int]$Delay = 0,
    
    [Parameter(Mandatory=$false)]
    [string]$Message = "Server shutdown",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "DomainServersShutdownReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

# Main execution
Write-Host "Domain Server Shutdown Tool" -ForegroundColor Cyan
Write-Host "===========================" -ForegroundColor Cyan
Write-Host ""
Write-Host "WARNING: This will shutdown ALL SERVERS in the domain!" -ForegroundColor Red
Write-Host ""

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "Active Directory PowerShell module is required."
    exit 1
}

Import-Module ActiveDirectory -ErrorAction Stop

try {
    $adParams = @{
        Filter = *
        Properties = @("Name", "OperatingSystem", "OperatingSystemVersion")
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
    
    # Exclude specific servers
    $excludeServers = @()
    if ($ExcludeList -and (Test-Path $ExcludeList)) {
        $excludeServers = Get-Content $ExcludeList | Where-Object { $_.Trim() -ne "" }
        $servers = $servers | Where-Object { $excludeServers -notcontains $_ }
        Write-Host "After exclusions: $($servers.Count) server(s)" -ForegroundColor Yellow
    }
    
    if ($servers.Count -eq 0) {
        Write-Error "No servers to process."
        exit 1
    }
    
    Write-Host "Servers to shutdown: $($servers.Count)" -ForegroundColor Yellow
    Write-Host "Server List:" -ForegroundColor Cyan
    foreach ($server in $servers) {
        Write-Host "  - $server" -ForegroundColor Gray
    }
    Write-Host ""
    
    if ($Force) {
        Write-Host "Force shutdown: ENABLED" -ForegroundColor Red
    }
    if ($Delay -gt 0) {
        Write-Host "Delay: $Delay seconds" -ForegroundColor Yellow
    }
    if ($WhatIf) {
        Write-Host "MODE: WHATIF (no servers will be shut down)" -ForegroundColor Yellow
    }
    Write-Host ""
    
    if (-not $WhatIf -and -not $PSCmdlet.ShouldProcess("Shutdown $($servers.Count) server(s) in domain", "THIS WILL SHUTDOWN ALL SERVERS! Continue?")) {
        Write-Host "Operation cancelled." -ForegroundColor Yellow
        exit 0
    }
    
    $results = @()
    foreach ($server in $servers) {
        Write-Host "Shutting down $server..." -NoNewline
        
        $result = [PSCustomObject]@{
            ServerName = $server
            Status = "Unknown"
            Error = $null
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        
        try {
            if (-not (Test-Connection -ComputerName $server -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
                $result.Status = "Offline"
            }
            elseif ($WhatIf) {
                $result.Status = "WhatIf - Would Shutdown"
            }
            else {
                $stopParams = @{
                    ComputerName = $server
                    Force = $Force.IsPresent
                }
                if ($Credential) {
                    $stopParams['Credential'] = $Credential
                }
                if ($Delay -gt 0) {
                    $stopParams['Delay'] = $Delay
                }
                
                Stop-Computer @stopParams
                $result.Status = "Shutdown Initiated"
            }
        }
        catch {
            $result.Status = "Error"
            $result.Error = $_.Exception.Message
        }
        
        $results += $result
        Write-Host " $($result.Status)" -ForegroundColor $(if ($result.Status -like "*Initiated*" -or $result.Status -like "WhatIf*") { "Green" } else { "Red" })
    }
    
    $results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
    Write-Host ""
    Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
    
    Write-Host ""
    Write-Host "Summary:" -ForegroundColor Cyan
    $success = ($results | Where-Object { $_.Status -like "*Initiated*" -or $_.Status -like "WhatIf*" }).Count
    Write-Host "Shutdown Initiated: $success" -ForegroundColor Green
    Write-Host "Offline: $(($results | Where-Object { $_.Status -eq 'Offline' }).Count)" -ForegroundColor Red
    Write-Host "Errors: $(($results | Where-Object { $_.Status -eq 'Error' }).Count)" -ForegroundColor Red
}
catch {
    Write-Error "Failed: $($_.Exception.Message)"
    exit 1
}

