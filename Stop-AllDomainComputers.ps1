<#
.SYNOPSIS
    Shuts down all computers in the domain.

.DESCRIPTION
    This script shuts down all computers in the specified domain.
    Use with extreme caution!

.PARAMETER Domain
    Domain to query for computers (default: current domain).

.PARAMETER ExcludeServers
    Exclude servers from shutdown (default: true).

.PARAMETER ExcludeList
    Path to text file with computer names to exclude.

.PARAMETER Force
    Force shutdown even if users are logged on.

.PARAMETER Delay
    Delay in seconds before shutdown (default: 0).

.PARAMETER Message
    Message to display before shutdown.

.PARAMETER OutputFile
    Path to CSV file. Default: DomainShutdownReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication.

.PARAMETER WhatIf
    Show what would be shut down without actually shutting down.

.EXAMPLE
    .\Stop-AllDomainComputers.ps1 -Domain "contoso.com" -ExcludeServers -WhatIf
    
.EXAMPLE
    .\Stop-AllDomainComputers.ps1 -Domain "contoso.com" -Delay 300 -Message "System shutdown in 5 minutes"
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false)]
    [string]$Domain,
    
    [Parameter(Mandatory=$false)]
    [switch]$ExcludeServers = $true,
    
    [Parameter(Mandatory=$false)]
    [string]$ExcludeList,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force,
    
    [Parameter(Mandatory=$false)]
    [int]$Delay = 0,
    
    [Parameter(Mandatory=$false)]
    [string]$Message = "System shutdown",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "DomainShutdownReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

# Main execution
Write-Host "Domain Computer Shutdown Tool" -ForegroundColor Cyan
Write-Host "=============================" -ForegroundColor Cyan
Write-Host ""
Write-Host "WARNING: This will shutdown ALL computers in the domain!" -ForegroundColor Red
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
    
    Write-Host "Querying computers from domain..." -ForegroundColor Yellow
    $allComputers = Get-ADComputer @adParams
    
    Write-Host "Found $($allComputers.Count) total computer(s)" -ForegroundColor Green
    
    # Filter out servers if requested
    $computers = @()
    if ($ExcludeServers) {
        foreach ($computer in $allComputers) {
            $os = $computer.OperatingSystem
            if ($os -and ($os -like "*Server*" -or $os -like "*Windows Server*")) {
                continue
            }
            $computers += $computer.Name
        }
        Write-Host "After excluding servers: $($computers.Count) computer(s)" -ForegroundColor Yellow
    }
    else {
        $computers = $allComputers | Select-Object -ExpandProperty Name
    }
    
    # Exclude specific computers
    $excludeComputers = @()
    if ($ExcludeList -and (Test-Path $ExcludeList)) {
        $excludeComputers = Get-Content $ExcludeList | Where-Object { $_.Trim() -ne "" }
        $computers = $computers | Where-Object { $excludeComputers -notcontains $_ }
        Write-Host "After exclusions: $($computers.Count) computer(s)" -ForegroundColor Yellow
    }
    
    if ($computers.Count -eq 0) {
        Write-Error "No computers to process."
        exit 1
    }
    
    Write-Host "Computers to shutdown: $($computers.Count)" -ForegroundColor Yellow
    if ($Force) {
        Write-Host "Force shutdown: ENABLED" -ForegroundColor Red
    }
    if ($Delay -gt 0) {
        Write-Host "Delay: $Delay seconds" -ForegroundColor Yellow
    }
    if ($WhatIf) {
        Write-Host "MODE: WHATIF (no computers will be shut down)" -ForegroundColor Yellow
    }
    Write-Host ""
    
    if (-not $WhatIf -and -not $PSCmdlet.ShouldProcess("Shutdown $($computers.Count) computer(s) in domain", "THIS WILL SHUTDOWN ALL COMPUTERS! Continue?")) {
        Write-Host "Operation cancelled." -ForegroundColor Yellow
        exit 0
    }
    
    $results = @()
    foreach ($computer in $computers) {
        Write-Host "Shutting down $computer..." -NoNewline
        
        $result = [PSCustomObject]@{
            ComputerName = $computer
            Status = "Unknown"
            Error = $null
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        
        try {
            if (-not (Test-Connection -ComputerName $computer -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
                $result.Status = "Offline"
            }
            elseif ($WhatIf) {
                $result.Status = "WhatIf - Would Shutdown"
            }
            else {
                $stopParams = @{
                    ComputerName = $computer
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

