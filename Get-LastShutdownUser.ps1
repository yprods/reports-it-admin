<#
.SYNOPSIS
    Gets who last shut down all servers in the domain.

.DESCRIPTION
    This script queries all servers in the domain to find who initiated
    the last shutdown event, including timestamp and user information.

.PARAMETER Domain
    Domain to search (default: current domain).

.PARAMETER OutputFile
    Path to CSV file. Default: LastShutdownUserReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication.

.PARAMETER DaysBack
    Number of days to look back for shutdown events (default: 30).

.EXAMPLE
    .\Get-LastShutdownUser.ps1 -Domain "contoso.com"
    
.EXAMPLE
    .\Get-LastShutdownUser.ps1 -DaysBack 7
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Domain,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "LastShutdownUserReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [int]$DaysBack = 30
)

# Function to get last shutdown user from a server
function Get-LastShutdownUser {
    param(
        [string]$Server,
        [int]$Days,
        [System.Management.Automation.PSCredential]$Cred
    )
    
    $scriptBlock = {
        param([int]$DaysBack)
        
        $shutdownInfo = @{
            LastShutdownTime = "Never"
            LastShutdownUser = "N/A"
            ShutdownType = "N/A"
            ShutdownReason = "N/A"
            EventID = $null
            Status = "Unknown"
            Error = $null
        }
        
        try {
            $cutoffDate = (Get-Date).AddDays(-$DaysBack)
            
            # Method 1: Query Event Log for shutdown events
            $shutdownEvents = Get-WinEvent -FilterHashtable @{
                LogName = 'System'
                ID = 1074, 1076, 6008  # Shutdown events
                StartTime = $cutoffDate
            } -ErrorAction SilentlyContinue | Sort-Object TimeCreated -Descending | Select-Object -First 1
            
            if ($shutdownEvents) {
                $event = $shutdownEvents
                $shutdownInfo.LastShutdownTime = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                $shutdownInfo.EventID = $event.Id
                
                # Parse event message for user and reason
                $eventXml = [xml]$event.ToXml()
                $eventData = $eventXml.Event.EventData.Data
                
                foreach ($data in $eventData) {
                    if ($data.Name -eq "SubjectUserName") {
                        $shutdownInfo.LastShutdownUser = $data.'#text'
                    }
                    if ($data.Name -eq "SubjectDomainName") {
                        if ($shutdownInfo.LastShutdownUser -ne "N/A") {
                            $shutdownInfo.LastShutdownUser = "$($data.'#text')\$($shutdownInfo.LastShutdownUser)"
                        }
                    }
                    if ($data.Name -eq "Reason") {
                        $shutdownInfo.ShutdownReason = $data.'#text'
                    }
                    if ($data.Name -eq "ReasonCode") {
                        $shutdownInfo.ShutdownType = $data.'#text'
                    }
                }
                
                # If user not found in event data, try to extract from message
                if ($shutdownInfo.LastShutdownUser -eq "N/A") {
                    $message = $event.Message
                    if ($message -match 'initiated by (?:computer|user):\s*([^\s]+)') {
                        $shutdownInfo.LastShutdownUser = $matches[1]
                    }
                    elseif ($message -match 'by\s+([^\s]+)') {
                        $shutdownInfo.LastShutdownUser = $matches[1]
                    }
                }
                
                $shutdownInfo.Status = "Success"
            }
            else {
                # Method 2: Check last boot time (indirect method)
                $os = Get-CimInstance -ClassName Win32_OperatingSystem
                $lastBoot = $os.LastBootUpTime
                
                if ($lastBoot -gt $cutoffDate) {
                    $shutdownInfo.LastShutdownTime = $lastBoot.ToString("yyyy-MM-dd HH:mm:ss")
                    $shutdownInfo.LastShutdownUser = "System (Estimated from boot time)"
                    $shutdownInfo.Status = "Estimated"
                }
                else {
                    $shutdownInfo.Status = "No Recent Shutdown"
                    $shutdownInfo.Error = "No shutdown events found in last $DaysBack days"
                }
            }
        }
        catch {
            $shutdownInfo.Status = "Error"
            $shutdownInfo.Error = $_.Exception.Message
        }
        
        return $shutdownInfo
    }
    
    $result = [PSCustomObject]@{
        ServerName = $Server
        LastShutdownTime = "N/A"
        LastShutdownUser = "N/A"
        ShutdownType = "N/A"
        ShutdownReason = "N/A"
        EventID = $null
        Status = "Unknown"
        Error = $null
    }
    
    try {
        if (-not (Test-Connection -ComputerName $Server -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            $result.Status = "Offline"
            $result.Error = "Computer is not reachable"
            return $result
        }
        
        $invokeParams = @{
            ComputerName = $Server
            ScriptBlock = $scriptBlock
            ArgumentList = @($Days)
        }
        if ($Cred) { $invokeParams['Credential'] = $Cred }
        
        $shutdownData = Invoke-Command @invokeParams
        
        $result.LastShutdownTime = $shutdownData.LastShutdownTime
        $result.LastShutdownUser = $shutdownData.LastShutdownUser
        $result.ShutdownType = $shutdownData.ShutdownType
        $result.ShutdownReason = $shutdownData.ShutdownReason
        $result.EventID = $shutdownData.EventID
        $result.Status = $shutdownData.Status
        $result.Error = $shutdownData.Error
    }
    catch {
        $result.Status = "Error"
        $result.Error = $_.Exception.Message
    }
    
    return $result
}

# Main execution
Write-Host "Last Shutdown User Query Tool" -ForegroundColor Cyan
Write-Host "=============================" -ForegroundColor Cyan
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
    Write-Host "Looking back: $DaysBack days" -ForegroundColor Yellow
    Write-Host ""
    
    $results = @()
    $total = $servers.Count
    $current = 0
    
    foreach ($server in $servers) {
        $current++
        Write-Progress -Activity "Querying Last Shutdown" -Status "Processing $server ($current of $total)" -PercentComplete (($current / $total) * 100)
        
        Write-Host "[$current/$total] Querying $server..." -NoNewline
        
        $result = Get-LastShutdownUser -Server $server -Days $DaysBack -Cred $Credential
        $results += $result
        
        $statusColor = switch ($result.Status) {
            "Success" { "Green" }
            "Estimated" { "Yellow" }
            "No Recent Shutdown" { "Gray" }
            "Offline" { "Red" }
            "Error" { "Red" }
            default { "Gray" }
        }
        
        Write-Host " $($result.Status)" -ForegroundColor $statusColor
        if ($result.LastShutdownTime -ne "Never" -and $result.LastShutdownTime -ne "N/A") {
            Write-Host "  Shutdown: $($result.LastShutdownTime) by $($result.LastShutdownUser)" -ForegroundColor Gray
        }
        if ($result.Error) {
            Write-Host "  Error: $($result.Error)" -ForegroundColor Red
        }
    }
    
    Write-Progress -Activity "Querying Last Shutdown" -Completed
    
    Write-Host ""
    Write-Host "Summary:" -ForegroundColor Cyan
    Write-Host "========" -ForegroundColor Cyan
    $success = ($results | Where-Object { $_.Status -eq "Success" }).Count
    $estimated = ($results | Where-Object { $_.Status -eq "Estimated" }).Count
    $noRecent = ($results | Where-Object { $_.Status -eq "No Recent Shutdown" }).Count
    $offline = ($results | Where-Object { $_.Status -eq "Offline" }).Count
    $errors = ($results | Where-Object { $_.Status -eq "Error" }).Count
    
    Write-Host "Success:            $success" -ForegroundColor Green
    Write-Host "Estimated:          $estimated" -ForegroundColor Yellow
    Write-Host "No Recent Shutdown: $noRecent" -ForegroundColor Gray
    Write-Host "Offline:            $offline" -ForegroundColor Red
    Write-Host "Errors:             $errors" -ForegroundColor Red
    Write-Host ""
    
    # Show shutdowns by user
    Write-Host "Shutdowns by User:" -ForegroundColor Cyan
    $results | Where-Object { $_.LastShutdownUser -ne "N/A" -and $_.Status -eq "Success" } | Group-Object -Property LastShutdownUser | Select-Object Count, Name | Sort-Object Count -Descending | Format-Table -AutoSize
    Write-Host ""
    
    # Export to CSV
    $results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
    Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
    
    Write-Host ""
    Write-Host "Recent Shutdowns:" -ForegroundColor Cyan
    $results | Where-Object { $_.LastShutdownTime -ne "Never" -and $_.LastShutdownTime -ne "N/A" } | Sort-Object LastShutdownTime -Descending | Format-Table -AutoSize ServerName, LastShutdownTime, LastShutdownUser, ShutdownType, Status
}
catch {
    Write-Error "Failed: $($_.Exception.Message)"
    exit 1
}

