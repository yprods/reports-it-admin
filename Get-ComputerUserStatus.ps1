<#
.SYNOPSIS
    Gets status of all computers showing how many users are logged on.

.DESCRIPTION
    This script queries all computers to determine how many users
    are currently logged on to each computer.

.PARAMETER ComputerList
    Path to text file with computer names.

.PARAMETER ComputerName
    Single or array of computer names.

.PARAMETER Domain
    Query all computers in domain.

.PARAMETER OutputFile
    Path to CSV file. Default: ComputerUserStatusReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication.

.EXAMPLE
    .\Get-ComputerUserStatus.ps1 -ComputerList "computers.txt"
    
.EXAMPLE
    .\Get-ComputerUserStatus.ps1 -Domain "contoso.com"
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
    [string]$OutputFile = "ComputerUserStatusReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential
)

function Get-ComputerUserStatus {
    param([string]$Computer, [System.Management.Automation.PSCredential]$Cred)
    
    $scriptBlock = {
        $sessions = @()
        
        try {
            # Query user sessions
            $queryResult = query user 2>&1
            if ($LASTEXITCODE -eq 0) {
                $lines = $queryResult | Where-Object { $_ -match '^\s+\S+\s+\S+\s+\d+\s+' }
                foreach ($line in $lines) {
                    if ($line -match '^\s+(\S+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\S+.*)') {
                        $sessions += @{
                            Username = $matches[2]
                            SessionID = $matches[3]
                            State = $matches[4]
                            IdleTime = $matches[5]
                        }
                    }
                }
            }
        }
        catch {
            # Try WMI method
            try {
                $logonSessions = Get-WmiObject -Class Win32_LogonSession | Where-Object { $_.LogonType -eq 2 -or $_.LogonType -eq 10 }
                foreach ($session in $logonSessions) {
                    $account = Get-WmiObject -Class Win32_LoggedOnUser | Where-Object { $_.Dependent -eq "Win32_LogonSession.LogonId=$($session.LogonId)" }
                    if ($account) {
                        $antUser = Get-WmiObject -Class Win32_Account | Where-Object { $_.__PATH -eq $account.Antecedent }
                        if ($antUser) {
                            $sessions += @{
                                Username = $antUser.Name
                                SessionID = $session.LogonId
                                State = "Active"
                                IdleTime = "N/A"
                            }
                        }
                    }
                }
            }
            catch { }
        }
        
        return $sessions
    }
    
    $result = [PSCustomObject]@{
        ComputerName = $Computer
        UserCount = 0
        Users = "N/A"
        Status = "Unknown"
        Error = $null
    }
    
    try {
        if (-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            $result.Status = "Offline"
            return $result
        }
        
        $invokeParams = @{
            ComputerName = $Computer
            ScriptBlock = $scriptBlock
        }
        if ($Cred) { $invokeParams['Credential'] = $Cred }
        
        $sessions = Invoke-Command @invokeParams
        
        $uniqueUsers = ($sessions | Select-Object -Unique Username).Username
        $result.UserCount = $uniqueUsers.Count
        $result.Users = ($uniqueUsers -join "; ")
        $result.Status = "Success"
    }
    catch {
        $result.Status = "Error"
        $result.Error = $_.Exception.Message
    }
    
    return $result
}

# Main execution
Write-Host "Computer User Status Query Tool" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

$computers = @()

if ($Domain) {
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        $adParams = @{ Filter = * }
        if ($Credential) { $adParams['Credential'] = $Credential; $adParams['Server'] = $Domain }
        $computers = (Get-ADComputer @adParams).Name
    }
}

if ($ComputerList -and (Test-Path $ComputerList)) {
    $computers += Get-Content $ComputerList | Where-Object { $_.Trim() -ne "" }
}

if ($ComputerName) {
    $computers += $ComputerName
}

$computers = $computers | Select-Object -Unique

if ($computers.Count -eq 0) {
    Write-Error "No computers specified."
    exit 1
}

Write-Host "Querying $($computers.Count) computer(s)..." -ForegroundColor Yellow

$results = @()
foreach ($computer in $computers) {
    Write-Host "Querying $computer..." -NoNewline
    $result = Get-ComputerUserStatus -Computer $computer -Cred $Credential
    $results += $result
    Write-Host " $($result.UserCount) user(s)" -ForegroundColor $(if ($result.Status -eq "Success") { "Green" } else { "Red" })
}

$results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "Results exported to: $OutputFile" -ForegroundColor Green

Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
$totalUsers = ($results | Measure-Object -Property UserCount -Sum).Sum
$computersWithUsers = ($results | Where-Object { $_.UserCount -gt 0 }).Count
Write-Host "Total Users Logged On: $totalUsers" -ForegroundColor Green
Write-Host "Computers with Users: $computersWithUsers" -ForegroundColor Cyan

$results | Format-Table -AutoSize ComputerName, UserCount, Users, Status

