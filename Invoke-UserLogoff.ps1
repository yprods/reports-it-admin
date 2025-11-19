<#
.SYNOPSIS
    Logs out a specific user from a list of computers using WMI and PowerShell.

.DESCRIPTION
    This script reads a list of computer names and logs out a specified user
    from each computer remotely. It supports multiple methods to find and log out user sessions.

.PARAMETER ComputerList
    Path to a text file containing computer names (one per line).

.PARAMETER ComputerName
    Single computer name or array of computer names to process.

.PARAMETER Username
    Username to log out. Can be in format "DOMAIN\Username" or just "Username".

.PARAMETER OutputFile
    Path to CSV file where results will be exported. Default: UserLogoffReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication (optional).

.PARAMETER Force
    Force logoff even if user has open applications (may cause data loss).

.EXAMPLE
    .\Invoke-UserLogoff.ps1 -ComputerList "computers.txt" -Username "DOMAIN\jdoe"
    
.EXAMPLE
    .\Invoke-UserLogoff.ps1 -ComputerName "PC01","PC02","PC03" -Username "jdoe"
    
.EXAMPLE
    .\Invoke-UserLogoff.ps1 -ComputerList "computers.txt" -Username "jdoe" -Force
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ComputerName,
    
    [Parameter(Mandatory=$true)]
    [string]$Username,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "UserLogoffReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force
)

# Function to log out a user from a single computer
function Invoke-UserLogoff {
    param(
        [string]$Computer,
        [string]$User,
        [System.Management.Automation.PSCredential]$Cred,
        [bool]$ForceLogoff
    )
    
    $result = [PSCustomObject]@{
        ComputerName = $Computer
        Username = $User
        SessionFound = $false
        SessionID = "N/A"
        Status = "Unknown"
        LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Error = $null
    }
    
    try {
        # Test connectivity first
        if (-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            $result.Status = "Offline"
            $result.Error = "Computer is not reachable"
            return $result
        }
        
        # Normalize username (remove domain if present for comparison)
        $userNameOnly = $User
        if ($User.Contains('\')) {
            $userNameOnly = $User.Split('\')[1]
        }
        
        # Method 1: Use query user command via Invoke-Command
        try {
            $sessionParams = @{
                ComputerName = $Computer
                ScriptBlock = {
                    param($targetUser)
                    $userNameOnly = $targetUser
                    if ($targetUser.Contains('\')) {
                        $userNameOnly = $targetUser.Split('\')[1]
                    }
                    
                    # Query user sessions
                    $queryResult = query user 2>&1
                    if ($LASTEXITCODE -eq 0) {
                        $sessions = @()
                        $lines = $queryResult | Where-Object { $_ -match '^\s+\S+\s+\S+\s+\d+\s+' }
                        foreach ($line in $lines) {
                            if ($line -match '^\s+(\S+)\s+(\S+)\s+(\d+)\s+') {
                                $sessionUser = $matches[2]
                                $sessionId = $matches[3]
                                
                                # Check if username matches (with or without domain)
                                if ($sessionUser -eq $targetUser -or $sessionUser -eq $userNameOnly) {
                                    $sessions += @{
                                        SessionID = $sessionId
                                        Username = $sessionUser
                                    }
                                }
                            }
                        }
                        return $sessions
                    }
                    return @()
                }
                ArgumentList = @($User)
                ErrorAction = "Stop"
            }
            
            if ($Cred) {
                $sessionParams['Credential'] = $Cred
            }
            
            $sessions = Invoke-Command @sessionParams
            
            if ($sessions -and $sessions.Count -gt 0) {
                $result.SessionFound = $true
                $result.SessionID = $sessions[0].SessionID
                
                # Log off each session found
                foreach ($session in $sessions) {
                    try {
                        $logoffParams = @{
                            ComputerName = $Computer
                            ScriptBlock = {
                                param($sessionId, $force)
                                if ($force) {
                                    logoff $sessionId /FORCE
                                } else {
                                    logoff $sessionId
                                }
                                return $LASTEXITCODE
                            }
                            ArgumentList = @($session.SessionID, $ForceLogoff)
                            ErrorAction = "Stop"
                        }
                        
                        if ($Cred) {
                            $logoffParams['Credential'] = $Cred
                        }
                        
                        $logoffResult = Invoke-Command @logoffParams
                        
                        if ($logoffResult -eq 0) {
                            $result.Status = "Success"
                        } else {
                            $result.Status = "Partial Success"
                            $result.Error = "Logoff command returned exit code: $logoffResult"
                        }
                    }
                    catch {
                        $result.Status = "Error"
                        $result.Error = "Failed to log off session $($session.SessionID): $($_.Exception.Message)"
                    }
                }
            }
            else {
                # Method 2: Try WMI to find logged-on users
                try {
                    $loggedOnParams = @{
                        ComputerName = $Computer
                        Class = "Win32_LoggedOnUser"
                        ErrorAction = "Stop"
                    }
                    
                    if ($Cred) {
                        $loggedOnParams['Credential'] = $Cred
                    }
                    
                    $loggedOnUsers = Get-CimInstance @loggedOnParams
                    
                    # Find matching user
                    $matchingSessions = @()
                    foreach ($loggedOn in $loggedOnUsers) {
                        $antUser = Get-CimInstance -InputObject $loggedOn -ResultClassName Win32_Account
                        if ($antUser) {
                            $accountName = $antUser.Name
                            if ($accountName -eq $User -or $accountName -eq $userNameOnly) {
                                $logonSession = Get-CimInstance -InputObject $loggedOn -ResultClassName Win32_LogonSession
                                if ($logonSession) {
                                    $matchingSessions += $logonSession
                                }
                            }
                        }
                    }
                    
                    if ($matchingSessions.Count -gt 0) {
                        $result.SessionFound = $true
                        $result.Status = "User Found (WMI)"
                        $result.Error = "User found via WMI but logoff requires query user method. Try running script locally on target computer."
                    }
                    else {
                        $result.Status = "User Not Found"
                        $result.Error = "User '$User' is not currently logged on"
                    }
                }
                catch {
                    $result.Status = "User Not Found"
                    $result.Error = "Could not query user sessions: $($_.Exception.Message)"
                }
            }
        }
        catch {
            # Method 3: Try direct WMI logoff (less reliable for specific users)
            try {
                $osParams = @{
                    ComputerName = $Computer
                    Class = "Win32_OperatingSystem"
                    ErrorAction = "Stop"
                }
                
                if ($Cred) {
                    $osParams['Credential'] = $Cred
                }
                
                $os = Get-CimInstance @osParams
                
                # Check if user is logged on first
                $loggedOnParams = @{
                    ComputerName = $Computer
                    Class = "Win32_ComputerSystem"
                    ErrorAction = "Stop"
                }
                
                if ($Cred) {
                    $loggedOnParams['Credential'] = $Cred
                }
                
                $cs = Get-CimInstance @loggedOnParams
                $currentUser = $cs.UserName
                
                if ($currentUser -and ($currentUser -eq $User -or $currentUser.EndsWith("\$userNameOnly"))) {
                    $result.SessionFound = $true
                    $result.Status = "User Found"
                    $result.Error = "User is logged on but specific session logoff requires query user. Use Invoke-Command method."
                }
                else {
                    $result.Status = "User Not Found"
                    $result.Error = "User '$User' is not the currently logged-on user"
                }
            }
            catch {
                $result.Status = "Error"
                $result.Error = $_.Exception.Message
            }
        }
    }
    catch {
        $result.Status = "Error"
        $result.Error = $_.Exception.Message
    }
    
    return $result
}

# Main execution
Write-Host "User Logoff Tool" -ForegroundColor Cyan
Write-Host "================" -ForegroundColor Cyan
Write-Host ""

# Confirm action if not using -Force
if (-not $Force -and -not $PSCmdlet.ShouldProcess("Log out user '$Username' from specified computers", "This will log out the user. Continue?")) {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
    exit 0
}

# Collect computer names
$computers = @()

if ($ComputerList) {
    if (Test-Path $ComputerList) {
        Write-Host "Reading computer list from: $ComputerList" -ForegroundColor Yellow
        $computers = Get-Content $ComputerList | Where-Object { $_.Trim() -ne "" } | ForEach-Object { $_.Trim() }
    }
    else {
        Write-Error "Computer list file not found: $ComputerList"
        exit 1
    }
}

if ($ComputerName) {
    $computers += $ComputerName
}

if ($computers.Count -eq 0) {
    Write-Error "No computers specified. Use -ComputerList or -ComputerName parameter."
    exit 1
}

Write-Host "Target Username: $Username" -ForegroundColor Yellow
Write-Host "Found $($computers.Count) computer(s) to process" -ForegroundColor Green
if ($Force) {
    Write-Host "Force logoff: ENABLED (may cause data loss)" -ForegroundColor Red
}
Write-Host ""

# Process each computer
$results = @()
$total = $computers.Count
$current = 0

foreach ($computer in $computers) {
    $current++
    Write-Progress -Activity "Logging Out User" -Status "Processing $computer ($current of $total)" -PercentComplete (($current / $total) * 100)
    
    Write-Host "[$current/$total] Processing $computer..." -NoNewline
    
    $result = Invoke-UserLogoff -Computer $computer -User $Username -Cred $Credential -ForceLogoff $Force.IsPresent
    
    $results += $result
    
    $statusColor = switch ($result.Status) {
        "Success" { "Green" }
        "Partial Success" { "Yellow" }
        "User Not Found" { "Gray" }
        "Offline" { "Red" }
        "Error" { "Red" }
        default { "Gray" }
    }
    
    Write-Host " $($result.Status)" -ForegroundColor $statusColor
    if ($result.SessionID -ne "N/A") {
        Write-Host "  Session ID: $($result.SessionID)" -ForegroundColor Gray
    }
    if ($result.Error) {
        Write-Host "  Error: $($result.Error)" -ForegroundColor Red
    }
}

Write-Progress -Activity "Logging Out User" -Completed

# Display summary
Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "========" -ForegroundColor Cyan
$success = ($results | Where-Object { $_.Status -eq "Success" }).Count
$partial = ($results | Where-Object { $_.Status -eq "Partial Success" }).Count
$notFound = ($results | Where-Object { $_.Status -eq "User Not Found" }).Count
$offline = ($results | Where-Object { $_.Status -eq "Offline" }).Count
$errors = ($results | Where-Object { $_.Status -eq "Error" }).Count

Write-Host "Success:        $success" -ForegroundColor Green
Write-Host "Partial:        $partial" -ForegroundColor Yellow
Write-Host "User Not Found: $notFound" -ForegroundColor Gray
Write-Host "Offline:        $offline" -ForegroundColor Red
Write-Host "Errors:         $errors" -ForegroundColor Red
Write-Host ""

# Export to CSV
try {
    $results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
    Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
}
catch {
    Write-Error "Failed to export results: $($_.Exception.Message)"
}

# Display results table
Write-Host ""
Write-Host "Detailed Results:" -ForegroundColor Cyan
Write-Host "================" -ForegroundColor Cyan
$results | Format-Table -AutoSize ComputerName, Username, SessionFound, SessionID, Status

