<#
.SYNOPSIS
    Sends popup messages to all computers in the domain.

.DESCRIPTION
    This script sends popup messages to users on remote computers using
    the msg.exe command or PowerShell messaging.

.PARAMETER Domain
    Domain to query for computers (default: current domain).

.PARAMETER ComputerList
    Path to text file with computer names (optional, overrides domain).

.PARAMETER ComputerName
    Single or array of computer names (optional).

.PARAMETER Message
    Message text to display in the popup.

.PARAMETER Title
    Title for the popup window (default: "System Message").

.PARAMETER Timeout
    Timeout in seconds before message auto-closes (default: 0 = no timeout).

.PARAMETER OutputFile
    Path to CSV file. Default: PopupMessageReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication.

.PARAMETER AllUsers
    Send to all logged on users (default: true).

.PARAMETER SpecificUser
    Send to specific username only.

.EXAMPLE
    .\Send-PopupMessage.ps1 -Domain "contoso.com" -Message "System maintenance in 30 minutes"
    
.EXAMPLE
    .\Send-PopupMessage.ps1 -ComputerList "computers.txt" -Message "Please save your work" -Title "Important Notice" -Timeout 60
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false)]
    [string]$Domain,
    
    [Parameter(Mandatory=$false)]
    [string]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ComputerName,
    
    [Parameter(Mandatory=$true)]
    [string]$Message,
    
    [Parameter(Mandatory=$false)]
    [string]$Title = "System Message",
    
    [Parameter(Mandatory=$false)]
    [int]$Timeout = 0,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "PopupMessageReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [switch]$AllUsers = $true,
    
    [Parameter(Mandatory=$false)]
    [string]$SpecificUser
)

function Send-PopupMessage {
    param([string]$Computer, [string]$Msg, [string]$MsgTitle, [int]$MsgTimeout, [bool]$All, [string]$User, [System.Management.Automation.PSCredential]$Cred)
    
    $scriptBlock = {
        param([string]$Message, [string]$Title, [int]$Timeout, [bool]$AllUsers, [string]$Username)
        
        $results = @()
        
        try {
            # Method 1: Use msg.exe command
            if ($AllUsers) {
                # Get all logged on users
                $sessions = query user 2>&1
                if ($LASTEXITCODE -eq 0) {
                    $lines = $sessions | Where-Object { $_ -match '^\s+\S+\s+\S+\s+\d+\s+' }
                    foreach ($line in $lines) {
                        if ($line -match '^\s+(\S+)\s+(\S+)\s+(\d+)\s+') {
                            $sessionUser = $matches[2]
                            $sessionId = $matches[3]
                            
                            try {
                                if ($Timeout -gt 0) {
                                    $msgCmd = "msg $sessionId /TIME:$Timeout `"$Message`""
                                } else {
                                    $msgCmd = "msg $sessionId `"$Message`""
                                }
                                Invoke-Expression $msgCmd | Out-Null
                                $results += @{
                                    User = $sessionUser
                                    SessionID = $sessionId
                                    Status = "Sent"
                                }
                            }
                            catch {
                                $results += @{
                                    User = $sessionUser
                                    SessionID = $sessionId
                                    Status = "Failed"
                                    Error = $_.Exception.Message
                                }
                            }
                        }
                    }
                }
            }
            elseif ($Username) {
                # Send to specific user
                $sessions = query user $Username 2>&1
                if ($LASTEXITCODE -eq 0) {
                    $lines = $sessions | Where-Object { $_ -match '^\s+\S+\s+\S+\s+\d+\s+' }
                    foreach ($line in $lines) {
                        if ($line -match '^\s+(\S+)\s+(\S+)\s+(\d+)\s+') {
                            $sessionId = $matches[3]
                            try {
                                if ($Timeout -gt 0) {
                                    $msgCmd = "msg $sessionId /TIME:$Timeout `"$Message`""
                                } else {
                                    $msgCmd = "msg $sessionId `"$Message`""
                                }
                                Invoke-Expression $msgCmd | Out-Null
                                $results += @{
                                    User = $Username
                                    SessionID = $sessionId
                                    Status = "Sent"
                                }
                            }
                            catch {
                                $results += @{
                                    User = $Username
                                    SessionID = $sessionId
                                    Status = "Failed"
                                    Error = $_.Exception.Message
                                }
                            }
                        }
                    }
                }
            }
            
            # Method 2: Use PowerShell popup (fallback)
            if ($results.Count -eq 0) {
                try {
                    Add-Type -AssemblyName System.Windows.Forms
                    $popup = New-Object System.Windows.Forms.Form
                    $popup.Text = $Title
                    $popup.Width = 400
                    $popup.Height = 200
                    $popup.StartPosition = "CenterScreen"
                    $popup.TopMost = $true
                    
                    $label = New-Object System.Windows.Forms.Label
                    $label.Text = $Message
                    $label.AutoSize = $false
                    $label.Width = 380
                    $label.Height = 150
                    $label.Location = New-Object System.Drawing.Point(10, 10)
                    $popup.Controls.Add($label)
                    
                    $button = New-Object System.Windows.Forms.Button
                    $button.Text = "OK"
                    $button.Location = New-Object System.Drawing.Point(150, 120)
                    $button.Add_Click({ $popup.Close() })
                    $popup.Controls.Add($button)
                    
                    if ($Timeout -gt 0) {
                        $timer = New-Object System.Windows.Forms.Timer
                        $timer.Interval = $Timeout * 1000
                        $timer.Add_Tick({ $popup.Close(); $timer.Stop() })
                        $timer.Start()
                    }
                    
                    $popup.ShowDialog() | Out-Null
                    $results += @{
                        User = "All"
                        SessionID = "N/A"
                        Status = "Sent (Popup)"
                    }
                }
                catch {
                    $results += @{
                        User = "N/A"
                        SessionID = "N/A"
                        Status = "Error"
                        Error = $_.Exception.Message
                    }
                }
            }
        }
        catch {
            $results += @{
                User = "N/A"
                SessionID = "N/A"
                Status = "Error"
                Error = $_.Exception.Message
            }
        }
        
        return $results
    }
    
    $allResults = @()
    
    try {
        if (-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            return @([PSCustomObject]@{
                ComputerName = $Computer
                User = "N/A"
                Status = "Offline"
                Error = "Computer is not reachable"
            })
        }
        
        $invokeParams = @{
            ComputerName = $Computer
            ScriptBlock = $scriptBlock
            ArgumentList = @($Msg, $MsgTitle, $MsgTimeout, $All, $User)
        }
        if ($Cred) { $invokeParams['Credential'] = $Cred }
        
        $messageResults = Invoke-Command @invokeParams
        
        foreach ($msgResult in $messageResults) {
            $allResults += [PSCustomObject]@{
                ComputerName = $Computer
                User = $msgResult.User
                Status = $msgResult.Status
                Error = if ($msgResult.Error) { $msgResult.Error } else { $null }
            }
        }
    }
    catch {
        $allResults += [PSCustomObject]@{
            ComputerName = $Computer
            User = "N/A"
            Status = "Error"
            Error = $_.Exception.Message
        }
    }
    
    return $allResults
}

# Main execution
Write-Host "Popup Message Tool" -ForegroundColor Cyan
Write-Host "==================" -ForegroundColor Cyan
Write-Host ""

$computers = @()

if ($Domain) {
    try {
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            Write-Warning "Active Directory module not found. Install RSAT-AD-PowerShell feature."
        }
        else {
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
            Write-Host "Querying computers from domain: $Domain" -ForegroundColor Yellow
            
            try {
                $domainParams = @{
                    Filter = *
                    Properties = Name
                }
                if ($Credential) {
                    $domainParams['Credential'] = $Credential
                    $domainParams['Server'] = $Domain
                }
                $domainComputers = Get-ADComputer @domainParams | Select-Object -ExpandProperty Name
                $computers += $domainComputers
                Write-Host "Found $($domainComputers.Count) computer(s) in domain" -ForegroundColor Green
            }
            catch {
                Write-Warning "Could not query domain. Error: $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Warning "Active Directory query failed: $($_.Exception.Message)"
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

Write-Host "Message: $Message" -ForegroundColor Yellow
Write-Host "Title: $Title" -ForegroundColor Yellow
Write-Host "Target: " -NoNewline
if ($AllUsers) {
    Write-Host "All Users" -ForegroundColor Cyan
} else {
    Write-Host "User: $SpecificUser" -ForegroundColor Cyan
}
Write-Host "Processing $($computers.Count) computer(s)..." -ForegroundColor Yellow
Write-Host ""

if (-not $PSCmdlet.ShouldProcess("Send message to $($computers.Count) computer(s)", "This will send popup messages. Continue?")) {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
    exit 0
}

$allResults = @()
foreach ($computer in $computers) {
    Write-Host "Sending message to $computer..." -NoNewline
    $results = Send-PopupMessage -Computer $computer -Msg $Message -MsgTitle $Title -MsgTimeout $Timeout -All $AllUsers.IsPresent -User $SpecificUser -Cred $Credential
    $allResults += $results
    
    $sentCount = ($results | Where-Object { $_.Status -like "*Sent*" }).Count
    Write-Host " $sentCount message(s) sent" -ForegroundColor $(if ($sentCount -gt 0) { "Green" } else { "Red" })
}

$allResults | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host ""
Write-Host "Results exported to: $OutputFile" -ForegroundColor Green

$totalSent = ($allResults | Where-Object { $_.Status -like "*Sent*" }).Count
Write-Host "Total messages sent: $totalSent" -ForegroundColor Green

$allResults | Format-Table -AutoSize

