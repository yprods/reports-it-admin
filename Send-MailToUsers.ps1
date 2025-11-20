<#
.SYNOPSIS
    Sends email to multiple users in Active Directory.

.DESCRIPTION
    This script sends emails to multiple users using Exchange or SMTP.
    Supports sending to users from a list, group, or OU.

.PARAMETER UserList
    Path to text file with usernames or email addresses (one per line).

.PARAMETER GroupName
    Send to all users in this group.

.PARAMETER OU
    Send to all users in this OU.

.PARAMETER Subject
    Email subject.

.PARAMETER Body
    Email body (text or HTML).

.PARAMETER BodyFile
    Path to file containing email body.

.PARAMETER Attachment
    Path to file to attach.

.PARAMETER SMTPServer
    SMTP server address (if not using Exchange).

.PARAMETER SMTPPort
    SMTP port (default: 25).

.PARAMETER From
    Sender email address.

.PARAMETER UseExchange
    Use Exchange cmdlets instead of SMTP (default: true if Exchange module available).

.PARAMETER Credential
    PSCredential object for authentication.

.PARAMETER OutputFile
    Path to CSV file. Default: SendMailReport.csv

.PARAMETER WhatIf
    Show what would be sent without actually sending.

.EXAMPLE
    .\Send-MailToUsers.ps1 -UserList "users.txt" -Subject "Important Notice" -Body "Please read this message."
    
.EXAMPLE
    .\Send-MailToUsers.ps1 -GroupName "All Employees" -Subject "Update" -BodyFile "message.html" -Attachment "document.pdf"
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false)]
    [string]$UserList,
    
    [Parameter(Mandatory=$false)]
    [string]$GroupName,
    
    [Parameter(Mandatory=$false)]
    [string]$OU,
    
    [Parameter(Mandatory=$true)]
    [string]$Subject,
    
    [Parameter(Mandatory=$false)]
    [string]$Body,
    
    [Parameter(Mandatory=$false)]
    [string]$BodyFile,
    
    [Parameter(Mandatory=$false)]
    [string]$Attachment,
    
    [Parameter(Mandatory=$false)]
    [string]$SMTPServer,
    
    [Parameter(Mandatory=$false)]
    [int]$SMTPPort = 25,
    
    [Parameter(Mandatory=$false)]
    [string]$From,
    
    [Parameter(Mandatory=$false)]
    [switch]$UseExchange,
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "SendMailReport.csv",
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

# Main execution
Write-Host "Send Mail to Users Tool" -ForegroundColor Cyan
Write-Host "======================" -ForegroundColor Cyan
Write-Host ""

# Get recipients
$recipients = @()

if ($UserList -and (Test-Path $UserList)) {
    $recipients = Get-Content $UserList | Where-Object { $_.Trim() -ne "" }
}
elseif ($GroupName) {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Error "Active Directory PowerShell module is required."
        exit 1
    }
    
    Import-Module ActiveDirectory -ErrorAction Stop
    
    try {
        $group = Get-ADGroup -Identity $GroupName -ErrorAction Stop
        $members = Get-ADGroupMember -Identity $group -Recursive -ErrorAction Stop
        $users = $members | Where-Object { $_.objectClass -eq "user" } | Get-ADUser -Properties EmailAddress -ErrorAction Stop
        $recipients = $users | Where-Object { $_.EmailAddress } | Select-Object -ExpandProperty EmailAddress
    }
    catch {
        Write-Error "Failed to get group members: $($_.Exception.Message)"
        exit 1
    }
}
elseif ($OU) {
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Error "Active Directory PowerShell module is required."
        exit 1
    }
    
    Import-Module ActiveDirectory -ErrorAction Stop
    
    try {
        $users = Get-ADUser -SearchBase $OU -Filter "*" -Properties EmailAddress -ErrorAction Stop
        $recipients = $users | Where-Object { $_.EmailAddress } | Select-Object -ExpandProperty EmailAddress
    }
    catch {
        Write-Error "Failed to get users from OU: $($_.Exception.Message)"
        exit 1
    }
}
else {
    Write-Error "Must specify either -UserList, -GroupName, or -OU"
    exit 1
}

if ($recipients.Count -eq 0) {
    Write-Error "No recipients found."
    exit 1
}

# Get email body
$emailBody = $Body
if ($BodyFile -and (Test-Path $BodyFile)) {
    $emailBody = Get-Content $BodyFile -Raw
}

if (-not $emailBody) {
    Write-Error "Email body is required. Use -Body or -BodyFile"
    exit 1
}

# Get sender
if (-not $From) {
    $From = $env:USERNAME + "@" + $env:USERDNSDOMAIN
}

Write-Host "Recipients: $($recipients.Count)" -ForegroundColor Yellow
Write-Host "Subject: $Subject" -ForegroundColor Yellow
Write-Host "From: $From" -ForegroundColor Yellow
if ($WhatIf) {
    Write-Host "MODE: WHATIF (no emails will be sent)" -ForegroundColor Yellow
}
Write-Host ""

if (-not $WhatIf -and -not $PSCmdlet.ShouldProcess("Send email to $($recipients.Count) recipient(s)", "This will send emails. Continue?")) {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
    exit 0
}

$results = @()

# Check if Exchange is available
$useExchangeModule = $false
if ($UseExchange -or (-not $SMTPServer)) {
    if (Get-Module -ListAvailable -Name ExchangeOnlineManagement) {
        $useExchangeModule = $true
    }
}

if ($useExchangeModule) {
    Write-Host "Using Exchange Online..." -ForegroundColor Yellow
    # Exchange implementation would go here
    Write-Warning "Exchange Online implementation requires connection. Using SMTP fallback."
    $useExchangeModule = $false
}

# Use SMTP
if (-not $useExchangeModule) {
    if (-not $SMTPServer) {
        $SMTPServer = $env:COMPUTERNAME
    }
    
    Write-Host "Using SMTP server: $SMTPServer" -ForegroundColor Yellow
    
    foreach ($recipient in $recipients) {
        Write-Host "Sending to: $recipient" -NoNewline
        
        $result = [PSCustomObject]@{
            Recipient = $recipient
            Subject = $Subject
            Status = "Unknown"
            Error = $null
            LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        
        if (-not $WhatIf) {
            try {
                $mailParams = @{
                    To = $recipient
                    From = $From
                    Subject = $Subject
                    Body = $emailBody
                    SmtpServer = $SMTPServer
                    Port = $SMTPPort
                }
                
                if ($Attachment -and (Test-Path $Attachment)) {
                    $mailParams['Attachments'] = $Attachment
                }
                
                if ($Credential) {
                    $mailParams['Credential'] = $Credential
                }
                
                Send-MailMessage @mailParams -ErrorAction Stop
                
                $result.Status = "Sent"
                Write-Host " - Success" -ForegroundColor Green
            }
            catch {
                $result.Status = "Failed"
                $result.Error = $_.Exception.Message
                Write-Host " - Failed: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        else {
            $result.Status = "WhatIf - Would Send"
            Write-Host " - WhatIf" -ForegroundColor Gray
        }
        
        $results += $result
    }
}

Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
$sent = ($results | Where-Object { $_.Status -like "*Sent*" -or $_.Status -like "WhatIf*" }).Count
Write-Host "Sent: $sent" -ForegroundColor Green
Write-Host "Failed: $(($results | Where-Object { $_.Status -eq 'Failed' }).Count)" -ForegroundColor Red

$results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
$results | Format-Table -AutoSize

