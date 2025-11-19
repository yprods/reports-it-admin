<#
.SYNOPSIS
    Deletes emails from all mailboxes in Exchange.

.DESCRIPTION
    This script connects to Exchange and deletes emails from all mailboxes
    based on search criteria (subject, sender, date range, etc.).

.PARAMETER Subject
    Email subject to search for (supports wildcards).

.PARAMETER Sender
    Email sender address to filter by.

.PARAMETER BeforeDate
    Delete emails before this date (format: yyyy-MM-dd).

.PARAMETER AfterDate
    Delete emails after this date (format: yyyy-MM-dd).

.PARAMETER DaysOld
    Delete emails older than specified days.

.PARAMETER MailboxList
    Path to text file with specific mailboxes to process (optional, processes all if not specified).

.PARAMETER OutputFile
    Path to CSV file. Default: EmailDeletionReport.csv

.PARAMETER Credential
    PSCredential object for Exchange authentication.

.PARAMETER ExchangeOnline
    Use Exchange Online (Office 365) instead of on-premises.

.PARAMETER WhatIf
    Show what would be deleted without actually deleting.

.PARAMETER HardDelete
    Permanently delete emails (bypass recoverable items, default: false).

.EXAMPLE
    .\Remove-ExchangeEmails.ps1 -Subject "*SPAM*" -DaysOld 30
    
.EXAMPLE
    .\Remove-ExchangeEmails.ps1 -Sender "spam@example.com" -BeforeDate "2024-01-01" -HardDelete
    
.EXAMPLE
    .\Remove-ExchangeEmails.ps1 -Subject "Test Email" -MailboxList "mailboxes.txt" -WhatIf
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false)]
    [string]$Subject,
    
    [Parameter(Mandatory=$false)]
    [string]$Sender,
    
    [Parameter(Mandatory=$false)]
    [string]$BeforeDate,
    
    [Parameter(Mandatory=$false)]
    [string]$AfterDate,
    
    [Parameter(Mandatory=$false)]
    [int]$DaysOld = 0,
    
    [Parameter(Mandatory=$false)]
    [string]$MailboxList,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "EmailDeletionReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [switch]$ExchangeOnline,
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf,
    
    [Parameter(Mandatory=$false)]
    [switch]$HardDelete
)

# Function to connect to Exchange
function Connect-Exchange {
    param([bool]$Online, [System.Management.Automation.PSCredential]$Cred)
    
    try {
        if ($Online) {
            # Exchange Online
            if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
                Write-Error "Exchange Online Management module not found. Install with: Install-Module -Name ExchangeOnlineManagement"
                return $false
            }
            
            Import-Module ExchangeOnlineManagement -ErrorAction Stop
            
            if ($Cred) {
                Connect-ExchangeOnline -Credential $Cred -ShowProgress $false
            }
            else {
                Connect-ExchangeOnline -ShowProgress $false
            }
        }
        else {
            # On-premises Exchange
            $session = $null
            try {
                $session = Get-PSSession | Where-Object { $_.ConfigurationName -eq "Microsoft.Exchange" }
                if (-not $session) {
                    Write-Host "Connecting to Exchange on-premises..." -ForegroundColor Yellow
                    if ($Cred) {
                        $session = New-PSSession -ConfigurationName Microsoft.Exchange -Credential $Cred
                    }
                    else {
                        $session = New-PSSession -ConfigurationName Microsoft.Exchange
                    }
                    Import-PSSession $session -DisableNameChecking
                }
            }
            catch {
                Write-Error "Failed to connect to Exchange: $($_.Exception.Message)"
                return $false
            }
        }
        
        return $true
    }
    catch {
        Write-Error "Exchange connection failed: $($_.Exception.Message)"
        return $false
    }
}

# Main execution
Write-Host "Exchange Email Deletion Tool" -ForegroundColor Cyan
Write-Host "===========================" -ForegroundColor Cyan
Write-Host ""

# Validate parameters
if (-not $Subject -and -not $Sender -and -not $BeforeDate -and -not $AfterDate -and $DaysOld -eq 0) {
    Write-Error "At least one search criteria must be specified (Subject, Sender, Date, or DaysOld)."
    exit 1
}

# Connect to Exchange
Write-Host "Connecting to Exchange..." -ForegroundColor Yellow
if (-not (Connect-Exchange -Online $ExchangeOnline.IsPresent -Cred $Credential)) {
    Write-Error "Failed to connect to Exchange. Exiting."
    exit 1
}
Write-Host "Connected successfully" -ForegroundColor Green
Write-Host ""

# Get mailboxes
$mailboxes = @()

if ($MailboxList -and (Test-Path $MailboxList)) {
    Write-Host "Reading mailbox list from: $MailboxList" -ForegroundColor Yellow
    $mailboxes = Get-Content $MailboxList | Where-Object { $_.Trim() -ne "" } | ForEach-Object { $_.Trim() }
}
else {
    Write-Host "Getting all mailboxes..." -ForegroundColor Yellow
    try {
        if ($ExchangeOnline) {
            $mailboxes = Get-Mailbox -ResultSize Unlimited | Select-Object -ExpandProperty PrimarySmtpAddress
        }
        else {
            $mailboxes = Get-Mailbox -ResultSize Unlimited | Select-Object -ExpandProperty PrimarySmtpAddress
        }
    }
    catch {
        Write-Error "Failed to get mailboxes: $($_.Exception.Message)"
        exit 1
    }
}

Write-Host "Found $($mailboxes.Count) mailbox(es) to process" -ForegroundColor Green
Write-Host ""

# Build search criteria
$searchCriteria = @()
if ($Subject) {
    $searchCriteria += "Subject:$Subject"
    Write-Host "Subject Filter: $Subject" -ForegroundColor Yellow
}
if ($Sender) {
    $searchCriteria += "From:$Sender"
    Write-Host "Sender Filter: $Sender" -ForegroundColor Yellow
}
if ($BeforeDate) {
    $searchCriteria += "Received<$(Get-Date $BeforeDate -Format 'yyyy-MM-dd')"
    Write-Host "Before Date: $BeforeDate" -ForegroundColor Yellow
}
if ($AfterDate) {
    $searchCriteria += "Received>$(Get-Date $AfterDate -Format 'yyyy-MM-dd')"
    Write-Host "After Date: $AfterDate" -ForegroundColor Yellow
}
if ($DaysOld -gt 0) {
    $cutoffDate = (Get-Date).AddDays(-$DaysOld)
    $searchCriteria += "Received<$($cutoffDate.ToString('yyyy-MM-dd'))"
    Write-Host "Days Old: $DaysOld (before $($cutoffDate.ToString('yyyy-MM-dd')))" -ForegroundColor Yellow
}

$searchQuery = $searchCriteria -join " AND "

if ($WhatIf) {
    Write-Host "MODE: WHATIF (no emails will be deleted)" -ForegroundColor Yellow
}
if ($HardDelete) {
    Write-Host "Hard Delete: ENABLED (permanent deletion)" -ForegroundColor Red
}
Write-Host ""

if (-not $WhatIf -and -not $PSCmdlet.ShouldProcess("Delete emails from $($mailboxes.Count) mailbox(es)", "This will delete emails matching criteria. Continue?")) {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
    exit 0
}

$results = @()
$total = $mailboxes.Count
$current = 0

foreach ($mailbox in $mailboxes) {
    $current++
    Write-Progress -Activity "Deleting Emails" -Status "Processing $mailbox ($current of $total)" -PercentComplete (($current / $total) * 100)
    
    Write-Host "[$current/$total] Processing $mailbox..." -NoNewline
    
    $result = [PSCustomObject]@{
        Mailbox = $mailbox
        EmailsFound = 0
        EmailsDeleted = 0
        Status = "Unknown"
        Error = $null
        LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    try {
        # Search for emails
        $searchParams = @{
            Mailbox = $mailbox
            SearchQuery = $searchQuery
            EstimateResultOnly = $false
        }
        
        $searchResults = Search-Mailbox @searchParams -ErrorAction Stop
        
        if ($searchResults) {
            $result.EmailsFound = $searchResults.ResultItemsCount
            
            if ($result.EmailsFound -gt 0) {
                if (-not $WhatIf) {
                    # Delete emails
                    $deleteParams = @{
                        Identity = $mailbox
                        SearchQuery = $searchQuery
                        DeleteContent = $true
                        Force = $true
                    }
                    
                    if ($HardDelete) {
                        $deleteParams['PermanentDelete'] = $true
                    }
                    
                    $deleteResult = Search-Mailbox @deleteParams -ErrorAction Stop
                    $result.EmailsDeleted = $deleteResult.ResultItemsCount
                    $result.Status = "Success"
                }
                else {
                    $result.EmailsDeleted = $result.EmailsFound
                    $result.Status = "WhatIf - Would Delete"
                }
            }
            else {
                $result.Status = "No Emails Found"
            }
        }
        else {
            $result.Status = "No Emails Found"
        }
    }
    catch {
        $result.Status = "Error"
        $result.Error = $_.Exception.Message
    }
    
    $results += $result
    
    $statusColor = switch ($result.Status) {
        "Success" { "Green" }
        "WhatIf - Would Delete" { "Yellow" }
        "No Emails Found" { "Gray" }
        "Error" { "Red" }
        default { "Gray" }
    }
    
    Write-Host " $($result.Status)" -ForegroundColor $statusColor
    if ($result.EmailsFound -gt 0) {
        Write-Host "  Found: $($result.EmailsFound), Deleted: $($result.EmailsDeleted)" -ForegroundColor Gray
    }
    if ($result.Error) {
        Write-Host "  Error: $($result.Error)" -ForegroundColor Red
    }
}

Write-Progress -Activity "Deleting Emails" -Completed

Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "========" -ForegroundColor Cyan
$totalFound = ($results | Measure-Object -Property EmailsFound -Sum).Sum
$totalDeleted = ($results | Measure-Object -Property EmailsDeleted -Sum).Sum
$success = ($results | Where-Object { $_.Status -eq "Success" -or $_.Status -like "WhatIf*" }).Count
$errors = ($results | Where-Object { $_.Status -eq "Error" }).Count

Write-Host "Total Emails Found:  $totalFound" -ForegroundColor Green
Write-Host "Total Emails Deleted: $totalDeleted" -ForegroundColor Yellow
Write-Host "Success:            $success" -ForegroundColor Green
Write-Host "Errors:             $errors" -ForegroundColor Red
Write-Host ""

$results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "Results exported to: $OutputFile" -ForegroundColor Green

$results | Format-Table -AutoSize Mailbox, EmailsFound, EmailsDeleted, Status

