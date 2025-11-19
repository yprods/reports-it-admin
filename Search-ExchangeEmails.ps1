<#
.SYNOPSIS
    Finds emails by subject in all mailboxes in Exchange domain.

.DESCRIPTION
    This script searches for emails by subject across all mailboxes in Exchange
    and provides detailed results including sender, date, and mailbox location.

.PARAMETER Subject
    Email subject to search for (supports wildcards, e.g., "*Important*", "Meeting").

.PARAMETER Sender
    Filter by sender email address (optional).

.PARAMETER BeforeDate
    Search emails before this date (format: yyyy-MM-dd).

.PARAMETER AfterDate
    Search emails after this date (format: yyyy-MM-dd).

.PARAMETER MailboxList
    Path to text file with specific mailboxes to search (optional, searches all if not specified).

.PARAMETER OutputFile
    Path to CSV file. Default: EmailSearchReport.csv

.PARAMETER Credential
    PSCredential object for Exchange authentication.

.PARAMETER ExchangeOnline
    Use Exchange Online (Office 365) instead of on-premises.

.PARAMETER MaxResultsPerMailbox
    Maximum number of results per mailbox (default: 1000).

.EXAMPLE
    .\Search-ExchangeEmails.ps1 -Subject "*Invoice*"
    
.EXAMPLE
    .\Search-ExchangeEmails.ps1 -Subject "Meeting" -Sender "manager@contoso.com" -AfterDate "2024-01-01"
    
.EXAMPLE
    .\Search-ExchangeEmails.ps1 -Subject "*SPAM*" -MailboxList "mailboxes.txt"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Subject,
    
    [Parameter(Mandatory=$false)]
    [string]$Sender,
    
    [Parameter(Mandatory=$false)]
    [string]$BeforeDate,
    
    [Parameter(Mandatory=$false)]
    [string]$AfterDate,
    
    [Parameter(Mandatory=$false)]
    [string]$MailboxList,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "EmailSearchReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [switch]$ExchangeOnline,
    
    [Parameter(Mandatory=$false)]
    [int]$MaxResultsPerMailbox = 1000
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
Write-Host "Exchange Email Search Tool" -ForegroundColor Cyan
Write-Host "=========================" -ForegroundColor Cyan
Write-Host ""

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

Write-Host "Found $($mailboxes.Count) mailbox(es) to search" -ForegroundColor Green
Write-Host ""

# Build search query
$searchQuery = "Subject:$Subject"

if ($Sender) {
    $searchQuery += " AND From:$Sender"
    Write-Host "Sender Filter: $Sender" -ForegroundColor Yellow
}
if ($BeforeDate) {
    $searchQuery += " AND Received<$(Get-Date $BeforeDate -Format 'yyyy-MM-dd')"
    Write-Host "Before Date: $BeforeDate" -ForegroundColor Yellow
}
if ($AfterDate) {
    $searchQuery += " AND Received>$(Get-Date $AfterDate -Format 'yyyy-MM-dd')"
    Write-Host "After Date: $AfterDate" -ForegroundColor Yellow
}

Write-Host "Search Query: $searchQuery" -ForegroundColor Yellow
Write-Host ""

$allResults = @()
$total = $mailboxes.Count
$current = 0

foreach ($mailbox in $mailboxes) {
    $current++
    Write-Progress -Activity "Searching Emails" -Status "Processing $mailbox ($current of $total)" -PercentComplete (($current / $total) * 100)
    
    Write-Host "[$current/$total] Searching $mailbox..." -NoNewline
    
    try {
        # Search mailbox
        $searchParams = @{
            Identity = $mailbox
            SearchQuery = $searchQuery
            ResultSize = $MaxResultsPerMailbox
            TargetMailbox = $mailbox
            TargetFolder = "SearchResults"
            LogLevel = "Suppress"
        }
        
        $searchResult = Search-Mailbox @searchParams -ErrorAction Stop
        
        if ($searchResult -and $searchResult.ResultItemsCount -gt 0) {
            Write-Host " Found $($searchResult.ResultItemsCount) email(s)" -ForegroundColor Green
            
            # Get detailed email information
            try {
                $items = Get-MailboxSearch -Identity "SearchResults" -ErrorAction SilentlyContinue
                
                # Alternative: Use ContentSearch for detailed results
                $contentSearch = New-ComplianceSearch -Name "TempSearch_$(Get-Date -Format 'yyyyMMddHHmmss')" -ContentMatchQuery $searchQuery -ExchangeLocation $mailbox -ErrorAction SilentlyContinue
                
                if ($contentSearch) {
                    Start-ComplianceSearch -Identity $contentSearch.Identity -ErrorAction SilentlyContinue
                    Start-Sleep -Seconds 5
                    
                    $searchDetails = Get-ComplianceSearch -Identity $contentSearch.Identity
                    
                    if ($searchDetails.Items -gt 0) {
                        $searchResults = Get-ComplianceSearch -Identity $contentSearch.Identity -Detail | Select-Object -ExpandProperty Results
                        
                        foreach ($item in $searchResults) {
                            $allResults += [PSCustomObject]@{
                                Mailbox = $mailbox
                                Subject = $item.Subject
                                Sender = $item.Sender
                                ReceivedDate = $item.ReceivedDate
                                ItemClass = $item.ItemClass
                                Size = $item.Size
                                HasAttachments = $item.HasAttachments
                                Status = "Found"
                            }
                        }
                    }
                    
                    # Clean up
                    Remove-ComplianceSearch -Identity $contentSearch.Identity -Confirm:$false -ErrorAction SilentlyContinue
                }
            }
            catch {
                # Fallback: Just record the count
                $allResults += [PSCustomObject]@{
                    Mailbox = $mailbox
                    Subject = "Multiple matches"
                    Sender = "N/A"
                    ReceivedDate = "N/A"
                    ItemClass = "N/A"
                    Size = $null
                    HasAttachments = $null
                    Status = "Found"
                    Count = $searchResult.ResultItemsCount
                }
            }
        }
        else {
            Write-Host " No matches" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host " Error" -ForegroundColor Red
        $allResults += [PSCustomObject]@{
            Mailbox = $mailbox
            Subject = "N/A"
            Sender = "N/A"
            ReceivedDate = "N/A"
            ItemClass = "N/A"
            Size = $null
            HasAttachments = $null
            Status = "Error"
            Error = $_.Exception.Message
        }
    }
}

Write-Progress -Activity "Searching Emails" -Completed

Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "========" -ForegroundColor Cyan
$totalFound = ($allResults | Where-Object { $_.Status -eq "Found" }).Count
$mailboxesWithMatches = ($allResults | Where-Object { $_.Status -eq "Found" } | Select-Object -Unique Mailbox).Count
$errors = ($allResults | Where-Object { $_.Status -eq "Error" }).Count

Write-Host "Total Emails Found:     $totalFound" -ForegroundColor Green
Write-Host "Mailboxes with Matches: $mailboxesWithMatches" -ForegroundColor Cyan
Write-Host "Errors:                 $errors" -ForegroundColor Red
Write-Host ""

$allResults | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "Results exported to: $OutputFile" -ForegroundColor Green

Write-Host ""
Write-Host "Mailboxes with Matches:" -ForegroundColor Cyan
$allResults | Where-Object { $_.Status -eq "Found" } | Group-Object -Property Mailbox | Select-Object Count, Name | Sort-Object Count -Descending | Format-Table -AutoSize

Write-Host ""
Write-Host "Sample Results (first 20):" -ForegroundColor Cyan
$allResults | Where-Object { $_.Status -eq "Found" } | Select-Object -First 20 | Format-Table -AutoSize Mailbox, Subject, Sender, ReceivedDate

