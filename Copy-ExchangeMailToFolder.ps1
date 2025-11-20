<#
.SYNOPSIS
    Copies emails from Outlook/Exchange to a folder.

.DESCRIPTION
    This script copies emails from Exchange mailboxes to a specified folder.
    Supports filtering by date, subject, sender, and folder.

.PARAMETER Mailbox
    Email address of mailbox to copy from.

.PARAMETER MailboxList
    Path to text file with mailbox addresses (one per line).

.PARAMETER DestinationFolder
    Destination folder path where emails will be copied.

.PARAMETER SourceFolder
    Source folder in mailbox (default: Inbox).

.PARAMETER DateFrom
    Copy emails from this date onwards (format: yyyy-MM-dd).

.PARAMETER DateTo
    Copy emails up to this date (format: yyyy-MM-dd).

.PARAMETER SubjectFilter
    Filter by subject (supports wildcards).

.PARAMETER SenderFilter
    Filter by sender email address.

.PARAMETER ExchangeOnline
    Use Exchange Online (Office 365) instead of on-premises.

.PARAMETER Credential
    PSCredential object for Exchange authentication.

.PARAMETER OutputFile
    Path to CSV file. Default: CopyMailReport.csv

.PARAMETER WhatIf
    Show what would be copied without actually copying.

.EXAMPLE
    .\Copy-ExchangeMailToFolder.ps1 -Mailbox "user@contoso.com" -DestinationFolder "C:\Exports\Emails"
    
.EXAMPLE
    .\Copy-ExchangeMailToFolder.ps1 -MailboxList "mailboxes.txt" -DestinationFolder "C:\Exports" -DateFrom "2024-01-01"
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false)]
    [string]$Mailbox,
    
    [Parameter(Mandatory=$false)]
    [string]$MailboxList,
    
    [Parameter(Mandatory=$true)]
    [string]$DestinationFolder,
    
    [Parameter(Mandatory=$false)]
    [string]$SourceFolder = "Inbox",
    
    [Parameter(Mandatory=$false)]
    [string]$DateFrom,
    
    [Parameter(Mandatory=$false)]
    [string]$DateTo,
    
    [Parameter(Mandatory=$false)]
    [string]$SubjectFilter,
    
    [Parameter(Mandatory=$false)]
    [string]$SenderFilter,
    
    [Parameter(Mandatory=$false)]
    [switch]$ExchangeOnline,
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "CopyMailReport.csv",
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

# Main execution
Write-Host "Copy Exchange Mail to Folder Tool" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan
Write-Host ""

# Get mailboxes
$mailboxes = @()

if ($MailboxList -and (Test-Path $MailboxList)) {
    $mailboxes = Get-Content $MailboxList | Where-Object { $_.Trim() -ne "" }
}

if ($Mailbox) {
    $mailboxes += $Mailbox
}

$mailboxes = $mailboxes | Select-Object -Unique

if ($mailboxes.Count -eq 0) {
    Write-Error "No mailboxes specified."
    exit 1
}

# Create destination folder
if (-not (Test-Path $DestinationFolder)) {
    try {
        New-Item -Path $DestinationFolder -ItemType Directory -Force | Out-Null
        Write-Host "Created destination folder: $DestinationFolder" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to create destination folder: $($_.Exception.Message)"
        exit 1
    }
}

Write-Host "Mailboxes: $($mailboxes.Count)" -ForegroundColor Yellow
Write-Host "Source Folder: $SourceFolder" -ForegroundColor Yellow
Write-Host "Destination: $DestinationFolder" -ForegroundColor Yellow
if ($DateFrom) {
    Write-Host "Date From: $DateFrom" -ForegroundColor Yellow
}
if ($DateTo) {
    Write-Host "Date To: $DateTo" -ForegroundColor Yellow
}
if ($WhatIf) {
    Write-Host "MODE: WHATIF (no emails will be copied)" -ForegroundColor Yellow
}
Write-Host ""

# Note: This is a simplified version. Full implementation would require:
# - Exchange PowerShell module connection
# - Proper email export using Export-Mailbox or Search-Mailbox
# - EML or PST file creation

Write-Warning "This script requires Exchange PowerShell module and proper permissions."
Write-Warning "Full implementation would use Export-Mailbox or Search-Mailbox cmdlets."

$results = @()

foreach ($mailbox in $mailboxes) {
    Write-Host "Processing: $mailbox" -NoNewline
    
    $result = [PSCustomObject]@{
        Mailbox = $mailbox
        SourceFolder = $SourceFolder
        DestinationFolder = $DestinationFolder
        EmailsCopied = 0
        Status = "Unknown"
        Error = "Exchange module connection required for full implementation"
        LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    if (-not $WhatIf) {
        # Placeholder for actual Exchange implementation
        $result.Status = "Not Implemented"
        Write-Host " - Requires Exchange connection" -ForegroundColor Yellow
    }
    else {
        $result.Status = "WhatIf - Would Copy"
        Write-Host " - WhatIf" -ForegroundColor Gray
    }
    
    $results += $result
}

$results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
$results | Format-Table -AutoSize

