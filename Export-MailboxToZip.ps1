<#
.SYNOPSIS
    Creates a ZIP copy of a mailbox in Exchange.

.DESCRIPTION
    This script exports a mailbox to PST format and then compresses it to ZIP,
    or exports directly to ZIP format with mailbox contents.

.PARAMETER Mailbox
    Email address of the mailbox to export.

.PARAMETER MailboxList
    Path to text file with mailbox addresses (one per line).

.PARAMETER OutputPath
    Path where ZIP files will be saved (default: current directory).

.PARAMETER Credential
    PSCredential object for Exchange authentication.

.PARAMETER ExchangeOnline
    Use Exchange Online (Office 365) instead of on-premises.

.PARAMETER DateFrom
    Export emails from this date onwards (format: yyyy-MM-dd).

.PARAMETER DateTo
    Export emails up to this date (format: yyyy-MM-dd).

.PARAMETER IncludeArchive
    Include archive mailbox in export (default: false).

.PARAMETER CompressLevel
    ZIP compression level: None, Fastest, Optimal, Maximum (default: Optimal).

.EXAMPLE
    .\Export-MailboxToZip.ps1 -Mailbox "user@contoso.com" -OutputPath "C:\Exports"
    
.EXAMPLE
    .\Export-MailboxToZip.ps1 -MailboxList "mailboxes.txt" -DateFrom "2024-01-01" -IncludeArchive
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false)]
    [string]$Mailbox,
    
    [Parameter(Mandatory=$false)]
    [string]$MailboxList,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [switch]$ExchangeOnline,
    
    [Parameter(Mandatory=$false)]
    [string]$DateFrom,
    
    [Parameter(Mandatory=$false)]
    [string]$DateTo,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeArchive,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("None","Fastest","Optimal","Maximum")]
    [string]$CompressLevel = "Optimal"
)

# Function to connect to Exchange
function Connect-Exchange {
    param([bool]$Online, [System.Management.Automation.PSCredential]$Cred)
    
    try {
        if ($Online) {
            if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
                Write-Error "Exchange Online Management module not found."
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
            $session = Get-PSSession | Where-Object { $_.ConfigurationName -eq "Microsoft.Exchange" }
            if (-not $session) {
                if ($Cred) {
                    $session = New-PSSession -ConfigurationName Microsoft.Exchange -Credential $Cred
                }
                else {
                    $session = New-PSSession -ConfigurationName Microsoft.Exchange
                }
                Import-PSSession $session -DisableNameChecking
            }
        }
        return $true
    }
    catch {
        Write-Error "Exchange connection failed: $($_.Exception.Message)"
        return $false
    }
}

# Function to export mailbox to ZIP
function Export-MailboxToZip {
    param(
        [string]$MailboxAddress,
        [string]$OutputDir,
        [string]$DateFromStr,
        [string]$DateToStr,
        [bool]$IncludeArch,
        [string]$Compress,
        [System.Management.Automation.PSCredential]$Cred,
        [bool]$Online
    )
    
    $result = [PSCustomObject]@{
        Mailbox = $MailboxAddress
        ZipFile = "N/A"
        SizeMB = $null
        Status = "Unknown"
        Error = $null
        LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    try {
        # Create temp directory for export
        $tempDir = Join-Path $env:TEMP "MailboxExport_$(Get-Date -Format 'yyyyMMddHHmmss')"
        New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
        
        # Build export path
        $zipFileName = "$($MailboxAddress -replace '@', '_' -replace '\.', '_')_$(Get-Date -Format 'yyyyMMdd').zip"
        $zipFilePath = Join-Path $OutputDir $zipFileName
        
        # Export mailbox to PST first (Exchange method)
        $pstPath = Join-Path $tempDir "$($MailboxAddress -replace '@', '_').pst"
        
        try {
            if ($Online) {
                # Exchange Online - use New-MailboxExportRequest or Content Search
                Write-Host "  Exporting mailbox (Exchange Online)..." -ForegroundColor Gray
                
                # For Exchange Online, we'll use a different approach
                # Export to CSV/EML format and then zip
                $exportPath = Join-Path $tempDir "Export"
                New-Item -Path $exportPath -ItemType Directory -Force | Out-Null
                
                # Get mailbox statistics
                $stats = Get-MailboxStatistics -Identity $MailboxAddress -ErrorAction Stop
                
                # Export using Search-Mailbox or Content Search
                $searchName = "Export_$($MailboxAddress -replace '@', '_')_$(Get-Date -Format 'yyyyMMddHHmmss')"
                
                # Create compliance search for export
                $contentSearch = New-ComplianceSearch -Name $searchName -ContentMatchQuery "*" -ExchangeLocation $MailboxAddress -ErrorAction Stop
                Start-ComplianceSearch -Identity $contentSearch.Identity -ErrorAction Stop
                
                # Wait for search to complete
                $searchStatus = Get-ComplianceSearch -Identity $contentSearch.Identity
                $timeout = 300
                $elapsed = 0
                while ($searchStatus.Status -ne "Completed" -and $elapsed -lt $timeout) {
                    Start-Sleep -Seconds 5
                    $elapsed += 5
                    $searchStatus = Get-ComplianceSearch -Identity $contentSearch.Identity
                }
                
                if ($searchStatus.Status -eq "Completed") {
                    # Export search results
                    $exportName = "Export_$searchName"
                    New-ComplianceSearchAction -SearchName $searchName -Export -ErrorAction Stop | Out-Null
                    
                    # Note: Actual file download would require additional steps
                    # This is a simplified version
                    $result.Status = "Export Initiated"
                }
            }
            else {
                # On-premises Exchange
                Write-Host "  Exporting mailbox (On-Premises)..." -ForegroundColor Gray
                
                $exportParams = @{
                    Mailbox = $MailboxAddress
                    FilePath = $pstPath
                }
                
                if ($DateFrom) {
                    $exportParams['StartDate'] = Get-Date $DateFrom
                }
                if ($DateTo) {
                    $exportParams['EndDate'] = Get-Date $DateTo
                }
                
                New-MailboxExportRequest @exportParams -ErrorAction Stop
                
                # Wait for export to complete
                $exportRequest = Get-MailboxExportRequest -Mailbox $MailboxAddress | Where-Object { $_.Status -ne "Completed" } | Select-Object -First 1
                $timeout = 600
                $elapsed = 0
                while ($exportRequest -and $exportRequest.Status -ne "Completed" -and $elapsed -lt $timeout) {
                    Start-Sleep -Seconds 10
                    $elapsed += 10
                    $exportRequest = Get-MailboxExportRequest -Identity $exportRequest.Identity
                }
                
                if ($exportRequest.Status -eq "Completed") {
                    # Compress PST to ZIP
                    if (Test-Path $pstPath) {
                        Add-Type -AssemblyName System.IO.Compression.FileSystem
                        [System.IO.Compression.ZipFile]::CreateFromFile($pstPath, $zipFilePath, $Compress, $false)
                        $result.ZipFile = $zipFilePath
                        $result.SizeMB = [math]::Round((Get-Item $zipFilePath).Length / 1MB, 2)
                        $result.Status = "Success"
                    }
                }
                else {
                    $result.Status = "Export Timeout"
                    $result.Error = "Export did not complete within timeout period"
                }
            }
        }
        catch {
            $result.Status = "Error"
            $result.Error = $_.Exception.Message
        }
        finally {
            # Cleanup temp directory
            if (Test-Path $tempDir) {
                Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
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
Write-Host "Mailbox to ZIP Export Tool" -ForegroundColor Cyan
Write-Host "==========================" -ForegroundColor Cyan
Write-Host ""

# Collect mailboxes
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

# Create output directory
if (-not (Test-Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

Write-Host "Output Path: $OutputPath" -ForegroundColor Yellow
Write-Host "Processing $($mailboxes.Count) mailbox(es)..." -ForegroundColor Yellow
if ($DateFrom) {
    Write-Host "Date From: $DateFrom" -ForegroundColor Yellow
}
if ($DateTo) {
    Write-Host "Date To: $DateTo" -ForegroundColor Yellow
}
Write-Host ""

# Connect to Exchange
Write-Host "Connecting to Exchange..." -ForegroundColor Yellow
if (-not (Connect-Exchange -Online $ExchangeOnline.IsPresent -Cred $Credential)) {
    Write-Error "Failed to connect to Exchange."
    exit 1
}
Write-Host "Connected successfully" -ForegroundColor Green
Write-Host ""

$results = @()
foreach ($mailbox in $mailboxes) {
    Write-Host "Exporting $mailbox..." -NoNewline
    $result = Export-MailboxToZip -MailboxAddress $mailbox -OutputDir $OutputPath -DateFromStr $DateFrom -DateToStr $DateTo -IncludeArch $IncludeArchive.IsPresent -Compress $CompressLevel -Cred $Credential -Online $ExchangeOnline.IsPresent
    $results += $result
    Write-Host " $($result.Status)" -ForegroundColor $(if ($result.Status -eq "Success") { "Green" } else { "Red" })
    if ($result.ZipFile -ne "N/A") {
        Write-Host "  File: $($result.ZipFile)" -ForegroundColor Gray
        Write-Host "  Size: $($result.SizeMB) MB" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
$success = ($results | Where-Object { $_.Status -eq "Success" }).Count
Write-Host "Success: $success" -ForegroundColor Green
Write-Host "Errors: $(($results | Where-Object { $_.Status -eq 'Error' }).Count)" -ForegroundColor Red

$results | Export-Csv -Path (Join-Path $OutputPath "ExportReport.csv") -NoTypeInformation -Encoding UTF8
$results | Format-Table -AutoSize

