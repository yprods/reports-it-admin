<#
.SYNOPSIS
    Searches for text in a URL or multiple URLs.

.DESCRIPTION
    This script searches for specific text patterns in web pages.
    It can search single URLs or multiple URLs from a list.

.PARAMETER URL
    Single URL or array of URLs to search.

.PARAMETER URLList
    Path to text file containing URLs (one per line).

.PARAMETER SearchText
    Text or pattern to search for (supports regex if -UseRegex is specified).

.PARAMETER UseRegex
    Treat SearchText as a regular expression pattern (default: false).

.PARAMETER CaseSensitive
    Perform case-sensitive search (default: false).

.PARAMETER OutputFile
    Path to CSV file where results will be exported. Default: URLSearchReport.csv

.PARAMETER Timeout
    Request timeout in seconds (default: 30).

.PARAMETER UserAgent
    Custom User-Agent string for web requests.

.PARAMETER ShowContext
    Show surrounding context around matches (default: false).

.PARAMETER ContextLines
    Number of lines to show before and after match (default: 3).

.EXAMPLE
    .\Search-URLText.ps1 -URL "https://example.com" -SearchText "Hello World"
    
.EXAMPLE
    .\Search-URLText.ps1 -URLList "urls.txt" -SearchText "error" -CaseSensitive
    
.EXAMPLE
    .\Search-URLText.ps1 -URL "https://example.com" -SearchText "\d{3}-\d{3}-\d{4}" -UseRegex -ShowContext
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string[]]$URL,
    
    [Parameter(Mandatory=$false)]
    [string]$URLList,
    
    [Parameter(Mandatory=$true)]
    [string]$SearchText,
    
    [Parameter(Mandatory=$false)]
    [switch]$UseRegex,
    
    [Parameter(Mandatory=$false)]
    [switch]$CaseSensitive,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "URLSearchReport.csv",
    
    [Parameter(Mandatory=$false)]
    [int]$Timeout = 30,
    
    [Parameter(Mandatory=$false)]
    [string]$UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    
    [Parameter(Mandatory=$false)]
    [switch]$ShowContext,
    
    [Parameter(Mandatory=$false)]
    [int]$ContextLines = 3
)

# Function to search text in a URL
function Search-URLText {
    param(
        [string]$Url,
        [string]$Text,
        [bool]$Regex,
        [bool]$CaseSensitive,
        [int]$TimeoutSeconds,
        [string]$UserAgentString,
        [bool]$ShowContextLines,
        [int]$ContextCount
    )
    
    $result = [PSCustomObject]@{
        URL = $Url
        SearchText = $Text
        Found = $false
        MatchCount = 0
        Matches = "N/A"
        Context = "N/A"
        Status = "Unknown"
        StatusCode = $null
        Error = $null
        LastChecked = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    try {
        # Create web request
        $request = [System.Net.WebRequest]::Create($Url)
        $request.Method = "GET"
        $request.Timeout = $TimeoutSeconds * 1000
        $request.UserAgent = $UserAgentString
        
        # Get response
        $response = $request.GetResponse()
        $result.StatusCode = $response.StatusCode.value__
        
        # Read content
        $stream = $response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($stream)
        $content = $reader.ReadToEnd()
        $reader.Close()
        $stream.Close()
        $response.Close()
        
        # Search for text
        $matches = @()
        $matchContexts = @()
        
        if ($Regex) {
            # Use regex search
            $options = if ($CaseSensitive) { [System.Text.RegularExpressions.RegexOptions]::None } else { [System.Text.RegularExpressions.RegexOptions]::IgnoreCase }
            $regex = New-Object System.Text.RegularExpressions.Regex($Text, $options)
            $matchCollection = $regex.Matches($content)
            
            foreach ($match in $matchCollection) {
                $matches += $match.Value
                
                if ($ShowContextLines) {
                    $startPos = [Math]::Max(0, $match.Index - 100)
                    $endPos = [Math]::Min($content.Length, $match.Index + $match.Length + 100)
                    $context = $content.Substring($startPos, $endPos - $startPos)
                    $matchContexts += "...$context..."
                }
            }
        }
        else {
            # Simple text search
            $comparison = if ($CaseSensitive) { [System.StringComparison]::Ordinal } else { [System.StringComparison]::OrdinalIgnoreCase }
            $index = 0
            $matchCount = 0
            $lines = $content -split "`n"
            
            foreach ($line in $lines) {
                if ($line.IndexOf($Text, $comparison) -ge 0) {
                    $matchCount++
                    $matches += $line.Trim()
                    
                    if ($ShowContextLines) {
                        $lineIndex = [Array]::IndexOf($lines, $line)
                        $startLine = [Math]::Max(0, $lineIndex - $ContextCount)
                        $endLine = [Math]::Min($lines.Count - 1, $lineIndex + $ContextCount)
                        $context = ($lines[$startLine..$endLine] -join "`n").Trim()
                        $matchContexts += $context
                    }
                }
            }
        }
        
        if ($matches.Count -gt 0) {
            $result.Found = $true
            $result.MatchCount = $matches.Count
            $result.Matches = ($matches | Select-Object -First 10) -join "; "
            if ($ShowContextLines -and $matchContexts.Count -gt 0) {
                $result.Context = ($matchContexts | Select-Object -First 3) -join "`n---`n"
            }
            $result.Status = "Found"
        }
        else {
            $result.Status = "Not Found"
        }
    }
    catch {
        $result.Status = "Error"
        $result.Error = $_.Exception.Message
    }
    
    return $result
}

# Main execution
Write-Host "URL Text Search Tool" -ForegroundColor Cyan
Write-Host "===================" -ForegroundColor Cyan
Write-Host ""

# Collect URLs
$urls = @()

if ($URLList) {
    if (Test-Path $URLList) {
        Write-Host "Reading URL list from: $URLList" -ForegroundColor Yellow
        $urls = Get-Content $URLList | Where-Object { $_.Trim() -ne "" } | ForEach-Object { $_.Trim() }
    }
    else {
        Write-Error "URL list file not found: $URLList"
        exit 1
    }
}

if ($URL) {
    $urls += $URL
}

# Remove duplicates
$urls = $urls | Select-Object -Unique

if ($urls.Count -eq 0) {
    Write-Error "No URLs specified. Use -URL or -URLList parameter."
    exit 1
}

Write-Host "Search Text: $SearchText" -ForegroundColor Yellow
Write-Host "Search Type: " -NoNewline
if ($UseRegex) {
    Write-Host "Regular Expression" -ForegroundColor Cyan
} else {
    Write-Host "Plain Text" -ForegroundColor Cyan
}
Write-Host "Case Sensitive: $CaseSensitive" -ForegroundColor Yellow
Write-Host "Found $($urls.Count) unique URL(s) to search" -ForegroundColor Green
if ($ShowContext) {
    Write-Host "Show Context: ENABLED ($ContextLines lines)" -ForegroundColor Cyan
}
Write-Host ""

# Search each URL
$results = @()
$total = $urls.Count
$current = 0

foreach ($url in $urls) {
    $current++
    Write-Progress -Activity "Searching URLs" -Status "Processing $url ($current of $total)" -PercentComplete (($current / $total) * 100)
    
    Write-Host "[$current/$total] Searching $url..." -NoNewline
    
    $result = Search-URLText -Url $url -Text $SearchText -Regex $UseRegex.IsPresent -CaseSensitive $CaseSensitive.IsPresent -TimeoutSeconds $Timeout -UserAgentString $UserAgent -ShowContextLines $ShowContext.IsPresent -ContextCount $ContextLines
    
    $results += $result
    
    $statusColor = switch ($result.Status) {
        "Found" { "Green" }
        "Not Found" { "Yellow" }
        "Error" { "Red" }
        default { "Gray" }
    }
    
    Write-Host " $($result.Status)" -ForegroundColor $statusColor
    if ($result.Found) {
        Write-Host "  Matches: $($result.MatchCount)" -ForegroundColor Gray
    }
    if ($result.StatusCode) {
        Write-Host "  Status Code: $($result.StatusCode)" -ForegroundColor Gray
    }
    if ($result.Error) {
        Write-Host "  Error: $($result.Error)" -ForegroundColor Red
    }
}

Write-Progress -Activity "Searching URLs" -Completed

# Display summary
Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "========" -ForegroundColor Cyan
$found = ($results | Where-Object { $_.Found -eq $true }).Count
$notFound = ($results | Where-Object { $_.Status -eq "Not Found" }).Count
$errors = ($results | Where-Object { $_.Status -eq "Error" }).Count
$totalMatches = ($results | Measure-Object -Property MatchCount -Sum).Sum

Write-Host "Found:         $found" -ForegroundColor Green
Write-Host "Not Found:     $notFound" -ForegroundColor Yellow
Write-Host "Errors:        $errors" -ForegroundColor Red
Write-Host "Total Matches: $totalMatches" -ForegroundColor Cyan
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
$results | Format-Table -AutoSize URL, Status, MatchCount, StatusCode, Error

# Show matches for found URLs
$foundResults = $results | Where-Object { $_.Found -eq $true }
if ($foundResults.Count -gt 0) {
    Write-Host ""
    Write-Host "URLs with Matches:" -ForegroundColor Cyan
    Write-Host "=================" -ForegroundColor Cyan
    foreach ($found in $foundResults) {
        Write-Host ""
        Write-Host "URL: $($found.URL)" -ForegroundColor Green
        Write-Host "Matches: $($found.MatchCount)" -ForegroundColor Yellow
        if ($found.Matches -ne "N/A") {
            Write-Host "Sample Matches:" -ForegroundColor Gray
            $found.Matches -split "; " | Select-Object -First 3 | ForEach-Object {
                Write-Host "  - $_" -ForegroundColor Gray
            }
        }
        if ($ShowContext -and $found.Context -ne "N/A") {
            Write-Host "Context:" -ForegroundColor Gray
            Write-Host $found.Context -ForegroundColor DarkGray
        }
    }
}

