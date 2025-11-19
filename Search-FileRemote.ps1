<#
.SYNOPSIS
    Searches for files or folders on remote computers by name or extension.

.DESCRIPTION
    This script searches for files or folders across multiple computers remotely.
    It supports searching by filename, extension, folder name, and can search
    specific drives or entire systems.

.PARAMETER ComputerList
    Path to a text file containing computer names (one per line).

.PARAMETER ComputerName
    Single computer name or array of computer names to search.

.PARAMETER Domain
    Search all computers in the specified domain (requires Active Directory module).

.PARAMETER SearchPath
    Path to search (e.g., "C:\", "C:\Users", "C:\Program Files"). Default: "C:\"

.PARAMETER SearchPattern
    File or folder name pattern to search for (supports wildcards, e.g., "*.txt", "config*").

.PARAMETER SearchType
    Type of search: File, Folder, or Both (default: Both).

.PARAMETER Extension
    File extension to search for (e.g., "txt", "exe", "pdf"). Overrides SearchPattern if specified.

.PARAMETER OutputFile
    Path to CSV file where results will be exported. Default: FileSearchReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication (optional).

.PARAMETER Recurse
    Search subdirectories recursively (default: true).

.PARAMETER MaxDepth
    Maximum depth for recursive search (default: unlimited).

.PARAMETER IncludeSystemFiles
    Include system and hidden files in search (default: false).

.EXAMPLE
    .\Search-FileRemote.ps1 -ComputerList "computers.txt" -SearchPattern "*.txt" -SearchPath "C:\Users"
    
.EXAMPLE
    .\Search-FileRemote.ps1 -ComputerName "PC01","PC02" -Extension "exe" -SearchPath "C:\Program Files"
    
.EXAMPLE
    .\Search-FileRemote.ps1 -Domain "contoso.com" -SearchPattern "config*" -SearchType File
    
.EXAMPLE
    .\Search-FileRemote.ps1 -ComputerList "computers.txt" -SearchPattern "Documents" -SearchType Folder
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
    [string]$SearchPath = "C:\",
    
    [Parameter(Mandatory=$false)]
    [string]$SearchPattern = "*",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("File","Folder","Both")]
    [string]$SearchType = "Both",
    
    [Parameter(Mandatory=$false)]
    [string]$Extension,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "FileSearchReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [switch]$Recurse = $true,
    
    [Parameter(Mandatory=$false)]
    [int]$MaxDepth = -1,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeSystemFiles
)

# Function to search for files/folders on a single computer
function Search-FileRemote {
    param(
        [string]$Computer,
        [string]$Path,
        [string]$Pattern,
        [string]$Type,
        [string]$Ext,
        [System.Management.Automation.PSCredential]$Cred,
        [bool]$Recursive,
        [int]$Depth,
        [bool]$IncludeSystem
    )
    
    $results = @()
    
    try {
        # Test connectivity first
        if (-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            $result = [PSCustomObject]@{
                ComputerName = $Computer
                Path = "N/A"
                Name = "N/A"
                Type = "N/A"
                Size = $null
                LastModified = "N/A"
                Status = "Offline"
                Error = "Computer is not reachable"
            }
            $results += $result
            return $results
        }
        
        # Build search script block
        $searchScript = {
            param(
                [string]$SearchPath,
                [string]$SearchPattern,
                [string]$SearchType,
                [string]$FileExtension,
                [bool]$RecursiveSearch,
                [int]$MaxDepth,
                [bool]$IncludeSystemFiles
            )
            
            $foundItems = @()
            
            try {
                # Validate search path exists
                if (-not (Test-Path $SearchPath)) {
                    return @(@{
                        Path = $SearchPath
                        Name = "N/A"
                        Type = "Error"
                        Size = $null
                        LastModified = "N/A"
                        Error = "Search path does not exist"
                    })
                }
                
                # Build search pattern
                $finalPattern = $SearchPattern
                if ($FileExtension) {
                    if ($FileExtension.StartsWith(".")) {
                        $finalPattern = "*$FileExtension"
                    } else {
                        $finalPattern = "*.$FileExtension"
                    }
                }
                
                # Set search options
                $searchOptions = @{
                    Path = $SearchPath
                    Filter = $finalPattern
                    ErrorAction = "SilentlyContinue"
                }
                
                if ($RecursiveSearch) {
                    $searchOptions['Recurse'] = $true
                }
                
                # Search for files
                if ($SearchType -eq "File" -or $SearchType -eq "Both") {
                    $fileOptions = $searchOptions.Clone()
                    if (-not $IncludeSystemFiles) {
                        $fileOptions['File'] = $true
                    }
                    
                    $files = Get-ChildItem @fileOptions | Where-Object {
                        -not $_.PSIsContainer -and
                        ($IncludeSystemFiles -or (-not $_.Attributes.HasFlag([System.IO.FileAttributes]::System) -and -not $_.Attributes.HasFlag([System.IO.FileAttributes]::Hidden)))
                    }
                    
                    foreach ($file in $files) {
                        $foundItems += @{
                            Path = $file.FullName
                            Name = $file.Name
                            Type = "File"
                            Size = $file.Length
                            LastModified = $file.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                            Error = $null
                        }
                    }
                }
                
                # Search for folders
                if ($SearchType -eq "Folder" -or $SearchType -eq "Both") {
                    $folderOptions = $searchOptions.Clone()
                    if (-not $IncludeSystemFiles) {
                        $folderOptions['Directory'] = $true
                    }
                    
                    $folders = Get-ChildItem @folderOptions | Where-Object {
                        $_.PSIsContainer -and
                        ($IncludeSystemFiles -or (-not $_.Attributes.HasFlag([System.IO.FileAttributes]::System) -and -not $_.Attributes.HasFlag([System.IO.FileAttributes]::Hidden)))
                    }
                    
                    foreach ($folder in $folders) {
                        $foundItems += @{
                            Path = $folder.FullName
                            Name = $folder.Name
                            Type = "Folder"
                            Size = $null
                            LastModified = $folder.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                            Error = $null
                        }
                    }
                }
            }
            catch {
                $foundItems += @{
                    Path = $SearchPath
                    Name = "N/A"
                    Type = "Error"
                    Size = $null
                    LastModified = "N/A"
                    Error = $_.Exception.Message
                }
            }
            
            return $foundItems
        }
        
        # Execute search remotely
        $invokeParams = @{
            ComputerName = $Computer
            ScriptBlock = $searchScript
            ArgumentList = @($Path, $Pattern, $Type, $Ext, $Recursive, $Depth, $IncludeSystem)
            ErrorAction = "Stop"
        }
        
        if ($Cred) {
            $invokeParams['Credential'] = $Cred
        }
        
        $searchResults = Invoke-Command @invokeParams
        
        # Format results
        foreach ($item in $searchResults) {
            $result = [PSCustomObject]@{
                ComputerName = $Computer
                Path = $item.Path
                Name = $item.Name
                Type = $item.Type
                Size = $item.Size
                SizeMB = if ($item.Size) { [math]::Round($item.Size / 1MB, 2) } else { $null }
                LastModified = $item.LastModified
                Status = "Found"
                Error = $item.Error
            }
            $results += $result
        }
    }
    catch {
        $result = [PSCustomObject]@{
            ComputerName = $Computer
            Path = "N/A"
            Name = "N/A"
            Type = "Error"
            Size = $null
            SizeMB = $null
            LastModified = "N/A"
            Status = "Error"
            Error = $_.Exception.Message
        }
        $results += $result
    }
    
    # If no results and no error, add a "not found" entry
    if ($results.Count -eq 0 -and -not ($results | Where-Object { $_.Status -eq "Error" -or $_.Status -eq "Offline" })) {
        $result = [PSCustomObject]@{
            ComputerName = $Computer
            Path = $Path
            Name = "N/A"
            Type = "Not Found"
            Size = $null
            SizeMB = $null
            LastModified = "N/A"
            Status = "Not Found"
            Error = "No matching files or folders found"
        }
        $results += $result
    }
    
    return $results
}

# Main execution
Write-Host "Remote File/Folder Search Tool" -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor Cyan
Write-Host ""

# Collect computer names
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
                $domainComputers = Get-ADComputer -Filter * -Properties Name | Select-Object -ExpandProperty Name
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

if ($ComputerList) {
    if (Test-Path $ComputerList) {
        Write-Host "Reading computer list from: $ComputerList" -ForegroundColor Yellow
        $computers += Get-Content $ComputerList | Where-Object { $_.Trim() -ne "" } | ForEach-Object { $_.Trim() }
    }
    else {
        Write-Error "Computer list file not found: $ComputerList"
        exit 1
    }
}

if ($ComputerName) {
    $computers += $ComputerName
}

# Remove duplicates
$computers = $computers | Select-Object -Unique

if ($computers.Count -eq 0) {
    Write-Error "No computers specified. Use -ComputerList, -ComputerName, or -Domain parameter."
    exit 1
}

# Build search description
$searchDesc = "Searching for "
if ($Extension) {
    $searchDesc += "files with extension: .$Extension"
} else {
    $searchDesc += "pattern: $SearchPattern"
}
$searchDesc += " (Type: $SearchType) in $SearchPath"

Write-Host $searchDesc -ForegroundColor Yellow
Write-Host "Found $($computers.Count) unique computer(s) to search" -ForegroundColor Green
if ($Recurse) {
    Write-Host "Recursive search: ENABLED" -ForegroundColor Cyan
}
Write-Host ""

# Search each computer
$allResults = @()
$total = $computers.Count
$current = 0

foreach ($computer in $computers) {
    $current++
    Write-Progress -Activity "Searching Files/Folders" -Status "Processing $computer ($current of $total)" -PercentComplete (($current / $total) * 100)
    
    Write-Host "[$current/$total] Searching $computer..." -NoNewline
    
    $results = Search-FileRemote -Computer $computer -Path $SearchPath -Pattern $SearchPattern -Type $SearchType -Ext $Extension -Cred $Credential -Recursive $Recurse.IsPresent -Depth $MaxDepth -IncludeSystem $IncludeSystemFiles.IsPresent
    $allResults += $results
    
    $foundCount = ($results | Where-Object { $_.Status -eq "Found" }).Count
    $fileCount = ($results | Where-Object { $_.Type -eq "File" }).Count
    $folderCount = ($results | Where-Object { $_.Type -eq "Folder" }).Count
    
    if ($foundCount -gt 0) {
        Write-Host " Found $foundCount item(s) ($fileCount file(s), $folderCount folder(s))" -ForegroundColor Green
    }
    else {
        $statusColor = switch ($results[0].Status) {
            "Offline" { "Red" }
            "Error" { "Red" }
            "Not Found" { "Yellow" }
            default { "Gray" }
        }
        Write-Host " $($results[0].Status)" -ForegroundColor $statusColor
        if ($results[0].Error) {
            Write-Host "  Error: $($results[0].Error)" -ForegroundColor Red
        }
    }
}

Write-Progress -Activity "Searching Files/Folders" -Completed

# Display summary
Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "========" -ForegroundColor Cyan
$totalFound = ($allResults | Where-Object { $_.Status -eq "Found" }).Count
$totalFiles = ($allResults | Where-Object { $_.Type -eq "File" }).Count
$totalFolders = ($allResults | Where-Object { $_.Type -eq "Folder" }).Count
$offline = ($allResults | Where-Object { $_.Status -eq "Offline" }).Count
$errors = ($allResults | Where-Object { $_.Status -eq "Error" }).Count
$notFound = ($allResults | Where-Object { $_.Status -eq "Not Found" }).Count

Write-Host "Total Found:       $totalFound" -ForegroundColor Green
Write-Host "Files:             $totalFiles" -ForegroundColor Cyan
Write-Host "Folders:           $totalFolders" -ForegroundColor Yellow
Write-Host "Not Found:         $notFound" -ForegroundColor Gray
Write-Host "Offline:           $offline" -ForegroundColor Red
Write-Host "Errors:            $errors" -ForegroundColor Red
Write-Host ""

# Calculate total size
$totalSize = ($allResults | Where-Object { $_.Size -ne $null } | Measure-Object -Property Size -Sum).Sum
if ($totalSize) {
    $totalSizeGB = [math]::Round($totalSize / 1GB, 2)
    Write-Host "Total Size:        $totalSizeGB GB" -ForegroundColor Cyan
    Write-Host ""
}

# Export to CSV
try {
    $allResults | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
    Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
}
catch {
    Write-Error "Failed to export results: $($_.Exception.Message)"
}

# Display results table (first 20)
Write-Host ""
Write-Host "Sample Results (first 20):" -ForegroundColor Cyan
Write-Host "===========================" -ForegroundColor Cyan
$allResults | Where-Object { $_.Status -eq "Found" } | Select-Object -First 20 | Format-Table -AutoSize ComputerName, Path, Type, SizeMB, LastModified

