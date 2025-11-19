<#
.SYNOPSIS
    Retrieves shared folder permissions for all file shares in the domain.

.DESCRIPTION
    This script queries all computers in the domain to find file shares and their
    permissions, listing all users and groups that have access.

.PARAMETER ComputerList
    Path to a text file containing computer names (one per line).

.PARAMETER ComputerName
    Single computer name or array of computer names to query.

.PARAMETER Domain
    Query all computers in the specified domain (default: current domain).

.PARAMETER OutputFile
    Path to CSV file where results will be exported. Default: SharePermissionsReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication (optional).

.PARAMETER ShareName
    Filter by specific share name (supports wildcards).

.EXAMPLE
    .\Get-SharePermissions.ps1 -ComputerList "computers.txt"
    
.EXAMPLE
    .\Get-SharePermissions.ps1 -ComputerName "PC01","PC02","PC03"
    
.EXAMPLE
    .\Get-SharePermissions.ps1 -Domain "contoso.com" -ShareName "Data*"
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
    [string]$OutputFile = "SharePermissionsReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [string]$ShareName = "*"
)

# Function to get share permissions from a single computer
function Get-SharePermissions {
    param(
        [string]$Computer,
        [string]$ShareFilter,
        [System.Management.Automation.PSCredential]$Cred
    )
    
    $results = @()
    
    try {
        # Test connectivity first
        if (-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            $result = [PSCustomObject]@{
                ComputerName = $Computer
                ShareName = "N/A"
                SharePath = "N/A"
                Account = "N/A"
                Permission = "N/A"
                AccessControlType = "N/A"
                Status = "Offline"
                Error = "Computer is not reachable"
            }
            $results += $result
            return $results
        }
        
        # Use PowerShell remoting to get shares and permissions
        $scriptBlock = {
            param($ShareFilter)
            
            $shareResults = @()
            
            try {
                # Get all shares
                $shares = Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -like $ShareFilter }
                
                if (-not $shares) {
                    # Try WMI method as fallback
                    $wmiShares = Get-WmiObject -Class Win32_Share -ErrorAction SilentlyContinue | Where-Object { $_.Name -like $ShareFilter }
                    foreach ($share in $wmiShares) {
                        $shareResults += @{
                            Name = $share.Name
                            Path = $share.Path
                            Description = $share.Description
                            Type = "WMI"
                        }
                    }
                }
                else {
                    foreach ($share in $shares) {
                        $shareResults += @{
                            Name = $share.Name
                            Path = $share.Path
                            Description = $share.Description
                            Type = "SMB"
                        }
                    }
                }
                
                # Get permissions for each share
                foreach ($shareInfo in $shareResults) {
                    try {
                        $shareName = $shareInfo.Name
                        $sharePath = $shareInfo.Path
                        
                        # Get SMB share access
                        try {
                            $access = Get-SmbShareAccess -Name $shareName -ErrorAction SilentlyContinue
                            foreach ($acc in $access) {
                                $shareResults += @{
                                    ShareName = $shareName
                                    SharePath = $sharePath
                                    Account = $acc.AccountName
                                    Permission = $acc.AccessRight
                                    AccessControlType = "Allow"
                                    Method = "SMB"
                                }
                            }
                        }
                        catch {
                            # Try NTFS permissions on the path
                            if ($sharePath -and (Test-Path $sharePath)) {
                                $acl = Get-Acl -Path $sharePath -ErrorAction SilentlyContinue
                                foreach ($ace in $acl.Access) {
                                    $shareResults += @{
                                        ShareName = $shareName
                                        SharePath = $sharePath
                                        Account = $ace.IdentityReference.Value
                                        Permission = $ace.FileSystemRights.ToString()
                                        AccessControlType = $ace.AccessControlType.ToString()
                                        Method = "NTFS"
                                    }
                                }
                            }
                        }
                    }
                    catch {
                        # Continue with next share
                    }
                }
            }
            catch {
                $shareResults += @{
                    ShareName = "Error"
                    SharePath = "N/A"
                    Account = "N/A"
                    Permission = "N/A"
                    AccessControlType = "N/A"
                    Method = "Error"
                    Error = $_.Exception.Message
                }
            }
            
            return $shareResults
        }
        
        $invokeParams = @{
            ComputerName = $Computer
            ScriptBlock = $scriptBlock
            ArgumentList = @($ShareFilter)
            ErrorAction = "Stop"
        }
        
        if ($Cred) {
            $invokeParams['Credential'] = $Cred
        }
        
        $shareData = Invoke-Command @invokeParams
        
        # Filter and format results
        foreach ($share in $shareData) {
            if ($share.ShareName) {
                $result = [PSCustomObject]@{
                    ComputerName = $Computer
                    ShareName = $share.ShareName
                    SharePath = if ($share.SharePath) { $share.SharePath } else { "N/A" }
                    Account = if ($share.Account) { $share.Account } else { "N/A" }
                    Permission = if ($share.Permission) { $share.Permission } else { "N/A" }
                    AccessControlType = if ($share.AccessControlType) { $share.AccessControlType } else { "N/A" }
                    Status = "Success"
                    Error = if ($share.Error) { $share.Error } else { $null }
                }
                $results += $result
            }
        }
        
        # If no shares found, try WMI method
        if ($results.Count -eq 0) {
            try {
                $wmiParams = @{
                    ComputerName = $Computer
                    Class = "Win32_Share"
                    Filter = "Type = 0"
                    ErrorAction = "Stop"
                }
                
                if ($Cred) {
                    $wmiParams['Credential'] = $Cred
                }
                
                $wmiShares = Get-CimInstance @wmiParams
                
                foreach ($share in $wmiShares) {
                    if ($share.Name -like $ShareFilter) {
                        $result = [PSCustomObject]@{
                            ComputerName = $Computer
                            ShareName = $share.Name
                            SharePath = $share.Path
                            Account = "N/A (WMI - Permissions require path access)"
                            Permission = "N/A"
                            AccessControlType = "N/A"
                            Status = "Share Found"
                            Error = "Use Get-NTFSAccess on share path for detailed permissions"
                        }
                        $results += $result
                    }
                }
            }
            catch {
                # No shares found
            }
        }
    }
    catch {
        $result = [PSCustomObject]@{
            ComputerName = $Computer
            ShareName = "N/A"
            SharePath = "N/A"
            Account = "N/A"
            Permission = "N/A"
            AccessControlType = "N/A"
            Status = "Error"
            Error = $_.Exception.Message
        }
        $results += $result
    }
    
    # If no results, add a default entry
    if ($results.Count -eq 0) {
        $result = [PSCustomObject]@{
            ComputerName = $Computer
            ShareName = "N/A"
            SharePath = "N/A"
            Account = "N/A"
            Permission = "N/A"
            AccessControlType = "N/A"
            Status = "No Shares Found"
            Error = "No file shares found or accessible"
        }
        $results += $result
    }
    
    return $results
}

# Main execution
Write-Host "Shared Folder Permissions Query Tool" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
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

Write-Host "Share Filter: $ShareName" -ForegroundColor Yellow
Write-Host "Found $($computers.Count) unique computer(s) to query" -ForegroundColor Green
Write-Host ""

# Query each computer
$allResults = @()
$total = $computers.Count
$current = 0

foreach ($computer in $computers) {
    $current++
    Write-Progress -Activity "Querying Share Permissions" -Status "Processing $computer ($current of $total)" -PercentComplete (($current / $total) * 100)
    
    Write-Host "[$current/$total] Querying $computer..." -NoNewline
    
    $results = Get-SharePermissions -Computer $computer -ShareFilter $ShareName -Cred $Credential
    $allResults += $results
    
    $shareCount = ($results | Where-Object { $_.Status -eq "Success" -or $_.Status -eq "Share Found" } | Select-Object -Unique ShareName).Count
    $permCount = ($results | Where-Object { $_.Status -eq "Success" -and $_.Account -ne "N/A" }).Count
    
    if ($shareCount -gt 0) {
        Write-Host " Found $shareCount share(s), $permCount permission(s)" -ForegroundColor Green
        foreach ($share in ($results | Where-Object { $_.Status -eq "Success" -or $_.Status -eq "Share Found" } | Select-Object -Unique ShareName)) {
            Write-Host "  - $($share.ShareName)" -ForegroundColor Gray
        }
    }
    else {
        $statusColor = switch ($results[0].Status) {
            "Offline" { "Red" }
            "Error" { "Red" }
            "No Shares Found" { "Yellow" }
            default { "Gray" }
        }
        Write-Host " $($results[0].Status)" -ForegroundColor $statusColor
        if ($results[0].Error) {
            Write-Host "  Error: $($results[0].Error)" -ForegroundColor Red
        }
    }
}

Write-Progress -Activity "Querying Share Permissions" -Completed

# Display summary
Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "========" -ForegroundColor Cyan
$totalShares = ($allResults | Where-Object { $_.Status -eq "Success" -or $_.Status -eq "Share Found" } | Select-Object -Unique ComputerName, ShareName).Count
$totalPermissions = ($allResults | Where-Object { $_.Status -eq "Success" -and $_.Account -ne "N/A" }).Count
$uniqueAccounts = ($allResults | Where-Object { $_.Account -ne "N/A" } | Select-Object -Unique Account).Count
$offline = ($allResults | Where-Object { $_.Status -eq "Offline" }).Count
$errors = ($allResults | Where-Object { $_.Status -eq "Error" }).Count
$noShares = ($allResults | Where-Object { $_.Status -eq "No Shares Found" }).Count

Write-Host "Total Shares:       $totalShares" -ForegroundColor Green
Write-Host "Total Permissions:  $totalPermissions" -ForegroundColor Cyan
Write-Host "Unique Accounts:   $uniqueAccounts" -ForegroundColor Yellow
Write-Host "Offline:            $offline" -ForegroundColor Red
Write-Host "Errors:             $errors" -ForegroundColor Red
Write-Host "No Shares:          $noShares" -ForegroundColor Gray
Write-Host ""

# Export to CSV
try {
    $allResults | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
    Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
}
catch {
    Write-Error "Failed to export results: $($_.Exception.Message)"
}

# Display results table
Write-Host ""
Write-Host "Sample Results (first 20):" -ForegroundColor Cyan
Write-Host "==========================" -ForegroundColor Cyan
$allResults | Where-Object { $_.Status -eq "Success" } | Select-Object -First 20 | Format-Table -AutoSize ComputerName, ShareName, Account, Permission

