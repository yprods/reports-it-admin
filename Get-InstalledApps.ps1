<#
.SYNOPSIS
    Gets all installed applications from remote computers.

.DESCRIPTION
    This script retrieves a list of all installed applications from remote computers.

.PARAMETER ComputerList
    Path to text file with computer names.

.PARAMETER ComputerName
    Single or array of computer names.

.PARAMETER OutputFile
    Path to CSV file. Default: InstalledAppsReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication.

.PARAMETER IncludeUpdates
    Include Windows updates in the list (default: false).

.EXAMPLE
    .\Get-InstalledApps.ps1 -ComputerList "computers.txt"
    
.EXAMPLE
    .\Get-InstalledApps.ps1 -ComputerName "PC01","PC02" -IncludeUpdates
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ComputerName,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "InstalledAppsReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeUpdates
)

function Get-InstalledApps {
    param([string]$Computer, [bool]$IncludeUpdates, [System.Management.Automation.PSCredential]$Cred)
    
    $scriptBlock = {
        param([bool]$IncludeUpdates)
        
        $apps = @()
        
        try {
            # Method 1: Win32_Product (slower but comprehensive)
            $products = Get-CimInstance -ClassName Win32_Product -ErrorAction SilentlyContinue
            foreach ($product in $products) {
                if (-not $IncludeUpdates -and $product.Name -like "*Update*" -and $product.Name -like "*KB*") {
                    continue
                }
                
                $apps += @{
                    Name = $product.Name
                    Version = $product.Version
                    Vendor = $product.Vendor
                    InstallDate = $product.InstallDate
                    Source = "Win32_Product"
                }
            }
            
            # Method 2: Registry (faster, more common)
            $regPaths = @(
                "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
                "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
            )
            
            foreach ($regPath in $regPaths) {
                $regApps = Get-ItemProperty $regPath -ErrorAction SilentlyContinue
                foreach ($app in $regApps) {
                    if ($app.DisplayName -and $app.DisplayName -ne "") {
                        if (-not $IncludeUpdates -and ($app.DisplayName -like "*Update*" -or $app.DisplayName -like "*KB*")) {
                            continue
                        }
                        
                        $apps += @{
                            Name = $app.DisplayName
                            Version = if ($app.DisplayVersion) { $app.DisplayVersion } else { "N/A" }
                            Vendor = if ($app.Publisher) { $app.Publisher } else { "N/A" }
                            InstallDate = if ($app.InstallDate) { $app.InstallDate } else { "N/A" }
                            Source = "Registry"
                        }
                    }
                }
            }
            
            # Remove duplicates
            $uniqueApps = $apps | Sort-Object Name -Unique
            return $uniqueApps
        }
        catch {
            return @(@{
                Name = "Error"
                Version = "N/A"
                Vendor = "N/A"
                InstallDate = "N/A"
                Source = "Error"
                Error = $_.Exception.Message
            })
        }
    }
    
    $results = @()
    
    try {
        if (-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            return @([PSCustomObject]@{
                ComputerName = $Computer
                AppName = "N/A"
                Version = "N/A"
                Vendor = "N/A"
                InstallDate = "N/A"
                Status = "Offline"
            })
        }
        
        $invokeParams = @{
            ComputerName = $Computer
            ScriptBlock = $scriptBlock
            ArgumentList = @($IncludeUpdates)
        }
        if ($Cred) { $invokeParams['Credential'] = $Cred }
        
        $apps = Invoke-Command @invokeParams
        
        foreach ($app in $apps) {
            $results += [PSCustomObject]@{
                ComputerName = $Computer
                AppName = $app.Name
                Version = $app.Version
                Vendor = $app.Vendor
                InstallDate = $app.InstallDate
                Source = $app.Source
                Status = "Success"
            }
        }
    }
    catch {
        $results += [PSCustomObject]@{
            ComputerName = $Computer
            AppName = "N/A"
            Version = "N/A"
            Vendor = "N/A"
            InstallDate = "N/A"
            Status = "Error"
            Error = $_.Exception.Message
        }
    }
    
    return $results
}

# Main execution
Write-Host "Installed Applications Query Tool" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan
Write-Host ""

$computers = @()
if ($ComputerList -and (Test-Path $ComputerList)) {
    $computers = Get-Content $ComputerList | Where-Object { $_.Trim() -ne "" }
}
if ($ComputerName) {
    $computers += $ComputerName
}
$computers = $computers | Select-Object -Unique

if ($computers.Count -eq 0) {
    Write-Error "No computers specified."
    exit 1
}

Write-Host "Querying $($computers.Count) computer(s)..." -ForegroundColor Yellow
if ($IncludeUpdates) {
    Write-Host "Including Windows Updates" -ForegroundColor Yellow
}
Write-Host ""

$allResults = @()
foreach ($computer in $computers) {
    Write-Host "Querying $computer..." -NoNewline
    $results = Get-InstalledApps -Computer $computer -IncludeUpdates $IncludeUpdates.IsPresent -Cred $Credential
    $allResults += $results
    
    $appCount = ($results | Where-Object { $_.Status -eq "Success" }).Count
    Write-Host " Found $appCount application(s)" -ForegroundColor Green
}

$allResults | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host ""
Write-Host "Results exported to: $OutputFile" -ForegroundColor Green

Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
$totalApps = ($allResults | Where-Object { $_.Status -eq "Success" }).Count
$uniqueApps = ($allResults | Where-Object { $_.Status -eq "Success" } | Select-Object -Unique AppName).Count
Write-Host "Total Applications: $totalApps" -ForegroundColor Green
Write-Host "Unique Applications: $uniqueApps" -ForegroundColor Cyan

# Show top applications
Write-Host ""
Write-Host "Top 10 Most Common Applications:" -ForegroundColor Cyan
$allResults | Where-Object { $_.Status -eq "Success" } | Group-Object -Property AppName | Sort-Object Count -Descending | Select-Object -First 10 | Format-Table -AutoSize Count, Name

