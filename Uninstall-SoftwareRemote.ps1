<#
.SYNOPSIS
    Uninstalls software from a list of remote computers.

.DESCRIPTION
    This script uninstalls software from multiple computers remotely.
    It supports MSI and EXE uninstallers with silent removal options.

.PARAMETER ComputerList
    Path to a text file containing computer names (one per line).

.PARAMETER ComputerName
    Single computer name or array of computer names to process.

.PARAMETER ApplicationName
    Name of the application to uninstall (supports wildcards, e.g., "Adobe*", "*Java*").

.PARAMETER ProductCode
    MSI Product Code (GUID) for MSI-based applications (optional).

.PARAMETER UninstallString
    Custom uninstall command/string (optional).

.PARAMETER OutputFile
    Path to CSV file where results will be exported. Default: UninstallReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication (optional).

.PARAMETER Force
    Force uninstall even if application is in use (may require restart).

.PARAMETER WhatIf
    Show what would be uninstalled without actually uninstalling.

.EXAMPLE
    .\Uninstall-SoftwareRemote.ps1 -ComputerList "computers.txt" -ApplicationName "Adobe Reader"
    
.EXAMPLE
    .\Uninstall-SoftwareRemote.ps1 -ComputerName "PC01","PC02" -ApplicationName "*Java*" -Force
    
.EXAMPLE
    .\Uninstall-SoftwareRemote.ps1 -ComputerList "computers.txt" -ProductCode "{GUID-HERE}"
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ComputerName,
    
    [Parameter(Mandatory=$false)]
    [string]$ApplicationName,
    
    [Parameter(Mandatory=$false)]
    [string]$ProductCode,
    
    [Parameter(Mandatory=$false)]
    [string]$UninstallString,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "UninstallReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force,
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

# Function to uninstall software on a single computer
function Uninstall-SoftwareRemote {
    param(
        [string]$Computer,
        [string]$AppName,
        [string]$ProdCode,
        [string]$UninstallCmd,
        [System.Management.Automation.PSCredential]$Cred,
        [bool]$ForceUninstall,
        [bool]$WhatIfMode
    )
    
    $result = [PSCustomObject]@{
        ComputerName = $Computer
        ApplicationName = "N/A"
        ProductCode = "N/A"
        Status = "Unknown"
        ExitCode = $null
        StartTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        EndTime = $null
        Error = $null
    }
    
    try {
        # Test connectivity first
        if (-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            $result.Status = "Offline"
            $result.Error = "Computer is not reachable"
            $result.EndTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            return $result
        }
        
        # Build uninstall script block
        $uninstallScript = {
            param(
                [string]$AppName,
                [string]$ProdCode,
                [string]$UninstallCmd,
                [bool]$Force,
                [bool]$WhatIf
            )
            
            $output = @{
                ApplicationName = "N/A"
                ProductCode = "N/A"
                ExitCode = -1
                Error = $null
            }
            
            try {
                # Method 1: Use ProductCode (MSI)
                if ($ProdCode) {
                    $output.ProductCode = $ProdCode
                    $output.ApplicationName = "MSI Product: $ProdCode"
                    
                    if (-not $WhatIf) {
                        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/x", "`"$ProdCode`"", "/qn", "/norestart" -Wait -PassThru -NoNewWindow
                        $output.ExitCode = $process.ExitCode
                        
                        if ($output.ExitCode -ne 0) {
                            $output.Error = "MSI uninstall failed with exit code: $($output.ExitCode)"
                        }
                    } else {
                        $output.ExitCode = 0
                        $output.Error = "WhatIf - Would uninstall"
                    }
                }
                # Method 2: Use ApplicationName (search registry)
                elseif ($AppName) {
                    $found = $false
                    $regPaths = @(
                        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
                        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
                    )
                    
                    foreach ($regPath in $regPaths) {
                        $apps = Get-ItemProperty $regPath -ErrorAction SilentlyContinue | Where-Object {
                            $_.DisplayName -like $AppName
                        }
                        
                        foreach ($app in $apps) {
                            $found = $true
                            $output.ApplicationName = $app.DisplayName
                            
                            if ($app.PSChildName -match '^{[A-F0-9-]+}$') {
                                # MSI Product Code
                                $output.ProductCode = $app.PSChildName
                                
                                if (-not $WhatIf) {
                                    $process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/x", "`"$($app.PSChildName)`"", "/qn", "/norestart" -Wait -PassThru -NoNewWindow
                                    $output.ExitCode = $process.ExitCode
                                    
                                    if ($output.ExitCode -ne 0) {
                                        $output.Error = "MSI uninstall failed with exit code: $($output.ExitCode)"
                                    }
                                } else {
                                    $output.ExitCode = 0
                                    $output.Error = "WhatIf - Would uninstall"
                                }
                            }
                            elseif ($app.UninstallString) {
                                # EXE uninstaller
                                $uninstallStr = $app.UninstallString
                                
                                # Extract executable and arguments
                                if ($uninstallStr -match '^"([^"]+)"\s*(.*)$') {
                                    $exe = $matches[1]
                                    $args = $matches[2]
                                }
                                elseif ($uninstallStr -match '^([^\s]+)\s*(.*)$') {
                                    $exe = $matches[1]
                                    $args = $matches[2]
                                }
                                else {
                                    $exe = $uninstallStr
                                    $args = ""
                                }
                                
                                # Add silent flags if not present
                                if ($args -notmatch '/S|/SILENT|/QUIET|/VERYSILENT') {
                                    if ($exe -like "*unins*.exe") {
                                        $args = "/SILENT " + $args
                                    }
                                    else {
                                        $args = "/S " + $args
                                    }
                                }
                                
                                if (-not $WhatIf) {
                                    $process = Start-Process -FilePath $exe -ArgumentList $args -Wait -PassThru -NoNewWindow
                                    $output.ExitCode = $process.ExitCode
                                    
                                    if ($output.ExitCode -ne 0) {
                                        $output.Error = "Uninstall failed with exit code: $($output.ExitCode)"
                                    }
                                } else {
                                    $output.ExitCode = 0
                                    $output.Error = "WhatIf - Would uninstall"
                                }
                            }
                            
                            break
                        }
                        
                        if ($found) { break }
                    }
                    
                    if (-not $found) {
                        $output.Error = "Application not found: $AppName"
                        $output.ExitCode = -1
                    }
                }
                # Method 3: Use custom uninstall string
                elseif ($UninstallCmd) {
                    $output.ApplicationName = "Custom Uninstall"
                    
                    if (-not $WhatIf) {
                        $parts = $UninstallCmd -split '\s+', 2
                        $exe = $parts[0]
                        $args = if ($parts.Count -gt 1) { $parts[1] } else { "" }
                        
                        $process = Start-Process -FilePath $exe -ArgumentList $args -Wait -PassThru -NoNewWindow
                        $output.ExitCode = $process.ExitCode
                        
                        if ($output.ExitCode -ne 0) {
                            $output.Error = "Custom uninstall failed with exit code: $($output.ExitCode)"
                        }
                    } else {
                        $output.ExitCode = 0
                        $output.Error = "WhatIf - Would uninstall"
                    }
                }
                else {
                    $output.Error = "No uninstall method specified"
                }
            }
            catch {
                $output.Error = $_.Exception.Message
                $output.ExitCode = -1
            }
            
            return $output
        }
        
        # Execute uninstall remotely
        $invokeParams = @{
            ComputerName = $Computer
            ScriptBlock = $uninstallScript
            ArgumentList = @($AppName, $ProdCode, $UninstallCmd, $ForceUninstall, $WhatIfMode)
            ErrorAction = "Stop"
        }
        
        if ($Cred) {
            $invokeParams['Credential'] = $Cred
        }
        
        Write-Host "  Executing uninstall on $Computer..." -ForegroundColor Gray
        
        $uninstallResult = Invoke-Command @invokeParams
        
        $result.ApplicationName = $uninstallResult.ApplicationName
        $result.ProductCode = $uninstallResult.ProductCode
        $result.ExitCode = $uninstallResult.ExitCode
        $result.Error = $uninstallResult.Error
        $result.EndTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        
        # Determine status based on exit code
        if ($uninstallResult.ExitCode -eq 0) {
            $result.Status = if ($WhatIfMode) { "WhatIf - Would Uninstall" } else { "Success" }
        }
        elseif ($uninstallResult.ExitCode -eq 3010 -or $uninstallResult.ExitCode -eq 1641) {
            $result.Status = "Success (Reboot Required)"
        }
        else {
            $result.Status = "Failed"
        }
    }
    catch {
        $result.Status = "Error"
        $result.Error = $_.Exception.Message
        $result.EndTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    return $result
}

# Main execution
Write-Host "Remote Software Uninstall Tool" -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor Cyan
Write-Host ""

# Validate parameters
if (-not $ApplicationName -and -not $ProductCode -and -not $UninstallString) {
    Write-Error "Either ApplicationName, ProductCode, or UninstallString must be specified."
    exit 1
}

# Collect computer names
$computers = @()

if ($ComputerList) {
    if (Test-Path $ComputerList) {
        Write-Host "Reading computer list from: $ComputerList" -ForegroundColor Yellow
        $computers = Get-Content $ComputerList | Where-Object { $_.Trim() -ne "" } | ForEach-Object { $_.Trim() }
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
    Write-Error "No computers specified. Use -ComputerList or -ComputerName parameter."
    exit 1
}

# Build uninstall description
$uninstallDesc = "Uninstalling "
if ($ProductCode) {
    $uninstallDesc += "MSI Product: $ProductCode"
} elseif ($ApplicationName) {
    $uninstallDesc += "Application: $ApplicationName"
} else {
    $uninstallDesc += "Custom: $UninstallString"
}

Write-Host $uninstallDesc -ForegroundColor Yellow
Write-Host "Found $($computers.Count) computer(s) to process" -ForegroundColor Green
if ($Force) {
    Write-Host "Force uninstall: ENABLED" -ForegroundColor Cyan
}
if ($WhatIf) {
    Write-Host "MODE: WHATIF (no software will be uninstalled)" -ForegroundColor Yellow
}
Write-Host ""

# Confirm action
if (-not $WhatIf -and -not $PSCmdlet.ShouldProcess("Uninstall software on $($computers.Count) computer(s)", "This will uninstall software on remote computers. Continue?")) {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
    exit 0
}

# Process each computer
$results = @()
$total = $computers.Count
$current = 0

foreach ($computer in $computers) {
    $current++
    Write-Progress -Activity "Uninstalling Software" -Status "Processing $computer ($current of $total)" -PercentComplete (($current / $total) * 100)
    
    Write-Host "[$current/$total] Processing $computer..." -NoNewline
    
    $result = Uninstall-SoftwareRemote -Computer $computer -AppName $ApplicationName -ProdCode $ProductCode -UninstallCmd $UninstallString -Cred $Credential -ForceUninstall $Force.IsPresent -WhatIfMode $WhatIf.IsPresent
    
    $results += $result
    
    $statusColor = switch ($result.Status) {
        "Success" { "Green" }
        "Success (Reboot Required)" { "Yellow" }
        "WhatIf - Would Uninstall" { "Yellow" }
        "Failed" { "Red" }
        "Offline" { "Red" }
        "Error" { "Red" }
        default { "Gray" }
    }
    
    Write-Host " $($result.Status)" -ForegroundColor $statusColor
    if ($result.ExitCode -ne $null) {
        Write-Host "  Exit Code: $($result.ExitCode)" -ForegroundColor Gray
    }
    if ($result.Error) {
        Write-Host "  Error: $($result.Error)" -ForegroundColor Red
    }
}

Write-Progress -Activity "Uninstalling Software" -Completed

# Display summary
Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "========" -ForegroundColor Cyan
$success = ($results | Where-Object { $_.Status -eq "Success" }).Count
$rebootRequired = ($results | Where-Object { $_.Status -eq "Success (Reboot Required)" }).Count
$failed = ($results | Where-Object { $_.Status -eq "Failed" }).Count
$offline = ($results | Where-Object { $_.Status -eq "Offline" }).Count
$errors = ($results | Where-Object { $_.Status -eq "Error" }).Count
$whatIf = ($results | Where-Object { $_.Status -like "WhatIf*" }).Count

Write-Host "Success:           $success" -ForegroundColor Green
Write-Host "Reboot Required:   $rebootRequired" -ForegroundColor Yellow
Write-Host "WhatIf:            $whatIf" -ForegroundColor Yellow
Write-Host "Failed:            $failed" -ForegroundColor Red
Write-Host "Offline:           $offline" -ForegroundColor Red
Write-Host "Errors:            $errors" -ForegroundColor Red
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
$results | Format-Table -AutoSize ComputerName, ApplicationName, Status, ExitCode, Error

