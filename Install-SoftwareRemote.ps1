<#
.SYNOPSIS
    Installs software on a list of remote computers using PowerShell remoting.

.DESCRIPTION
    This script reads a list of computer names and installs software on each computer
    remotely. It supports MSI, EXE, and other installer types with silent installation options.

.PARAMETER ComputerList
    Path to a text file containing computer names (one per line).

.PARAMETER ComputerName
    Single computer name or array of computer names to process.

.PARAMETER InstallerPath
    Path to the installer file (MSI, EXE, etc.). Can be a network path (\\server\share) or local path.

.PARAMETER InstallerType
    Type of installer: MSI, EXE, or AUTO (default: AUTO - auto-detect from file extension).

.PARAMETER InstallArgs
    Additional installation arguments (e.g., "/S" for silent, "/qn" for MSI silent).

.PARAMETER OutputFile
    Path to CSV file where results will be exported. Default: SoftwareInstallReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication (optional).

.PARAMETER CopyToLocal
    Copy installer to local temp folder on remote computer before installation (recommended for network paths).

.PARAMETER WaitForCompletion
    Wait for installation to complete before proceeding to next computer (default: true).

.PARAMETER Timeout
    Timeout in seconds for each installation (default: 600 seconds / 10 minutes).

.EXAMPLE
    .\Install-SoftwareRemote.ps1 -ComputerList "computers.txt" -InstallerPath "\\server\share\software.msi" -InstallerType MSI
    
.EXAMPLE
    .\Install-SoftwareRemote.ps1 -ComputerName "PC01","PC02" -InstallerPath "C:\installers\app.exe" -InstallerType EXE -InstallArgs "/S"
    
.EXAMPLE
    .\Install-SoftwareRemote.ps1 -ComputerList "computers.txt" -InstallerPath "\\server\share\setup.exe" -CopyToLocal -Timeout 900
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ComputerName,
    
    [Parameter(Mandatory=$true)]
    [string]$InstallerPath,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("MSI","EXE","AUTO")]
    [string]$InstallerType = "AUTO",
    
    [Parameter(Mandatory=$false)]
    [string]$InstallArgs = "",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "SoftwareInstallReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [switch]$CopyToLocal,
    
    [Parameter(Mandatory=$false)]
    [switch]$WaitForCompletion = $true,
    
    [Parameter(Mandatory=$false)]
    [int]$Timeout = 600
)

# Function to install software on a single computer
function Install-SoftwareRemote {
    param(
        [string]$Computer,
        [string]$Installer,
        [string]$Type,
        [string]$Args,
        [System.Management.Automation.PSCredential]$Cred,
        [bool]$CopyLocal,
        [bool]$Wait,
        [int]$TimeoutSeconds
    )
    
    $result = [PSCustomObject]@{
        ComputerName = $Computer
        InstallerPath = $Installer
        InstallerType = $Type
        Status = "Unknown"
        ExitCode = $null
        StartTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        EndTime = $null
        Duration = $null
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
        
        # Test if WinRM is available
        try {
            $testConnection = Test-WSMan -ComputerName $Computer -ErrorAction Stop
        }
        catch {
            $result.Status = "WinRM Not Available"
            $result.Error = "WinRM is not enabled on target computer. Enable with: Enable-PSRemoting"
            $result.EndTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            return $result
        }
        
        # Determine installer type if AUTO
        $detectedType = $Type
        if ($Type -eq "AUTO") {
            $extension = [System.IO.Path]::GetExtension($Installer).ToLower()
            switch ($extension) {
                ".msi" { $detectedType = "MSI" }
                ".exe" { $detectedType = "EXE" }
                default { 
                    $result.Status = "Error"
                    $result.Error = "Cannot auto-detect installer type from extension: $extension"
                    $result.EndTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    return $result
                }
            }
        }
        $result.InstallerType = $detectedType
        
        # Build installation script block
        $installScript = {
            param(
                [string]$InstallerPath,
                [string]$InstallerType,
                [string]$InstallArgs,
                [bool]$CopyToLocal,
                [int]$TimeoutSeconds
            )
            
            $startTime = Get-Date
            $exitCode = -1
            $errorMsg = $null
            
            try {
                # Determine actual installer path
                $actualInstaller = $InstallerPath
                
                # If network path and copy requested, copy to local temp
                if ($CopyToLocal -and ($InstallerPath.StartsWith("\\") -or $InstallerPath.StartsWith("http"))) {
                    $tempPath = Join-Path $env:TEMP ([System.IO.Path]::GetFileName($InstallerPath))
                    Write-Host "Copying installer to: $tempPath"
                    
                    try {
                        Copy-Item -Path $InstallerPath -Destination $tempPath -Force -ErrorAction Stop
                        $actualInstaller = $tempPath
                        Write-Host "Copy successful"
                    }
                    catch {
                        $errorMsg = "Failed to copy installer: $($_.Exception.Message)"
                        throw
                    }
                }
                
                # Verify installer exists
                if (-not (Test-Path $actualInstaller)) {
                    $errorMsg = "Installer file not found: $actualInstaller"
                    throw $errorMsg
                }
                
                # Build installation command based on type
                $processArgs = @()
                $processName = $null
                
                switch ($InstallerType) {
                    "MSI" {
                        $processName = "msiexec.exe"
                        if ($InstallArgs -eq "") {
                            $processArgs = @("/i", "`"$actualInstaller`"", "/qn", "/norestart", "/L*v", "`"$env:TEMP\install.log`"")
                        } else {
                            $processArgs = @("/i", "`"$actualInstaller`"", $InstallArgs, "/L*v", "`"$env:TEMP\install.log`"")
                        }
                    }
                    "EXE" {
                        $processName = $actualInstaller
                        if ($InstallArgs -eq "") {
                            $processArgs = @("/S", "/norestart")
                        } else {
                            $processArgs = $InstallArgs.Split(' ')
                        }
                    }
                }
                
                # Start installation process
                Write-Host "Starting installation: $processName"
                $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo
                $processStartInfo.FileName = $processName
                $processStartInfo.Arguments = $processArgs -join " "
                $processStartInfo.UseShellExecute = $false
                $processStartInfo.RedirectStandardOutput = $true
                $processStartInfo.RedirectStandardError = $true
                $processStartInfo.CreateNoWindow = $true
                
                $process = New-Object System.Diagnostics.Process
                $process.StartInfo = $processStartInfo
                
                Write-Host "Command: $processName $($processStartInfo.Arguments)"
                
                $process.Start() | Out-Null
                
                # Wait for completion with timeout
                $completed = $process.WaitForExit($TimeoutSeconds * 1000)
                
                if (-not $completed) {
                    $process.Kill()
                    $errorMsg = "Installation timed out after $TimeoutSeconds seconds"
                    $exitCode = -2
                } else {
                    $exitCode = $process.ExitCode
                    $stdout = $process.StandardOutput.ReadToEnd()
                    $stderr = $process.StandardError.ReadToEnd()
                    
                    if ($exitCode -ne 0) {
                        $errorMsg = "Installation failed with exit code: $exitCode"
                        if ($stderr) {
                            $errorMsg += " Error: $stderr"
                        }
                    }
                }
                
                # Clean up copied file if applicable
                if ($CopyToLocal -and $actualInstaller -ne $InstallerPath -and (Test-Path $actualInstaller)) {
                    Remove-Item -Path $actualInstaller -Force -ErrorAction SilentlyContinue
                }
            }
            catch {
                $errorMsg = $_.Exception.Message
                $exitCode = -1
            }
            
            $endTime = Get-Date
            $duration = ($endTime - $startTime).TotalSeconds
            
            return @{
                ExitCode = $exitCode
                Error = $errorMsg
                Duration = $duration
                EndTime = $endTime.ToString("yyyy-MM-dd HH:mm:ss")
            }
        }
        
        # Execute installation remotely
        $invokeParams = @{
            ComputerName = $Computer
            ScriptBlock = $installScript
            ArgumentList = @($Installer, $detectedType, $Args, $CopyLocal, $TimeoutSeconds)
            ErrorAction = "Stop"
        }
        
        if ($Cred) {
            $invokeParams['Credential'] = $Cred
        }
        
        Write-Host "  Executing installation on $Computer..." -ForegroundColor Gray
        
        $installResult = Invoke-Command @invokeParams
        
        $result.ExitCode = $installResult.ExitCode
        $result.Error = $installResult.Error
        $result.Duration = [math]::Round($installResult.Duration, 2)
        $result.EndTime = $installResult.EndTime
        
        # Determine status based on exit code
        if ($installResult.ExitCode -eq 0) {
            $result.Status = "Success"
        }
        elseif ($installResult.ExitCode -eq -2) {
            $result.Status = "Timeout"
        }
        elseif ($installResult.ExitCode -eq 3010 -or $installResult.ExitCode -eq 1641) {
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
        
        if ($result.Duration -eq $null) {
            $start = [DateTime]::ParseExact($result.StartTime, "yyyy-MM-dd HH:mm:ss", $null)
            $end = [DateTime]::ParseExact($result.EndTime, "yyyy-MM-dd HH:mm:ss", $null)
            $result.Duration = [math]::Round(($end - $start).TotalSeconds, 2)
        }
    }
    
    return $result
}

# Main execution
Write-Host "Remote Software Installation Tool" -ForegroundColor Cyan
Write-Host "===================================" -ForegroundColor Cyan
Write-Host ""

# Validate installer path
if (-not (Test-Path $InstallerPath) -and -not $InstallerPath.StartsWith("\\") -and -not $InstallerPath.StartsWith("http")) {
    Write-Error "Installer file not found: $InstallerPath"
    Write-Host "Note: Network paths (\\server\share) and HTTP URLs are supported." -ForegroundColor Yellow
    exit 1
}

# Confirm action
if (-not $PSCmdlet.ShouldProcess("Install software on specified computers", "This will install software on remote computers. Continue?")) {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
    exit 0
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

if ($computers.Count -eq 0) {
    Write-Error "No computers specified. Use -ComputerList or -ComputerName parameter."
    exit 1
}

Write-Host "Installer: $InstallerPath" -ForegroundColor Yellow
Write-Host "Type: $InstallerType" -ForegroundColor Yellow
if ($InstallArgs) {
    Write-Host "Arguments: $InstallArgs" -ForegroundColor Yellow
}
Write-Host "Found $($computers.Count) computer(s) to process" -ForegroundColor Green
if ($CopyToLocal) {
    Write-Host "Copy to local: ENABLED" -ForegroundColor Cyan
}
Write-Host ""

# Process each computer
$results = @()
$total = $computers.Count
$current = 0

foreach ($computer in $computers) {
    $current++
    Write-Progress -Activity "Installing Software" -Status "Processing $computer ($current of $total)" -PercentComplete (($current / $total) * 100)
    
    Write-Host "[$current/$total] Processing $computer..." -NoNewline
    
    $result = Install-SoftwareRemote -Computer $computer -Installer $InstallerPath -Type $InstallerType -Args $InstallArgs -Cred $Credential -CopyLocal $CopyToLocal.IsPresent -Wait $WaitForCompletion.IsPresent -TimeoutSeconds $Timeout
    
    $results += $result
    
    $statusColor = switch ($result.Status) {
        "Success" { "Green" }
        "Success (Reboot Required)" { "Yellow" }
        "Timeout" { "Red" }
        "Failed" { "Red" }
        "Offline" { "Red" }
        "WinRM Not Available" { "Red" }
        "Error" { "Red" }
        default { "Gray" }
    }
    
    Write-Host " $($result.Status)" -ForegroundColor $statusColor
    if ($result.ExitCode -ne $null) {
        Write-Host "  Exit Code: $($result.ExitCode)" -ForegroundColor Gray
    }
    if ($result.Duration) {
        Write-Host "  Duration: $($result.Duration) seconds" -ForegroundColor Gray
    }
    if ($result.Error) {
        Write-Host "  Error: $($result.Error)" -ForegroundColor Red
    }
    
    if ($WaitForCompletion -and $current -lt $total) {
        Start-Sleep -Seconds 2
    }
}

Write-Progress -Activity "Installing Software" -Completed

# Display summary
Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "========" -ForegroundColor Cyan
$success = ($results | Where-Object { $_.Status -eq "Success" }).Count
$rebootRequired = ($results | Where-Object { $_.Status -eq "Success (Reboot Required)" }).Count
$failed = ($results | Where-Object { $_.Status -eq "Failed" }).Count
$timeout = ($results | Where-Object { $_.Status -eq "Timeout" }).Count
$offline = ($results | Where-Object { $_.Status -eq "Offline" }).Count
$winrmError = ($results | Where-Object { $_.Status -eq "WinRM Not Available" }).Count
$errors = ($results | Where-Object { $_.Status -eq "Error" }).Count

Write-Host "Success:           $success" -ForegroundColor Green
Write-Host "Reboot Required:   $rebootRequired" -ForegroundColor Yellow
Write-Host "Failed:            $failed" -ForegroundColor Red
Write-Host "Timeout:           $timeout" -ForegroundColor Red
Write-Host "Offline:           $offline" -ForegroundColor Red
Write-Host "WinRM Not Avail:   $winrmError" -ForegroundColor Red
Write-Host "Errors:            $errors" -ForegroundColor Red
Write-Host ""

# Calculate average duration
$avgDuration = ($results | Where-Object { $_.Duration -ne $null } | Measure-Object -Property Duration -Average).Average
if ($avgDuration) {
    Write-Host "Average Duration:  $([math]::Round($avgDuration, 2)) seconds" -ForegroundColor Cyan
    Write-Host ""
}

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
$results | Format-Table -AutoSize ComputerName, Status, ExitCode, Duration, Error

