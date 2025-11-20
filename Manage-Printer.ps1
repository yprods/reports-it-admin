<#
.SYNOPSIS
    Adds or removes printers from local or remote computers.

.DESCRIPTION
    This script manages printers on Windows computers. Supports adding local printers,
    network printers, shared printers, and removing printers.

.PARAMETER ComputerList
    Path to text file with computer names (one per line) or array of computer names.
    Use "." or "localhost" for local computer.

.PARAMETER Action
    Action to perform: Add, Remove, List (default: Add).

.PARAMETER PrinterName
    Name for the printer (for Add) or name of printer to remove (for Remove).

.PARAMETER PrinterPath
    Printer path:
    - For network printer: \\server\printer
    - For local printer: Port name (e.g., "USB001", "LPT1:", "COM1:")
    - For TCP/IP printer: IP address or hostname

.PARAMETER DriverName
    Printer driver name (required for local printers).

.PARAMETER PortName
    Port name for local printer (e.g., "USB001", "LPT1:", "IP_192.168.1.100").

.PARAMETER IPAddress
    IP address for TCP/IP printer.

.PARAMETER PortNumber
    Port number for TCP/IP printer (default: 9100).

.PARAMETER SetAsDefault
    Set printer as default (default: false).

.PARAMETER Shared
    Share the printer (default: false).

.PARAMETER ShareName
    Share name for the printer.

.PARAMETER Credential
    PSCredential object for remote authentication.

.PARAMETER OutputFile
    Path to CSV file. Default: PrinterManagementReport.csv

.PARAMETER WhatIf
    Show what would be done without actually doing it.

.EXAMPLE
    .\Manage-Printer.ps1 -ComputerList "computers.txt" -Action "Add" -PrinterName "HP LaserJet" -PrinterPath "\\server\HPPrinter"
    
.EXAMPLE
    .\Manage-Printer.ps1 -ComputerList @("PC01", "PC02") -Action "Add" -PrinterName "Network Printer" -IPAddress "192.168.1.100" -DriverName "HP Universal Printing PCL 6"
    
.EXAMPLE
    .\Manage-Printer.ps1 -ComputerList "computers.txt" -Action "Remove" -PrinterName "Old Printer"
    
.EXAMPLE
    .\Manage-Printer.ps1 -ComputerList "." -Action "List"
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$true)]
    [object]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Add","Remove","List")]
    [string]$Action = "Add",
    
    [Parameter(Mandatory=$false)]
    [string]$PrinterName,
    
    [Parameter(Mandatory=$false)]
    [string]$PrinterPath,
    
    [Parameter(Mandatory=$false)]
    [string]$DriverName,
    
    [Parameter(Mandatory=$false)]
    [string]$PortName,
    
    [Parameter(Mandatory=$false)]
    [string]$IPAddress,
    
    [Parameter(Mandatory=$false)]
    [int]$PortNumber = 9100,
    
    [Parameter(Mandatory=$false)]
    [switch]$SetAsDefault,
    
    [Parameter(Mandatory=$false)]
    [switch]$Shared,
    
    [Parameter(Mandatory=$false)]
    [string]$ShareName,
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "PrinterManagementReport.csv",
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

# Function to add printer
function Add-PrinterRemote {
    param(
        [string]$Computer,
        [string]$Name,
        [string]$Path,
        [string]$Driver,
        [string]$Port,
        [string]$IP,
        [int]$PortNum,
        [bool]$Default,
        [bool]$Share,
        [string]$ShareN,
        [System.Management.Automation.PSCredential]$Cred
    )
    
    try {
        $scriptBlock = {
            param($PrinterName, $PrinterPath, $DriverName, $PortName, $IPAddr, $PortNumber, $SetDefault, $SharePrinter, $ShareName)
            
            $result = @{
                Success = $false
                Error = $null
                PrinterName = $PrinterName
            }
            
            try {
                # Determine printer type and path
                if ($PrinterPath) {
                    # Network or shared printer
                    if ($PrinterPath -like "\\*") {
                        # Network printer
                        Add-Printer -ConnectionName $PrinterPath -ErrorAction Stop
                        $result.Success = $true
                    }
                    else {
                        # Local printer with port
                        if (-not $DriverName) {
                            $result.Error = "DriverName is required for local printers"
                            return $result
                        }
                        
                        Add-Printer -Name $PrinterName -DriverName $DriverName -PortName $PrinterPath -ErrorAction Stop
                        $result.Success = $true
                    }
                }
                elseif ($IPAddr) {
                    # TCP/IP printer
                    if (-not $DriverName) {
                        $result.Error = "DriverName is required for TCP/IP printers"
                        return $result
                    }
                    
                    # Create port if it doesn't exist
                    $portName = "IP_$IPAddr"
                    $existingPort = Get-PrinterPort -Name $portName -ErrorAction SilentlyContinue
                    if (-not $existingPort) {
                        Add-PrinterPort -Name $portName -PrinterHostAddress $IPAddr -PortNumber $PortNumber -ErrorAction Stop
                    }
                    
                    Add-Printer -Name $PrinterName -DriverName $DriverName -PortName $portName -ErrorAction Stop
                    $result.Success = $true
                }
                elseif ($PortName) {
                    # Local printer with specified port
                    if (-not $DriverName) {
                        $result.Error = "DriverName is required for local printers"
                        return $result
                    }
                    
                    Add-Printer -Name $PrinterName -DriverName $DriverName -PortName $PortName -ErrorAction Stop
                    $result.Success = $true
                }
                else {
                    $result.Error = "Must specify PrinterPath, IPAddress, or PortName"
                    return $result
                }
                
                # Set as default if requested
                if ($SetDefault -and $result.Success) {
                    Set-Printer -Name $PrinterName -PrinterDefault -ErrorAction SilentlyContinue
                }
                
                # Share printer if requested
                if ($SharePrinter -and $result.Success) {
                    $share = if ($ShareName) { $ShareName } else { $PrinterName }
                    Set-Printer -Name $PrinterName -Shared $true -ShareName $share -ErrorAction SilentlyContinue
                }
            }
            catch {
                $result.Error = $_.Exception.Message
            }
            
            return $result
        }
        
        if ($Computer -eq "." -or $Computer -eq "localhost" -or $Computer -eq $env:COMPUTERNAME) {
            return & $scriptBlock -PrinterName $Name -PrinterPath $Path -DriverName $Driver -PortName $Port -IPAddr $IP -PortNumber $PortNum -SetDefault $Default -SharePrinter $Share -ShareName $ShareN
        }
        else {
            if ($Cred) {
                return Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -ArgumentList $Name, $Path, $Driver, $Port, $IP, $PortNum, $Default, $Share, $ShareN -Credential $Cred -ErrorAction Stop
            }
            else {
                return Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -ArgumentList $Name, $Path, $Driver, $Port, $IP, $PortNum, $Default, $Share, $ShareN -ErrorAction Stop
            }
        }
    }
    catch {
        return @{ Success = $false; Error = $_.Exception.Message; PrinterName = $Name }
    }
}

# Function to remove printer
function Remove-PrinterRemote {
    param(
        [string]$Computer,
        [string]$PrinterName,
        [System.Management.Automation.PSCredential]$Cred
    )
    
    try {
        $scriptBlock = {
            param($Name)
            
            $result = @{
                Success = $false
                Error = $null
                PrinterName = $Name
            }
            
            try {
                # Check if printer exists
                $printer = Get-Printer -Name $Name -ErrorAction SilentlyContinue
                if (-not $printer) {
                    $result.Error = "Printer not found"
                    return $result
                }
                
                # Remove printer
                Remove-Printer -Name $Name -ErrorAction Stop
                $result.Success = $true
            }
            catch {
                $result.Error = $_.Exception.Message
            }
            
            return $result
        }
        
        if ($Computer -eq "." -or $Computer -eq "localhost" -or $Computer -eq $env:COMPUTERNAME) {
            return & $scriptBlock -Name $PrinterName
        }
        else {
            if ($Cred) {
                return Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -ArgumentList $PrinterName -Credential $Cred -ErrorAction Stop
            }
            else {
                return Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -ArgumentList $PrinterName -ErrorAction Stop
            }
        }
    }
    catch {
        return @{ Success = $false; Error = $_.Exception.Message; PrinterName = $PrinterName }
    }
}

# Function to list printers
function Get-PrinterListRemote {
    param(
        [string]$Computer,
        [System.Management.Automation.PSCredential]$Cred
    )
    
    try {
        $scriptBlock = {
            $printers = Get-Printer -ErrorAction SilentlyContinue | Select-Object Name, DriverName, PortName, PrinterStatus, Shared, Default
            return $printers
        }
        
        if ($Computer -eq "." -or $Computer -eq "localhost" -or $Computer -eq $env:COMPUTERNAME) {
            return & $scriptBlock
        }
        else {
            if ($Cred) {
                return Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -Credential $Cred -ErrorAction Stop
            }
            else {
                return Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -ErrorAction Stop
            }
        }
    }
    catch {
        Write-Warning "Failed to list printers on $Computer : $($_.Exception.Message)"
        return @()
    }
}

# Main execution
Write-Host "Printer Management Tool" -ForegroundColor Cyan
Write-Host "=====================" -ForegroundColor Cyan
Write-Host ""

# Get computer list
$computers = @()

if ($ComputerList -is [string]) {
    if (Test-Path $ComputerList) {
        $computers = Get-Content $ComputerList | Where-Object { $_.Trim() -ne "" }
    }
    else {
        $computers = @($ComputerList)
    }
}
elseif ($ComputerList -is [array]) {
    $computers = $ComputerList
}
else {
    Write-Error "ComputerList must be a file path (string) or array of computer names."
    exit 1
}

if ($computers.Count -eq 0) {
    Write-Error "No computers specified."
    exit 1
}

# Validate action parameters
if ($Action -eq "Add" -and -not $PrinterName) {
    Write-Error "PrinterName is required for Add action."
    exit 1
}

if ($Action -eq "Remove" -and -not $PrinterName) {
    Write-Error "PrinterName is required for Remove action."
    exit 1
}

Write-Host "Action: $Action" -ForegroundColor Yellow
Write-Host "Computers: $($computers.Count)" -ForegroundColor Yellow
if ($PrinterName) {
    Write-Host "Printer Name: $PrinterName" -ForegroundColor Yellow
}
if ($PrinterPath) {
    Write-Host "Printer Path: $PrinterPath" -ForegroundColor Yellow
}
if ($IPAddress) {
    Write-Host "IP Address: $IPAddress" -ForegroundColor Yellow
}
if ($DriverName) {
    Write-Host "Driver: $DriverName" -ForegroundColor Yellow
}
if ($WhatIf) {
    Write-Host "MODE: WHATIF (no changes will be made)" -ForegroundColor Yellow
}
Write-Host ""

if (-not $WhatIf -and $Action -ne "List" -and -not $PSCmdlet.ShouldProcess("$Action printer on $($computers.Count) computer(s)", "This will $Action printer(s). Continue?")) {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
    exit 0
}

$results = @()

foreach ($computer in $computers) {
    Write-Host "Processing: $computer" -ForegroundColor Cyan
    
    if ($Action -eq "List") {
        Write-Host "  Listing printers..." -NoNewline
        $printers = Get-PrinterListRemote -Computer $computer -Cred $Credential
        
        if ($printers.Count -gt 0) {
            Write-Host " - Found $($printers.Count) printer(s)" -ForegroundColor Green
            foreach ($printer in $printers) {
                $default = if ($printer.Default) { " (Default)" } else { "" }
                $shared = if ($printer.Shared) { " (Shared)" } else { "" }
                Write-Host "    - $($printer.Name)$default$shared" -ForegroundColor Gray
                Write-Host "      Driver: $($printer.DriverName) | Port: $($printer.PortName)" -ForegroundColor DarkGray
            }
            
            $results += $printers | ForEach-Object {
                [PSCustomObject]@{
                    Computer = $computer
                    Action = "List"
                    PrinterName = $_.Name
                    DriverName = $_.DriverName
                    PortName = $_.PortName
                    Status = $_.PrinterStatus
                    Shared = $_.Shared
                    Default = $_.Default
                    Result = "Listed"
                    Error = $null
                    LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
            }
        }
        else {
            Write-Host " - No printers found" -ForegroundColor Yellow
        }
    }
    elseif ($Action -eq "Add") {
        Write-Host "  Adding printer: $PrinterName" -NoNewline
        
        $result = [PSCustomObject]@{
            Computer = $computer
            Action = "Add"
            PrinterName = $PrinterName
            PrinterPath = $PrinterPath
            IPAddress = $IPAddress
            DriverName = $DriverName
            SetAsDefault = $SetAsDefault
            Shared = $Shared
            Status = "Unknown"
            Error = $null
            LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        
        if (-not $WhatIf) {
            $addResult = Add-PrinterRemote -Computer $computer -Name $PrinterName -Path $PrinterPath -Driver $DriverName -Port $PortName -IP $IPAddress -PortNum $PortNumber -Default $SetAsDefault.IsPresent -Share $Shared.IsPresent -ShareN $ShareName -Cred $Credential
            
            if ($addResult.Success) {
                $result.Status = "Added"
                Write-Host " - Success" -ForegroundColor Green
            }
            else {
                $result.Status = "Failed"
                $result.Error = $addResult.Error
                Write-Host " - Failed: $($addResult.Error)" -ForegroundColor Red
            }
        }
        else {
            $result.Status = "WhatIf - Would Add"
            Write-Host " - WhatIf" -ForegroundColor Gray
        }
        
        $results += $result
    }
    elseif ($Action -eq "Remove") {
        Write-Host "  Removing printer: $PrinterName" -NoNewline
        
        $result = [PSCustomObject]@{
            Computer = $computer
            Action = "Remove"
            PrinterName = $PrinterName
            Status = "Unknown"
            Error = $null
            LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        
        if (-not $WhatIf) {
            $removeResult = Remove-PrinterRemote -Computer $computer -PrinterName $PrinterName -Cred $Credential
            
            if ($removeResult.Success) {
                $result.Status = "Removed"
                Write-Host " - Success" -ForegroundColor Green
            }
            else {
                $result.Status = "Failed"
                $result.Error = $removeResult.Error
                Write-Host " - Failed: $($removeResult.Error)" -ForegroundColor Red
            }
        }
        else {
            $result.Status = "WhatIf - Would Remove"
            Write-Host " - WhatIf" -ForegroundColor Gray
        }
        
        $results += $result
    }
}

Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan

if ($Action -eq "List") {
    $totalPrinters = ($results | Measure-Object).Count
    Write-Host "Total Printers Found: $totalPrinters" -ForegroundColor Green
}
elseif ($Action -eq "Add") {
    $added = ($results | Where-Object { $_.Status -like "*Added*" -or $_.Status -like "WhatIf*" }).Count
    Write-Host "Added: $added" -ForegroundColor Green
    Write-Host "Failed: $(($results | Where-Object { $_.Status -eq 'Failed' }).Count)" -ForegroundColor Red
}
elseif ($Action -eq "Remove") {
    $removed = ($results | Where-Object { $_.Status -like "*Removed*" -or $_.Status -like "WhatIf*" }).Count
    Write-Host "Removed: $removed" -ForegroundColor Green
    Write-Host "Failed: $(($results | Where-Object { $_.Status -eq 'Failed' }).Count)" -ForegroundColor Red
}

if ($results.Count -gt 0) {
    $results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
    Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
    $results | Format-Table -AutoSize
}

