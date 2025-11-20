<#
.SYNOPSIS
    Changes computer name remotely from a list of computers.

.DESCRIPTION
    This script renames computers remotely using WMI or Invoke-Command.
    Supports renaming multiple computers from a list.

.PARAMETER ComputerList
    Path to text file with computer names (one per line) or array of computer names.

.PARAMETER NewName
    New computer name to set (if same for all).

.PARAMETER NameMap
    Path to CSV file with columns: ComputerName, NewName (for different names per computer).

.PARAMETER Restart
    Restart computer after renaming (default: true).

.PARAMETER Credential
    PSCredential object for remote authentication.

.PARAMETER OutputFile
    Path to CSV file. Default: RenameComputerReport.csv

.PARAMETER DelayRestart
    Delay in seconds before restart (default: 30).

.PARAMETER WhatIf
    Show what would be renamed without actually renaming.

.EXAMPLE
    .\Rename-ComputerRemote.ps1 -ComputerList "computers.txt" -NewName "PC-NEW-001"
    
.EXAMPLE
    .\Rename-ComputerRemote.ps1 -ComputerList @("PC01", "PC02") -NameMap "names.csv" -Restart
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$true)]
    [object]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [string]$NewName,
    
    [Parameter(Mandatory=$false)]
    [string]$NameMap,
    
    [Parameter(Mandatory=$false)]
    [switch]$Restart = $true,
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "RenameComputerReport.csv",
    
    [Parameter(Mandatory=$false)]
    [int]$DelayRestart = 30,
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

# Function to rename computer
function Rename-ComputerRemote {
    param(
        [string]$Computer,
        [string]$NewComputerName,
        [System.Management.Automation.PSCredential]$Cred,
        [bool]$ShouldRestart,
        [int]$RestartDelay
    )
    
    try {
        $scriptBlock = {
            param($NewName, $Restart, $Delay)
            
            $result = @{
                Success = $false
                OldName = $env:COMPUTERNAME
                NewName = $NewName
                Error = $null
            }
            
            try {
                # Get current name
                $currentName = $env:COMPUTERNAME
                
                if ($currentName -eq $NewName) {
                    $result.Success = $true
                    $result.Error = "Computer already has this name"
                    return $result
                }
                
                # Validate new name
                if ($NewName.Length -gt 15) {
                    $result.Error = "Computer name cannot exceed 15 characters"
                    return $result
                }
                
                if ($NewName -match '[^a-zA-Z0-9\-]') {
                    $result.Error = "Computer name contains invalid characters"
                    return $result
                }
                
                # Rename computer
                Rename-Computer -NewName $NewName -Force -ErrorAction Stop
                
                $result.Success = $true
                $result.NewName = $NewName
                
                # Schedule restart if needed
                if ($Restart) {
                    Start-Sleep -Seconds $Delay
                    Restart-Computer -Force
                }
            }
            catch {
                $result.Error = $_.Exception.Message
            }
            
            return $result
        }
        
        if ($Cred) {
            return Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -ArgumentList $NewComputerName, $ShouldRestart, $RestartDelay -Credential $Cred -ErrorAction Stop
        }
        else {
            return Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -ArgumentList $NewComputerName, $ShouldRestart, $RestartDelay -ErrorAction Stop
        }
    }
    catch {
        return @{
            Success = $false
            OldName = "Unknown"
            NewName = $NewComputerName
            Error = $_.Exception.Message
        }
    }
}

# Main execution
Write-Host "Rename Computer Remote Tool" -ForegroundColor Cyan
Write-Host "============================" -ForegroundColor Cyan
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

# Get name mapping
$nameMap = @{}

if ($NameMap -and (Test-Path $NameMap)) {
    $mapping = Import-Csv -Path $NameMap
    foreach ($row in $mapping) {
        if ($row.ComputerName -and $row.NewName) {
            $nameMap[$row.ComputerName] = $row.NewName
        }
    }
    Write-Host "Loaded name mapping from: $NameMap" -ForegroundColor Green
}
elseif ($NewName) {
    foreach ($computer in $computers) {
        $nameMap[$computer] = $NewName
    }
}
else {
    Write-Error "Must specify either -NewName or -NameMap"
    exit 1
}

Write-Host "Computers: $($computers.Count)" -ForegroundColor Yellow
Write-Host "Restart after rename: $Restart" -ForegroundColor Yellow
if ($Restart) {
    Write-Host "Restart delay: $DelayRestart seconds" -ForegroundColor Yellow
}
if ($WhatIf) {
    Write-Host "MODE: WHATIF (no computers will be renamed)" -ForegroundColor Yellow
}
Write-Host ""

if (-not $WhatIf -and -not $PSCmdlet.ShouldProcess("Rename $($computers.Count) computer(s)", "This will rename computers and may restart them. Continue?")) {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
    exit 0
}

$results = @()

foreach ($computer in $computers) {
    if (-not $nameMap.ContainsKey($computer)) {
        Write-Warning "No new name specified for $computer, skipping..."
        continue
    }
    
    $newName = $nameMap[$computer]
    Write-Host "Renaming: $computer -> $newName" -NoNewline
    
    $result = [PSCustomObject]@{
        Computer = $computer
        OldName = "Unknown"
        NewName = $newName
        Status = "Unknown"
        Error = $null
        Restarted = $Restart
        LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    if (-not $WhatIf) {
        $renameResult = Rename-ComputerRemote -Computer $computer -NewComputerName $newName -Cred $Credential -ShouldRestart $Restart.IsPresent -RestartDelay $DelayRestart
        
        $result.OldName = $renameResult.OldName
        $result.NewName = $renameResult.NewName
        
        if ($renameResult.Success) {
            $result.Status = "Renamed"
            Write-Host " - Success" -ForegroundColor Green
        }
        else {
            $result.Status = "Failed"
            $result.Error = $renameResult.Error
            Write-Host " - Failed: $($renameResult.Error)" -ForegroundColor Red
        }
    }
    else {
        $result.Status = "WhatIf - Would Rename"
        Write-Host " - WhatIf" -ForegroundColor Gray
    }
    
    $results += $result
}

Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
$renamed = ($results | Where-Object { $_.Status -like "*Renamed*" -or $_.Status -like "WhatIf*" }).Count
Write-Host "Renamed: $renamed" -ForegroundColor Green
Write-Host "Failed: $(($results | Where-Object { $_.Status -eq 'Failed' }).Count)" -ForegroundColor Red

$results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
$results | Format-Table -AutoSize

if ($Restart -and -not $WhatIf) {
    Write-Host ""
    Write-Host "Computers will restart in $DelayRestart seconds..." -ForegroundColor Yellow
}

