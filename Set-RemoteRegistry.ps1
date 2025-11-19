<#
.SYNOPSIS
    Changes remote registry values on multiple computers.

.DESCRIPTION
    This script modifies registry values on remote computers.

.PARAMETER ComputerList
    Path to text file with computer names.

.PARAMETER ComputerName
    Single or array of computer names.

.PARAMETER RegistryPath
    Registry path (e.g., "HKLM:\Software\MyApp").

.PARAMETER ValueName
    Registry value name.

.PARAMETER ValueType
    Type: String, DWord, QWord, Binary, ExpandString, MultiString.

.PARAMETER Value
    Value to set.

.PARAMETER OutputFile
    Path to CSV file. Default: RegistryChangeReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication.

.PARAMETER WhatIf
    Show what would be changed without actually changing.

.EXAMPLE
    .\Set-RemoteRegistry.ps1 -ComputerList "computers.txt" -RegistryPath "HKLM:\Software\MyApp" -ValueName "Setting" -Value "1" -ValueType DWord
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ComputerName,
    
    [Parameter(Mandatory=$true)]
    [string]$RegistryPath,
    
    [Parameter(Mandatory=$true)]
    [string]$ValueName,
    
    [Parameter(Mandatory=$true)]
    [ValidateSet("String","DWord","QWord","Binary","ExpandString","MultiString")]
    [string]$ValueType,
    
    [Parameter(Mandatory=$true)]
    [object]$Value,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "RegistryChangeReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

function Set-RemoteRegistry {
    param([string]$Computer, [string]$Path, [string]$Name, [string]$Type, [object]$Val, [System.Management.Automation.PSCredential]$Cred, [bool]$WhatIfMode)
    
    $scriptBlock = {
        param([string]$RegPath, [string]$ValName, [string]$ValType, [object]$Val, [bool]$WhatIf)
        
        try {
            # Ensure path exists
            if (-not (Test-Path $RegPath)) {
                New-Item -Path $RegPath -Force | Out-Null
            }
            
            if (-not $WhatIf) {
                Set-ItemProperty -Path $RegPath -Name $ValName -Value $Val -Type $ValType -ErrorAction Stop
                return @{
                    Success = $true
                    OldValue = "N/A"
                    NewValue = $Val.ToString()
                }
            } else {
                $currentValue = (Get-ItemProperty -Path $RegPath -Name $ValName -ErrorAction SilentlyContinue).$ValName
                return @{
                    Success = $true
                    OldValue = if ($currentValue) { $currentValue.ToString() } else { "Not Set" }
                    NewValue = $Val.ToString()
                    Action = "WhatIf - Would Set"
                }
            }
        }
        catch {
            return @{
                Success = $false
                Error = $_.Exception.Message
            }
        }
    }
    
    $result = [PSCustomObject]@{
        ComputerName = $Computer
        RegistryPath = $Path
        ValueName = $Name
        OldValue = "N/A"
        NewValue = $Val.ToString()
        Status = "Unknown"
        Error = $null
    }
    
    try {
        if (-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            $result.Status = "Offline"
            return $result
        }
        
        $invokeParams = @{
            ComputerName = $Computer
            ScriptBlock = $scriptBlock
            ArgumentList = @($Path, $Name, $Type, $Val, $WhatIfMode)
        }
        if ($Cred) { $invokeParams['Credential'] = $Cred }
        
        $regResult = Invoke-Command @invokeParams
        
        if ($regResult.Success) {
            $result.Status = if ($WhatIfMode) { "WhatIf" } else { "Success" }
            $result.OldValue = $regResult.OldValue
            $result.NewValue = $regResult.NewValue
        } else {
            $result.Status = "Error"
            $result.Error = $regResult.Error
        }
    }
    catch {
        $result.Status = "Error"
        $result.Error = $_.Exception.Message
    }
    
    return $result
}

# Main execution
Write-Host "Remote Registry Change Tool" -ForegroundColor Cyan
Write-Host "==========================" -ForegroundColor Cyan
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

Write-Host "Registry Path: $RegistryPath" -ForegroundColor Yellow
Write-Host "Value Name: $ValueName" -ForegroundColor Yellow
Write-Host "Value Type: $ValueType" -ForegroundColor Yellow
Write-Host "Value: $Value" -ForegroundColor Yellow
Write-Host "Processing $($computers.Count) computer(s)..." -ForegroundColor Yellow
if ($WhatIf) {
    Write-Host "MODE: WHATIF (no changes will be made)" -ForegroundColor Yellow
}
Write-Host ""

if (-not $WhatIf -and -not $PSCmdlet.ShouldProcess("Change registry on $($computers.Count) computer(s)", "This will modify registry values. Continue?")) {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
    exit 0
}

$results = @()
foreach ($computer in $computers) {
    Write-Host "Processing $computer..." -NoNewline
    $result = Set-RemoteRegistry -Computer $computer -Path $RegistryPath -Name $ValueName -Type $ValueType -Val $Value -Cred $Credential -WhatIfMode $WhatIf.IsPresent
    $results += $result
    Write-Host " $($result.Status)" -ForegroundColor $(if ($result.Status -eq "Success") { "Green" } else { "Yellow" })
}

$results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
$results | Format-Table -AutoSize

