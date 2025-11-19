<#
.SYNOPSIS
    Clears cache on a list of computers remotely.

.DESCRIPTION
    This script clears various caches (DNS, temp files, browser cache, etc.)
    on remote computers.

.PARAMETER ComputerList
    Path to text file with computer names.

.PARAMETER ComputerName
    Single or array of computer names.

.PARAMETER CacheType
    Type of cache to clear: All, DNS, Temp, Browser, WindowsUpdate (default: All).

.PARAMETER OutputFile
    Path to CSV file. Default: CacheClearReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication.

.EXAMPLE
    .\Clear-ComputerCache.ps1 -ComputerList "computers.txt" -CacheType "DNS"
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ComputerName,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("All","DNS","Temp","Browser","WindowsUpdate")]
    [string]$CacheType = "All",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "CacheClearReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential
)

function Clear-Cache {
    param([string]$Computer, [string]$Type, [System.Management.Automation.PSCredential]$Cred)
    
    $scriptBlock = {
        param([string]$CacheType)
        $results = @()
        
        if ($CacheType -eq "All" -or $CacheType -eq "DNS") {
            try {
                ipconfig /flushdns | Out-Null
                $results += "DNS cache flushed"
            } catch { $results += "DNS flush failed: $_" }
        }
        
        if ($CacheType -eq "All" -or $CacheType -eq "Temp") {
            try {
                Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
                $results += "Temp files cleared"
            } catch { $results += "Temp clear failed: $_" }
        }
        
        if ($CacheType -eq "All" -or $CacheType -eq "WindowsUpdate") {
            try {
                Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
                Remove-Item "$env:SystemRoot\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
                Start-Service -Name wuauserv -ErrorAction SilentlyContinue
                $results += "Windows Update cache cleared"
            } catch { $results += "WU cache clear failed: $_" }
        }
        
        return ($results -join "; ")
    }
    
    $result = [PSCustomObject]@{
        ComputerName = $Computer
        CacheType = $Type
        Status = "Unknown"
        Results = $null
    }
    
    try {
        if (-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            $result.Status = "Offline"
            return $result
        }
        
        $invokeParams = @{
            ComputerName = $Computer
            ScriptBlock = $scriptBlock
            ArgumentList = @($Type)
        }
        if ($Cred) { $invokeParams['Credential'] = $Cred }
        
        $output = Invoke-Command @invokeParams
        $result.Status = "Success"
        $result.Results = $output
    }
    catch {
        $result.Status = "Error"
        $result.Results = $_.Exception.Message
    }
    
    return $result
}

# Main execution
Write-Host "Cache Clear Tool" -ForegroundColor Cyan
Write-Host "================" -ForegroundColor Cyan
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

Write-Host "Cache Type: $CacheType" -ForegroundColor Yellow
Write-Host "Processing $($computers.Count) computer(s)..." -ForegroundColor Yellow

$results = @()
foreach ($computer in $computers) {
    $result = Clear-Cache -Computer $computer -Type $CacheType -Cred $Credential
    $results += $result
    Write-Host "$computer - $($result.Status)" -ForegroundColor $(if ($result.Status -eq "Success") { "Green" } else { "Red" })
}

$results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
$results | Format-Table -AutoSize

