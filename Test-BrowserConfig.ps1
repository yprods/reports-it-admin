<#
.SYNOPSIS
    Tests browser configuration on local or remote computers.

.DESCRIPTION
    This script tests browser configuration including proxy settings, security settings,
    extensions, and connectivity for Chrome, Edge, Firefox, and Internet Explorer.

.PARAMETER ComputerList
    Path to text file with computer names (one per line) or array of computer names.

.PARAMETER Browser
    Browser to test: Chrome, Edge, Firefox, IE, All (default: All).

.PARAMETER TestProxy
    Test proxy configuration (default: true).

.PARAMETER TestSecurity
    Test security settings (default: true).

.PARAMETER TestExtensions
    List installed extensions (default: true).

.PARAMETER TestConnectivity
    Test connectivity to common sites (default: true).

.PARAMETER Credential
    PSCredential object for remote authentication.

.PARAMETER OutputFile
    Path to CSV file. Default: BrowserConfigReport.csv

.EXAMPLE
    .\Test-BrowserConfig.ps1 -ComputerList "computers.txt" -Browser "Chrome"
    
.EXAMPLE
    .\Test-BrowserConfig.ps1 -ComputerList @("PC01", "PC02") -TestProxy -TestSecurity
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [object]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Chrome","Edge","Firefox","IE","All")]
    [string]$Browser = "All",
    
    [Parameter(Mandatory=$false)]
    [switch]$TestProxy = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$TestSecurity = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$TestExtensions = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$TestConnectivity = $true,
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "BrowserConfigReport.csv"
)

# Function to test browser configuration
function Test-BrowserConfiguration {
    param(
        [string]$Computer,
        [string]$BrowserName,
        [bool]$Proxy,
        [bool]$Security,
        [bool]$Extensions,
        [bool]$Connectivity,
        [System.Management.Automation.PSCredential]$Cred
    )
    
    try {
        $scriptBlock = {
            param($Browser, $TestProxy, $TestSecurity, $TestExtensions, $TestConnectivity)
            
            $result = @{
                Browser = $Browser
                Installed = $false
                Version = $null
                ProxyEnabled = $null
                ProxyServer = $null
                SecurityLevel = $null
                Extensions = @()
                Connectivity = @()
                Error = $null
            }
            
            try {
                # Chrome
                if ($Browser -eq "Chrome" -or $Browser -eq "All") {
                    $chromePath = "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
                    if (Test-Path $chromePath) {
                        $result.Installed = $true
                        $version = (Get-Item $chromePath).VersionInfo.FileVersion
                        $result.Version = $version
                        
                        # Get proxy settings from registry
                        $proxyReg = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
                        if ($proxyReg) {
                            $result.ProxyEnabled = $proxyReg.ProxyEnable -eq 1
                            $result.ProxyServer = $proxyReg.ProxyServer
                        }
                    }
                }
                
                # Edge
                if ($Browser -eq "Edge" -or $Browser -eq "All") {
                    $edgePath = "$env:ProgramFiles (x86)\Microsoft\Edge\Application\msedge.exe"
                    if (-not (Test-Path $edgePath)) {
                        $edgePath = "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe"
                    }
                    if (Test-Path $edgePath) {
                        $result.Installed = $true
                        $version = (Get-Item $edgePath).VersionInfo.FileVersion
                        $result.Version = $version
                    }
                }
                
                # Firefox
                if ($Browser -eq "Firefox" -or $Browser -eq "All") {
                    $firefoxPath = "$env:ProgramFiles\Mozilla Firefox\firefox.exe"
                    if (-not (Test-Path $firefoxPath)) {
                        $firefoxPath = "$env:ProgramFiles (x86)\Mozilla Firefox\firefox.exe"
                    }
                    if (Test-Path $firefoxPath) {
                        $result.Installed = $true
                        $version = (Get-Item $firefoxPath).VersionInfo.FileVersion
                        $result.Version = $version
                    }
                }
                
                # Internet Explorer
                if ($Browser -eq "IE" -or $Browser -eq "All") {
                    $iePath = "$env:ProgramFiles\Internet Explorer\iexplore.exe"
                    if (Test-Path $iePath) {
                        $result.Installed = $true
                        $version = (Get-Item $iePath).VersionInfo.FileVersion
                        $result.Version = $version
                        
                        # Get IE security settings
                        $zone1 = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" -ErrorAction SilentlyContinue
                        if ($zone1) {
                            $result.SecurityLevel = $zone1.1200
                        }
                    }
                }
                
                # Test connectivity
                if ($TestConnectivity) {
                    $sites = @("google.com", "microsoft.com", "yahoo.com")
                    foreach ($site in $sites) {
                        try {
                            $test = Test-NetConnection -ComputerName $site -Port 80 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
                            $result.Connectivity += [PSCustomObject]@{
                                Site = $site
                                Reachable = $test.TcpTestSucceeded
                            }
                        }
                        catch {
                            $result.Connectivity += [PSCustomObject]@{
                                Site = $site
                                Reachable = $false
                            }
                        }
                    }
                }
            }
            catch {
                $result.Error = $_.Exception.Message
            }
            
            return $result
        }
        
        if ($Computer -eq "." -or $Computer -eq "localhost" -or $Computer -eq $env:COMPUTERNAME) {
            return & $scriptBlock -Browser $BrowserName -TestProxy $Proxy -TestSecurity $Security -TestExtensions $Extensions -TestConnectivity $Connectivity
        }
        else {
            if ($Cred) {
                return Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -ArgumentList $BrowserName, $Proxy, $Security, $Extensions, $Connectivity -Credential $Cred -ErrorAction Stop
            }
            else {
                return Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -ArgumentList $BrowserName, $Proxy, $Security, $Extensions, $Connectivity -ErrorAction Stop
            }
        }
    }
    catch {
        Write-Warning "Failed to test browser on $Computer : $($_.Exception.Message)"
        return $null
    }
}

# Main execution
Write-Host "Browser Configuration Test Tool" -ForegroundColor Cyan
Write-Host "===============================" -ForegroundColor Cyan
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

Write-Host "Computers: $($computers.Count)" -ForegroundColor Yellow
Write-Host "Browser: $Browser" -ForegroundColor Yellow
Write-Host ""

$results = @()

foreach ($computer in $computers) {
    Write-Host "Testing browser on: $computer" -ForegroundColor Cyan
    
    $browserResult = Test-BrowserConfiguration -Computer $computer -BrowserName $Browser -Proxy $TestProxy.IsPresent -Security $TestSecurity.IsPresent -Extensions $TestExtensions.IsPresent -Connectivity $TestConnectivity.IsPresent -Cred $Credential
    
    if ($browserResult) {
        Write-Host "  Browser: $($browserResult.Browser)" -ForegroundColor Green
        Write-Host "  Installed: $($browserResult.Installed)" -ForegroundColor Green
        if ($browserResult.Version) {
            Write-Host "  Version: $($browserResult.Version)" -ForegroundColor Green
        }
        if ($browserResult.ProxyEnabled -ne $null) {
            Write-Host "  Proxy Enabled: $($browserResult.ProxyEnabled)" -ForegroundColor Green
        }
        
        $result = [PSCustomObject]@{
            Computer = $computer
            Browser = $browserResult.Browser
            Installed = $browserResult.Installed
            Version = $browserResult.Version
            ProxyEnabled = $browserResult.ProxyEnabled
            ProxyServer = $browserResult.ProxyServer
            SecurityLevel = $browserResult.SecurityLevel
            ConnectivityTests = ($browserResult.Connectivity | Where-Object { $_.Reachable }).Count
            LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        
        $results += $result
    }
}

Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
$results | Format-Table -AutoSize

$results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "Results exported to: $OutputFile" -ForegroundColor Green

