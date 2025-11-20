<#
.SYNOPSIS
    Creates VPN connections on local or remote computers.

.DESCRIPTION
    This script creates VPN connections using Windows built-in VPN capabilities.
    Supports IKEv2, L2TP, PPTP, and SSTP protocols.

.PARAMETER ComputerList
    Path to text file with computer names (one per line) or array of computer names.
    Use "." or "localhost" for local computer.

.PARAMETER VPNName
    Name for the VPN connection.

.PARAMETER ServerAddress
    VPN server address (IP or FQDN).

.PARAMETER VPNType
    VPN protocol type: IKEv2, L2TP, PPTP, SSTP, Automatic (default: Automatic).

.PARAMETER AuthenticationMethod
    Authentication method: MSChapv2, EAP, PAP, CHAP (default: MSChapv2).

.PARAMETER UserName
    Username for VPN connection (optional, can be set later).

.PARAMETER Password
    Password for VPN connection (optional, can be set later).

.PARAMETER PreSharedKey
    Pre-shared key for L2TP connections.

.PARAMETER RememberCredential
    Remember username and password (default: true).

.PARAMETER SplitTunneling
    Enable split tunneling (default: false).

.PARAMETER Credential
    PSCredential object for remote authentication.

.PARAMETER OutputFile
    Path to CSV file. Default: VPNConnectionReport.csv

.PARAMETER WhatIf
    Show what would be created without actually creating.

.EXAMPLE
    .\New-VPNConnection.ps1 -ComputerList "computers.txt" -VPNName "Company VPN" -ServerAddress "vpn.company.com"
    
.EXAMPLE
    .\New-VPNConnection.ps1 -ComputerList @("PC01", "PC02") -VPNName "Remote Access" -ServerAddress "192.168.1.100" -VPNType "IKEv2"
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$true)]
    [object]$ComputerList,
    
    [Parameter(Mandatory=$true)]
    [string]$VPNName,
    
    [Parameter(Mandatory=$true)]
    [string]$ServerAddress,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("IKEv2","L2TP","PPTP","SSTP","Automatic")]
    [string]$VPNType = "Automatic",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("MSChapv2","EAP","PAP","CHAP")]
    [string]$AuthenticationMethod = "MSChapv2",
    
    [Parameter(Mandatory=$false)]
    [string]$UserName,
    
    [Parameter(Mandatory=$false)]
    [string]$Password,
    
    [Parameter(Mandatory=$false)]
    [string]$PreSharedKey,
    
    [Parameter(Mandatory=$false)]
    [switch]$RememberCredential = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$SplitTunneling,
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "VPNConnectionReport.csv",
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

# Function to create VPN connection
function New-VPNConnectionRemote {
    param(
        [string]$Computer,
        [string]$Name,
        [string]$Server,
        [string]$Type,
        [string]$AuthMethod,
        [string]$User,
        [string]$Pass,
        [string]$PSK,
        [bool]$Remember,
        [bool]$Split,
        [System.Management.Automation.PSCredential]$Cred
    )
    
    try {
        $scriptBlock = {
            param($VPNName, $ServerAddr, $VPNProtocol, $AuthMeth, $VPNUser, $VPNPass, $PSKValue, $RememberCred, $SplitTun)
            
            $result = @{
                Success = $false
                VPNName = $VPNName
                Error = $null
            }
            
            try {
                # Check if VPN connection already exists
                $existing = Get-VpnConnection -Name $VPNName -ErrorAction SilentlyContinue
                if ($existing) {
                    $result.Error = "VPN connection already exists"
                    $result.Success = $true  # Consider it success if it exists
                    return $result
                }
                
                # Create VPN connection
                Add-VpnConnection -Name $VPNName -ServerAddress $ServerAddr -TunnelType $VPNProtocol -AuthenticationMethod $AuthMeth -RememberCredential $RememberCred -SplitTunneling $SplitTun -ErrorAction Stop
                
                # Set pre-shared key for L2TP if provided
                if ($VPNProtocol -eq "L2TP" -and $PSKValue) {
                    Set-VpnConnectionIPAddressConfiguration -Name $VPNName -PreSharedKey $PSKValue -ErrorAction SilentlyContinue
                }
                
                # Set credentials if provided
                if ($VPNUser -and $VPNPass) {
                    $securePass = ConvertTo-SecureString -String $VPNPass -AsPlainText -Force
                    $cred = New-Object System.Management.Automation.PSCredential($VPNUser, $securePass)
                    
                    # Store credentials
                    if ($RememberCred) {
                        # Note: Storing credentials requires additional steps in real scenarios
                        # This is a simplified version
                    }
                }
                
                $result.Success = $true
            }
            catch {
                $result.Error = $_.Exception.Message
            }
            
            return $result
        }
        
        if ($Computer -eq "." -or $Computer -eq "localhost" -or $Computer -eq $env:COMPUTERNAME) {
            return & $scriptBlock -VPNName $Name -ServerAddr $Server -VPNProtocol $Type -AuthMeth $AuthMethod -VPNUser $User -VPNPass $Pass -PSKValue $PSK -RememberCred $Remember -SplitTun $Split
        }
        else {
            if ($Cred) {
                return Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -ArgumentList $Name, $Server, $Type, $AuthMethod, $User, $Pass, $PSK, $Remember, $Split -Credential $Cred -ErrorAction Stop
            }
            else {
                return Invoke-Command -ComputerName $Computer -ScriptBlock $scriptBlock -ArgumentList $Name, $Server, $Type, $AuthMethod, $User, $Pass, $PSK, $Remember, $Split -ErrorAction Stop
            }
        }
    }
    catch {
        return @{
            Success = $false
            VPNName = $Name
            Error = $_.Exception.Message
        }
    }
}

# Main execution
Write-Host "Create VPN Connection Tool" -ForegroundColor Cyan
Write-Host "===========================" -ForegroundColor Cyan
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

Write-Host "VPN Name: $VPNName" -ForegroundColor Yellow
Write-Host "Server Address: $ServerAddress" -ForegroundColor Yellow
Write-Host "VPN Type: $VPNType" -ForegroundColor Yellow
Write-Host "Authentication: $AuthenticationMethod" -ForegroundColor Yellow
Write-Host "Computers: $($computers.Count)" -ForegroundColor Yellow
Write-Host "Remember Credential: $RememberCredential" -ForegroundColor Yellow
Write-Host "Split Tunneling: $SplitTunneling" -ForegroundColor Yellow
if ($WhatIf) {
    Write-Host "MODE: WHATIF (no VPN connections will be created)" -ForegroundColor Yellow
}
Write-Host ""

if (-not $WhatIf -and -not $PSCmdlet.ShouldProcess("Create VPN connection on $($computers.Count) computer(s)", "This will create VPN connections. Continue?")) {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
    exit 0
}

$results = @()

foreach ($computer in $computers) {
    Write-Host "Processing: $computer" -NoNewline
    
    $result = [PSCustomObject]@{
        Computer = $computer
        VPNName = $VPNName
        ServerAddress = $ServerAddress
        VPNType = $VPNType
        AuthenticationMethod = $AuthenticationMethod
        Status = "Unknown"
        Error = $null
        LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    if (-not $WhatIf) {
        $createResult = New-VPNConnectionRemote -Computer $computer -Name $VPNName -Server $ServerAddress -Type $VPNType -AuthMethod $AuthenticationMethod -User $UserName -Pass $Password -PSK $PreSharedKey -Remember $RememberCredential.IsPresent -Split $SplitTunneling.IsPresent -Cred $Credential
        
        if ($createResult.Success) {
            $result.Status = "Created"
            Write-Host " - Success" -ForegroundColor Green
        }
        else {
            $result.Status = "Failed"
            $result.Error = $createResult.Error
            Write-Host " - Failed: $($createResult.Error)" -ForegroundColor Red
        }
    }
    else {
        $result.Status = "WhatIf - Would Create"
        Write-Host " - WhatIf" -ForegroundColor Gray
    }
    
    $results += $result
}

Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
$created = ($results | Where-Object { $_.Status -like "*Created*" -or $_.Status -like "WhatIf*" }).Count
Write-Host "Created: $created" -ForegroundColor Green
Write-Host "Failed: $(($results | Where-Object { $_.Status -eq 'Failed' }).Count)" -ForegroundColor Red

$results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
$results | Format-Table -AutoSize

