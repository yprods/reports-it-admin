<#
.SYNOPSIS
    Creates local administrator accounts on remote computers.

.DESCRIPTION
    This script creates local administrator accounts on multiple computers.

.PARAMETER ComputerList
    Path to text file with computer names.

.PARAMETER ComputerName
    Single or array of computer names.

.PARAMETER Username
    Username for the local admin account.

.PARAMETER Password
    Secure string password for the account.

.PARAMETER OutputFile
    Path to CSV file. Default: LocalAdminCreationReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication.

.PARAMETER WhatIf
    Show what would be created without actually creating.

.EXAMPLE
    .\New-LocalAdmin.ps1 -ComputerList "computers.txt" -Username "LocalAdmin" -Password (ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force)
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ComputerName,
    
    [Parameter(Mandatory=$true)]
    [string]$Username,
    
    [Parameter(Mandatory=$true)]
    [System.Security.SecureString]$Password,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "LocalAdminCreationReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

function New-LocalAdmin {
    param([string]$Computer, [string]$User, [System.Security.SecureString]$Pass, [System.Management.Automation.PSCredential]$Cred, [bool]$WhatIfMode)
    
    $scriptBlock = {
        param([string]$UserName, [string]$Password, [bool]$WhatIf)
        
        try {
            # Check if user exists
            $existingUser = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
            
            if ($existingUser) {
                return @{
                    Success = $false
                    Error = "User already exists"
                }
            }
            
            if (-not $WhatIf) {
                # Create user
                $securePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
                New-LocalUser -Name $UserName -Password $securePassword -Description "Local Administrator" -ErrorAction Stop
                
                # Add to Administrators group
                Add-LocalGroupMember -Group "Administrators" -Member $UserName -ErrorAction Stop
                
                return @{
                    Success = $true
                    Action = "Created"
                }
            } else {
                return @{
                    Success = $true
                    Action = "WhatIf - Would Create"
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
        Username = $User
        Status = "Unknown"
        Error = $null
    }
    
    try {
        if (-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            $result.Status = "Offline"
            return $result
        }
        
        # Convert secure string to plain text for remote execution
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Pass)
        $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        
        $invokeParams = @{
            ComputerName = $Computer
            ScriptBlock = $scriptBlock
            ArgumentList = @($User, $plainPassword, $WhatIfMode)
        }
        if ($Cred) { $invokeParams['Credential'] = $Cred }
        
        $createResult = Invoke-Command @invokeParams
        
        if ($createResult.Success) {
            $result.Status = $createResult.Action
        } else {
            $result.Status = "Error"
            $result.Error = $createResult.Error
        }
    }
    catch {
        $result.Status = "Error"
        $result.Error = $_.Exception.Message
    }
    
    return $result
}

# Main execution
Write-Host "Local Admin Creation Tool" -ForegroundColor Cyan
Write-Host "========================" -ForegroundColor Cyan
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

Write-Host "Username: $Username" -ForegroundColor Yellow
Write-Host "Processing $($computers.Count) computer(s)..." -ForegroundColor Yellow
if ($WhatIf) {
    Write-Host "MODE: WHATIF (no accounts will be created)" -ForegroundColor Yellow
}
Write-Host ""

if (-not $WhatIf -and -not $PSCmdlet.ShouldProcess("Create local admin on $($computers.Count) computer(s)", "This will create local administrator accounts. Continue?")) {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
    exit 0
}

$results = @()
foreach ($computer in $computers) {
    Write-Host "Processing $computer..." -NoNewline
    $result = New-LocalAdmin -Computer $computer -User $Username -Pass $Password -Cred $Credential -WhatIfMode $WhatIf.IsPresent
    $results += $result
    Write-Host " $($result.Status)" -ForegroundColor $(if ($result.Status -like "*Created*") { "Green" } else { "Red" })
}

$results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
$results | Format-Table -AutoSize

