<#
.SYNOPSIS
    Joins or removes computers from a domain remotely.

.DESCRIPTION
    This script joins or removes computers from a domain using PowerShell remoting.
    Supports both joining and leaving domain operations.

.PARAMETER ComputerList
    Path to a text file containing computer names (one per line).

.PARAMETER ComputerName
    Single computer name or array of computer names to process.

.PARAMETER Domain
    Domain name to join (e.g., "contoso.com").

.PARAMETER DomainUser
    Username for domain join operation (domain\username format).

.PARAMETER DomainPassword
    Secure string password for domain join operation.

.PARAMETER OUPath
    Organizational Unit path to place computer in (e.g., "OU=Computers,DC=contoso,DC=com").

.PARAMETER Action
    Action to perform: Join or Leave (default: Join).

.PARAMETER OutputFile
    Path to CSV file where results will be exported. Default: DomainJoinReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication (optional).

.PARAMETER Restart
    Restart computer after domain operation (default: true for join, false for leave).

.EXAMPLE
    .\Set-DomainJoin.ps1 -ComputerList "computers.txt" -Domain "contoso.com" -DomainUser "contoso\admin" -Action Join
    
.EXAMPLE
    .\Set-DomainJoin.ps1 -ComputerName "PC01","PC02" -Domain "contoso.com" -Action Leave
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ComputerName,
    
    [Parameter(Mandatory=$true)]
    [string]$Domain,
    
    [Parameter(Mandatory=$false)]
    [string]$DomainUser,
    
    [Parameter(Mandatory=$false)]
    [System.Security.SecureString]$DomainPassword,
    
    [Parameter(Mandatory=$false)]
    [string]$OUPath,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Join","Leave")]
    [string]$Action = "Join",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "DomainJoinReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [switch]$Restart
)

# Function to join/leave domain on a single computer
function Set-DomainJoin {
    param(
        [string]$Computer,
        [string]$DomainName,
        [string]$User,
        [System.Security.SecureString]$Password,
        [string]$OU,
        [string]$Operation,
        [System.Management.Automation.PSCredential]$Cred,
        [bool]$ShouldRestart
    )
    
    $result = [PSCustomObject]@{
        ComputerName = $Computer
        Action = $Operation
        Domain = $DomainName
        Status = "Unknown"
        CurrentDomain = "N/A"
        OU = "N/A"
        LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Error = $null
    }
    
    try {
        # Test connectivity first
        if (-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            $result.Status = "Offline"
            $result.Error = "Computer is not reachable"
            return $result
        }
        
        # Build script block
        $scriptBlock = {
            param(
                [string]$Domain,
                [string]$DomainUser,
                [string]$DomainPassword,
                [string]$OUPath,
                [string]$Action,
                [bool]$Restart
            )
            
            $output = @{
                Status = "Unknown"
                CurrentDomain = "N/A"
                Error = $null
            }
            
            try {
                # Get current domain/workgroup
                $currentDomain = (Get-WmiObject -Class Win32_ComputerSystem).Domain
                $output.CurrentDomain = $currentDomain
                
                if ($Action -eq "Join") {
                    # Check if already in domain
                    if ($currentDomain -eq $Domain) {
                        $output.Status = "Already Joined"
                        return $output
                    }
                    
                    # Prepare credentials
                    $cred = $null
                    if ($DomainUser -and $DomainPassword) {
                        $securePassword = ConvertTo-SecureString -String $DomainPassword -AsPlainText -Force
                        $cred = New-Object System.Management.Automation.PSCredential($DomainUser, $securePassword)
                    }
                    
                    # Join domain
                    if ($OUPath) {
                        Add-Computer -DomainName $Domain -OUPath $OUPath -Credential $cred -ErrorAction Stop
                    }
                    else {
                        Add-Computer -DomainName $Domain -Credential $cred -ErrorAction Stop
                    }
                    
                    $output.Status = "Joined Successfully"
                    
                    if ($Restart) {
                        Restart-Computer -Force
                    }
                }
                elseif ($Action -eq "Leave") {
                    # Check if in workgroup
                    if ($currentDomain -eq "WORKGROUP" -or $currentDomain -notlike "*.*") {
                        $output.Status = "Already in Workgroup"
                        return $output
                    }
                    
                    # Leave domain
                    Remove-Computer -UnjoinDomainCredential $cred -WorkgroupName "WORKGROUP" -ErrorAction Stop
                    
                    $output.Status = "Left Successfully"
                    
                    if ($Restart) {
                        Restart-Computer -Force
                    }
                }
            }
            catch {
                $output.Status = "Error"
                $output.Error = $_.Exception.Message
            }
            
            return $output
        }
        
        # Prepare password for remote execution
        $passwordPlain = $null
        if ($Password) {
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
            $passwordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        }
        
        # Execute remotely
        $invokeParams = @{
            ComputerName = $Computer
            ScriptBlock = $scriptBlock
            ArgumentList = @($DomainName, $User, $passwordPlain, $OU, $Operation, $ShouldRestart)
            ErrorAction = "Stop"
        }
        
        if ($Cred) {
            $invokeParams['Credential'] = $Cred
        }
        
        $joinResult = Invoke-Command @invokeParams
        
        $result.Status = $joinResult.Status
        $result.CurrentDomain = $joinResult.CurrentDomain
        $result.Error = $joinResult.Error
        $result.OU = if ($OU) { $OU } else { "Default" }
    }
    catch {
        $result.Status = "Error"
        $result.Error = $_.Exception.Message
    }
    
    return $result
}

# Main execution
Write-Host "Domain Join/Leave Tool" -ForegroundColor Cyan
Write-Host "=====================" -ForegroundColor Cyan
Write-Host ""

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

# Validate join operation requirements
if ($Action -eq "Join") {
    if (-not $DomainUser) {
        Write-Warning "DomainUser not specified. Will attempt join with current credentials."
    }
    if (-not $DomainPassword -and $DomainUser) {
        Write-Host "Please enter password for domain user: $DomainUser" -ForegroundColor Yellow
        $DomainPassword = Read-Host -AsSecureString "Password"
    }
}

Write-Host "Action: $Action" -ForegroundColor Yellow
Write-Host "Domain: $Domain" -ForegroundColor Yellow
if ($OUPath) {
    Write-Host "OU Path: $OUPath" -ForegroundColor Yellow
}
Write-Host "Found $($computers.Count) unique computer(s) to process" -ForegroundColor Green
if ($Restart) {
    Write-Host "Restart after operation: ENABLED" -ForegroundColor Cyan
}
Write-Host ""

# Confirm action
if (-not $PSCmdlet.ShouldProcess("$Action domain operation on $($computers.Count) computer(s)", "This will $Action computers from/to domain. Continue?")) {
    Write-Host "Operation cancelled." -ForegroundColor Yellow
    exit 0
}

# Process each computer
$results = @()
$total = $computers.Count
$current = 0

foreach ($computer in $computers) {
    $current++
    Write-Progress -Activity "Domain $Action Operation" -Status "Processing $computer ($current of $total)" -PercentComplete (($current / $total) * 100)
    
    Write-Host "[$current/$total] Processing $computer..." -NoNewline
    
    $result = Set-DomainJoin -Computer $computer -DomainName $Domain -User $DomainUser -Password $DomainPassword -OU $OUPath -Operation $Action -Cred $Credential -ShouldRestart $Restart.IsPresent
    
    $results += $result
    
    $statusColor = switch ($result.Status) {
        "Joined Successfully" { "Green" }
        "Left Successfully" { "Green" }
        "Already Joined" { "Yellow" }
        "Already in Workgroup" { "Yellow" }
        "Offline" { "Red" }
        "Error" { "Red" }
        default { "Gray" }
    }
    
    Write-Host " $($result.Status)" -ForegroundColor $statusColor
    if ($result.Error) {
        Write-Host "  Error: $($result.Error)" -ForegroundColor Red
    }
}

Write-Progress -Activity "Domain $Action Operation" -Completed

# Display summary
Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "========" -ForegroundColor Cyan
$success = ($results | Where-Object { $_.Status -like "*Successfully*" }).Count
$alreadyDone = ($results | Where-Object { $_.Status -like "Already*" }).Count
$offline = ($results | Where-Object { $_.Status -eq "Offline" }).Count
$errors = ($results | Where-Object { $_.Status -eq "Error" }).Count

Write-Host "Success:      $success" -ForegroundColor Green
Write-Host "Already Done: $alreadyDone" -ForegroundColor Yellow
Write-Host "Offline:      $offline" -ForegroundColor Red
Write-Host "Errors:       $errors" -ForegroundColor Red
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
Write-Host "Results:" -ForegroundColor Cyan
Write-Host "========" -ForegroundColor Cyan
$results | Format-Table -AutoSize ComputerName, Action, Status, CurrentDomain, Error

