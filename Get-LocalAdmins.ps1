<#
.SYNOPSIS
    Retrieves local administrator accounts from all computers in the domain.

.DESCRIPTION
    This script queries all computers in the domain to retrieve local administrator
    group members using WMI and PowerShell remoting.

.PARAMETER ComputerList
    Path to a text file containing computer names (one per line).

.PARAMETER ComputerName
    Single computer name or array of computer names to query.

.PARAMETER Domain
    Query all computers in the specified domain (default: current domain).

.PARAMETER OutputFile
    Path to CSV file where results will be exported. Default: LocalAdminsReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication (optional).

.EXAMPLE
    .\Get-LocalAdmins.ps1 -ComputerList "computers.txt"
    
.EXAMPLE
    .\Get-LocalAdmins.ps1 -ComputerName "PC01","PC02","PC03"
    
.EXAMPLE
    .\Get-LocalAdmins.ps1 -Domain "contoso.com"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerList,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ComputerName,
    
    [Parameter(Mandatory=$false)]
    [string]$Domain,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "LocalAdminsReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential
)

# Function to get local administrators from a single computer
function Get-LocalAdmins {
    param(
        [string]$Computer,
        [System.Management.Automation.PSCredential]$Cred
    )
    
    $results = @()
    
    try {
        # Test connectivity first
        if (-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
            $result = [PSCustomObject]@{
                ComputerName = $Computer
                AdminAccount = "N/A"
                AccountType = "N/A"
                Domain = "N/A"
                SID = "N/A"
                Status = "Offline"
                Error = "Computer is not reachable"
            }
            $results += $result
            return $results
        }
        
        # Method 1: Use WinRM/PowerShell remoting
        try {
            $scriptBlock = {
                try {
                    $admins = @()
                    $adminGroup = [ADSI]"WinNT://./Administrators,group"
                    $members = $adminGroup.Members()
                    
                    foreach ($member in $members) {
                        $memberPath = $member.GetType().InvokeMember("ADsPath", "GetProperty", $null, $member, $null)
                        $memberType = $member.GetType().InvokeMember("Class", "GetProperty", $null, $member, $null)
                        
                        # Parse account information
                        if ($memberPath -like "WinNT://*") {
                            $parts = $memberPath -replace "WinNT://", "" -split "/"
                            $domainName = $parts[0]
                            $accountName = $parts[1]
                            
                            # Get SID
                            $sid = $null
                            try {
                                $account = [ADSI]$memberPath
                                $sidBytes = $account.objectSid
                                if ($sidBytes) {
                                    $sid = (New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)).Value
                                }
                            }
                            catch {
                                # SID retrieval failed, continue
                            }
                            
                            $admins += @{
                                Account = $accountName
                                Domain = $domainName
                                Type = $memberType
                                SID = $sid
                            }
                        }
                    }
                    return $admins
                }
                catch {
                    return @(@{
                        Account = "Error"
                        Domain = "N/A"
                        Type = "Error"
                        SID = "N/A"
                        Error = $_.Exception.Message
                    })
                }
            }
            
            $invokeParams = @{
                ComputerName = $Computer
                ScriptBlock = $scriptBlock
                ErrorAction = "Stop"
            }
            
            if ($Cred) {
                $invokeParams['Credential'] = $Cred
            }
            
            $adminAccounts = Invoke-Command @invokeParams
            
            foreach ($admin in $adminAccounts) {
                $result = [PSCustomObject]@{
                    ComputerName = $Computer
                    AdminAccount = $admin.Account
                    AccountType = $admin.Type
                    Domain = $admin.Domain
                    SID = if ($admin.SID) { $admin.SID } else { "N/A" }
                    Status = "Success"
                    Error = if ($admin.Error) { $admin.Error } else { $null }
                }
                $results += $result
            }
        }
        catch {
            # Method 2: Try WMI Win32_GroupUser
            try {
                $groupParams = @{
                    ComputerName = $Computer
                    Class = "Win32_GroupUser"
                    ErrorAction = "Stop"
                }
                
                if ($Cred) {
                    $groupParams['Credential'] = $Cred
                }
                
                $groupUsers = Get-CimInstance @groupParams
                $adminGroup = $groupUsers | Where-Object {
                    $group = Get-CimInstance -InputObject $_ -ResultClassName Win32_Group
                    $group -and $group.Name -eq "Administrators"
                }
                
                foreach ($groupUser in $adminGroup) {
                    $user = Get-CimInstance -InputObject $groupUser -ResultClassName Win32_Account
                    if ($user) {
                        $result = [PSCustomObject]@{
                            ComputerName = $Computer
                            AdminAccount = $user.Name
                            AccountType = $user.Class
                            Domain = $user.Domain
                            SID = $user.SID
                            Status = "Success"
                            Error = $null
                        }
                        $results += $result
                    }
                }
            }
            catch {
                $result = [PSCustomObject]@{
                    ComputerName = $Computer
                    AdminAccount = "N/A"
                    AccountType = "N/A"
                    Domain = "N/A"
                    SID = "N/A"
                    Status = "Error"
                    Error = $_.Exception.Message
                }
                $results += $result
            }
        }
    }
    catch {
        $result = [PSCustomObject]@{
            ComputerName = $Computer
            AdminAccount = "N/A"
            AccountType = "N/A"
            Domain = "N/A"
            SID = "N/A"
            Status = "Error"
            Error = $_.Exception.Message
        }
        $results += $result
    }
    
    # If no results, add a default entry
    if ($results.Count -eq 0) {
        $result = [PSCustomObject]@{
            ComputerName = $Computer
            AdminAccount = "N/A"
            AccountType = "N/A"
            Domain = "N/A"
            SID = "N/A"
            Status = "No Admins Found"
            Error = "Could not retrieve local administrators"
        }
        $results += $result
    }
    
    return $results
}

# Main execution
Write-Host "Local Administrators Query Tool" -ForegroundColor Cyan
Write-Host "===============================" -ForegroundColor Cyan
Write-Host ""

# Collect computer names
$computers = @()

if ($Domain) {
    try {
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            Write-Warning "Active Directory module not found. Install RSAT-AD-PowerShell feature."
        }
        else {
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
            Write-Host "Querying computers from domain: $Domain" -ForegroundColor Yellow
            
            try {
                $domainParams = @{
                    Filter = *
                    Properties = Name
                }
                if ($Credential) {
                    $domainParams['Credential'] = $Credential
                    $domainParams['Server'] = $Domain
                }
                $domainComputers = Get-ADComputer @domainParams | Select-Object -ExpandProperty Name
                $computers += $domainComputers
                Write-Host "Found $($domainComputers.Count) computer(s) in domain" -ForegroundColor Green
            }
            catch {
                Write-Warning "Could not query domain. Error: $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Warning "Active Directory query failed: $($_.Exception.Message)"
    }
}

if ($ComputerList) {
    if (Test-Path $ComputerList) {
        Write-Host "Reading computer list from: $ComputerList" -ForegroundColor Yellow
        $computers += Get-Content $ComputerList | Where-Object { $_.Trim() -ne "" } | ForEach-Object { $_.Trim() }
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
    Write-Error "No computers specified. Use -ComputerList, -ComputerName, or -Domain parameter."
    exit 1
}

Write-Host "Found $($computers.Count) unique computer(s) to query" -ForegroundColor Green
Write-Host ""

# Query each computer
$allResults = @()
$total = $computers.Count
$current = 0

foreach ($computer in $computers) {
    $current++
    Write-Progress -Activity "Querying Local Administrators" -Status "Processing $computer ($current of $total)" -PercentComplete (($current / $total) * 100)
    
    Write-Host "[$current/$total] Querying $computer..." -NoNewline
    
    $results = Get-LocalAdmins -Computer $computer -Cred $Credential
    $allResults += $results
    
    $successCount = ($results | Where-Object { $_.Status -eq "Success" }).Count
    
    if ($successCount -gt 0) {
        Write-Host " Found $successCount admin(s)" -ForegroundColor Green
        foreach ($admin in $results | Where-Object { $_.Status -eq "Success" }) {
            Write-Host "  - $($admin.Domain)\$($admin.AdminAccount)" -ForegroundColor Gray
        }
    }
    else {
        $statusColor = switch ($results[0].Status) {
            "Offline" { "Red" }
            "Error" { "Red" }
            "No Admins Found" { "Yellow" }
            default { "Gray" }
        }
        Write-Host " $($results[0].Status)" -ForegroundColor $statusColor
        if ($results[0].Error) {
            Write-Host "  Error: $($results[0].Error)" -ForegroundColor Red
        }
    }
}

Write-Progress -Activity "Querying Local Administrators" -Completed

# Display summary
Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "========" -ForegroundColor Cyan
$totalAdmins = ($allResults | Where-Object { $_.Status -eq "Success" }).Count
$uniqueAdmins = ($allResults | Where-Object { $_.Status -eq "Success" } | Select-Object -Unique AdminAccount, Domain).Count
$offline = ($allResults | Where-Object { $_.Status -eq "Offline" }).Count
$errors = ($allResults | Where-Object { $_.Status -eq "Error" }).Count
$notFound = ($allResults | Where-Object { $_.Status -eq "No Admins Found" }).Count

Write-Host "Total Admin Entries: $totalAdmins" -ForegroundColor Green
Write-Host "Unique Admin Accounts: $uniqueAdmins" -ForegroundColor Cyan
Write-Host "Offline:              $offline" -ForegroundColor Red
Write-Host "Errors:               $errors" -ForegroundColor Red
Write-Host "Not Found:            $notFound" -ForegroundColor Yellow
Write-Host ""

# Export to CSV
try {
    $allResults | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
    Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
}
catch {
    Write-Error "Failed to export results: $($_.Exception.Message)"
}

# Display results table
Write-Host ""
Write-Host "Detailed Results:" -ForegroundColor Cyan
Write-Host "================" -ForegroundColor Cyan
$allResults | Where-Object { $_.Status -eq "Success" } | Format-Table -AutoSize ComputerName, Domain, AdminAccount, AccountType

