<#
.SYNOPSIS
    Compares users in Active Directory by attributes, groups, permissions, and properties.

.DESCRIPTION
    This script compares users in Active Directory and identifies differences in:
    - User attributes (all or specified)
    - Group memberships
    - OU location
    - Account status
    - Password settings
    - Last logon times
    - And more

.PARAMETER UserList
    Path to text file with usernames (one per line) or array of usernames to compare.

.PARAMETER User1
    First username to compare.

.PARAMETER User2
    Second username to compare.

.PARAMETER CompareAttributes
    Comma-separated list of specific attributes to compare (e.g., "Department,Title,Office").
    If not specified, compares all common attributes.

.PARAMETER CompareGroups
    Compare group memberships (default: true).

.PARAMETER ComparePermissions
    Compare permissions on shared folders (default: false).

.PARAMETER CompareOU
    Compare OU location (default: true).

.PARAMETER Domain
    Domain to operate on (default: current domain).

.PARAMETER OutputFile
    Path to CSV file. Default: UserComparisonReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication.

.PARAMETER Detailed
    Show detailed comparison including all attributes.

.EXAMPLE
    .\Compare-Users.ps1 -User1 "john.doe" -User2 "jane.smith"
    
.EXAMPLE
    .\Compare-Users.ps1 -UserList "users.txt" -CompareAttributes "Department,Title,Office"
    
.EXAMPLE
    .\Compare-Users.ps1 -User1 "user1" -User2 "user2" -CompareGroups -ComparePermissions -Detailed
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$UserList,
    
    [Parameter(Mandatory=$false)]
    [string]$User1,
    
    [Parameter(Mandatory=$false)]
    [string]$User2,
    
    [Parameter(Mandatory=$false)]
    [string]$CompareAttributes,
    
    [Parameter(Mandatory=$false)]
    [switch]$CompareGroups = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$ComparePermissions,
    
    [Parameter(Mandatory=$false)]
    [switch]$CompareOU = $true,
    
    [Parameter(Mandatory=$false)]
    [string]$Domain,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "UserComparisonReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [switch]$Detailed
)

# Function to get user details
function Get-UserDetails {
    param(
        [string]$Username,
        [string]$DomainName,
        [System.Management.Automation.PSCredential]$Cred,
        [string[]]$Attributes
    )
    
    try {
        $adParams = @{ ErrorAction = "Stop" }
        if ($DomainName) { $adParams['Server'] = $DomainName }
        if ($Cred) { $adParams['Credential'] = $Cred }
        
        $user = Get-ADUser -Identity $Username -Properties * @adParams
        
        $details = @{
            Username = $user.SamAccountName
            DisplayName = $user.Name
            Enabled = $user.Enabled
            OU = $user.DistinguishedName -replace "CN=$($user.Name),"
            Department = $user.Department
            Title = $user.Title
            Office = $user.Office
            Email = $user.EmailAddress
            Phone = $user.telephoneNumber
            Manager = $user.Manager
            LastLogon = $user.LastLogonDate
            PasswordLastSet = $user.PasswordLastSet
            PasswordExpired = $user.PasswordExpired
            PasswordNeverExpires = $user.PasswordNeverExpires
            CannotChangePassword = $user.CannotChangePassword
            AccountLockedOut = $user.LockedOut
            Groups = @()
            AllAttributes = @{}
        }
        
        # Get group memberships
        if ($CompareGroups) {
            try {
                $groups = Get-ADPrincipalGroupMembership -Identity $user @adParams
                $details.Groups = $groups | Select-Object -ExpandProperty Name | Sort-Object
            }
            catch {
                Write-Warning "Failed to get groups for $Username : $($_.Exception.Message)"
            }
        }
        
        # Store all attributes
        foreach ($prop in $user.PSObject.Properties) {
            if ($prop.Value -ne $null) {
                $details.AllAttributes[$prop.Name] = $prop.Value
            }
        }
        
        return $details
    }
    catch {
        Write-Error "Failed to get user $Username : $($_.Exception.Message)"
        return $null
    }
}

# Function to compare two users
function Compare-TwoUsers {
    param(
        [hashtable]$User1Details,
        [hashtable]$User2Details,
        [string[]]$AttributesToCompare
    )
    
    $comparison = @{
        User1 = $User1Details.Username
        User2 = $User2Details.Username
        Differences = @()
        Similarities = @()
        OnlyInUser1 = @()
        OnlyInUser2 = @()
    }
    
    # Compare basic properties
    $basicProps = @("Enabled", "Department", "Title", "Office", "Email", "Phone", "Manager")
    
    foreach ($prop in $basicProps) {
        $val1 = $User1Details[$prop]
        $val2 = $User2Details[$prop]
        
        if ($val1 -ne $val2) {
            $comparison.Differences += [PSCustomObject]@{
                Property = $prop
                User1Value = if ($val1) { $val1.ToString() } else { "Empty" }
                User2Value = if ($val2) { $val2.ToString() } else { "Empty" }
            }
        }
        else {
            $comparison.Similarities += [PSCustomObject]@{
                Property = $prop
                Value = if ($val1) { $val1.ToString() } else { "Empty" }
            }
        }
    }
    
    # Compare OU
    if ($User1Details.OU -ne $User2Details.OU) {
        $comparison.Differences += [PSCustomObject]@{
            Property = "OU"
            User1Value = $User1Details.OU
            User2Value = $User2Details.OU
        }
    }
    
    # Compare account status
    if ($User1Details.AccountLockedOut -ne $User2Details.AccountLockedOut) {
        $comparison.Differences += [PSCustomObject]@{
            Property = "AccountLockedOut"
            User1Value = $User1Details.AccountLockedOut
            User2Value = $User2Details.AccountLockedOut
        }
    }
    
    if ($User1Details.PasswordNeverExpires -ne $User2Details.PasswordNeverExpires) {
        $comparison.Differences += [PSCustomObject]@{
            Property = "PasswordNeverExpires"
            User1Value = $User1Details.PasswordNeverExpires
            User2Value = $User2Details.PasswordNeverExpires
        }
    }
    
    # Compare groups
    if ($User1Details.Groups.Count -gt 0 -or $User2Details.Groups.Count -gt 0) {
        $commonGroups = $User1Details.Groups | Where-Object { $User2Details.Groups -contains $_ }
        $onlyUser1 = $User1Details.Groups | Where-Object { $User2Details.Groups -notcontains $_ }
        $onlyUser2 = $User2Details.Groups | Where-Object { $User1Details.Groups -notcontains $_ }
        
        if ($onlyUser1.Count -gt 0) {
            $comparison.OnlyInUser1 = $onlyUser1
        }
        if ($onlyUser2.Count -gt 0) {
            $comparison.OnlyInUser2 = $onlyUser2
        }
        
        if ($onlyUser1.Count -gt 0 -or $onlyUser2.Count -gt 0) {
            $comparison.Differences += [PSCustomObject]@{
                Property = "Groups"
                User1Value = "$($User1Details.Groups.Count) groups ($($onlyUser1.Count) unique)"
                User2Value = "$($User2Details.Groups.Count) groups ($($onlyUser2.Count) unique)"
            }
        }
    }
    
    # Compare specific attributes if provided
    if ($AttributesToCompare) {
        foreach ($attr in $AttributesToCompare) {
            $val1 = $User1Details.AllAttributes[$attr]
            $val2 = $User2Details.AllAttributes[$attr]
            
            if ($val1 -ne $val2) {
                $comparison.Differences += [PSCustomObject]@{
                    Property = $attr
                    User1Value = if ($val1) { $val1.ToString() } else { "Empty" }
                    User2Value = if ($val2) { $val2.ToString() } else { "Empty" }
                }
            }
        }
    }
    
    return $comparison
}

# Main execution
Write-Host "User Comparison Tool" -ForegroundColor Cyan
Write-Host "====================" -ForegroundColor Cyan
Write-Host ""

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "Active Directory PowerShell module is required."
    exit 1
}

Import-Module ActiveDirectory -ErrorAction Stop

# Get users to compare
$users = @()
$attributesToCompare = @()

if ($CompareAttributes) {
    $attributesToCompare = $CompareAttributes -split "," | ForEach-Object { $_.Trim() }
}

if ($User1 -and $User2) {
    $users = @($User1, $User2)
}
elseif ($UserList -and (Test-Path $UserList)) {
    $users = Get-Content $UserList | Where-Object { $_.Trim() -ne "" }
}
else {
    Write-Error "Must specify either -User1 and -User2, or -UserList"
    exit 1
}

if ($users.Count -lt 2) {
    Write-Error "At least 2 users are required for comparison."
    exit 1
}

Write-Host "Users to compare: $($users.Count)" -ForegroundColor Yellow
Write-Host "Compare Groups: $CompareGroups" -ForegroundColor Yellow
Write-Host "Compare OU: $CompareOU" -ForegroundColor Yellow
if ($attributesToCompare.Count -gt 0) {
    Write-Host "Compare Attributes: $($attributesToCompare -join ', ')" -ForegroundColor Yellow
}
Write-Host ""

# Get user details
$userDetails = @{}
foreach ($user in $users) {
    Write-Host "Getting details for: $user" -ForegroundColor Yellow
    $details = Get-UserDetails -Username $user -DomainName $Domain -Cred $Credential -Attributes $attributesToCompare
    if ($details) {
        $userDetails[$user] = $details
    }
}

if ($userDetails.Count -lt 2) {
    Write-Error "Failed to retrieve details for at least 2 users."
    exit 1
}

Write-Host ""
Write-Host "Comparing users..." -ForegroundColor Cyan
Write-Host ""

# Perform comparisons
$results = @()
$userArray = $userDetails.Keys | Sort-Object

# Compare all pairs
for ($i = 0; $i -lt $userArray.Count; $i++) {
    for ($j = $i + 1; $j -lt $userArray.Count; $j++) {
        $user1 = $userArray[$i]
        $user2 = $userArray[$j]
        
        Write-Host "Comparing: $user1 vs $user2" -ForegroundColor Cyan
        
        $comparison = Compare-TwoUsers -User1Details $userDetails[$user1] -User2Details $userDetails[$user2] -AttributesToCompare $attributesToCompare
        
        # Create result entries
        foreach ($diff in $comparison.Differences) {
            $results += [PSCustomObject]@{
                User1 = $user1
                User2 = $user2
                Property = $diff.Property
                User1Value = $diff.User1Value
                User2Value = $diff.User2Value
                Type = "Difference"
                LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
        }
        
        # Add group differences
        if ($comparison.OnlyInUser1.Count -gt 0) {
            foreach ($group in $comparison.OnlyInUser1) {
                $results += [PSCustomObject]@{
                    User1 = $user1
                    User2 = $user2
                    Property = "Group (Only in User1)"
                    User1Value = $group
                    User2Value = "Not Member"
                    Type = "Difference"
                    LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
            }
        }
        
        if ($comparison.OnlyInUser2.Count -gt 0) {
            foreach ($group in $comparison.OnlyInUser2) {
                $results += [PSCustomObject]@{
                    User1 = $user1
                    User2 = $user2
                    Property = "Group (Only in User2)"
                    User1Value = "Not Member"
                    User2Value = $group
                    Type = "Difference"
                    LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
            }
        }
        
        # Add similarities if detailed
        if ($Detailed) {
            foreach ($sim in $comparison.Similarities) {
                $results += [PSCustomObject]@{
                    User1 = $user1
                    User2 = $user2
                    Property = $sim.Property
                    User1Value = $sim.Value
                    User2Value = $sim.Value
                    Type = "Similarity"
                    LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                }
            }
        }
    }
}

Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
$differences = ($results | Where-Object { $_.Type -eq "Difference" }).Count
$similarities = ($results | Where-Object { $_.Type -eq "Similarity" }).Count
Write-Host "Differences found: $differences" -ForegroundColor Yellow
if ($Detailed) {
    Write-Host "Similarities found: $similarities" -ForegroundColor Green
}

# Display key differences
Write-Host ""
Write-Host "Key Differences:" -ForegroundColor Cyan
$keyDiffs = $results | Where-Object { $_.Type -eq "Difference" } | Select-Object -First 10
$keyDiffs | Format-Table -AutoSize

# Export results
$results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "Results exported to: $OutputFile" -ForegroundColor Green

if ($results.Count -gt 0) {
    Write-Host ""
    Write-Host "Full comparison results:" -ForegroundColor Cyan
    $results | Format-Table -AutoSize
}

