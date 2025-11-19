<#
.SYNOPSIS
    Builds a tree of all Active Directory objects by numbers of each kind.

.DESCRIPTION
    This script creates a comprehensive tree showing counts of all AD object types.

.PARAMETER Domain
    Domain to search (default: current domain).

.PARAMETER OutputFile
    Path to output file. Default: ADObjectTree.txt

.PARAMETER Credential
    PSCredential object for remote authentication.

.PARAMETER SearchBase
    Specific OU to start from (default: entire domain).

.EXAMPLE
    .\Get-ADObjectTree.ps1
    
.EXAMPLE
    .\Get-ADObjectTree.ps1 -SearchBase "OU=Users,DC=contoso,DC=com"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Domain,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "ADObjectTree.txt",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [string]$SearchBase
)

# Main execution
Write-Host "AD Object Tree Builder" -ForegroundColor Cyan
Write-Host "======================" -ForegroundColor Cyan
Write-Host ""

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "Active Directory PowerShell module is required."
    exit 1
}

Import-Module ActiveDirectory -ErrorAction Stop

try {
    $adParams = @{ ErrorAction = "Stop" }
    if ($Domain) { $adParams['Server'] = $Domain }
    if ($Credential) { $adParams['Credential'] = $Credential }
    if ($SearchBase) { $adParams['SearchBase'] = $SearchBase }
    
    Write-Host "Querying Active Directory objects..." -ForegroundColor Yellow
    
    # Count different object types
    $users = (Get-ADUser -Filter * @adParams).Count
    $computers = (Get-ADComputer -Filter * @adParams).Count
    $groups = (Get-ADGroup -Filter * @adParams).Count
    $ous = (Get-ADOrganizationalUnit -Filter * @adParams).Count
    
    # Get OUs with counts
    $ouTree = @{}
    $allOUs = Get-ADOrganizationalUnit -Filter * @adParams
    
    foreach ($ou in $allOUs) {
        $ouUsers = (Get-ADUser -SearchBase $ou.DistinguishedName -Filter * @adParams).Count
        $ouComputers = (Get-ADComputer -SearchBase $ou.DistinguishedName -Filter * @adParams).Count
        $ouGroups = (Get-ADGroup -SearchBase $ou.DistinguishedName -Filter * @adParams).Count
        
        $ouTree[$ou.DistinguishedName] = @{
            Name = $ou.Name
            Users = $ouUsers
            Computers = $ouComputers
            Groups = $ouGroups
            Path = $ou.CanonicalName
        }
    }
    
    $output = @()
    $output += "ACTIVE DIRECTORY OBJECT TREE"
    $output += "============================"
    $output += ""
    $output += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $output += ""
    $output += "TOTAL COUNTS"
    $output += "------------"
    $output += "Users:      $users"
    $output += "Computers:  $computers"
    $output += "Groups:     $groups"
    $output += "OUs:        $ous"
    $output += ""
    $output += "OBJECTS BY ORGANIZATIONAL UNIT"
    $output += "==============================="
    $output += ""
    
    foreach ($ou in ($ouTree.Keys | Sort-Object)) {
        $ouData = $ouTree[$ou]
        $output += "[$($ouData.Name)]"
        $output += "  Path: $($ouData.Path)"
        $output += "  Users: $($ouData.Users)"
        $output += "  Computers: $($ouData.Computers)"
        $output += "  Groups: $($ouData.Groups)"
        $output += ""
    }
    
    $output | Out-File -FilePath $OutputFile -Encoding UTF8
    $output | Write-Host
    
    Write-Host ""
    Write-Host "Tree exported to: $OutputFile" -ForegroundColor Green
}
catch {
    Write-Error "Failed: $($_.Exception.Message)"
    exit 1
}

