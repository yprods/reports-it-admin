<#
.SYNOPSIS
    Creates an organizational tree based on user attributes (State and SamAccountName).

.DESCRIPTION
    This script generates an organizational tree/hierarchy based on Active Directory
    user attributes, organizing by state (st) and samaccountname patterns.

.PARAMETER Domain
    Domain to search (default: current domain).

.PARAMETER OutputFile
    Path to output file. Default: OrganizationTree.txt

.PARAMETER Credential
    PSCredential object for remote authentication (optional).

.PARAMETER Attribute
    Primary attribute to organize by (default: st for State).

.PARAMETER SecondaryAttribute
    Secondary attribute for sub-organization (default: SamAccountName prefix).

.EXAMPLE
    .\Get-OrganizationTree.ps1
    
.EXAMPLE
    .\Get-OrganizationTree.ps1 -Attribute "Department" -SecondaryAttribute "Title"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Domain,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "OrganizationTree.txt",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [string]$Attribute = "st",
    
    [Parameter(Mandatory=$false)]
    [string]$SecondaryAttribute = "SamAccountName"
)

# Main execution
Write-Host "Organization Tree Generator" -ForegroundColor Cyan
Write-Host "===========================" -ForegroundColor Cyan
Write-Host ""

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "Active Directory PowerShell module is required."
    exit 1
}

Import-Module ActiveDirectory -ErrorAction Stop

try {
    $adParams = @{
        Filter = "*"
        Properties = @($Attribute, $SecondaryAttribute, "Name", "SamAccountName", "Department", "Title", "Manager")
        ErrorAction = "Stop"
    }
    
    if ($Domain) { $adParams['Server'] = $Domain }
    if ($Credential) { $adParams['Credential'] = $Credential }
    
    Write-Host "Querying users..." -ForegroundColor Yellow
    $users = Get-ADUser @adParams
    
    Write-Host "Found $($users.Count) users" -ForegroundColor Green
    Write-Host "Building tree..." -ForegroundColor Yellow
    
    $tree = @{}
    
    foreach ($user in $users) {
        $primaryValue = if ($user.$Attribute) { $user.$Attribute } else { "Unknown" }
        $secondaryValue = if ($user.$SecondaryAttribute) { 
            if ($SecondaryAttribute -eq "SamAccountName") {
                $user.SamAccountName.Substring(0, [Math]::Min(3, $user.SamAccountName.Length))
            } else {
                $user.$SecondaryAttribute
            }
        } else { "Unknown" }
        
        if (-not $tree.ContainsKey($primaryValue)) {
            $tree[$primaryValue] = @{}
        }
        if (-not $tree[$primaryValue].ContainsKey($secondaryValue)) {
            $tree[$primaryValue][$secondaryValue] = @()
        }
        
        $tree[$primaryValue][$secondaryValue] += $user
    }
    
    $output = @()
    $output += "ORGANIZATION TREE"
    $output += "================="
    $output += ""
    $output += "Organized by: $Attribute (Primary), $SecondaryAttribute (Secondary)"
    $output += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $output += ""
    
    foreach ($primary in ($tree.Keys | Sort-Object)) {
        $output += "[$primary]"
        $output += "-" * 50
        foreach ($secondary in ($tree[$primary].Keys | Sort-Object)) {
            $output += "  [$secondary]"
            foreach ($user in $tree[$primary][$secondary]) {
                $output += "    - $($user.Name) ($($user.SamAccountName))"
            }
            $output += ""
        }
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

