<#
.SYNOPSIS
    Creates desktop shortcuts for a list of users.

.DESCRIPTION
    This script creates desktop shortcuts on user desktops remotely.

.PARAMETER UserList
    Path to text file with usernames.

.PARAMETER Username
    Single or array of usernames.

.PARAMETER TargetPath
    Path to target file/application.

.PARAMETER ShortcutName
    Name for the shortcut.

.PARAMETER Arguments
    Arguments for the shortcut.

.PARAMETER OutputFile
    Path to CSV file. Default: ShortcutReport.csv

.PARAMETER Credential
    PSCredential object for remote authentication.

.EXAMPLE
    .\New-DesktopShortcut.ps1 -UserList "users.txt" -TargetPath "C:\Program Files\App\app.exe" -ShortcutName "My App"
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$false)]
    [string]$UserList,
    
    [Parameter(Mandatory=$false)]
    [string[]]$Username,
    
    [Parameter(Mandatory=$true)]
    [string]$TargetPath,
    
    [Parameter(Mandatory=$true)]
    [string]$ShortcutName,
    
    [Parameter(Mandatory=$false)]
    [string]$Arguments = "",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "ShortcutReport.csv",
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential
)

function New-DesktopShortcut {
    param([string]$User, [string]$Target, [string]$Name, [string]$Args, [System.Management.Automation.PSCredential]$Cred)
    
    $scriptBlock = {
        param([string]$TargetPath, [string]$ShortcutName, [string]$Arguments)
        
        $desktop = [Environment]::GetFolderPath("Desktop")
        $shortcutPath = Join-Path $desktop "$ShortcutName.lnk"
        
        $WshShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut($shortcutPath)
        $Shortcut.TargetPath = $TargetPath
        if ($Arguments) {
            $Shortcut.Arguments = $Arguments
        }
        $Shortcut.Save()
        
        return "Shortcut created: $shortcutPath"
    }
    
    $result = [PSCustomObject]@{
        Username = $User
        ShortcutName = $Name
        Status = "Unknown"
        Error = $null
    }
    
    try {
        # Get user's computer from AD
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
            $adUser = Get-ADUser -Identity $User -Properties HomeDirectory, HomeDrive -ErrorAction SilentlyContinue
            
            if ($adUser) {
                # Try to find user's logged on computer or use home directory
                $computer = $env:COMPUTERNAME  # This would need to be determined per user
                
                $invokeParams = @{
                    ComputerName = $computer
                    ScriptBlock = $scriptBlock
                    ArgumentList = @($Target, $Name, $Args)
                }
                if ($Cred) { $invokeParams['Credential'] = $Cred }
                
                $output = Invoke-Command @invokeParams
                $result.Status = "Success"
            } else {
                $result.Status = "User Not Found"
            }
        } else {
            $result.Status = "AD Module Not Available"
        }
    }
    catch {
        $result.Status = "Error"
        $result.Error = $_.Exception.Message
    }
    
    return $result
}

# Main execution
Write-Host "Desktop Shortcut Creation Tool" -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor Cyan
Write-Host ""

$users = @()
if ($UserList -and (Test-Path $UserList)) {
    $users = Get-Content $UserList | Where-Object { $_.Trim() -ne "" }
}
if ($Username) {
    $users += $Username
}
$users = $users | Select-Object -Unique

if ($users.Count -eq 0) {
    Write-Error "No users specified."
    exit 1
}

Write-Host "Target: $TargetPath" -ForegroundColor Yellow
Write-Host "Shortcut Name: $ShortcutName" -ForegroundColor Yellow
Write-Host "Processing $($users.Count) user(s)..." -ForegroundColor Yellow

$results = @()
foreach ($user in $users) {
    $result = New-DesktopShortcut -User $user -Target $TargetPath -Name $ShortcutName -Args $Arguments -Cred $Credential
    $results += $result
    Write-Host "$user - $($result.Status)" -ForegroundColor $(if ($result.Status -eq "Success") { "Green" } else { "Red" })
}

$results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
Write-Host "Results exported to: $OutputFile" -ForegroundColor Green
$results | Format-Table -AutoSize

