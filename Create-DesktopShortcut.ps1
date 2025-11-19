<#
.SYNOPSIS
    Creates a desktop shortcut to launch the IT Admin Portal.

.DESCRIPTION
    This script creates a desktop shortcut that launches the IT Admin Portal WPF application.

.EXAMPLE
    .\Create-DesktopShortcut.ps1
#>

[CmdletBinding()]
param()

Write-Host "Creating Desktop Shortcut for IT Admin Portal" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

try {
    # Get desktop path
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $shortcutPath = Join-Path $desktopPath "IT Admin Portal.lnk"
    
    # Get launcher script path
    $launcherPath = Join-Path $PSScriptRoot "Launch-ITAdminPortal.ps1"
    
    # Create WScript Shell object
    $WScriptShell = New-Object -ComObject WScript.Shell
    $shortcut = $WScriptShell.CreateShortcut($shortcutPath)
    
    # Set shortcut properties
    $shortcut.TargetPath = "powershell.exe"
    $shortcut.Arguments = "-ExecutionPolicy Bypass -File `"$launcherPath`""
    $shortcut.WorkingDirectory = $PSScriptRoot
    $shortcut.Description = "IT Admin Portal - PowerShell Script Gallery"
    $shortcut.IconLocation = "powershell.exe,0"
    
    # Save shortcut
    $shortcut.Save()
    
    Write-Host "Desktop shortcut created successfully!" -ForegroundColor Green
    Write-Host "Location: $shortcutPath" -ForegroundColor Gray
    Write-Host ""
    Write-Host "You can now launch IT Admin Portal from your desktop." -ForegroundColor Yellow
}
catch {
    Write-Error "Failed to create shortcut: $($_.Exception.Message)"
    exit 1
}

