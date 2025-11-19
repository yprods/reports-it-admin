<#
.SYNOPSIS
    Launches the IT Admin Portal WPF application.

.DESCRIPTION
    This script builds and launches the IT Admin Portal C# WPF application.
    It will build the project if needed and then launch the executable.

.PARAMETER Build
    Force rebuild the project before launching.

.PARAMETER NoBuild
    Skip building and just launch if executable exists.

.EXAMPLE
    .\Launch-ITAdminPortal.ps1
    
.EXAMPLE
    .\Launch-ITAdminPortal.ps1 -Build
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$Build,
    
    [Parameter(Mandatory=$false)]
    [switch]$NoBuild
)

Write-Host "IT Admin Portal Launcher" -ForegroundColor Cyan
Write-Host "=======================" -ForegroundColor Cyan
Write-Host ""

$projectPath = Join-Path $PSScriptRoot "ITAdminPortal"
$projectFile = Join-Path $projectPath "ITAdminPortal.csproj"
$exePath = Join-Path $projectPath "bin\Debug\net8.0-windows\ITAdminPortal.exe"
$exePathRelease = Join-Path $projectPath "bin\Release\net8.0-windows\ITAdminPortal.exe"

# Check if project exists
if (-not (Test-Path $projectFile)) {
    Write-Error "Project file not found: $projectFile"
    exit 1
}

# Build if needed
if (-not $NoBuild) {
    Write-Host "Checking build status..." -ForegroundColor Yellow
    
    $shouldBuild = $Build
    if (-not $shouldBuild) {
        # Check if executable exists
        if (-not (Test-Path $exePath) -and -not (Test-Path $exePathRelease)) {
            $shouldBuild = $true
            Write-Host "Executable not found. Building project..." -ForegroundColor Yellow
        }
    }
    
    if ($shouldBuild) {
        Write-Host "Building IT Admin Portal..." -ForegroundColor Yellow
        
        # Try to find dotnet CLI
        $dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
        if (-not $dotnet) {
            Write-Error "dotnet CLI not found. Please install .NET SDK."
            exit 1
        }
        
        Push-Location $projectPath
        try {
            if ($Build) {
                dotnet build --configuration Release
            }
            else {
                dotnet build
            }
            
            if ($LASTEXITCODE -ne 0) {
                Write-Error "Build failed!"
                exit 1
            }
            
            Write-Host "Build completed successfully!" -ForegroundColor Green
        }
        catch {
            Write-Error "Build error: $($_.Exception.Message)"
            exit 1
        }
        finally {
            Pop-Location
        }
    }
    else {
        Write-Host "Executable found. Skipping build." -ForegroundColor Green
    }
}

# Find executable
$exeToRun = $null
if (Test-Path $exePathRelease) {
    $exeToRun = $exePathRelease
}
elseif (Test-Path $exePath) {
    $exeToRun = $exePath
}

if (-not $exeToRun) {
    Write-Error "Executable not found. Please build the project first."
    exit 1
}

Write-Host ""
Write-Host "Launching IT Admin Portal..." -ForegroundColor Green
Write-Host "Executable: $exeToRun" -ForegroundColor Gray
Write-Host ""

# Launch the application
try {
    Start-Process -FilePath $exeToRun -WorkingDirectory (Split-Path $exeToRun -Parent)
    Write-Host "IT Admin Portal launched successfully!" -ForegroundColor Green
}
catch {
    Write-Error "Failed to launch application: $($_.Exception.Message)"
    exit 1
}

