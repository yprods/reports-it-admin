@echo off
REM IT Admin Portal Launcher Batch File
REM This batch file launches the IT Admin Portal WPF application

echo IT Admin Portal Launcher
echo =======================
echo.

set "PROJECT_PATH=%~dp0ITAdminPortal"
set "EXE_PATH=%PROJECT_PATH%\bin\Debug\net8.0-windows\ITAdminPortal.exe"
set "EXE_PATH_RELEASE=%PROJECT_PATH%\bin\Release\net8.0-windows\ITAdminPortal.exe"

REM Check if project directory exists
if not exist "%PROJECT_PATH%" (
    echo ERROR: Project directory not found: %PROJECT_PATH%
    pause
    exit /b 1
)

REM Check for executable
if exist "%EXE_PATH_RELEASE%" (
    set "EXE_TO_RUN=%EXE_PATH_RELEASE%"
) else if exist "%EXE_PATH%" (
    set "EXE_TO_RUN=%EXE_PATH%"
) else (
    echo Executable not found. Building project...
    echo.
    
    REM Try to build with dotnet
    cd /d "%PROJECT_PATH%"
    dotnet build --configuration Release
    
    if errorlevel 1 (
        echo.
        echo ERROR: Build failed!
        pause
        exit /b 1
    )
    
    if exist "bin\Release\net8.0-windows\ITAdminPortal.exe" (
        set "EXE_TO_RUN=%PROJECT_PATH%\bin\Release\net8.0-windows\ITAdminPortal.exe"
    ) else if exist "bin\Debug\net8.0-windows\ITAdminPortal.exe" (
        set "EXE_TO_RUN=%PROJECT_PATH%\bin\Debug\net8.0-windows\ITAdminPortal.exe"
    ) else (
        echo ERROR: Executable not found after build.
        pause
        exit /b 1
    )
    
    cd /d "%~dp0"
)

echo.
echo Launching IT Admin Portal...
echo Executable: %EXE_TO_RUN%
echo.

REM Launch the application
start "" "%EXE_TO_RUN%"

if errorlevel 1 (
    echo ERROR: Failed to launch application.
    pause
    exit /b 1
)

echo IT Admin Portal launched successfully!
timeout /t 2 >nul

