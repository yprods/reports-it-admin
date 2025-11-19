# IT Admin Portal - WPF Application

A cyber-style WPF application that serves as a gallery and launcher for PowerShell IT administration scripts.

## Features

- 🎨 **Cyber-style UI** with neon green/cyan theme
- 🌐 **Hebrew/English** language support
- 📁 **Dynamic Script Loading** - Automatically discovers PowerShell scripts
- 🔍 **Search & Filter** - Find scripts by name, description, or category
- 🚀 **Script Runner** - Execute scripts directly from the portal
- 📊 **Categorized Scripts** - Organized by Monitoring, User Management, AD, Security, Network, Installation

## Requirements

- .NET 8.0 SDK or later
- Windows 10/11
- PowerShell 5.1 or later
- Active Directory PowerShell Module (for AD scripts)

## Building the Project

### Using Visual Studio
1. Open `ITAdminPortal.csproj` in Visual Studio
2. Build → Build Solution (Ctrl+Shift+B)
3. Run → Start Debugging (F5)

### Using Command Line
```powershell
cd ITAdminPortal
dotnet build
dotnet run
```

### Build for Release
```powershell
cd ITAdminPortal
dotnet build --configuration Release
```

## Running the Application

### Option 1: Use the Launcher Scripts
From the project root directory:
```powershell
.\Launch-ITAdminPortal.ps1
```

Or use the batch file:
```cmd
Launch-ITAdminPortal.bat
```

### Option 2: Direct Execution
Navigate to the build output:
```powershell
cd ITAdminPortal\bin\Debug\net6.0-windows
.\ITAdminPortal.exe
```

### Option 3: Create Desktop Shortcut
```powershell
.\Create-DesktopShortcut.ps1
```

## Project Structure

```
ITAdminPortal/
├── App.xaml                 # Application definition
├── App.xaml.cs              # Application code-behind
├── MainWindow.xaml          # Main gallery window
├── MainWindow.xaml.cs       # Main window logic
├── ScriptRunnerWindow.xaml  # Script execution window
├── ScriptRunnerWindow.xaml.cs # Script runner logic
├── ScriptInfo.cs            # Script information model
├── Styles/
│   └── CyberTheme.xaml      # Cyber-style theme
├── app.manifest             # Application manifest
└── ITAdminPortal.csproj     # Project file
```

## Usage

1. **Launch the Portal** - Run the application using any method above
2. **Browse Scripts** - View all available PowerShell scripts organized by category
3. **Search** - Use the search box to find specific scripts
4. **Filter by Category** - Click category buttons to filter scripts
5. **Run Script** - Click on a script card to open the script runner
6. **Execute** - Click "Run Script" to execute the PowerShell script
7. **View Output** - See script output in the runner window

## Language Support

Click the "עברית / English" button in the top-right to toggle between Hebrew and English.

## Script Discovery

The application automatically discovers PowerShell scripts (`.ps1` files) in:
- Project root directory
- Current working directory
- Application directory
- Documents/reports-it-admin directory

## Troubleshooting

### Script Not Found
- Ensure PowerShell scripts are in the same directory as the launcher
- Check that script paths are correct in the error message
- Verify script file names match exactly

### Build Errors
- Ensure .NET 8.0 SDK is installed
- Run `dotnet restore` to restore packages
- Check that all dependencies are available

### Execution Errors
- Verify PowerShell execution policy allows script execution
- Ensure required PowerShell modules are installed
- Check that you have necessary permissions for the scripts

## Development

### Adding New Scripts
1. Add your PowerShell script to the project root
2. The application will automatically discover it
3. Scripts are categorized based on filename keywords

### Customizing Categories
Edit `MainWindow.xaml.cs` and modify the `DetermineCategory()` method to customize how scripts are categorized.

### Modifying Theme
Edit `Styles/CyberTheme.xaml` to customize the cyber-style appearance.

## License

This project is part of the IT Administration Scripts collection.
