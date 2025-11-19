# IT Admin Portal - WPF Application

A cyber-styled WPF portal application for managing and running PowerShell scripts.

## Features

- **Cyber Style Interface**: Modern dark theme with neon green/cyan accents
- **Hebrew/English Support**: Bilingual interface
- **Script Gallery**: Browse 40+ PowerShell scripts organized by category
- **Script Runner**: Execute scripts directly from the portal
- **Search Functionality**: Find scripts quickly
- **Category Filtering**: Filter scripts by category

## Categories

- **Monitoring**: System monitoring scripts
- **User Management**: User administration scripts
- **Computer Management**: Computer control scripts
- **Active Directory**: AD management scripts
- **Security**: Security-related scripts
- **Network**: Network tools
- **Installation**: Software installation scripts

## Requirements

- .NET 6.0 or later
- Windows OS
- PowerShell 5.1 or later
- Access to script files in parent directory

## Building

```bash
dotnet build
```

## Running

```bash
dotnet run
```

Or build and run the executable from the bin folder.

## Scripts Location

The portal expects PowerShell scripts to be in the parent directory of the project. Update the path in `ScriptRunnerWindow.xaml.cs` if your scripts are located elsewhere.

