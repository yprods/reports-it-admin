# Secure Boot Status Query Tool

This PowerShell script queries Secure Boot status from multiple computers using WMI (Windows Management Instrumentation).

## Features

- Query Secure Boot status from multiple computers remotely
- Supports both SCCM and direct WMI queries
- Multiple fallback methods for maximum compatibility
- Export results to CSV
- Progress tracking and detailed error reporting
- Works with Windows 8/Server 2012 and later

## Prerequisites

- PowerShell 3.0 or later
- Administrative access to target computers
- WMI access enabled on target computers
- Network connectivity to target computers

## Usage

### Method 1: Using a Computer List File

1. Create a text file (`computers.txt`) with one computer name per line:
   ```
   PC01
   PC02
   SERVER01
   ```

2. Run the script:
   ```powershell
   .\Get-SecureBootStatus.ps1 -ComputerList "computers.txt"
   ```

### Method 2: Using Computer Names Directly

```powershell
.\Get-SecureBootStatus.ps1 -ComputerName "PC01","PC02","SERVER01"
```

### Method 3: With Custom Output File

```powershell
.\Get-SecureBootStatus.ps1 -ComputerList "computers.txt" -OutputFile "SecureBoot_Report_$(Get-Date -Format 'yyyyMMdd').csv"
```

### Method 4: With Credentials

```powershell
$cred = Get-Credential
.\Get-SecureBootStatus.ps1 -ComputerList "computers.txt" -Credential $cred
```

## Parameters

- **ComputerList** (Optional): Path to a text file containing computer names (one per line)
- **ComputerName** (Optional): Single computer name or array of computer names
- **OutputFile** (Optional): Path to CSV file for results. Default: `SecureBootReport.csv`
- **Credential** (Optional): PSCredential object for remote authentication

## How It Works

The script uses multiple methods to query Secure Boot status:

1. **Primary Method**: Queries the `SecureBootUEFI` WMI class in the `root\Microsoft\Windows\SecureBoot` namespace
2. **Fallback Method 1**: Queries the registry via WMI (`HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State\UEFISecureBootEnabled`)
3. **Fallback Method 2**: Tries alternative registry path
4. **Fallback Method 3**: Attempts to get basic system information if Secure Boot status is unavailable

## Output

The script generates:
- Console output with progress and summary
- CSV file with detailed results including:
  - ComputerName
  - SecureBootEnabled (True/False)
  - Status (Enabled/Disabled/Offline/Error/Unknown)
  - LastUpdated timestamp
  - Error messages (if any)

## Example Output

```
Secure Boot Status Query Tool
==============================

Found 3 computer(s) to query

[1/3] Querying PC01... Enabled
[2/3] Querying PC02... Disabled
[3/3] Querying SERVER01... Offline

Summary:
========
Enabled:  1
Disabled: 1
Offline:  1
Errors:   0
Unknown:  0

Results exported to: SecureBootReport.csv
```

## Troubleshooting

### "Access Denied" Errors
- Ensure you're running PowerShell as Administrator
- Verify you have administrative rights on target computers
- Check WMI permissions on target computers

### "Computer is not reachable"
- Verify network connectivity
- Check if Windows Firewall allows WMI traffic (ports 135, 445, and dynamic ports)
- Ensure target computers are powered on

### "Secure Boot status not available"
- Some older systems or non-UEFI systems may not support Secure Boot
- Virtual machines may not expose Secure Boot status via WMI

## SCCM Integration

If you're using SCCM, you can:

1. Export a list of computers from SCCM to use with this script
2. Use SCCM's built-in reporting for Secure Boot status
3. Run this script on computers managed by SCCM

## Notes

- The script requires WMI access, which may need to be enabled via Group Policy
- Some systems may require WinRM to be enabled for remote WMI queries
- Results are cached per query session

