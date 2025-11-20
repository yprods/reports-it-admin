<#
.SYNOPSIS
    Creates hashed credentials for Run As operations.

.DESCRIPTION
    This script creates secure hashed credentials that can be used for Run As operations.
    The credentials are encrypted and can be stored securely for later use.

.PARAMETER Username
    Username for the credential.

.PARAMETER Password
    Password for the credential (will prompt if not provided).

.PARAMETER Domain
    Domain name (optional).

.PARAMETER OutputFile
    Path to save encrypted credential file. Default: credential.xml

.PARAMETER ExportToRegistry
    Export credential to registry (default: false).

.PARAMETER RegistryPath
    Registry path for credential storage (default: HKCU:\Software\ITAdmin\Credentials).

.PARAMETER UseSecureString
    Use SecureString encryption (default: true).

.EXAMPLE
    .\New-RunAsCredential.ps1 -Username "admin" -Password "P@ssw0rd" -OutputFile "admin.cred"
    
.EXAMPLE
    .\New-RunAsCredential.ps1 -Username "service.account" -Domain "CONTOSO" -ExportToRegistry
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Username,
    
    [Parameter(Mandatory=$false)]
    [string]$Password,
    
    [Parameter(Mandatory=$false)]
    [string]$Domain,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile = "credential.xml",
    
    [Parameter(Mandatory=$false)]
    [switch]$ExportToRegistry,
    
    [Parameter(Mandatory=$false)]
    [string]$RegistryPath = "HKCU:\Software\ITAdmin\Credentials",
    
    [Parameter(Mandatory=$false)]
    [switch]$UseSecureString = $true
)

# Main execution
Write-Host "Create Run As Credential Tool" -ForegroundColor Cyan
Write-Host "============================" -ForegroundColor Cyan
Write-Host ""

# Get password
if (-not $Password) {
    $securePassword = Read-Host -Prompt "Enter password" -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
    $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
}

# Build full username
$fullUsername = $Username
if ($Domain) {
    $fullUsername = "$Domain\$Username"
}

Write-Host "Username: $fullUsername" -ForegroundColor Yellow
Write-Host ""

# Create credential object
try {
    $securePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential($fullUsername, $securePassword)
    
    Write-Host "Credential created successfully" -ForegroundColor Green
    Write-Host ""
    
    # Export to file
    if ($UseSecureString) {
        # Export credential object (encrypted for current user)
        $credential | Export-Clixml -Path $OutputFile -Force
        Write-Host "Credential exported to: $OutputFile" -ForegroundColor Green
        Write-Host "  (Encrypted for current user: $env:USERNAME)" -ForegroundColor Gray
    }
    else {
        # Export as base64 encoded (less secure, but portable)
        $credentialBytes = [System.Text.Encoding]::UTF8.GetBytes("$fullUsername:$Password")
        $encodedCredential = [Convert]::ToBase64String($credentialBytes)
        $encodedCredential | Out-File -FilePath $OutputFile -Encoding UTF8 -Force
        Write-Host "Credential exported to: $OutputFile (Base64 encoded)" -ForegroundColor Yellow
        Write-Host "  WARNING: Base64 encoding is not secure! Use only for testing." -ForegroundColor Red
    }
    
    # Export to registry if requested
    if ($ExportToRegistry) {
        try {
            if (-not (Test-Path $RegistryPath)) {
                New-Item -Path $RegistryPath -Force | Out-Null
            }
            
            if ($UseSecureString) {
                # Store encrypted credential
                $credentialKey = "$RegistryPath\$Username"
                if (-not (Test-Path $credentialKey)) {
                    New-Item -Path $credentialKey -Force | Out-Null
                }
                
                # Convert to encrypted string
                $encryptedPassword = $credential.Password | ConvertFrom-SecureString
                
                Set-ItemProperty -Path $credentialKey -Name "Username" -Value $fullUsername -Force
                Set-ItemProperty -Path $credentialKey -Name "EncryptedPassword" -Value $encryptedPassword -Force
                if ($Domain) {
                    Set-ItemProperty -Path $credentialKey -Name "Domain" -Value $Domain -Force
                }
                
                Write-Host "Credential exported to registry: $credentialKey" -ForegroundColor Green
            }
            else {
                Write-Warning "Registry export requires UseSecureString. Skipping registry export."
            }
        }
        catch {
            Write-Warning "Failed to export to registry: $($_.Exception.Message)"
        }
    }
    
    Write-Host ""
    Write-Host "Usage Example:" -ForegroundColor Cyan
    Write-Host "  `$cred = Import-Clixml -Path `"$OutputFile`"" -ForegroundColor Gray
    Write-Host "  Start-Process -FilePath `"app.exe`" -Credential `$cred" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Or for registry:" -ForegroundColor Cyan
    Write-Host "  `$encrypted = (Get-ItemProperty `"$RegistryPath\$Username`").EncryptedPassword" -ForegroundColor Gray
    Write-Host "  `$secure = `$encrypted | ConvertTo-SecureString" -ForegroundColor Gray
    Write-Host "  `$cred = New-Object PSCredential(`"$fullUsername`", `$secure)" -ForegroundColor Gray
}
catch {
    Write-Error "Failed to create credential: $($_.Exception.Message)"
    exit 1
}

