<#
.SYNOPSIS
    Installs the NeoPass native messaging host for Chrome, Edge, and Firefox.
.DESCRIPTION
    Copies the native host binary and registers it with browser native messaging registries.
#>

param(
    [string]$BinaryPath = "",
    [string]$ChromeExtensionID = "",
    [string]$EdgeExtensionID = "",
    # Legacy parameter — treated as ChromeExtensionID if ChromeExtensionID is empty
    [string]$ExtensionID = ""
)

$ErrorActionPreference = "Stop"
$AppName = "com.quantum.passwordmanager"
$DisplayName = "NeoPass Native Host"

# Support legacy -ExtensionID parameter
if (-not $ChromeExtensionID -and $ExtensionID) {
    $ChromeExtensionID = $ExtensionID
}

# Determine binary path
if (-not $BinaryPath) {
    $BinaryPath = Join-Path $PSScriptRoot "..\bin\neopass-native-host.exe"
}

if (-not (Test-Path $BinaryPath)) {
    Write-Error "Native host binary not found at: $BinaryPath"
    exit 1
}

$BinaryPath = (Resolve-Path $BinaryPath).Path

# Install directory
$InstallDir = Join-Path $env:APPDATA "QuantumPasswordManager"
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

$InstalledBinary = Join-Path $InstallDir "neopass-native-host.exe"
Copy-Item -Path $BinaryPath -Destination $InstalledBinary -Force
Write-Host "Installed binary to: $InstalledBinary"

# Chrome manifest
$chromeOrigins = @()
if ($ChromeExtensionID) {
    $chromeOrigins += "chrome-extension://$ChromeExtensionID/"
}
$ChromeManifest = @{
    name = $AppName
    description = $DisplayName
    path = $InstalledBinary
    type = "stdio"
    allowed_origins = $chromeOrigins
} | ConvertTo-Json -Depth 3

$ChromeManifestPath = Join-Path $InstallDir "$AppName.chrome.json"
$ChromeManifest | Set-Content -Path $ChromeManifestPath -Encoding UTF8
Write-Host "Created Chrome manifest: $ChromeManifestPath"

# Edge manifest (separate file so Edge can have its own extension ID)
$edgeOrigins = @()
if ($EdgeExtensionID) {
    $edgeOrigins += "chrome-extension://$EdgeExtensionID/"
}
$EdgeManifest = @{
    name = $AppName
    description = $DisplayName
    path = $InstalledBinary
    type = "stdio"
    allowed_origins = $edgeOrigins
} | ConvertTo-Json -Depth 3

$EdgeManifestPath = Join-Path $InstallDir "$AppName.edge.json"
$EdgeManifest | Set-Content -Path $EdgeManifestPath -Encoding UTF8
Write-Host "Created Edge manifest: $EdgeManifestPath"

# Firefox manifest
$FirefoxManifest = @{
    name = $AppName
    description = $DisplayName
    path = $InstalledBinary
    type = "stdio"
    allowed_extensions = @("neopass@lancastergroup.com")
} | ConvertTo-Json -Depth 3

$FirefoxManifestPath = Join-Path $InstallDir "$AppName.firefox.json"
$FirefoxManifest | Set-Content -Path $FirefoxManifestPath -Encoding UTF8
Write-Host "Created Firefox manifest: $FirefoxManifestPath"

# Register in Windows Registry — Chrome
$ChromeRegPath = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$AppName"
if (-not (Test-Path $ChromeRegPath)) {
    New-Item -Path $ChromeRegPath -Force | Out-Null
}
Set-ItemProperty -Path $ChromeRegPath -Name "(Default)" -Value $ChromeManifestPath
Write-Host "Registered Chrome native messaging host"

# Register in Windows Registry — Edge
$EdgeRegPath = "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\$AppName"
if (-not (Test-Path $EdgeRegPath)) {
    New-Item -Path $EdgeRegPath -Force | Out-Null
}
Set-ItemProperty -Path $EdgeRegPath -Name "(Default)" -Value $EdgeManifestPath
Write-Host "Registered Edge native messaging host"

# Register in Windows Registry — Firefox
$FirefoxRegPath = "HKCU:\Software\Mozilla\NativeMessagingHosts\$AppName"
if (-not (Test-Path $FirefoxRegPath)) {
    New-Item -Path $FirefoxRegPath -Force | Out-Null
}
Set-ItemProperty -Path $FirefoxRegPath -Name "(Default)" -Value $FirefoxManifestPath
Write-Host "Registered Firefox native messaging host"

Write-Host ""
Write-Host "Native messaging host installed successfully." -ForegroundColor Green
Write-Host "Chrome Extension ID: $(if ($ChromeExtensionID) { $ChromeExtensionID } else { '(any)' })" -ForegroundColor Cyan
Write-Host "Edge Extension ID:   $(if ($EdgeExtensionID) { $EdgeExtensionID } else { '(any)' })" -ForegroundColor Cyan
Write-Host "Firefox Extension ID: neopass@lancastergroup.com" -ForegroundColor Cyan
Write-Host "Restart your browsers for changes to take effect."
