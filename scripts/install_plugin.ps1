param(
    [string]$PluginRoot = "$env:APPDATA\Hex-Rays\IDA Pro\plugins"
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$OverlayRoot = Join-Path $RepoRoot "plugin_overlay"
$TargetPackage = Join-Path $PluginRoot "idea_ida_backend"
$TargetLoader = Join-Path $PluginRoot "idea_ida.py"
$LegacyPackage = Join-Path $PluginRoot "ida_mcp"
$LegacyLoader = Join-Path $PluginRoot "ida_mcp.py"
$PluginHome = Split-Path -Parent $PluginRoot
$BackupRoot = Join-Path $PluginHome "plugin-backups"

if (-not (Test-Path $OverlayRoot)) {
    throw "Plugin bundle root not found: $OverlayRoot"
}

New-Item -ItemType Directory -Path $PluginRoot -Force | Out-Null
New-Item -ItemType Directory -Path $BackupRoot -Force | Out-Null

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$backup = Join-Path $BackupRoot ("ida-hybrid-backup-" + $timestamp)

if ((Test-Path $TargetLoader) -or (Test-Path $TargetPackage) -or (Test-Path $LegacyLoader) -or (Test-Path $LegacyPackage)) {
    New-Item -ItemType Directory -Path $backup | Out-Null
    if (Test-Path $TargetLoader) {
        Copy-Item $TargetLoader -Destination $backup -Force
    }
    if (Test-Path $TargetPackage) {
        Copy-Item $TargetPackage -Destination $backup -Recurse -Force
    }
    if (Test-Path $LegacyLoader) {
        Copy-Item $LegacyLoader -Destination $backup -Force
    }
    if (Test-Path $LegacyPackage) {
        Copy-Item $LegacyPackage -Destination $backup -Recurse -Force
    }
    Write-Output ("Backup: " + $backup)
}

if (Test-Path $TargetLoader) {
    Remove-Item $TargetLoader -Force
}
if (Test-Path $TargetPackage) {
    Remove-Item $TargetPackage -Recurse -Force
}
if (Test-Path $LegacyLoader) {
    Remove-Item $LegacyLoader -Force
}
if (Test-Path $LegacyPackage) {
    Remove-Item $LegacyPackage -Recurse -Force
}

New-Item -ItemType Directory -Path $TargetPackage -Force | Out-Null
Copy-Item (Join-Path $OverlayRoot "idea_ida.py") -Destination $TargetLoader -Force
Copy-Item (Join-Path $OverlayRoot "idea_ida_backend\*") -Destination $TargetPackage -Recurse -Force

Write-Output "Plugin bundle installed."
