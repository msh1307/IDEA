param(
    [string]$PluginRoot = "$env:APPDATA\Hex-Rays\IDA Pro\plugins"
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$OverlayRoot = Join-Path $RepoRoot "plugin_overlay"
$TargetPackage = Join-Path $PluginRoot "ida_mcp"
$TargetLoader = Join-Path $PluginRoot "ida_mcp.py"

if (-not (Test-Path $OverlayRoot)) {
    throw "Plugin bundle root not found: $OverlayRoot"
}

New-Item -ItemType Directory -Path $PluginRoot -Force | Out-Null

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$backup = Join-Path $PluginRoot ("ida-hybrid-backup-" + $timestamp)

if ((Test-Path $TargetLoader) -or (Test-Path $TargetPackage)) {
    New-Item -ItemType Directory -Path $backup | Out-Null
    if (Test-Path $TargetLoader) {
        Copy-Item $TargetLoader -Destination $backup -Force
    }
    if (Test-Path $TargetPackage) {
        Copy-Item $TargetPackage -Destination $backup -Recurse -Force
    }
    Write-Output ("Backup: " + $backup)
}

if (Test-Path $TargetLoader) {
    Remove-Item $TargetLoader -Force
}
if (Test-Path $TargetPackage) {
    Remove-Item $TargetPackage -Recurse -Force
}

New-Item -ItemType Directory -Path $TargetPackage -Force | Out-Null
Copy-Item (Join-Path $OverlayRoot "ida_mcp.py") -Destination $TargetLoader -Force
Copy-Item (Join-Path $OverlayRoot "ida_mcp\*") -Destination $TargetPackage -Recurse -Force

Write-Output "Plugin bundle installed."
