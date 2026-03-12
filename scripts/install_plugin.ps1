param(
    [string]$PluginRoot = "$env:APPDATA\Hex-Rays\IDA Pro\plugins"
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$OverlayRoot = Join-Path $RepoRoot "plugin_overlay"
$TargetPackage = Join-Path $PluginRoot "ida_mcp"
$TargetLoader = Join-Path $PluginRoot "ida_mcp.py"

if (-not (Test-Path $OverlayRoot)) {
    throw "Overlay root not found: $OverlayRoot"
}

if (-not (Test-Path $TargetPackage)) {
    throw "Target ida_mcp package not found: $TargetPackage"
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$backup = Join-Path $PluginRoot ("ida-hybrid-backup-" + $timestamp)
New-Item -ItemType Directory -Path $backup | Out-Null

Copy-Item $TargetLoader -Destination $backup -Force
Copy-Item $TargetPackage -Destination $backup -Recurse -Force

Copy-Item (Join-Path $OverlayRoot "ida_mcp.py") -Destination $TargetLoader -Force
Copy-Item (Join-Path $OverlayRoot "ida_mcp\*") -Destination $TargetPackage -Recurse -Force

Write-Output ("Backup: " + $backup)
Write-Output "Plugin overlay installed."
