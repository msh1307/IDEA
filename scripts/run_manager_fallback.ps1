param(
    [string]$Config = "",
    [string]$Distro = "Ubuntu-24.04",
    [string]$WslRepo = "/root/ida-hybrid-manager",
    [string]$StageRoot = "",
    [string]$IdaInstallRoot = "C:\Program Files\IDA Professional 9.3",
    [string]$Profile = "lite"
)

$ErrorActionPreference = "Stop"
$FallbackRoot = $PSScriptRoot
$WindowsTemp = ""
$ArtifactRoot = ""
$ReplayRoot = ""

function Convert-ToWslPath([string]$Path) {
    if ($Path -match '^([A-Za-z]):[\\/](.*)$') {
        $drive = $Matches[1].ToLowerInvariant()
        $rest = $Matches[2].Replace('\', '/')
        return "/mnt/$drive/$rest"
    }
    return $Path
}

if ($Config) {
    if (-not (Test-Path -LiteralPath $Config)) {
        throw "Install config not found: $Config"
    }
    $settings = Get-Content -LiteralPath $Config -Raw | ConvertFrom-Json
    if ([int]$settings.version -ne 1) {
        throw "Unsupported install config version: $($settings.version)"
    }
    $Distro = [string]$settings.wsl_distro
    $WslRepo = [string]$settings.wsl_repo
    $StageRoot = [string]$settings.stage_root
    $IdaInstallRoot = [string]$settings.ida_install_root
    $Profile = [string]$settings.profile
    $WindowsTemp = [string]$settings.temp_root
    $ArtifactRoot = [string]$settings.artifact_root
    $ReplayRoot = [string]$settings.replay_root
    if ([IO.Path]::GetFullPath([string]$settings.fallback_root) -ne [IO.Path]::GetFullPath($FallbackRoot)) {
        throw "Install config fallback_root does not match the launcher location."
    }
}

$forceWindows = $env:IDA_FORCE_WINDOWS_FALLBACK -match '^(1|true|yes)$'
if (-not $forceWindows) {
    try {
        $health = Invoke-RestMethod -Uri "http://127.0.0.1:18080/healthz" -TimeoutSec 1
        $forceWindows = $health.host_platform -eq "windows"
    } catch {
        $forceWindows = $false
    }
}
$running = @()
if (-not $forceWindows) {
    try {
        $running = @(wsl.exe --list --running --quiet 2>$null)
    } catch {
        $running = @()
    }
}

if ($running -contains $Distro) {
    $wslStageRoot = Convert-ToWslPath $StageRoot
    $wslArgs = @(
        "-d", $Distro,
        "--cd", $WslRepo,
        "env",
        "IDA_INSTALL_ROOT=$IdaInstallRoot",
        "IDA_MCP_PROFILE=$Profile"
    )
    if ($wslStageRoot) {
        $wslArgs += "IDA_MCP_STAGE_ROOT=$wslStageRoot"
    }
    if ($WindowsTemp) {
        $wslArgs += "IDA_WSL_TEMP=$(Convert-ToWslPath $WindowsTemp)"
    }
    if ($ArtifactRoot) {
        $wslArgs += "IDA_MCP_ARTIFACT_DIR=$(Convert-ToWslPath $ArtifactRoot)"
    }
    if ($ReplayRoot) {
        $wslArgs += "IDA_MCP_REPLAY_DIR=$(Convert-ToWslPath $ReplayRoot)"
    }
    $wslArgs += @("./.venv/bin/python", "-m", "ida_hybrid_manager.server", "--transport", "stdio")
    & wsl.exe @wslArgs
    if ($LASTEXITCODE -eq 0) {
        exit 0
    }
}

$env:IDA_MCP_CONNECT_HOST = "127.0.0.1"
$env:IDA_INSTALL_ROOT = $IdaInstallRoot
$env:IDA_MCP_PROFILE = $Profile
if ($StageRoot) {
    $env:IDA_MCP_STAGE_ROOT = $StageRoot
}
if ($WindowsTemp) {
    $env:IDA_WINDOWS_TEMP = $WindowsTemp
}
if ($ArtifactRoot) {
    $env:IDA_MCP_ARTIFACT_DIR = $ArtifactRoot
}
if ($ReplayRoot) {
    $env:IDA_MCP_REPLAY_DIR = $ReplayRoot
}
& "$FallbackRoot\.venv\Scripts\python.exe" -m ida_hybrid_manager.server --transport stdio
exit $LASTEXITCODE
