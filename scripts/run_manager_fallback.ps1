param(
    [string]$Distro = "Ubuntu-24.04",
    [string]$WslRepo = "/root/ida-hybrid-manager",
    [string]$StageRoot = "",
    [string]$IdaInstallRoot = "C:\Program Files\IDA Professional 9.3",
    [string]$Profile = "lite"
)

$ErrorActionPreference = "Stop"
$FallbackRoot = $PSScriptRoot

function Convert-ToWslPath([string]$Path) {
    if ($Path -match '^([A-Za-z]):[\\/](.*)$') {
        $drive = $Matches[1].ToLowerInvariant()
        $rest = $Matches[2].Replace('\', '/')
        return "/mnt/$drive/$rest"
    }
    return $Path
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
& "$FallbackRoot\.venv\Scripts\python.exe" -m ida_hybrid_manager.server --transport stdio
exit $LASTEXITCODE
