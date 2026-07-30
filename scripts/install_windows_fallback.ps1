param(
    [string]$FallbackRoot = "",
    [string]$SourceRoot = "",
    [string]$PythonVersion = "3.12"
)

$ErrorActionPreference = "Stop"
$RepoRoot = if ($SourceRoot) { $SourceRoot } else { Split-Path -Parent $PSScriptRoot }

if (-not $FallbackRoot) {
    $FallbackRoot = $env:IDA_WINDOWS_FALLBACK_ROOT
}
if (-not $FallbackRoot) {
    $FallbackRoot = Join-Path ([Environment]::GetFolderPath("LocalApplicationData")) "ida-hybrid-manager"
}

New-Item -ItemType Directory -Path $FallbackRoot -Force | Out-Null
$marker = Join-Path $FallbackRoot ".ida-hybrid-manager-native"
if (-not (Test-Path $marker)) {
    $managedEntries = @("src", "plugin_overlay", ".venv") |
        ForEach-Object { Join-Path $FallbackRoot $_ } |
        Where-Object { Test-Path $_ }
    if ($managedEntries) {
        throw "Refusing to replace an unmarked fallback directory: $FallbackRoot"
    }
    New-Item -ItemType File -Path $marker | Out-Null
}
if ([IO.Path]::GetFullPath($RepoRoot) -ne [IO.Path]::GetFullPath($FallbackRoot)) {
    foreach ($name in @("src", "plugin_overlay")) {
        $target = Join-Path $FallbackRoot $name
        if (Test-Path $target) {
            Remove-Item $target -Recurse -Force
        }
        Copy-Item (Join-Path $RepoRoot $name) -Destination $target -Recurse -Force
    }
    Copy-Item (Join-Path $RepoRoot "pyproject.toml") -Destination $FallbackRoot -Force
    Copy-Item (Join-Path $PSScriptRoot "run_manager_fallback.ps1") -Destination $FallbackRoot -Force
}

$venvPython = Join-Path $FallbackRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    & py.exe "-$PythonVersion" -m venv (Join-Path $FallbackRoot ".venv")
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create the Windows fallback virtual environment."
    }
}
& $venvPython -m pip install --disable-pip-version-check -e $FallbackRoot
if ($LASTEXITCODE -ne 0) {
    throw "Failed to install ida-hybrid-manager into the Windows fallback environment."
}

Write-Output $FallbackRoot
