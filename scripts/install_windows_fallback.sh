#!/usr/bin/env bash
set -euo pipefail

run_windows() {
  local attempt
  for attempt in 1 2 3; do
    "$@" && return 0
    ((attempt == 3)) || sleep 1
  done
  return 1
}

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FALLBACK_ROOT="${IDA_WINDOWS_FALLBACK_ROOT:-}"
if [[ -z "$FALLBACK_ROOT" ]]; then
  WINDOWS_LOCAL_APPDATA="$(
    run_windows powershell.exe -NoProfile -Command '[Environment]::GetFolderPath("LocalApplicationData")' |
      tr -d '\r'
  )"
  FALLBACK_ROOT="$(wslpath -u "${WINDOWS_LOCAL_APPDATA}\\ida-hybrid-manager")"
fi
if [[ "$FALLBACK_ROOT" =~ ^[A-Za-z]:[\\/].* ]]; then
  FALLBACK_ROOT="$(wslpath -u "$FALLBACK_ROOT")"
elif [[ "$FALLBACK_ROOT" =~ ^[A-Za-z]: ]]; then
  echo "Fallback root must be absolute: $FALLBACK_ROOT" >&2
  exit 2
fi
MARKER="$FALLBACK_ROOT/.ida-hybrid-manager-native"

mkdir -p "$FALLBACK_ROOT"
if [[ ! -f "$MARKER" ]] &&
   [[ -e "$FALLBACK_ROOT/src" || -e "$FALLBACK_ROOT/plugin_overlay" || -e "$FALLBACK_ROOT/.venv" ]]; then
  echo "Refusing to replace an unmarked fallback directory: $FALLBACK_ROOT" >&2
  exit 1
fi
touch "$MARKER"
rm -rf "$FALLBACK_ROOT/src" "$FALLBACK_ROOT/plugin_overlay"
cp -a "$REPO_ROOT/src" "$REPO_ROOT/plugin_overlay" "$FALLBACK_ROOT/"
cp "$REPO_ROOT/pyproject.toml" \
   "$REPO_ROOT/scripts/run_manager_fallback.ps1" \
   "$REPO_ROOT/scripts/install_windows_fallback.ps1" \
   "$FALLBACK_ROOT/"

WINDOWS_ROOT="$(wslpath -w "$FALLBACK_ROOT")"
DEPENDENCY_HASH="$(sha256sum "$FALLBACK_ROOT/pyproject.toml" | awk '{print $1}')"
DEPENDENCY_MARKER="$FALLBACK_ROOT/.ida-hybrid-manager-deps.sha256"
INSTALLED_HASH=""
if [[ -f "$DEPENDENCY_MARKER" ]]; then
  INSTALLED_HASH="$(tr -d '[:space:]' <"$DEPENDENCY_MARKER")"
fi
VENV_PYTHON="$FALLBACK_ROOT/.venv/Scripts/python.exe"
if [[ ! -f "$VENV_PYTHON" || "$INSTALLED_HASH" != "$DEPENDENCY_HASH" ]]; then
  if ! run_windows powershell.exe -NoProfile -ExecutionPolicy Bypass \
    -File "${WINDOWS_ROOT}\\install_windows_fallback.ps1" \
    -FallbackRoot "$WINDOWS_ROOT" \
    -SourceRoot "$WINDOWS_ROOT" >&2; then
    echo "Windows dependency refresh deferred until the native fallback is first used." >&2
  fi
fi
printf '%s\n' "$WINDOWS_ROOT"
