#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

usage() {
  echo "Usage: $0 [--root WINDOWS_OR_WSL_PATH]"
}

MANAGER_ROOT=""
while (($#)); do
  case "$1" in
    --root)
      [[ $# -ge 2 && -n "$2" ]] || { usage >&2; exit 2; }
      MANAGER_ROOT="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

CONFIG_ARGS=(--repo-root "$ROOT")
if [[ -n "$MANAGER_ROOT" ]]; then
  CONFIG_ARGS+=(--root "$MANAGER_ROOT")
fi
CONFIG_OUTPUT="$(python3 -m scripts.install_manager_config "${CONFIG_ARGS[@]}")"
mapfile -t INSTALL_CONFIG <<<"$CONFIG_OUTPUT"
[[ ${#INSTALL_CONFIG[@]} -eq 12 ]] || {
  echo "Invalid install config output" >&2
  exit 1
}
CONFIG_WINDOWS="${INSTALL_CONFIG[0]}"
MANAGER_WINDOWS="${INSTALL_CONFIG[1]}"
FALLBACK_WSL="${INSTALL_CONFIG[2]}"
FALLBACK_WINDOWS="${INSTALL_CONFIG[3]}"
STAGE_WINDOWS="${INSTALL_CONFIG[4]}"
TEMP_WINDOWS="${INSTALL_CONFIG[5]}"
ARTIFACT_WINDOWS="${INSTALL_CONFIG[6]}"
REPLAY_WINDOWS="${INSTALL_CONFIG[7]}"
IDA_ROOT="${INSTALL_CONFIG[8]}"
WSL_DISTRO="${INSTALL_CONFIG[9]}"
PROFILE="${INSTALL_CONFIG[10]}"
WINDOWS_USER="${INSTALL_CONFIG[11]}"

python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
WINDOWS_FALLBACK_ROOT="$(
  IDA_WINDOWS_FALLBACK_ROOT="$FALLBACK_WSL" bash scripts/install_windows_fallback.sh
)"
[[ "$WINDOWS_FALLBACK_ROOT" == "$FALLBACK_WINDOWS" ]] || {
  echo "Fallback path mismatch: $WINDOWS_FALLBACK_ROOT != $FALLBACK_WINDOWS" >&2
  exit 1
}
IDA_MANAGER_CONFIG="$CONFIG_WINDOWS" \
  IDA_WINDOWS_FALLBACK_ROOT="$FALLBACK_WINDOWS" \
  IDA_MCP_STAGE_ROOT="$STAGE_WINDOWS" \
  IDA_WINDOWS_TEMP="$TEMP_WINDOWS" \
  IDA_MCP_ARTIFACT_DIR="$ARTIFACT_WINDOWS" \
  IDA_MCP_REPLAY_DIR="$REPLAY_WINDOWS" \
  IDA_INSTALL_ROOT="$IDA_ROOT" \
  IDA_WSL_DISTRO="$WSL_DISTRO" \
  IDA_MCP_PROFILE="$PROFILE" \
  IDA_WINDOWS_USER="$WINDOWS_USER" \
  python scripts/install_codex_config.py

echo "Installed ida-hybrid-manager into $ROOT/.venv"
echo "Installed Windows fallback into $WINDOWS_FALLBACK_ROOT"
echo "Install config: $CONFIG_WINDOWS"
echo "Manager root: $MANAGER_WINDOWS"
