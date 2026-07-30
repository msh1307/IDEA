#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
WINDOWS_FALLBACK_ROOT="$(bash scripts/install_windows_fallback.sh)"
IDA_WINDOWS_FALLBACK_ROOT="$WINDOWS_FALLBACK_ROOT" python scripts/install_codex_config.py

echo "Installed ida-hybrid-manager into $ROOT/.venv"
echo "Installed Windows fallback into $WINDOWS_FALLBACK_ROOT"
