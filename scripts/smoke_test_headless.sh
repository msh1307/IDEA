#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -x .venv/bin/python ]]; then
  echo "Missing .venv. Run ./scripts/install_wsl.sh first." >&2
  exit 1
fi

WIN_USER="${IDA_WINDOWS_USER:-$(powershell.exe -NoProfile -Command '$env:USERNAME' 2>/dev/null | tr -d '\r' | tail -n 1)}"
TARGET="${1:-/mnt/c/Users/${WIN_USER}/Desktop/ssh-binaries/actionengined}"

PYTHONPATH="$ROOT/src" .venv/bin/python - <<'PY' "$TARGET"
import asyncio
import json
import sys

from ida_hybrid_manager.backend import call_backend_tool_any

TARGET = sys.argv[1]
MANAGER = ["http://127.0.0.1:18081/mcp"]


async def call(name, args):
    return await call_backend_tool_any(MANAGER, name, args)


async def main():
    opened = await call("open_binary", {"path": TARGET, "mode": "headless", "reuse": False})
    print("OPEN")
    print(json.dumps(opened, indent=2))
    sid = opened.get("structuredContent", {}).get("session_id")
    if not sid:
        return

    looked_up = await call("lookup_funcs", {"queries": ["0xa200"], "session_id": sid})
    print("LOOKUP")
    print(json.dumps(looked_up, indent=2)[:3000])

    closed = await call("close_session", {"session_id": sid, "save": False})
    print("CLOSE")
    print(json.dumps(closed, indent=2))


asyncio.run(main())
PY
