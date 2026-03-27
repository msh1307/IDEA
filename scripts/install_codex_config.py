#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
from pathlib import Path


SECTION_NAME = "mcp_servers.ida-hybrid-manager"
SECTION_PATTERN = re.compile(
    rf"(?ms)^\[{re.escape(SECTION_NAME)}\]\n.*?(?=^\[|\Z)"
)


def _run(command: list[str]) -> str:
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
        encoding="utf-8",
        errors="ignore",
    )
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


def discover_windows_host() -> str:
    env = os.getenv("IDA_MCP_CONNECT_HOST", "").strip()
    if env:
        return env.split(",", 1)[0].strip()

    commands = [
        ["sh", "-lc", "ip route show default | awk '/default/ {print $3; exit}'"],
        ["sh", "-lc", "awk '/nameserver/ {print $2; exit}' /etc/resolv.conf"],
    ]
    for command in commands:
        value = _run(command).strip()
        if value:
            return value
    return "127.0.0.1"


def discover_windows_user() -> str:
    env = os.getenv("IDA_WINDOWS_USER", "").strip()
    if env:
        return env

    for command in (
        ["powershell.exe", "-NoProfile", "-Command", "$env:USERNAME"],
        ["cmd.exe", "/c", "echo", "%USERNAME%"],
    ):
        value = _run(command).splitlines()
        if value:
            candidate = value[-1].strip()
            if candidate:
                return candidate
    return "USER"


def render_server_block(repo_root: Path, host: str) -> str:
    shell_command = (
        f"cd {shlex.quote(str(repo_root))} && "
        f"IDA_MCP_CONNECT_HOST={host} ./.venv/bin/python -m ida_hybrid_manager.server --transport stdio"
    )
    args = json.dumps(["bash", "-lc", shell_command], ensure_ascii=True)
    return "\n".join(
        [
            f"[{SECTION_NAME}]",
            'command = "/usr/bin/env"',
            f"args = {args}",
            "startup_timeout_sec = 90.0",
            "tool_timeout_sec = 120.0",
            "",
        ]
    )


def upsert_config(path: Path, block: str) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    original = path.read_text(encoding="utf-8") if path.exists() else ""

    if SECTION_PATTERN.search(original):
        updated = SECTION_PATTERN.sub(block, original, count=1)
        action = "updated"
    else:
        prefix = original.rstrip()
        updated = f"{prefix}\n\n{block}" if prefix else block
        action = "created"

    if updated != original:
        path.write_text(updated, encoding="utf-8")
    else:
        action = "unchanged"
    return action


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    host = discover_windows_host()
    windows_user = discover_windows_user()
    block = render_server_block(repo_root, host)

    targets = [
        Path.home() / ".codex" / "config.toml",
        Path(f"/mnt/c/Users/{windows_user}/.codex/config.toml"),
    ]

    for target in targets:
        action = upsert_config(target, block)
        print(f"{action}: {target}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
