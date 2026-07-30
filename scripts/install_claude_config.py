#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PureWindowsPath

from scripts.install_codex_config import discover_windows_host
from scripts.install_manager_config import _wsl_path


SERVER_NAME = "ida-hybrid-manager"
LEGACY_SERVER_NAME = "ida-pro-mcp"


def _load(path: Path) -> dict:
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, dict):
        raise ValueError(f"Claude config must contain a JSON object: {path}")
    return payload


def _write(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = path.stat().st_mode if path.exists() else 0o600
    temp = path.with_name(f"{path.name}.tmp")
    temp.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temp.chmod(mode)
    os.replace(temp, path)


def upsert(path: Path, entry: dict) -> str:
    payload = _load(path)
    servers = payload.setdefault("mcpServers", {})
    if not isinstance(servers, dict):
        raise ValueError(f"mcpServers must contain a JSON object: {path}")
    before = json.dumps(servers, sort_keys=True)
    servers.pop(LEGACY_SERVER_NAME, None)
    servers[SERVER_NAME] = entry
    if json.dumps(servers, sort_keys=True) == before:
        return "unchanged"
    action = "updated" if path.exists() else "created"
    _write(path, payload)
    return action


def wsl_entry(settings: dict) -> dict:
    root = str(settings["wsl_repo"])
    return {
        "type": "stdio",
        "command": f"{root}/.venv/bin/python",
        "args": ["-m", "ida_hybrid_manager.server", "--transport", "stdio"],
        "env": {
            "IDA_MCP_CONNECT_HOST": discover_windows_host(),
            "IDA_INSTALL_ROOT": str(settings["ida_install_root"]),
            "IDA_MCP_PROFILE": str(settings["profile"]),
            "IDA_MCP_STAGE_ROOT": _wsl_path(str(settings["stage_root"])),
            "IDA_WSL_TEMP": _wsl_path(str(settings["temp_root"])),
            "IDA_MCP_ARTIFACT_DIR": _wsl_path(str(settings["artifact_root"])),
            "IDA_MCP_REPLAY_DIR": _wsl_path(str(settings["replay_root"])),
        },
    }


def windows_entry(settings: dict, config_windows: str) -> dict:
    launcher = str(PureWindowsPath(str(settings["fallback_root"])) / "run_manager_fallback.ps1")
    return {
        "type": "stdio",
        "command": "powershell.exe",
        "args": [
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            launcher,
            "-Config",
            config_windows,
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Install ida-hybrid-manager into Claude MCP configs")
    parser.add_argument("--config", required=True, help="Windows path to the manager config")
    args = parser.parse_args()

    config_windows = args.config.strip()
    settings = _load(Path(_wsl_path(config_windows)))
    windows_user = str(settings.get("windows_user") or "").strip()
    if not windows_user:
        raise ValueError("windows_user is missing from the manager config")

    targets = (
        (Path.home() / ".claude.json", wsl_entry(settings)),
        (Path(f"/mnt/c/Users/{windows_user}/.claude.json"), windows_entry(settings, config_windows)),
        (
            Path(f"/mnt/c/Users/{windows_user}/AppData/Roaming/Claude/claude_desktop_config.json"),
            {key: value for key, value in windows_entry(settings, config_windows).items() if key != "type"},
        ),
    )
    for path, entry in targets:
        print(f"{upsert(path, entry)}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
