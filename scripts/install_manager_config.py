#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PureWindowsPath
import re
import subprocess
import time

from scripts.install_codex_config import discover_ida_install_root


WINDOWS_DRIVE_RE = re.compile(r"^(?P<drive>[a-zA-Z]):[\\/](?P<rest>.*)$")
WSL_DRIVE_RE = re.compile(r"^/mnt/(?P<drive>[a-zA-Z])(?:/(?P<rest>.*))?$")


def _run(command: list[str]) -> str:
    result = None
    for _attempt in range(3):
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            encoding="utf-8",
            errors="ignore",
        )
        if result.returncode == 0:
            return result.stdout.strip()
        if _attempt < 2:
            time.sleep(1)
    assert result is not None
    raise RuntimeError(result.stderr.strip() or result.stdout.strip() or f"failed: {command[0]}")


def _windows_path(value: str) -> str:
    value = value.strip()
    match = WSL_DRIVE_RE.match(value)
    if match:
        rest = (match.group("rest") or "").replace("/", "\\")
        return f"{match.group('drive').upper()}:\\{rest}"
    match = WINDOWS_DRIVE_RE.match(value)
    if not match:
        raise ValueError(r"root must be an absolute Windows or /mnt/<drive> path")
    rest = match.group("rest").replace("/", "\\")
    return f"{match.group('drive').upper()}:\\{rest}"


def _wsl_path(value: str) -> str:
    match = WINDOWS_DRIVE_RE.match(value)
    if not match:
        raise ValueError(f"not a Windows drive path: {value}")
    rest = match.group("rest").replace("\\", "/")
    suffix = f"/{rest}" if rest else ""
    return f"/mnt/{match.group('drive').lower()}{suffix}"


def _read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"install config must contain a JSON object: {path}")
    return payload


def _config_paths(repo_root: Path) -> tuple[Path, str]:
    configured = os.getenv("IDA_MANAGER_CONFIG", "").strip()
    if configured:
        if WINDOWS_DRIVE_RE.match(configured):
            return Path(_wsl_path(configured)), _windows_path(configured)
        path = Path(configured).expanduser().resolve()
        return path, _windows_path(str(path))

    candidates = sorted(
        Path("/mnt/c/Users").glob("*/AppData/Local/ida-hybrid-manager/config.json")
    )
    if candidates:
        resolved_repo = str(repo_root.resolve())
        matching = [
            path
            for path in candidates
            if str(_read_json(path).get("wsl_repo") or "") == resolved_repo
        ]
        selected = matching[0] if len(matching) == 1 else candidates[0] if len(candidates) == 1 else None
        if selected is None:
            raise ValueError("multiple install configs found; set IDA_MANAGER_CONFIG")
        return selected, _windows_path(str(selected))

    local_appdata = _run(
        ["powershell.exe", "-NoProfile", "-Command", '[Environment]::GetFolderPath("LocalApplicationData")']
    ).splitlines()[-1].strip()
    windows = str(PureWindowsPath(local_appdata) / "ida-hybrid-manager" / "config.json")
    return Path(_wsl_path(windows)), windows


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f"{path.name}.tmp")
    temp.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(temp, path)


def main() -> int:
    parser = argparse.ArgumentParser(description="Create or update the ida-hybrid-manager install config")
    parser.add_argument("--root", default="")
    parser.add_argument("--repo-root", required=True)
    args = parser.parse_args()

    repo_root = Path(args.repo_root)
    config_wsl, config_windows = _config_paths(repo_root)
    existing = _read_json(config_wsl)

    requested_root = args.root or os.getenv("IDA_MANAGER_ROOT", "") or str(existing.get("windows_root") or "")
    default_root = str(PureWindowsPath(config_windows).parent)
    windows_root = _windows_path(requested_root or default_root)
    root = PureWindowsPath(windows_root)
    profile = (os.getenv("IDA_MCP_PROFILE") or str(existing.get("profile") or "lite")).strip().lower()
    if profile not in {"full", "lite"}:
        raise ValueError("profile must be full or lite")

    payload = {
        "version": 1,
        "windows_root": str(root),
        "fallback_root": str(root / "native"),
        "stage_root": str(root / "staging"),
        "temp_root": str(root / "temp"),
        "artifact_root": str(root / "artifacts"),
        "replay_root": str(root / "replay"),
        "wsl_repo": str(repo_root.resolve()),
        "wsl_distro": (
            os.getenv("IDA_WSL_DISTRO") or str(existing.get("wsl_distro") or "Ubuntu-24.04")
        ).strip(),
        "ida_install_root": (
            os.getenv("IDA_INSTALL_ROOT")
            or str(existing.get("ida_install_root") or "")
            or discover_ida_install_root()
        ).strip(),
        "profile": profile,
    }
    _write_json(config_wsl, payload)

    for value in (
        config_windows,
        payload["windows_root"],
        _wsl_path(payload["fallback_root"]),
        payload["fallback_root"],
        payload["stage_root"],
        payload["temp_root"],
        payload["artifact_root"],
        payload["replay_root"],
        payload["ida_install_root"],
        payload["wsl_distro"],
        payload["profile"],
    ):
        print(value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
