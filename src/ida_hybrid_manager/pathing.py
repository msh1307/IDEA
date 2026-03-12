from __future__ import annotations

import os
import re
from dataclasses import dataclass


WINDOWS_DRIVE_RE = re.compile(r"^(?P<drive>[a-zA-Z]):[\\/](?P<rest>.*)$")
WSL_DRIVE_RE = re.compile(r"^/mnt/(?P<drive>[a-zA-Z])/(?P<rest>.*)$")


@dataclass
class NormalizedPath:
    input_path: str
    windows_path: str
    wsl_path: str


def to_windows_path(path: str) -> str:
    path = path.strip()
    match = WINDOWS_DRIVE_RE.match(path)
    if match:
        rest = match.group("rest").replace("/", "\\")
        return f"{match.group('drive').upper()}:\\{rest}"
    match = WSL_DRIVE_RE.match(path)
    if match:
        rest = match.group("rest").replace("/", "\\")
        return f"{match.group('drive').upper()}:\\{rest}"
    return path.replace("/", "\\")


def to_wsl_path(path: str) -> str:
    path = path.strip()
    match = WSL_DRIVE_RE.match(path)
    if match:
        return f"/mnt/{match.group('drive').lower()}/{match.group('rest')}"
    match = WINDOWS_DRIVE_RE.match(path)
    if match:
        rest = match.group("rest").replace("\\", "/")
        return f"/mnt/{match.group('drive').lower()}/{rest}"
    return path.replace("\\", "/")


def normalize_path(path: str) -> NormalizedPath:
    if not WINDOWS_DRIVE_RE.match(path):
        resolved = os.path.realpath(path)
        if resolved:
            path = resolved
    windows_path = to_windows_path(path)
    wsl_path = to_wsl_path(path)
    return NormalizedPath(input_path=path, windows_path=windows_path, wsl_path=wsl_path)
