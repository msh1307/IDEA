from __future__ import annotations

import json
import socket
import subprocess
import uuid
from pathlib import Path

from .models import PendingLaunch
from .pathing import normalize_path, to_windows_path


IDA_INSTALL = r"C:\Program Files\IDA Professional 9.1"
PLUGIN_ROOT = r"C:\Users\msh\AppData\Roaming\Hex-Rays\IDA Pro\plugins"
WINDOWS_TEMP = r"C:\Users\msh\AppData\Local\Temp\ida-hybrid-manager"
WSL_TEMP = "/mnt/c/Users/msh/AppData/Local/Temp/ida-hybrid-manager"


def pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("0.0.0.0", 0))
        return sock.getsockname()[1]


class IdaLauncher:
    def __init__(self) -> None:
        self.ida_gui = rf"{IDA_INSTALL}\ida.exe"
        self.ida_headless = rf"{IDA_INSTALL}\idat.exe"
        self.plugin_root = PLUGIN_ROOT
        self.wsl_temp = Path(WSL_TEMP)
        self.wsl_temp.mkdir(parents=True, exist_ok=True)

    def _powershell(self, command: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            check=False,
        )

    def _write_headless_bootstrap(self, *, port: int, launch_token: str, manager_url: str) -> str:
        script_path = self.wsl_temp / f"headless-{launch_token}.py"
        script_path.write_text(
            "\n".join(
                [
                    "import os",
                    "import sys",
                    f"os.environ['IDA_MCP_MANAGER_URL'] = {manager_url!r}",
                    "os.environ.setdefault('IDA_MCP_REGISTER_WITH_MANAGER', '0')",
                    f"plugin_root = {self.plugin_root!r}",
                    "if plugin_root not in sys.path:",
                    "    sys.path.insert(0, plugin_root)",
                    "from ida_mcp.runtime import IdaMcpRuntime",
                    "runtime = IdaMcpRuntime()",
                    f"runtime.start('0.0.0.0', {port}, background=False, engine='headless', launch_token={launch_token!r})",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        return to_windows_path(str(script_path))

    def _start_process(self, executable: str, arguments: list[str], *, hidden: bool = False) -> int | None:
        escaped_args = []
        for arg in arguments:
            escaped_args.append("'" + arg.replace("'", "''") + "'")
        quoted_args = ", ".join(escaped_args)
        window_style = "-WindowStyle Hidden" if hidden else ""
        ps = (
            f"$p = Start-Process -FilePath '{executable}' -ArgumentList @({quoted_args}) "
            f"-PassThru {window_style}; "
            "$p.Id"
        )
        result = self._powershell(ps)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "failed to launch IDA")
        stdout = result.stdout.strip()
        return int(stdout) if stdout.isdigit() else None

    def launch_headless(self, binary_path: str, manager_url: str) -> PendingLaunch:
        binary_windows = normalize_path(binary_path).windows_path
        launch_token = f"launch-{uuid.uuid4().hex[:12]}"
        port = pick_free_port()
        bootstrap_path = self._write_headless_bootstrap(
            port=port,
            launch_token=launch_token,
            manager_url=manager_url,
        )
        idb_path = f"{binary_windows}.i64"
        args = [
            "-A",
            f"-S{bootstrap_path}",
            binary_windows,
        ]
        pid = self._start_process(self.ida_headless, args, hidden=True)
        return PendingLaunch(
            launch_token=launch_token,
            binary_path=binary_windows,
            idb_path=idb_path,
            engine="headless",
            port=port,
            pid=pid,
        )

    def launch_gui(self, binary_path: str) -> PendingLaunch:
        binary_windows = normalize_path(binary_path).windows_path
        pid = self._start_process(self.ida_gui, [binary_windows], hidden=False)
        return PendingLaunch(
            launch_token=f"gui-{uuid.uuid4().hex[:12]}",
            binary_path=binary_windows,
            idb_path=f"{binary_windows}.i64",
            engine="gui",
            port=None,
            pid=pid,
        )

    def terminate_process(self, pid: int) -> None:
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                f"Stop-Process -Id {pid} -Force",
            ],
            capture_output=True,
            text=True,
            check=False,
            encoding="utf-8",
            errors="ignore",
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip() or f"failed to kill pid {pid}")
