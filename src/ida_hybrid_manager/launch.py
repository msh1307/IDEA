from __future__ import annotations

import json
import shutil
import socket
import subprocess
import uuid
from pathlib import Path
from urllib.parse import urlsplit

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
        self.stage_root = self.wsl_temp / "staged"
        self.stage_root.mkdir(parents=True, exist_ok=True)

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
                    "os.environ['IDA_MCP_ENGINE'] = 'headless'",
                    f"os.environ['IDA_MCP_MANAGER_URL'] = {manager_url!r}",
                    "os.environ.setdefault('IDA_MCP_REGISTER_WITH_MANAGER', '0')",
                    f"plugin_root = {self.plugin_root!r}",
                    "if plugin_root not in sys.path:",
                    "    sys.path.insert(0, plugin_root)",
                    "from ida_mcp.runtime import IdaMcpRuntime",
                    "runtime = IdaMcpRuntime()",
                    "if not runtime.running:",
                    f"    runtime.start('0.0.0.0', {port}, background=False, engine='headless', launch_token={launch_token!r})",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        return to_windows_path(str(script_path))

    def _prepare_binary_path(self, binary_path: str) -> tuple[str, str, dict[str, str]]:
        normalized = normalize_path(binary_path)
        windows_path = normalized.windows_path
        if len(windows_path) >= 3 and windows_path[1:3] == ":\\":
            return windows_path, windows_path, {}

        source_wsl = Path(normalized.wsl_path)
        if not source_wsl.exists():
            raise FileNotFoundError(f"Input binary not found: {binary_path}")

        staged_dir = self.stage_root / uuid.uuid4().hex[:12]
        staged_dir.mkdir(parents=True, exist_ok=True)
        staged_path = staged_dir / source_wsl.name
        shutil.copy2(source_wsl, staged_path)
        return to_windows_path(str(staged_path)), normalized.input_path, {
            "staged_dir": str(staged_dir),
            "staged_binary_path": str(staged_path),
        }

    def _start_process(
        self,
        executable: str,
        arguments: list[str],
        *,
        hidden: bool = False,
        env: dict[str, str] | None = None,
    ) -> int | None:
        escaped_args = []
        for arg in arguments:
            escaped_args.append("'" + arg.replace("'", "''") + "'")
        quoted_args = ", ".join(escaped_args)
        window_style = "-WindowStyle Hidden" if hidden else ""
        env_prefix = ""
        if env:
            for key, value in env.items():
                escaped_value = value.replace("'", "''")
                env_prefix += f"$env:{key} = '{escaped_value}'; "
        ps = (
            f"{env_prefix}"
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
        binary_windows, display_path, metadata = self._prepare_binary_path(binary_path)
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
        pid = self._start_process(
            self.ida_headless,
            args,
            hidden=True,
            env={
                # Headless sessions are manager-owned, but the plugin's auto-start
                # path is the most reliable way to make idat keep serving MCP.
                # Force that auto-start path onto the manager-selected port so the
                # backend endpoint matches the session metadata.
                "IDA_MCP_AUTO_START": "1",
                "IDA_MCP_PORT": str(port),
                "IDA_MCP_ENGINE": "headless",
                "IDA_MCP_REGISTER_WITH_MANAGER": "0",
            },
        )
        return PendingLaunch(
            launch_token=launch_token,
            binary_path=display_path,
            idb_path=idb_path,
            engine="headless",
            port=port,
            pid=pid,
            metadata=metadata,
        )

    def list_idat_pids(self) -> list[int]:
        result = self._powershell(
            "Get-Process idat -ErrorAction SilentlyContinue | "
            "Select-Object -ExpandProperty Id"
        )
        if result.returncode != 0:
            return []
        pids: list[int] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.isdigit():
                pids.append(int(line))
        return pids

    def terminate_untracked_idat(self, tracked_pids: set[int]) -> list[int]:
        terminated: list[int] = []
        for pid in self.list_idat_pids():
            if pid in tracked_pids:
                continue
            try:
                self.terminate_process(pid)
                terminated.append(pid)
            except Exception:
                continue
        return terminated

    def launch_gui(self, binary_path: str) -> PendingLaunch:
        binary_windows, display_path, metadata = self._prepare_binary_path(binary_path)
        pid = self._start_process(self.ida_gui, [binary_windows], hidden=False)
        return PendingLaunch(
            launch_token=f"gui-{uuid.uuid4().hex[:12]}",
            binary_path=display_path,
            idb_path=f"{binary_windows}.i64",
            engine="gui",
            port=None,
            pid=pid,
            metadata=metadata,
        )

    def terminate_process(self, pid: int) -> None:
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                f"$p = Get-Process -Id {pid} -ErrorAction SilentlyContinue; "
                f"if ($null -eq $p) {{ exit 0 }}; "
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

    def lookup_listener_pid(self, endpoint_url: str) -> int | None:
        parsed = urlsplit(endpoint_url)
        port = parsed.port
        if port is None:
            return None
        result = self._powershell(
            f"$conn = Get-NetTCPConnection -State Listen -LocalPort {port} -ErrorAction SilentlyContinue | "
            "Select-Object -First 1 -ExpandProperty OwningProcess; "
            "if ($null -ne $conn) { $conn }"
        )
        if result.returncode != 0:
            return None
        stdout = result.stdout.strip()
        return int(stdout) if stdout.isdigit() else None

    def cleanup_staged_dir(self, staged_dir: str) -> bool:
        if not staged_dir:
            return False
        path = Path(staged_dir)
        if not path.exists():
            return False
        try:
            shutil.rmtree(path)
            return True
        except FileNotFoundError:
            return False
