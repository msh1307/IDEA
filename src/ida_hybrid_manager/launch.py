from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from .models import PendingLaunch
from .networking import discover_windows_host
from .pathing import normalize_path, to_windows_path, to_wsl_path


DEFAULT_IDA_INSTALL = r"C:\Program Files\IDA Professional 9.3"
DEFAULT_WINDOWS_USER = "USER"


def _powershell_value(command: str) -> str:
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        check=False,
        encoding="utf-8",
        errors="ignore",
        stdin=subprocess.DEVNULL,
    )
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


def _windows_username() -> str:
    env = os.getenv("IDA_WINDOWS_USER", "").strip()
    if env:
        return env
    return _powershell_value("$env:USERNAME") or DEFAULT_WINDOWS_USER


def _windows_roaming_appdata() -> str:
    env = os.getenv("IDA_WINDOWS_APPDATA", "").strip()
    if env:
        return env
    return _powershell_value('[Environment]::GetFolderPath("ApplicationData")')


def _windows_local_appdata() -> str:
    env = os.getenv("IDA_WINDOWS_LOCALAPPDATA", "").strip()
    if env:
        return env
    return _powershell_value('[Environment]::GetFolderPath("LocalApplicationData")')


def _default_plugin_root() -> str:
    env = os.getenv("IDA_PLUGIN_ROOT", "").strip()
    if env:
        return env
    appdata = _windows_roaming_appdata()
    if appdata:
        return rf"{appdata}\Hex-Rays\IDA Pro\plugins"
    return rf"C:\Users\{_windows_username()}\AppData\Roaming\Hex-Rays\IDA Pro\plugins"


def _default_windows_temp() -> str:
    env = os.getenv("IDA_WINDOWS_TEMP", "").strip()
    if env:
        return env
    local_appdata = _windows_local_appdata()
    if local_appdata:
        return rf"{local_appdata}\Temp\ida-hybrid-manager"
    return rf"C:\Users\{_windows_username()}\AppData\Local\Temp\ida-hybrid-manager"


def _default_wsl_temp(windows_temp: str) -> str:
    env = os.getenv("IDA_WSL_TEMP", "").strip()
    if env:
        return env
    return to_wsl_path(windows_temp)


def pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("0.0.0.0", 0))
        return sock.getsockname()[1]


class IdaLauncher:
    def __init__(self) -> None:
        ida_install = os.getenv("IDA_INSTALL_ROOT", DEFAULT_IDA_INSTALL).strip() or DEFAULT_IDA_INSTALL
        self.ida_gui = rf"{ida_install}\ida.exe"
        self.ida_headless = rf"{ida_install}\idat.exe"
        self.plugin_root = _default_plugin_root()
        self.wsl_temp = Path(_default_wsl_temp(_default_windows_temp()))
        self.wsl_temp.mkdir(parents=True, exist_ok=True)
        self.stage_root = self.wsl_temp / "staged"
        self.stage_root.mkdir(parents=True, exist_ok=True)

    def _powershell(self, command: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            check=False,
            stdin=subprocess.DEVNULL,
        )

    def _write_headless_bootstrap(self, *, port: int, launch_token: str, manager_url: str, background: bool, persist: bool) -> str:
        script_path = self.wsl_temp / f"headless-{launch_token}.py"
        log_path = self.wsl_temp / f"headless-{launch_token}.log"
        script_path.write_text(
            "\n".join(
                [
                    "import traceback",
                    "import os",
                    "import sys",
                    "os.environ['IDEA_IDA_ENGINE'] = 'headless'",
                    f"os.environ['IDEA_IDA_MANAGER_URL'] = {manager_url!r}",
                    "os.environ.setdefault('IDEA_IDA_REGISTER_WITH_MANAGER', '1')",
                    f"plugin_root = {self.plugin_root!r}",
                    f"log_path = {to_windows_path(str(log_path))!r}",
                    "log_file = open(log_path, 'a', encoding='utf-8', buffering=1)",
                    "sys.stdout = log_file",
                    "sys.stderr = log_file",
                    "print('[IDEA] headless bootstrap start')",
                    "if plugin_root not in sys.path:",
                    "    sys.path.insert(0, plugin_root)",
                    "try:",
                    "    from idea_ida_backend.runtime import IdeaIdaRuntime",
                    "    from idea_ida_backend.sync import pump_main_thread",
                    "    print('[IDEA] runtime import ok')",
                    "    runtime = IdeaIdaRuntime()",
                    "    if not runtime.running:",
                    f"        runtime.start('0.0.0.0', {port}, background={str(background)}, engine='headless', launch_token={launch_token!r})",
                    f"    if {str(persist)}:",
                    "        import time",
                    "        print('[IDEA] entering persistent headless loop')",
                    "        while runtime.running:",
                    "            pump_main_thread(0.1)",
                    "            time.sleep(0.05)",
                    "except Exception as exc:",
                    "    print('[IDEA] headless bootstrap failed:', repr(exc))",
                    "    traceback.print_exc()",
                    "    raise",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        return to_windows_path(str(script_path))

    def _prepare_binary_path(self, binary_path: str, *, always_stage: bool = False) -> tuple[str, str, dict[str, str]]:
        normalized = normalize_path(binary_path)
        windows_path = normalized.windows_path
        source_metadata = {
            "source_input_path": normalized.input_path,
            "source_windows_path": normalized.windows_path,
            "source_wsl_path": normalized.wsl_path,
        }
        if len(windows_path) >= 3 and windows_path[1:3] == ":\\" and not always_stage:
            return windows_path, windows_path, source_metadata

        source_wsl = Path(normalized.wsl_path)
        if not source_wsl.exists():
            raise FileNotFoundError(f"Input binary not found: {binary_path}")

        staged_dir = self.stage_root / uuid.uuid4().hex[:12]
        staged_dir.mkdir(parents=True, exist_ok=True)
        staged_path = staged_dir / source_wsl.name
        shutil.copy2(source_wsl, staged_path)
        display_path = windows_path if len(windows_path) >= 3 and windows_path[1:3] == ":\\" else normalized.input_path
        metadata = {
            "staged_dir": str(staged_dir),
            "staged_binary_path": str(staged_path),
        }
        metadata.update(source_metadata)
        return to_windows_path(str(staged_path)), display_path, metadata

    def _start_process(
        self,
        executable: str,
        arguments: list[str],
        *,
        hidden: bool = False,
        env: dict[str, str] | None = None,
        stdout_path: str | None = None,
        stderr_path: str | None = None,
        working_directory: str | None = None,
    ) -> int | None:
        escaped_args = []
        for arg in arguments:
            escaped_args.append("'" + arg.replace("'", "''") + "'")
        quoted_args = ", ".join(escaped_args)
        window_style = "-WindowStyle Hidden" if hidden else ""
        working_dir = working_directory or executable.rsplit("\\", 1)[0]
        working_dir_arg = f"-WorkingDirectory '{working_dir}' " if working_dir else ""
        env_prefix = ""
        if env:
            for key, value in env.items():
                escaped_value = value.replace("'", "''")
                env_prefix += f"$env:{key} = '{escaped_value}'; "
        ps = (
            f"{env_prefix}"
            f"$p = Start-Process -FilePath '{executable}' -ArgumentList @({quoted_args}) "
            f"-PassThru {working_dir_arg}{window_style}; "
            "$p.Id"
        )
        result = self._powershell(ps)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "failed to launch IDA")
        stdout = result.stdout.strip()
        return int(stdout) if stdout.isdigit() else None

    def launch_headless(self, binary_path: str, manager_url: str) -> PendingLaunch:
        binary_windows, display_path, metadata = self._prepare_binary_path(binary_path, always_stage=True)
        launch_token = f"launch-{uuid.uuid4().hex[:12]}"
        port = pick_free_port()
        endpoint_host = os.getenv("IDA_MCP_CONNECT_HOST", "").strip() or discover_windows_host() or "127.0.0.1"
        stdout_log_path = to_windows_path(str(self.wsl_temp / f"{launch_token}.stdout.log"))
        stderr_log_path = to_windows_path(str(self.wsl_temp / f"{launch_token}.stderr.log"))
        headless_mode = (os.getenv("IDA_HEADLESS_MODE", "idat").strip() or "idat").lower()
        use_gui_hidden = headless_mode in {"gui", "gui-hidden", "ida", "auto"}
        idat_log_path = to_windows_path(str(self.wsl_temp / f"{launch_token}.idat.log"))
        bootstrap_path = self._write_headless_bootstrap(
            port=port,
            launch_token=launch_token,
            manager_url=manager_url,
            background=True,
            persist=not use_gui_hidden,
        )
        idb_path = f"{binary_windows}.i64"
        args = ["-A"]
        if not use_gui_hidden:
            args.extend(
                [
                    "-c",
                    f"-o{idb_path}",
                    f"-L{idat_log_path}",
                ]
            )
        args.extend(
            [
                f"-S{bootstrap_path}",
                binary_windows,
            ]
        )
        pid = self._start_process(
            self.ida_gui if use_gui_hidden else self.ida_headless,
            args,
            hidden=True,
            env={
                "IDEA_IDA_AUTO_START": "0",
                "IDEA_IDA_PORT": str(port),
                "IDEA_IDA_ENGINE": "headless",
                "IDEA_IDA_REGISTER_WITH_MANAGER": "1",
                "IDEA_IDA_ENDPOINT_HOST": endpoint_host,
                "IDEA_IDA_SYNC_MODE": "execute_sync" if use_gui_hidden else "queue",
            },
            stdout_path=stdout_log_path,
            stderr_path=stderr_log_path,
        )
        metadata["stdout_log_path"] = to_wsl_path(stdout_log_path)
        metadata["stderr_log_path"] = to_wsl_path(stderr_log_path)
        metadata["idat_log_path"] = to_wsl_path(idat_log_path)
        metadata["headless_mode"] = "gui-hidden" if use_gui_hidden else "idat"
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

    def is_process_alive(self, pid: int | None) -> bool:
        if pid is None:
            return False
        result = self._powershell(
            f"$p = Get-Process -Id {pid} -ErrorAction SilentlyContinue; "
            "if ($null -eq $p) { '0' } else { '1' }"
        )
        if result.returncode != 0:
            return False
        return result.stdout.strip() == "1"

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
