from __future__ import annotations

import json
import os
import re
import stat
import shutil
import socket
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .models import PendingLaunch
from .networking import candidate_windows_hosts, discover_windows_host
from .pathing import normalize_path, to_windows_path, to_wsl_path


DEFAULT_IDA_INSTALL = r"C:\Program Files\IDA Professional 9.3"
DEFAULT_WINDOWS_USER = "USER"
STAGE_METADATA_NAME = ".ida-hybrid-session.json"


def _architecture_options(
    *,
    processor: str | None = None,
    compiler: str | None = None,
    bitness: int | None = None,
    thumb_mode: bool | None = None,
    thumb_address: int | str | None = None,
) -> dict[str, Any]:
    """Validate explicit IDA architecture settings without guessing defaults."""
    normalized_processor = str(processor or "").strip() or None
    normalized_compiler = str(compiler or "").strip() or None
    if isinstance(bitness, bool) or (isinstance(bitness, float) and not bitness.is_integer()):
        raise ValueError("bitness must be an integer: 16, 32, or 64")
    normalized_bitness = None if bitness is None else int(bitness)
    if normalized_bitness is not None and normalized_bitness not in {16, 32, 64}:
        raise ValueError("bitness must be 16, 32, or 64")
    if thumb_mode is not None and not isinstance(thumb_mode, bool):
        raise ValueError("thumb_mode must be true or false")
    normalized_address = None
    if thumb_address not in (None, ""):
        if isinstance(thumb_address, bool):
            raise ValueError("thumb_address must be a numeric address")
        if isinstance(thumb_address, float) and not thumb_address.is_integer():
            raise ValueError("thumb_address must be an integer address")
        try:
            normalized_address = int(thumb_address, 0) if isinstance(thumb_address, str) else int(thumb_address)
        except (TypeError, ValueError) as exc:
            raise ValueError("thumb_address must be a decimal or hexadecimal address") from exc
        if normalized_address < 0:
            raise ValueError("thumb_address must be non-negative")
    if normalized_address is not None and thumb_mode is None:
        raise ValueError("thumb_mode is required when thumb_address is set")
    return {
        "processor": normalized_processor,
        "compiler": normalized_compiler,
        "bitness": normalized_bitness,
        "thumb_mode": thumb_mode,
        "thumb_address": normalized_address,
    }


def _architecture_args(options: dict[str, Any]) -> list[str]:
    args: list[str] = []
    if options.get("processor"):
        args.append(f"-p{options['processor']}")
    if options.get("compiler"):
        args.append(f"-C{options['compiler']}")
    return args


def _architecture_metadata(options: dict[str, Any]) -> dict[str, Any]:
    address = options.get("thumb_address")
    return {
        "processor": options.get("processor"),
        "compiler": options.get("compiler"),
        "bitness": options.get("bitness"),
        "thumb_mode": options.get("thumb_mode"),
        "thumb_address": hex(address) if address is not None else None,
    }


def _architecture_needs_script(options: dict[str, Any]) -> bool:
    return options.get("bitness") is not None or options.get("thumb_mode") is not None


def _launch_handshake_timeout_sec() -> float:
    """Bound only the PowerShell launcher handshake, never the IDA child."""
    try:
        value = float(os.getenv("IDA_LAUNCHER_HANDSHAKE_TIMEOUT_SEC", "20") or 20.0)
    except (TypeError, ValueError):
        value = 20.0
    return max(5.0, min(60.0, value))


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


def _default_stage_root(wsl_temp: Path) -> Path:
    env = os.getenv("IDA_MCP_STAGE_ROOT", "").strip()
    if not env:
        return wsl_temp / "staged"
    return Path(normalize_path(env).wsl_path)


def pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("0.0.0.0", 0))
        return sock.getsockname()[1]


class IdaLauncher:
    def __init__(self) -> None:
        ida_install = os.getenv("IDA_INSTALL_ROOT", DEFAULT_IDA_INSTALL).strip() or DEFAULT_IDA_INSTALL
        self.ida_gui = rf"{ida_install}\ida.exe"
        self.ida_headless = rf"{ida_install}\idat.exe"
        self.repo_root = Path(__file__).resolve().parents[2]
        self.plugin_root = _default_plugin_root()
        self.wsl_temp = Path(_default_wsl_temp(_default_windows_temp()))
        self.wsl_temp.mkdir(parents=True, exist_ok=True)
        self.stage_root = _default_stage_root(self.wsl_temp)
        self.stage_root.mkdir(parents=True, exist_ok=True)
        self.overlay_root = self.wsl_temp / "overlay"
        self.overlay_root.mkdir(parents=True, exist_ok=True)
        self.cleanup_stale_temp()

    def _stage_roots(self) -> list[Path]:
        roots = [self.stage_root, self.wsl_temp / "staged"]
        return list(dict.fromkeys(root.resolve() for root in roots))

    def is_managed_staged_dir(self, path: Path) -> bool:
        resolved = path.resolve()
        if not re.fullmatch(r"[0-9a-f]{12}", resolved.name, re.IGNORECASE):
            return False
        return any(resolved.parent == root for root in self._stage_roots())

    def _write_stage_metadata(self, staged_dir: Path, metadata: dict[str, Any]) -> None:
        path = staged_dir / STAGE_METADATA_NAME
        temp = staged_dir / f"{STAGE_METADATA_NAME}.tmp"
        temp.write_text(json.dumps(metadata, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
        temp.chmod(0o600)
        os.replace(temp, path)

    def recover_staged_metadata(self, idb_path: str) -> dict[str, Any]:
        try:
            staged_idb = Path(normalize_path(idb_path).wsl_path)
        except (TypeError, ValueError):
            return {}
        staged_dir = staged_idb.parent
        if not self.is_managed_staged_dir(staged_dir):
            return {}
        try:
            payload = json.loads((staged_dir / STAGE_METADATA_NAME).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        if not isinstance(payload, dict) or not (
            payload.get("source_wsl_path") or payload.get("source_idb_wsl_path")
        ):
            return {}
        metadata = dict(payload)
        metadata["staged_dir"] = str(staged_dir)
        metadata["staged_idb_path"] = str(staged_idb)
        return metadata

    def cleanup_stale_temp(self, max_age_sec: int | None = None) -> dict[str, Any]:
        """Remove only old manager-generated staging/log entries.

        User binaries, IDBs, exports, and the plugin overlay are outside this
        allowlist and are never removed here. Active launches are normally much
        newer than the default seven-day TTL; normal session close still does
        immediate staging cleanup.
        """
        if max_age_sec is None:
            try:
                max_age_sec = max(3600, int(os.getenv("IDA_MCP_TEMP_TTL_SEC", str(7 * 24 * 3600))))
            except ValueError:
                max_age_sec = 7 * 24 * 3600
        cutoff = time.time() - max_age_sec
        removed_files = 0
        removed_dirs = 0
        errors: list[str] = []
        file_prefixes = ("headless-", "headless-launch-", "architecture-", "launch-")
        file_suffixes = (".py", ".log", ".stdout.log", ".stderr.log", ".idat.log")
        try:
            entries = list(self.wsl_temp.iterdir())
        except OSError as exc:
            return {"removed_files": 0, "removed_dirs": 0, "errors": [str(exc)]}
        for path in entries:
            if not path.is_file() or not path.name.startswith(file_prefixes):
                continue
            if not path.name.endswith(file_suffixes):
                continue
            try:
                if path.stat().st_mtime >= cutoff:
                    continue
                path.unlink()
                removed_files += 1
            except OSError as exc:
                errors.append(f"{path}: {exc}")
        staged_entries: list[Path] = []
        for root in self._stage_roots():
            try:
                staged_entries.extend(root.iterdir())
            except FileNotFoundError:
                continue
            except OSError as exc:
                errors.append(f"{root}: {exc}")
        for path in staged_entries:
            try:
                if not path.is_dir() or not self.is_managed_staged_dir(path) or path.stat().st_mtime >= cutoff:
                    continue
                if self.cleanup_staged_dir(str(path)):
                    removed_dirs += 1
            except OSError as exc:
                errors.append(f"{path}: {exc}")
        return {"removed_files": removed_files, "removed_dirs": removed_dirs, "errors": errors}

    def _powershell(self, command: str, *, timeout_sec: float | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            check=False,
            stdin=subprocess.DEVNULL,
            timeout=timeout_sec,
        )

    def _reserve_headless_port(self) -> int:
        # The WSL manager still owns the launch lifecycle. This PowerShell probe
        # only asks Windows for a bindable port for the current on-demand launch.
        result = self._powershell(
            "& { "
            "$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, 0); "
            "$listener.Start(); "
            "$port = $listener.LocalEndpoint.Port; "
            "$listener.Stop(); "
            "Write-Output $port "
            "}"
        )
        if result.returncode == 0:
            stdout = result.stdout.strip()
            if stdout.isdigit():
                return int(stdout)
        return pick_free_port()

    def _resolve_connect_hosts(self) -> list[str]:
        hosts = candidate_windows_hosts()
        return hosts or [discover_windows_host() or "127.0.0.1"]

    def _windows_path_exists(self, path: str) -> bool:
        escaped = path.replace("'", "''")
        result = self._powershell(
            f"if (Test-Path -LiteralPath '{escaped}') {{ '1' }} else {{ '0' }}"
        )
        if result.returncode != 0:
            return False
        return result.stdout.strip() == "1"

    def _stage_bundled_headless_backend(self) -> tuple[str, str]:
        source_root = self.repo_root / "plugin_overlay" / "idea_ida_backend"
        target_root = self.overlay_root
        target_package = target_root / "idea_ida_backend"

        if source_root.is_dir():
            if target_package.exists():
                shutil.rmtree(target_package)
            shutil.copytree(source_root, target_package)
            return to_windows_path(str(target_root)), "bundled-overlay"

        installed_package = rf"{self.plugin_root}\idea_ida_backend"
        if self._windows_path_exists(installed_package):
            return self.plugin_root, "installed-plugin"

        raise FileNotFoundError(
            "Unable to locate headless backend package. "
            f"Missing bundled source at {source_root} and installed package at {installed_package}."
        )

    def inspect_environment(self) -> dict[str, Any]:
        gui_loader = rf"{self.plugin_root}\idea_ida.py"
        gui_backend = rf"{self.plugin_root}\idea_ida_backend"
        legacy_loader = rf"{self.plugin_root}\ida_mcp.py"
        legacy_backend = rf"{self.plugin_root}\ida_mcp"
        bundled_source = self.repo_root / "plugin_overlay" / "idea_ida_backend"

        gui_plugin_installed = self._windows_path_exists(gui_loader) and self._windows_path_exists(gui_backend)
        legacy_installed = self._windows_path_exists(legacy_loader) or self._windows_path_exists(legacy_backend)

        notes: list[str] = []
        if not gui_plugin_installed:
            notes.append("GUI mode requires the native Windows plugin bundle (`idea_ida.py` + `idea_ida_backend`).")
        if legacy_installed and not gui_plugin_installed:
            notes.append("Legacy `ida_mcp` was detected, but it does not register GUI sessions for this manager.")
        if bundled_source.is_dir():
            notes.append("Headless mode can bootstrap from the bundled repo overlay even if the Windows plugin is not installed.")
        else:
            notes.append("Bundled headless overlay is missing; headless mode falls back to the installed Windows plugin package.")

        return {
            "ida_gui_path": self.ida_gui,
            "ida_gui_exists": self._windows_path_exists(self.ida_gui),
            "ida_headless_path": self.ida_headless,
            "ida_headless_exists": self._windows_path_exists(self.ida_headless),
            "plugin_root": self.plugin_root,
            "gui_plugin_installed": gui_plugin_installed,
            "gui_plugin_files": {
                "loader": gui_loader,
                "backend": gui_backend,
            },
            "legacy_ida_mcp_detected": legacy_installed,
            "legacy_ida_mcp_files": {
                "loader": legacy_loader,
                "backend": legacy_backend,
            },
            "bundled_headless_backend": {
                "source_root": str(bundled_source),
                "source_exists": bundled_source.is_dir(),
                "staging_root": str(self.overlay_root),
                "staged_package_exists": (self.overlay_root / "idea_ida_backend").is_dir(),
            },
            "session_stage_root": str(self.stage_root),
            "notes": notes,
        }

    def _write_headless_bootstrap(
        self,
        *,
        port: int,
        launch_token: str,
        manager_url: str,
        background: bool,
        persist: bool,
        bootstrap_root: str,
        architecture_script: str | None,
    ) -> str:
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
                    f"bootstrap_root = {bootstrap_root!r}",
                    f"log_path = {to_windows_path(str(log_path))!r}",
                    "log_file = open(log_path, 'a', encoding='utf-8', buffering=1)",
                    "sys.stdout = log_file",
                    "sys.stderr = log_file",
                    "print('[IDEA] headless bootstrap start')",
                    "print('[IDEA] bootstrap root:', bootstrap_root)",
                    "if bootstrap_root not in sys.path:",
                    "    sys.path.insert(0, bootstrap_root)",
                    "try:",
                    "    from idea_ida_backend.runtime import IdeaIdaRuntime",
                    "    from idea_ida_backend.sync import pump_main_thread",
                    "    print('[IDEA] runtime import ok')",
                    f"    architecture_script = {architecture_script!r}",
                    "    if architecture_script:",
                    "        try:",
                    "            with open(architecture_script, 'r', encoding='utf-8') as config_file:",
                    "                exec(compile(config_file.read(), architecture_script, 'exec'), globals(), globals())",
                    "        except Exception as exc:",
                    "            print('[IDEA] architecture options failed:', repr(exc))",
                    "            raise",
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

    def _write_architecture_script(self, launch_token: str, architecture: dict[str, Any]) -> str:
        script_path = self.wsl_temp / f"architecture-{launch_token}.py"
        script_path.write_text(
            "\n".join(
                [
                    "import ida_idaapi",
                    "import ida_segment",
                    "import idc",
                    f"architecture = {architecture!r}",
                    "bitness = architecture.get('bitness')",
                    "if bitness is not None:",
                    "    for index in range(ida_segment.get_segm_qty()):",
                    "        segment = ida_segment.getnseg(index)",
                    "        if segment is not None:",
                    "            if not idc.set_segm_addressing(segment.start_ea, {16: 0, 32: 1, 64: 2}[bitness]):",
                    "                raise RuntimeError(f'failed to set segment bitness at {segment.start_ea:#x}')",
                    "thumb_mode = architecture.get('thumb_mode')",
                    "if thumb_mode is not None:",
                    "    thumb_value = 1 if thumb_mode else 0",
                    "    thumb_address = architecture.get('thumb_address')",
                    "    if thumb_address is None:",
                    "        if not idc.set_default_sreg_value(ida_idaapi.BADADDR, 'T', thumb_value):",
                    "            raise RuntimeError('failed to set default ARM T register')",
                    "    else:",
                    "        if not idc.split_sreg_range(thumb_address, 'T', thumb_value):",
                    "            raise RuntimeError(f'failed to set ARM T register at {thumb_address:#x}')",
                    "print('[IDEA] architecture options applied:', architecture)",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        return to_windows_path(str(script_path))

    def _prepare_binary_path(
        self,
        binary_path: str,
        *,
        always_stage: bool = False,
        allow_existing_idb: bool = True,
    ) -> tuple[str, str, dict[str, Any]]:
        normalized = normalize_path(binary_path)
        windows_path = normalized.windows_path
        source_wsl = Path(normalized.wsl_path)
        source_idb = source_wsl.with_name(f"{source_wsl.name}.i64")
        source_idb_exists = source_idb.exists()
        source_idb_stat = source_idb.stat() if source_idb_exists else None
        source_metadata = {
            "source_input_path": normalized.input_path,
            "source_windows_path": normalized.windows_path,
            "source_wsl_path": normalized.wsl_path,
            "source_idb_wsl_path": str(source_idb),
            "source_idb_exists": source_idb_exists,
            "source_idb_size": int(source_idb_stat.st_size) if source_idb_stat is not None else None,
            "source_idb_mtime_ns": int(source_idb_stat.st_mtime_ns) if source_idb_stat is not None else None,
            "existing_idb_allowed": allow_existing_idb,
        }
        if len(windows_path) >= 3 and windows_path[1:3] == ":\\" and not always_stage:
            return windows_path, windows_path, source_metadata

        if not source_wsl.exists():
            raise FileNotFoundError(f"Input binary not found: {binary_path}")

        staged_dir = self.stage_root / uuid.uuid4().hex[:12]
        staged_dir.mkdir(parents=True, exist_ok=True)
        staged_path = staged_dir / source_wsl.name
        try:
            shutil.copy2(source_wsl, staged_path)
            staged_idb = staged_path.with_name(f"{staged_path.name}.i64")
            if allow_existing_idb and source_idb_exists:
                shutil.copy2(source_idb, staged_idb)
        except Exception:
            shutil.rmtree(staged_dir, ignore_errors=True)
            raise
        display_path = windows_path if len(windows_path) >= 3 and windows_path[1:3] == ":\\" else normalized.input_path
        metadata = {
            "staged_dir": str(staged_dir),
            "staged_binary_path": str(staged_path),
            "staged_idb_path": str(staged_idb),
            "staged_from_existing_idb": allow_existing_idb and source_idb_exists,
        }
        metadata.update(source_metadata)
        try:
            self._write_stage_metadata(staged_dir, metadata)
        except Exception:
            shutil.rmtree(staged_dir, ignore_errors=True)
            raise
        return to_windows_path(str(staged_path)), display_path, metadata

    def _prepare_idb_path(
        self,
        idb_path: str,
        *,
        always_stage: bool = False,
    ) -> tuple[str, str, dict[str, Any]]:
        normalized = normalize_path(idb_path)
        windows_path = normalized.windows_path
        source_idb = Path(normalized.wsl_path)
        if source_idb.suffix.lower() != ".i64":
            raise ValueError(f"Expected an .i64 path, got: {idb_path}")
        if not source_idb.exists():
            raise FileNotFoundError(f"Input IDB not found: {idb_path}")
        source_binary = Path(str(source_idb)[:-4])
        source_idb_stat = source_idb.stat()
        source_metadata = {
            "source_input_kind": "idb",
            "source_input_path": normalized.input_path,
            "source_windows_path": normalized.windows_path,
            "source_wsl_path": normalized.wsl_path,
            "source_idb_wsl_path": normalized.wsl_path,
            "source_idb_exists": True,
            "source_idb_size": int(source_idb_stat.st_size),
            "source_idb_mtime_ns": int(source_idb_stat.st_mtime_ns),
            "source_binary_wsl_path": str(source_binary),
            "source_binary_windows_path": to_windows_path(str(source_binary)),
            "staged_from_existing_idb": True,
        }
        if len(windows_path) >= 3 and windows_path[1:3] == ":\\" and not always_stage:
            return windows_path, normalized.input_path, source_metadata

        staged_dir = self.stage_root / uuid.uuid4().hex[:12]
        staged_dir.mkdir(parents=True, exist_ok=True)
        staged_idb = staged_dir / source_idb.name
        try:
            shutil.copy2(source_idb, staged_idb)
        except Exception:
            shutil.rmtree(staged_dir, ignore_errors=True)
            raise
        metadata = {
            "staged_dir": str(staged_dir),
            "staged_binary_path": "",
            "staged_idb_path": str(staged_idb),
        }
        metadata.update(source_metadata)
        try:
            self._write_stage_metadata(staged_dir, metadata)
        except Exception:
            shutil.rmtree(staged_dir, ignore_errors=True)
            raise
        return to_windows_path(str(staged_idb)), normalized.input_path, metadata

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
        def ps_quote(value: str) -> str:
            return "'" + str(value).replace("'", "''") + "'"

        escaped_args = []
        for arg in arguments:
            escaped_args.append(ps_quote(arg))
        quoted_args = ", ".join(escaped_args)
        window_style = "-WindowStyle Hidden" if hidden else ""
        working_dir = working_directory or executable.rsplit("\\", 1)[0]
        working_dir_arg = f"-WorkingDirectory {ps_quote(working_dir)} " if working_dir else ""
        redirect_args = ""
        if stdout_path:
            redirect_args += f"-RedirectStandardOutput {ps_quote(stdout_path)} "
        if stderr_path:
            redirect_args += f"-RedirectStandardError {ps_quote(stderr_path)} "
        env_prefix = ""
        if env:
            for key, value in env.items():
                escaped_value = value.replace("'", "''")
                env_prefix += f"$env:{key} = '{escaped_value}'; "
        ps = (
            f"{env_prefix}"
            f"$p = Start-Process -FilePath {ps_quote(executable)} -ArgumentList @({quoted_args}) "
            f"-PassThru {working_dir_arg}{redirect_args}{window_style}; "
            "$p.Id"
        )
        try:
            result = self._powershell(ps, timeout_sec=_launch_handshake_timeout_sec())
        except subprocess.TimeoutExpired:
            # The watchdog only releases the WSL manager from a stuck
            # PowerShell wrapper.  It does not address or terminate the IDA
            # child; the launch token/session heartbeat remains authoritative.
            return None
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "failed to launch IDA")
        stdout = result.stdout.strip()
        return int(stdout) if stdout.isdigit() else None

    def _launch_headless_open_path(
        self,
        *,
        open_path_windows: str,
        display_path: str,
        idb_path: str,
        metadata: dict[str, Any],
        manager_url: str,
        existing_idb: bool,
        architecture: dict[str, Any],
    ) -> PendingLaunch:
        launch_token = f"launch-{uuid.uuid4().hex[:12]}"
        port = self._reserve_headless_port()
        connect_hosts = self._resolve_connect_hosts()
        endpoint_host = connect_hosts[0]
        bootstrap_root, bootstrap_source = self._stage_bundled_headless_backend()
        stdout_log_path = to_windows_path(str(self.wsl_temp / f"{launch_token}.stdout.log"))
        stderr_log_path = to_windows_path(str(self.wsl_temp / f"{launch_token}.stderr.log"))
        headless_mode = (os.getenv("IDA_HEADLESS_MODE", "idat").strip() or "idat").lower()
        use_gui_hidden = headless_mode in {"gui", "gui-hidden", "ida", "auto"}
        idat_log_path = to_windows_path(str(self.wsl_temp / f"{launch_token}.idat.log"))
        architecture_script = None
        if _architecture_needs_script(architecture):
            architecture_script = self._write_architecture_script(launch_token, architecture)
        bootstrap_path = self._write_headless_bootstrap(
            port=port,
            launch_token=launch_token,
            manager_url=manager_url,
            background=True,
            persist=not use_gui_hidden,
            bootstrap_root=bootstrap_root,
            architecture_script=architecture_script,
        )
        args: list[str] = _architecture_args(architecture)
        if not existing_idb:
            args.append("-A")
        if not use_gui_hidden and not existing_idb:
            args.extend(
                [
                    "-c",
                    f"-o{idb_path}",
                    f"-L{idat_log_path}",
                ]
            )
        elif not use_gui_hidden:
            args.append(f"-L{idat_log_path}")
        args.extend(
            [
                f"-S{bootstrap_path}",
                open_path_windows,
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
        if pid is None:
            metadata["launcher_handshake_timed_out"] = True
            metadata["launcher_handshake_timeout_sec"] = _launch_handshake_timeout_sec()
        metadata["stdout_log_path"] = to_wsl_path(stdout_log_path)
        metadata["stderr_log_path"] = to_wsl_path(stderr_log_path)
        metadata["idat_log_path"] = to_wsl_path(idat_log_path)
        metadata["headless_mode"] = "gui-hidden" if use_gui_hidden else "idat"
        metadata["opened_existing_idb"] = existing_idb
        metadata["architecture"] = _architecture_metadata(architecture)
        metadata["connect_host"] = endpoint_host
        metadata["connect_host_candidates"] = connect_hosts
        metadata["bootstrap_root"] = to_wsl_path(bootstrap_root)
        metadata["bootstrap_source"] = bootstrap_source
        return PendingLaunch(
            launch_token=launch_token,
            binary_path=display_path,
            idb_path=idb_path,
            engine="headless",
            port=port,
            pid=pid,
            metadata=metadata,
        )

    def launch_headless(
        self,
        binary_path: str,
        manager_url: str,
        *,
        allow_existing_idb: bool = True,
        processor: str | None = None,
        compiler: str | None = None,
        bitness: int | None = None,
        thumb_mode: bool | None = None,
        thumb_address: int | str | None = None,
    ) -> PendingLaunch:
        architecture = _architecture_options(
            processor=processor,
            compiler=compiler,
            bitness=bitness,
            thumb_mode=thumb_mode,
            thumb_address=thumb_address,
        )
        binary_windows, display_path, metadata = self._prepare_binary_path(
            binary_path,
            always_stage=True,
            allow_existing_idb=allow_existing_idb,
        )
        staged_idb_path = str(metadata.get("staged_idb_path") or "")
        existing_idb = allow_existing_idb and bool(metadata.get("staged_from_existing_idb")) and bool(staged_idb_path)
        open_path_windows = to_windows_path(staged_idb_path) if existing_idb else binary_windows
        idb_path = to_windows_path(staged_idb_path) if existing_idb else f"{binary_windows}.i64"
        try:
            return self._launch_headless_open_path(
                open_path_windows=open_path_windows,
                display_path=display_path,
                idb_path=idb_path,
                metadata=metadata,
                manager_url=manager_url,
                existing_idb=existing_idb,
                architecture=architecture,
            )
        except Exception:
            self._cleanup_launch_staging(metadata)
            raise

    def launch_headless_idb(
        self,
        idb_path: str,
        manager_url: str,
        *,
        processor: str | None = None,
        compiler: str | None = None,
        bitness: int | None = None,
        thumb_mode: bool | None = None,
        thumb_address: int | str | None = None,
    ) -> PendingLaunch:
        architecture = _architecture_options(
            processor=processor,
            compiler=compiler,
            bitness=bitness,
            thumb_mode=thumb_mode,
            thumb_address=thumb_address,
        )
        idb_windows, display_path, metadata = self._prepare_idb_path(idb_path, always_stage=True)
        try:
            return self._launch_headless_open_path(
                open_path_windows=idb_windows,
                display_path=display_path,
                idb_path=idb_windows,
                metadata=metadata,
                manager_url=manager_url,
                existing_idb=True,
                architecture=architecture,
            )
        except Exception:
            self._cleanup_launch_staging(metadata)
            raise

    def _cleanup_launch_staging(self, metadata: dict[str, Any]) -> None:
        staged_dir = str(metadata.get("staged_dir") or "")
        if not staged_dir:
            return
        try:
            self.cleanup_staged_dir(staged_dir)
        except OSError:
            pass

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

    def list_managed_headless_pids(self) -> list[int]:
        result = self._powershell(
            "Get-CimInstance -Query \"SELECT ProcessId,CommandLine FROM Win32_Process WHERE Name='idat.exe' OR Name='ida.exe'\" | "
            "Where-Object { $_.CommandLine -like '*ida-hybrid-manager*headless-launch-*' } | "
            "Select-Object -ExpandProperty ProcessId"
        )
        if result.returncode != 0:
            return []
        pids: list[int] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.isdigit():
                pids.append(int(line))
        return pids

    def is_managed_headless_process(self, pid: int, *, launch_token: str = "") -> bool:
        result = self._powershell(
            f"Get-CimInstance -Query \"SELECT ProcessId,CommandLine FROM Win32_Process WHERE ProcessId={int(pid)}\" | "
            "Select-Object -ExpandProperty CommandLine"
        )
        if result.returncode != 0:
            return False
        cmdline = result.stdout.strip()
        if "ida-hybrid-manager" not in cmdline or "headless-launch-" not in cmdline:
            return False
        return not launch_token or launch_token in cmdline

    def terminate_untracked_idat(self, tracked_pids: set[int]) -> list[int]:
        terminated: list[int] = []
        for pid in self.list_managed_headless_pids():
            if pid in tracked_pids:
                continue
            try:
                self.terminate_process(pid)
                terminated.append(pid)
            except Exception:
                continue
        return terminated

    def launch_gui(
        self,
        binary_path: str,
        *,
        allow_existing_idb: bool = True,
        processor: str | None = None,
        compiler: str | None = None,
        bitness: int | None = None,
        thumb_mode: bool | None = None,
        thumb_address: int | str | None = None,
    ) -> PendingLaunch:
        architecture = _architecture_options(
            processor=processor,
            compiler=compiler,
            bitness=bitness,
            thumb_mode=thumb_mode,
            thumb_address=thumb_address,
        )
        binary_windows, display_path, metadata = self._prepare_binary_path(binary_path, allow_existing_idb=allow_existing_idb)
        launch_token = f"gui-{uuid.uuid4().hex[:12]}"
        try:
            args = _architecture_args(architecture)
            if _architecture_needs_script(architecture):
                args.append(f"-S{self._write_architecture_script(launch_token, architecture)}")
            args.append(binary_windows)
            metadata["architecture"] = _architecture_metadata(architecture)
            pid = self._start_process(self.ida_gui, args, hidden=False)
            return PendingLaunch(
                launch_token=launch_token,
                binary_path=display_path,
                idb_path=f"{binary_windows}.i64",
                engine="gui",
                port=None,
                pid=pid,
                metadata=metadata,
            )
        except Exception:
            self._cleanup_launch_staging(metadata)
            raise

    def launch_gui_idb(
        self,
        idb_path: str,
        *,
        processor: str | None = None,
        compiler: str | None = None,
        bitness: int | None = None,
        thumb_mode: bool | None = None,
        thumb_address: int | str | None = None,
    ) -> PendingLaunch:
        architecture = _architecture_options(
            processor=processor,
            compiler=compiler,
            bitness=bitness,
            thumb_mode=thumb_mode,
            thumb_address=thumb_address,
        )
        idb_windows, display_path, metadata = self._prepare_idb_path(idb_path)
        launch_token = f"gui-{uuid.uuid4().hex[:12]}"
        try:
            args = _architecture_args(architecture)
            if _architecture_needs_script(architecture):
                args.append(f"-S{self._write_architecture_script(launch_token, architecture)}")
            args.append(idb_windows)
            metadata["architecture"] = _architecture_metadata(architecture)
            pid = self._start_process(self.ida_gui, args, hidden=False)
            return PendingLaunch(
                launch_token=launch_token,
                binary_path=display_path,
                idb_path=idb_windows,
                engine="gui",
                port=None,
                pid=pid,
                metadata=metadata,
            )
        except Exception:
            self._cleanup_launch_staging(metadata)
            raise

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
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if not self.is_process_alive(pid):
                return
            time.sleep(0.1)
        raise RuntimeError(f"process {pid} did not exit after Stop-Process")

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
        if not self.is_managed_staged_dir(path):
            raise ValueError(f"Refusing to remove a directory outside managed staging roots: {path}")
        if not path.exists():
            return False
        def _retry_readonly(func, target, exc_info):
            try:
                os.chmod(target, stat.S_IWRITE | stat.S_IREAD)
                func(target)
            except FileNotFoundError:
                return

        deadline = time.monotonic() + 5.0
        while True:
            try:
                shutil.rmtree(path, onerror=_retry_readonly)
                return True
            except FileNotFoundError:
                return False
            except PermissionError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.2)
