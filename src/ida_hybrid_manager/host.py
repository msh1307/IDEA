from __future__ import annotations

from contextlib import ExitStack, contextmanager
import os
from pathlib import Path
import select
import socket
import subprocess
import tempfile
import time
from typing import Any, Iterator, TextIO
from urllib.parse import urlsplit


class WslHostAdapter:
    native_windows = False
    platform = "wsl"

    @property
    def runtime_temp_dir(self) -> Path:
        return Path(tempfile.gettempdir())

    def windows_path_exists(self, path: str) -> bool:
        escaped = path.replace("'", "''")
        result = self._powershell(
            f"if (Test-Path -LiteralPath '{escaped}') {{ '1' }} else {{ '0' }}"
        )
        return result.returncode == 0 and result.stdout.strip() == "1"

    def reserve_windows_port(self) -> int:
        result = self._powershell(
            "& { "
            "$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, 0); "
            "$listener.Start(); "
            "$port = $listener.LocalEndpoint.Port; "
            "$listener.Stop(); "
            "Write-Output $port "
            "}"
        )
        stdout = result.stdout.strip()
        if result.returncode == 0 and stdout.isdigit():
            return int(stdout)
        return self._free_port()

    def start_windows_process(
        self,
        executable: str,
        arguments: list[str],
        *,
        hidden: bool,
        env: dict[str, str] | None,
        stdout_path: str | None,
        stderr_path: str | None,
        working_directory: str | None,
        handshake_timeout_sec: float,
    ) -> int | None:
        def quote(value: str) -> str:
            return "'" + str(value).replace("'", "''") + "'"

        quoted_args = ", ".join(quote(arg) for arg in arguments)
        working_dir = working_directory or executable.rsplit("\\", 1)[0]
        working_dir_arg = f"-WorkingDirectory {quote(working_dir)} " if working_dir else ""
        redirect_args = ""
        if stdout_path:
            redirect_args += f"-RedirectStandardOutput {quote(stdout_path)} "
        if stderr_path:
            redirect_args += f"-RedirectStandardError {quote(stderr_path)} "
        env_prefix = "".join(f"$env:{key} = {quote(value)}; " for key, value in (env or {}).items())
        command = (
            f"{env_prefix}"
            f"$p = Start-Process -FilePath {quote(executable)} -ArgumentList @({quoted_args}) "
            f"-PassThru {working_dir_arg}{redirect_args}{'-WindowStyle Hidden' if hidden else ''}; "
            "$p.Id"
        )
        wrapper = subprocess.Popen(
            ["powershell.exe", "-NoProfile", "-Command", command],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="ignore",
        )
        output: list[str] = []
        try:
            deadline = time.monotonic() + handshake_timeout_sec
            while time.monotonic() < deadline and wrapper.stdout is not None:
                ready, _, _ = select.select([wrapper.stdout], [], [], max(0.0, deadline - time.monotonic()))
                if not ready:
                    break
                line = wrapper.stdout.readline()
                if not line:
                    break
                output.append(line.strip())
                if output[-1].isdigit():
                    return int(output[-1])
            if wrapper.poll() not in {None, 0}:
                raise RuntimeError("\n".join(output) or "failed to launch IDA")
            return None
        finally:
            if wrapper.poll() is None:
                wrapper.terminate()
                try:
                    wrapper.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    wrapper.kill()
                    wrapper.wait()
            if wrapper.stdout is not None:
                wrapper.stdout.close()

    @contextmanager
    def daemon_lock(self, handle: TextIO) -> Iterator[None]:
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def listener_pid(self, port: int) -> int | None:
        try:
            output = subprocess.check_output(["ss", "-ltnp"], text=True, stderr=subprocess.DEVNULL)
        except Exception:
            return None
        for line in output.splitlines():
            if f":{port} " not in line and not line.rstrip().endswith(f":{port}"):
                continue
            try:
                pid = line.split("pid=", 1)[1].split(",", 1)[0].split(")", 1)[0].strip()
                return int(pid) if pid.isdigit() else None
            except Exception:
                continue
        return None

    def process_command(self, pid: int) -> str:
        try:
            return Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "ignore").strip()
        except Exception:
            return ""

    def terminate_local_process(self, pid: int) -> None:
        try:
            os.kill(pid, 15)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if not Path(f"/proc/{pid}").exists():
                return
            time.sleep(0.1)
        try:
            os.kill(pid, 9)
        except ProcessLookupError:
            pass

    def spawn_daemon(self, command: list[str], cwd: Path, log: Any, env: dict[str, str]) -> subprocess.Popen[Any]:
        return subprocess.Popen(
            command,
            cwd=str(cwd),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

    @staticmethod
    def _powershell(command: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            check=False,
            stdin=subprocess.DEVNULL,
            encoding="utf-8",
            errors="ignore",
        )

    @staticmethod
    def _free_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("0.0.0.0", 0))
            return int(sock.getsockname()[1])


class WindowsHostAdapter(WslHostAdapter):
    native_windows = True
    platform = "windows"

    def windows_path_exists(self, path: str) -> bool:
        return Path(path).exists()

    def reserve_windows_port(self) -> int:
        return self._free_port()

    def start_windows_process(
        self,
        executable: str,
        arguments: list[str],
        *,
        hidden: bool,
        env: dict[str, str] | None,
        stdout_path: str | None,
        stderr_path: str | None,
        working_directory: str | None,
        handshake_timeout_sec: float,
    ) -> int | None:
        process_env = os.environ.copy()
        process_env.update(env or {})
        working_dir = working_directory or executable.rsplit("\\", 1)[0]
        with ExitStack() as stack:
            stdout_handle = stack.enter_context(open(stdout_path, "ab")) if stdout_path else subprocess.DEVNULL
            stderr_handle = stack.enter_context(open(stderr_path, "ab")) if stderr_path else subprocess.DEVNULL
            process = subprocess.Popen(
                [executable, *arguments],
                cwd=working_dir or None,
                env=process_env,
                stdin=subprocess.DEVNULL,
                stdout=stdout_handle,
                stderr=stderr_handle,
                creationflags=(
                    getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                    | (getattr(subprocess, "CREATE_NO_WINDOW", 0) if hidden else 0)
                ),
            )
            return process.pid

    @contextmanager
    def daemon_lock(self, handle: TextIO) -> Iterator[None]:
        import msvcrt

        handle.seek(0)
        if not handle.read(1):
            handle.seek(0)
            handle.write("\0")
            handle.flush()
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        try:
            yield
        finally:
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)

    def listener_pid(self, port: int) -> int | None:
        try:
            output = subprocess.check_output(
                ["netstat.exe", "-ano", "-p", "tcp"],
                text=True,
                stderr=subprocess.DEVNULL,
                encoding="utf-8",
                errors="ignore",
            )
        except Exception:
            return None
        for line in output.splitlines():
            parts = line.split()
            if len(parts) < 5 or parts[0].upper() != "TCP" or parts[3].upper() != "LISTENING":
                continue
            try:
                local_port = urlsplit(f"tcp://{parts[1]}").port
            except ValueError:
                continue
            if local_port != port:
                continue
            return int(parts[4]) if parts[4].isdigit() else None
        return None

    def process_command(self, pid: int) -> str:
        result = self._powershell(
            f"(Get-CimInstance Win32_Process -Filter \"ProcessId={int(pid)}\" "
            "| Select-Object -ExpandProperty CommandLine)"
        )
        return result.stdout.strip() if result.returncode == 0 else ""

    def terminate_local_process(self, pid: int) -> None:
        subprocess.run(
            ["taskkill.exe", "/PID", str(int(pid)), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )

    def spawn_daemon(self, command: list[str], cwd: Path, log: Any, env: dict[str, str]) -> subprocess.Popen[Any]:
        return subprocess.Popen(
            command,
            cwd=str(cwd),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            creationflags=(
                getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                | getattr(subprocess, "CREATE_NO_WINDOW", 0)
            ),
        )


HOST = WindowsHostAdapter() if os.name == "nt" else WslHostAdapter()
