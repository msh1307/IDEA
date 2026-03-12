import json
import os
import subprocess
import threading
import time
import urllib.error
import urllib.request

import ida_loader
import ida_nalt
import idaapi
import idc
import ida_kernwin
import ida_netnode

from .rpc import MCP_SERVER
from .sync import idasync


DEFAULT_MANAGER_URL = "http://127.0.0.1:18080"
DEFAULT_HEARTBEAT_INTERVAL_SEC = 10.0


def _config_json_get(key: str, default):
    node = ida_netnode.netnode(f"$ ida_mcp.{key}")
    blob = node.getblob(0, "C")
    if blob is None:
        return default
    try:
        return json.loads(blob)
    except Exception:
        return default


def _config_bool(key: str, default: bool) -> bool:
    env = os.getenv(f"IDA_MCP_{key.upper()}")
    if env is not None:
        return env.strip().lower() not in {"0", "false", "no", "off"}
    return bool(_config_json_get(key, default))


def _config_str(key: str, default: str) -> str:
    env = os.getenv(f"IDA_MCP_{key.upper()}")
    if env:
        return env
    value = _config_json_get(key, default)
    return value if isinstance(value, str) and value else default


def _config_float(key: str, default: float) -> float:
    env = os.getenv(f"IDA_MCP_{key.upper()}")
    if env:
        try:
            return float(env)
        except ValueError:
            return default
    value = _config_json_get(key, default)
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


@idasync
def collect_registration_snapshot(host: str, port: int, engine: str, launch_token: str | None) -> dict:
    sha256_bytes = ida_nalt.retrieve_input_file_sha256() or b""
    binary_path = ida_nalt.get_input_file_path() or ""
    idb_path = idc.get_idb_path() or ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or ""
    display_name = ida_nalt.get_root_filename() or os.path.basename(binary_path or idb_path or "ida")
    endpoint_host = _config_str("endpoint_host", "127.0.0.1")

    return {
        "engine": engine,
        "display_name": display_name,
        "binary_path": binary_path,
        "binary_hash": f"sha256:{sha256_bytes.hex()}" if sha256_bytes else "",
        "idb_path": idb_path,
        "status": "ready",
        "capabilities": sorted(MCP_SERVER.tools.methods.keys()),
        "endpoint": {
            "transport": "streamable-http",
            "url": f"http://{endpoint_host}:{port}/mcp",
        },
        "owner_pid": os.getpid(),
        "metadata": {
            "ida_version": idaapi.get_kernel_version(),
            "plugin_version": "hybrid-local",
            "readonly": False,
            "launch_token": launch_token,
            "headless": engine == "headless",
        },
    }


@idasync
def collect_heartbeat_snapshot() -> dict:
    current_ea = ida_kernwin.get_screen_ea()
    current_func = idaapi.get_func(current_ea)
    current_func_name = ""
    if current_func is not None:
        current_func_name = idaapi.get_func_name(current_func.start_ea) or ""

    return {
        "status": "ready",
        "current_address": hex(current_ea) if current_ea != idaapi.BADADDR else "",
        "current_function": current_func_name,
        "busy": False,
    }


class SessionBridge:
    def __init__(self, host: str, port: int, *, engine: str = "gui", launch_token: str | None = None):
        self.host = host
        self.port = port
        self.engine = engine
        self.launch_token = launch_token
        self.session_id: str | None = None
        self._stop = threading.Event()
        self._refresh = threading.Event()
        self._thread: threading.Thread | None = None
        self._manager_url = DEFAULT_MANAGER_URL
        self._manager_urls: list[str] = [DEFAULT_MANAGER_URL]
        self._enabled = True
        self._heartbeat_interval_sec = DEFAULT_HEARTBEAT_INTERVAL_SEC

    def _discover_manager_urls(self) -> list[str]:
        urls: list[str] = []
        seen: set[str] = set()

        def add(url: str):
            url = (url or "").strip().rstrip("/")
            if not url or url in seen:
                return
            seen.add(url)
            urls.append(url)

        add(_config_str("manager_url", DEFAULT_MANAGER_URL))
        add(DEFAULT_MANAGER_URL)
        add("http://localhost:18080")

        try:
            result = subprocess.run(
                ["wsl.exe", "-d", "Ubuntu-24.04", "sh", "-lc", "hostname -I"],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            for token in result.stdout.split():
                if token.count(".") == 3:
                    add(f"http://{token}:18080")
        except Exception:
            pass

        return urls or [DEFAULT_MANAGER_URL]

    @idasync
    def _refresh_config(self):
        self._manager_urls = self._discover_manager_urls()
        self._manager_url = self._manager_urls[0]
        self._enabled = _config_bool("register_with_manager", False)
        interval = _config_float("manager_heartbeat_sec", DEFAULT_HEARTBEAT_INTERVAL_SEC)
        self._heartbeat_interval_sec = max(2.0, interval)

    @property
    def manager_url(self) -> str:
        return self._manager_url

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def heartbeat_interval_sec(self) -> float:
        return self._heartbeat_interval_sec

    def update_endpoint(self, host: str, port: int, *, engine: str | None = None, launch_token: str | None = None):
        self.host = host
        self.port = port
        if engine is not None:
            self.engine = engine
        if launch_token is not None:
            self.launch_token = launch_token

    def start(self):
        self._refresh_config()
        if not self.enabled or self._thread is not None:
            return
        self._stop.clear()
        self._refresh.set()
        self._thread = threading.Thread(target=self._run, name="ida-mcp-session-bridge", daemon=True)
        self._thread.start()

    def request_refresh(self, reason: str = ""):
        if reason:
            print(f"[MCP] Session refresh requested: {reason}")
        self._refresh.set()

    def stop(self, reason: str = "shutdown"):
        self._stop.set()
        self._refresh.set()
        self._send_unregister(reason)
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def _post_json(self, path: str, payload: dict) -> dict | None:
        data = json.dumps(payload).encode("utf-8")
        for base_url in self._manager_urls:
            url = f"{base_url}{path}"
            req = urllib.request.Request(
                url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    body = resp.read().decode("utf-8")
                self._manager_url = base_url
                try:
                    return json.loads(body) if body else {}
                except Exception:
                    return {}
            except urllib.error.HTTPError as exc:
                try:
                    body = exc.read().decode("utf-8")
                    parsed = json.loads(body) if body else {}
                except Exception:
                    parsed = {"ok": False, "error": f"http_{exc.code}"}
                print(f"[MCP] Session bridge HTTP error for {url}: {exc.code}")
                self._manager_url = base_url
                return parsed
            except urllib.error.URLError as exc:
                print(f"[MCP] Session bridge request failed for {url}: {exc}")
            except Exception as exc:
                print(f"[MCP] Session bridge request error for {url}: {exc}")
        return None

    def _send_register(self) -> bool:
        payload = {
            "session": collect_registration_snapshot(
                self.host,
                self.port,
                self.engine,
                self.launch_token,
            )
        }
        if self.session_id:
            payload["session_id"] = self.session_id
        response = self._post_json("/api/sessions/register", payload)
        if not response or not response.get("ok"):
            return False
        self.session_id = response.get("session_id") or self.session_id
        return True

    def _send_heartbeat(self) -> bool:
        if not self.session_id:
            return self._send_register()
        payload = {"session_id": self.session_id}
        payload.update(collect_heartbeat_snapshot())
        response = self._post_json("/api/sessions/heartbeat", payload)
        if response and response.get("ok"):
            return True
        if response and response.get("error") == "unknown_session":
            print("[MCP] Session bridge heartbeat rejected; re-registering session")
            self.session_id = None
            return self._send_register()
        return False

    def _send_unregister(self, reason: str):
        if not self.session_id or not self.enabled:
            return
        self._post_json(
            "/api/sessions/unregister",
            {"session_id": self.session_id, "reason": reason},
        )
        self.session_id = None

    def _run(self):
        next_heartbeat = 0.0
        while not self._stop.is_set():
            now = time.monotonic()
            if self._refresh.is_set() or now >= next_heartbeat or self.session_id is None:
                self._refresh.clear()
                ok = self._send_register() if self.session_id is None else self._send_heartbeat()
                next_heartbeat = time.monotonic() + self.heartbeat_interval_sec
                if not ok:
                    time.sleep(min(self.heartbeat_interval_sec, 5.0))
                    continue
            self._stop.wait(0.5)
