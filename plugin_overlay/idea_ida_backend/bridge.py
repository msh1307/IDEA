from __future__ import annotations

import json
import os
import subprocess
import threading
import time
import urllib.error
import urllib.request

import ida_auto
import ida_ida
import ida_idaapi
import ida_kernwin
import ida_loader
import ida_nalt
import ida_netnode
import ida_segment
import idaapi
import idc

from .sync import idasync
from .tools import TOOL_DEFINITIONS


DEFAULT_MANAGER_URL = "http://127.0.0.1:18080"
DEFAULT_HEARTBEAT_INTERVAL_SEC = 10.0
_AUTO_QUEUE_NAMES = (
    "AU_UNK",
    "AU_CODE",
    "AU_WEAK",
    "AU_PROC",
    "AU_TAIL",
    "AU_FCHUNK",
    "AU_USED",
    "AU_USD2",
    "AU_TYPE",
    "AU_LIBF",
    "AU_LBF2",
    "AU_LBF3",
    "AU_CHLB",
    "AU_FINAL",
)
_AUTO_QUEUE_LABELS = {
    "AU_UNK": "marking unexplored bytes",
    "AU_CODE": "creating instructions",
    "AU_WEAK": "creating speculative instructions",
    "AU_PROC": "creating functions",
    "AU_TAIL": "creating function tails",
    "AU_FCHUNK": "finding function chunks",
    "AU_USED": "reanalyzing references",
    "AU_USD2": "reanalyzing references (pass 2)",
    "AU_TYPE": "applying type information",
    "AU_LIBF": "matching library signatures",
    "AU_LBF2": "matching library signatures (pass 2)",
    "AU_LBF3": "matching library signatures (pass 3)",
    "AU_CHLB": "loading signature files",
    "AU_FINAL": "running the final analysis pass",
}


def _config_json_get(key: str, default):
    node = ida_netnode.netnode(f"$ idea_ida.{key}")
    blob = node.getblob(0, "C")
    if blob is None:
        return default
    try:
        return json.loads(blob)
    except Exception:
        return default


def _config_bool(key: str, default: bool) -> bool:
    env = os.getenv(f"IDEA_IDA_{key.upper()}")
    if env is not None:
        return env.strip().lower() not in {"0", "false", "no", "off"}
    return bool(_config_json_get(key, default))


def _config_str(key: str, default: str) -> str:
    env = os.getenv(f"IDEA_IDA_{key.upper()}")
    if env:
        return env
    value = _config_json_get(key, default)
    return value if isinstance(value, str) and value else default


def _config_float(key: str, default: float) -> float:
    env = os.getenv(f"IDEA_IDA_{key.upper()}")
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


def _collect_autoanalysis_snapshot(source: str) -> dict:
    try:
        complete = bool(ida_auto.auto_is_ok())
    except Exception:
        complete = False

    definitions = []
    seen = set()
    for name in _AUTO_QUEUE_NAMES:
        value = getattr(ida_auto, name, None)
        if value is None or int(value) in seen:
            continue
        seen.add(int(value))
        definitions.append((name, int(value)))

    try:
        min_ea = int(ida_ida.inf_get_min_ea())
        max_ea = int(ida_ida.inf_get_max_ea())
    except Exception:
        min_ea, max_ea = 0, int(ida_idaapi.BADADDR)

    current_ea = int(ida_idaapi.BADADDR)
    phase_id = int(getattr(ida_auto, "AU_NONE", -1))
    if hasattr(ida_auto, "auto_display_t") and hasattr(ida_auto, "get_auto_display"):
        try:
            display = ida_auto.auto_display_t()
            if ida_auto.get_auto_display(display):
                current_ea = int(display.ea)
                phase_id = int(display.type)
        except Exception:
            pass

    if (current_ea == ida_idaapi.BADADDR or phase_id == int(getattr(ida_auto, "AU_NONE", -1))) and hasattr(ida_auto, "peek_auto_queue"):
        for _, queue_type in definitions:
            try:
                pending_ea = int(ida_auto.peek_auto_queue(min_ea, queue_type))
            except Exception:
                continue
            if pending_ea == ida_idaapi.BADADDR:
                continue
            current_ea = pending_ea
            phase_id = queue_type
            break

    phase_index = -1
    phase_name = "AU_NONE" if phase_id == int(getattr(ida_auto, "AU_NONE", -1)) else f"AU_{phase_id}"
    for index, (name, queue_type) in enumerate(definitions):
        if queue_type == phase_id:
            phase_index = index
            phase_name = name
            break
    phase = {
        "name": phase_name,
        "label": _AUTO_QUEUE_LABELS.get(phase_name, "idle" if phase_name == "AU_NONE" else "unknown analysis phase"),
    }

    current = None
    address_fraction = 0.0
    if current_ea != ida_idaapi.BADADDR:
        image_base = int(idaapi.get_imagebase())
        segment = ida_segment.getseg(current_ea)
        segment_name = ida_segment.get_segm_name(segment) if segment is not None else ""
        current = {
            "address": f"0x{current_ea:X}",
            "rva": f"0x{max(0, current_ea - image_base):X}",
            "segment": segment_name,
            "segment_percent": None,
        }
        if segment is not None:
            size = max(0, int(segment.end_ea - segment.start_ea))
            offset = max(0, min(size, int(current_ea - segment.start_ea)))
            current["segment_percent"] = round((offset / size) * 100.0, 2) if size else 100.0
        if max_ea > min_ea:
            address_fraction = max(0.0, min(1.0, (current_ea - min_ea) / (max_ea - min_ea)))

    if complete:
        progress_percent = 100.0
    elif phase_index >= 0 and definitions:
        progress_percent = round(min(99.9, ((phase_index + address_fraction) / len(definitions)) * 100.0), 2)
    else:
        progress_percent = round(min(99.9, address_fraction * 100.0), 2)

    if complete:
        message = "IDA autoanalysis complete"
    elif current and current.get("segment"):
        segment_percent = current.get("segment_percent")
        segment_progress = f" {segment_percent:.2f}%" if isinstance(segment_percent, (int, float)) else ""
        message = f"{phase_name} {current['segment']}{segment_progress} at {current['address']}"
    elif current:
        message = f"{phase_name} at {current['address']}"
    else:
        message = f"{phase_name} (analysis queues pending)"

    return {
        "autoanalysis_complete": complete,
        "status": "complete" if complete else "analyzing",
        "message": message,
        "progress_percent": progress_percent,
        "phase": phase,
        "current": current,
        "source": source,
        "checked_at_epoch": time.time(),
    }


@idasync
def collect_registration_snapshot(host: str, port: int, engine: str, launch_token: str | None) -> dict:
    sha256_bytes = ida_nalt.retrieve_input_file_sha256() or b""
    binary_path = ida_nalt.get_input_file_path() or ""
    idb_path = idc.get_idb_path() or ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or ""
    display_name = ida_nalt.get_root_filename() or os.path.basename(binary_path or idb_path or "ida")
    endpoint_host = _config_str("endpoint_host", "127.0.0.1")
    autoanalysis = _collect_autoanalysis_snapshot("bridge_registration")
    return {
        "engine": engine,
        "display_name": display_name,
        "binary_path": binary_path,
        "binary_hash": f"sha256:{sha256_bytes.hex()}" if sha256_bytes else "",
        "idb_path": idb_path,
        "status": "ready" if autoanalysis["autoanalysis_complete"] else "busy",
        "capabilities": sorted(tool["name"] for tool in TOOL_DEFINITIONS),
        "endpoint": {"transport": "native-http", "url": f"http://{endpoint_host}:{port}"},
        "owner_pid": os.getpid(),
        "metadata": {
            "ida_version": idaapi.get_kernel_version(),
            "plugin_version": "idea-native-v1",
            "readonly": False,
            "launch_token": launch_token,
            "headless": engine == "headless",
            "autoanalysis": autoanalysis,
        },
    }


@idasync
def collect_heartbeat_snapshot() -> dict:
    current_ea = ida_kernwin.get_screen_ea()
    current_func = idaapi.get_func(current_ea)
    current_func_name = ""
    if current_func is not None:
        current_func_name = idaapi.get_func_name(current_func.start_ea) or ""
    autoanalysis = _collect_autoanalysis_snapshot("bridge_heartbeat")
    return {
        "status": "ready" if autoanalysis["autoanalysis_complete"] else "busy",
        "current_address": hex(current_ea) if current_ea != idaapi.BADADDR else "",
        "current_function": current_func_name,
        "busy": not autoanalysis["autoanalysis_complete"],
        "autoanalysis": autoanalysis,
    }


class ManagerBridge:
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

        def add(url: str) -> None:
            candidate = (url or "").strip().rstrip("/")
            if not candidate or candidate in seen:
                return
            seen.add(candidate)
            urls.append(candidate)

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
    def _refresh_config(self) -> None:
        self._manager_urls = self._discover_manager_urls()
        self._manager_url = self._manager_urls[0]
        self._enabled = _config_bool("register_with_manager", True)
        interval = _config_float("manager_heartbeat_sec", DEFAULT_HEARTBEAT_INTERVAL_SEC)
        self._heartbeat_interval_sec = max(2.0, interval)

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def heartbeat_interval_sec(self) -> float:
        return self._heartbeat_interval_sec

    def update_endpoint(self, host: str, port: int, *, engine: str | None = None, launch_token: str | None = None) -> None:
        self.host = host
        self.port = port
        if engine is not None:
            self.engine = engine
        if launch_token is not None:
            self.launch_token = launch_token

    def start(self) -> None:
        self._refresh_config()
        print(f"[IDEA] bridge config: enabled={self.enabled} manager_urls={self._manager_urls}")
        if not self.enabled or self._thread is not None:
            return
        self._stop.clear()
        self._refresh.set()
        self._thread = threading.Thread(target=self._run, name="idea-ida-bridge", daemon=True)
        self._thread.start()
        # Headless/bootstrap mode proved unreliable when the first registration
        # depended on the background thread scheduling. Send one register now.
        self._send_register()

    def request_refresh(self, reason: str = "") -> None:
        if reason:
            print(f"[IDEA] Session refresh requested: {reason}")
        self._refresh.set()

    def stop(self, reason: str = "shutdown") -> None:
        self._stop.set()
        self._refresh.set()
        self._send_unregister(reason)
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def _post_json(self, path: str, payload: dict) -> dict | None:
        data = json.dumps(payload).encode("utf-8")
        for base_url in self._manager_urls:
            print(f"[IDEA] bridge POST {base_url}{path}")
            req = urllib.request.Request(
                f"{base_url}{path}",
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    body = resp.read().decode("utf-8")
                self._manager_url = base_url
                print(f"[IDEA] bridge response {base_url}{path}: {body}")
                return json.loads(body) if body else {}
            except urllib.error.HTTPError as exc:
                try:
                    body = exc.read().decode("utf-8")
                    print(f"[IDEA] bridge HTTP error {base_url}{path}: {exc.code} {body}")
                    return json.loads(body) if body else {"ok": False, "error": f"http_{exc.code}"}
                except Exception:
                    print(f"[IDEA] bridge HTTP error {base_url}{path}: {exc.code}")
                    return {"ok": False, "error": f"http_{exc.code}"}
            except Exception as exc:
                print(f"[IDEA] bridge request failed {base_url}{path}: {exc!r}")
                continue
        return None

    def _send_register(self) -> bool:
        payload = {"session": collect_registration_snapshot(self.host, self.port, self.engine, self.launch_token)}
        if self.session_id:
            payload["session_id"] = self.session_id
        print(f"[IDEA] bridge register launch_token={self.launch_token} session_id={self.session_id}")
        response = self._post_json("/api/sessions/register", payload)
        if not response or not response.get("ok"):
            print(f"[IDEA] bridge register failed: {response}")
            return False
        self.session_id = response.get("session_id") or self.session_id
        print(f"[IDEA] bridge register ok: session_id={self.session_id}")
        return True

    def _send_heartbeat(self) -> bool:
        if not self.session_id:
            return self._send_register()
        payload = {"session_id": self.session_id}
        payload.update(collect_heartbeat_snapshot())
        response = self._post_json("/api/sessions/heartbeat", payload)
        print(f"[IDEA] bridge heartbeat: {response}")
        if response and response.get("ok"):
            return True
        if response and response.get("error") == "unknown_session":
            print("[IDEA] bridge heartbeat lost session, re-registering")
            self.session_id = None
            return self._send_register()
        return False

    def _send_unregister(self, reason: str) -> bool:
        if not self.session_id:
            return False
        response = self._post_json("/api/sessions/unregister", {"session_id": self.session_id, "reason": reason})
        print(f"[IDEA] bridge unregister: {response}")
        return bool(response and response.get("ok"))

    def _run(self) -> None:
        next_heartbeat = 0.0
        while not self._stop.is_set():
            if self._refresh.is_set():
                self._refresh.clear()
                self._send_register()
                next_heartbeat = time.monotonic() + self.heartbeat_interval_sec

            now = time.monotonic()
            if now >= next_heartbeat:
                self._send_heartbeat()
                next_heartbeat = now + self.heartbeat_interval_sec
            self._stop.wait(0.5)
