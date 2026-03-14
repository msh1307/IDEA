from __future__ import annotations

import argparse
import asyncio
import fcntl
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit
import uuid

from mcp.server.fastmcp import FastMCP

from .backend import call_backend_tool_any, list_backend_tools_any
from .launch import IdaLauncher
from .manager_api import ManagerApiServer
from .models import PendingLaunch
from .pathing import normalize_path
from .registry import SessionRegistry


DAEMON_HOST = "127.0.0.1"
DAEMON_PORT = 18080
DAEMON_URL = f"http://{DAEMON_HOST}:{DAEMON_PORT}"
DAEMON_LOCK_PATH = Path("/tmp/ida-hybrid-manager-daemon.lock")
DAEMON_LOG_PATH = Path("/tmp/ida-hybrid-manager-daemon.log")

registry = SessionRegistry()
launcher = IdaLauncher()
ACTIVE_BACKEND = "local"
CLIENT_ID: str | None = None
_client_lock = threading.RLock()
_client_current_sessions: dict[str, str | None] = {}

mcp = FastMCP(
    "IDA Hybrid Manager",
    instructions="Manage and route live IDA GUI or manager-owned headless sessions.",
    host="0.0.0.0",
    port=18081,
)


def manager_url() -> str:
    return DAEMON_URL


def _serialize_sessions(records) -> list[dict[str, Any]]:
    return [record.to_dict() for record in records]


def _client_connect(client_name: str = "", client_pid: int | None = None) -> dict[str, Any]:
    client_id = f"client-{uuid.uuid4().hex[:12]}"
    with _client_lock:
        _client_current_sessions[client_id] = None
    return {"client_id": client_id, "client_name": client_name, "client_pid": client_pid}


def _client_get_current_session_id(client_id: str | None) -> str | None:
    if not client_id:
        return None
    with _client_lock:
        return _client_current_sessions.get(client_id)


def _client_set_current_session(client_id: str | None, session_id: str | None) -> None:
    if not client_id:
        return
    with _client_lock:
        if client_id not in _client_current_sessions:
            _client_current_sessions[client_id] = None
        _client_current_sessions[client_id] = session_id


def _client_clear_session_references(session_id: str) -> None:
    with _client_lock:
        for client_id, current in list(_client_current_sessions.items()):
            if current == session_id:
                _client_current_sessions[client_id] = None


def _session_to_client_dict(record, client_id: str | None) -> dict[str, Any]:
    data = record.to_dict()
    data["current"] = bool(client_id and record.session_id == _client_get_current_session_id(client_id))
    return data


def _serialize_sessions_for_client(records, client_id: str | None) -> list[dict[str, Any]]:
    return [_session_to_client_dict(record, client_id) for record in records]


def _tracked_headless_pids() -> set[int]:
    tracked: set[int] = set()
    for record in registry.list_sessions(include_dead=False):
        if record.engine != "headless":
            continue
        if record.owner_pid is None:
            continue
        tracked.add(record.owner_pid)
    return tracked


def _wait_for_session(pending: PendingLaunch, timeout_sec: float = 90.0):
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        sessions = registry.list_sessions(include_dead=False)
        for record in sessions:
            if record.metadata.get("launch_token") == pending.launch_token:
                registry.select_session(record.session_id)
                return record
            if pending.engine == "gui" and record.engine == "gui" and record.binary_path.lower() == pending.binary_path.lower():
                registry.select_session(record.session_id)
                return record
        time.sleep(1.0)
    return None


def _current_or_explicit(session_id: str | None, client_id: str | None = None):
    if session_id is None:
        session_id = _client_get_current_session_id(client_id)
    record = registry.get_session(session_id)
    if record is None:
        raise ValueError("No active session selected")
    if record.status not in {"ready", "busy"}:
        raise ValueError(f"Session {record.session_id} is not available: {record.status}")
    return record


def _backend_candidates(record) -> list[str]:
    candidates = record.metadata.get("endpoint_candidates")
    if isinstance(candidates, list) and candidates:
        return candidates
    return [record.endpoint["url"]]


def _backend_ready(record, timeout_sec: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        for candidate in _backend_candidates(record):
            parsed = urlsplit(candidate)
            host = parsed.hostname
            port = parsed.port
            if not host or not port:
                continue
            try:
                with socket.create_connection((host, port), timeout=2):
                    return True
            except OSError:
                continue
        time.sleep(2.0)
    return False


def _coerce_tool_arguments(arguments: Any) -> dict[str, Any]:
    if arguments is None or arguments == "":
        return {}
    if isinstance(arguments, dict):
        return arguments
    if isinstance(arguments, str):
        parsed = json.loads(arguments)
        if not isinstance(parsed, dict):
            raise ValueError("arguments JSON must decode to an object")
        return parsed
    raise ValueError("arguments must be an object or a JSON object string")


def _resolve_output_path(path: str) -> Path:
    target = Path(path).expanduser()
    if not target.is_absolute():
        target = (Path.cwd() / target).resolve()
    return target


def _render_tool_result(result: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(result, ensure_ascii=False, indent=2)
    content = result.get("content")
    if isinstance(content, list):
        text_chunks = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                text_chunks.append(str(item.get("text", "")))
        if text_chunks:
            return "\n".join(text_chunks).strip() + "\n"
    structured = result.get("structuredContent")
    if structured is not None:
        return json.dumps(structured, ensure_ascii=False, indent=2) + "\n"
    return json.dumps(result, ensure_ascii=False, indent=2) + "\n"


def _attach_managed_headless(pending: PendingLaunch):
    display_name = pending.binary_path.rsplit("\\", 1)[-1]
    if pending.port is None:
        raise ValueError("headless launch did not provide a listener port")
    return registry.register_managed_session(
        engine="headless",
        display_name=display_name,
        binary_path=pending.binary_path,
        idb_path=pending.idb_path,
        owner_pid=pending.pid,
        endpoint_url=f"http://127.0.0.1:{pending.port}/mcp",
        metadata=pending.metadata,
    )


def _daemon_healthz_ok(timeout_sec: float = 2.0) -> bool:
    req = urllib.request.Request(f"{DAEMON_URL}/healthz", method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        return (
            bool(payload.get("ok"))
            and payload.get("service") == "ida-hybrid-manager"
            and int(payload.get("daemon_api_version", 0)) >= 2
        )
    except Exception:
        return False


def _listener_pid_for_port(port: int) -> int | None:
    try:
        output = subprocess.check_output(["ss", "-ltnp"], text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return None
    for line in output.splitlines():
        if f":{port} " not in line and not line.rstrip().endswith(f":{port}"):
            continue
        if "users:((" not in line:
            continue
        try:
            pid_part = line.split('pid=', 1)[1]
            pid_text = pid_part.split(',', 1)[0].split(')', 1)[0].strip()
            if pid_text.isdigit():
                return int(pid_text)
        except Exception:
            continue
    return None


def _process_command(pid: int) -> str:
    try:
        return Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", "ignore").strip()
    except Exception:
        return ""


def _terminate_local_process(pid: int) -> None:
    try:
        os.kill(pid, 15)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if not Path(f"/proc/{pid}").exists():
            return
        time.sleep(0.1)
    try:
        os.kill(pid, 9)
    except ProcessLookupError:
        return


def _replace_incompatible_daemon() -> None:
    pid = _listener_pid_for_port(DAEMON_PORT)
    if pid is None:
        return
    cmdline = _process_command(pid)
    if "ida_hybrid_manager.server" not in cmdline:
        raise RuntimeError(f"Port {DAEMON_PORT} is occupied by another process: {cmdline or pid}")
    _terminate_local_process(pid)


def _spawn_daemon() -> None:
    env = os.environ.copy()
    DAEMON_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with DAEMON_LOG_PATH.open("ab") as log_file:
        subprocess.Popen(
            [sys.executable, "-m", "ida_hybrid_manager.server", "--transport", "daemon"],
            cwd=str(Path(__file__).resolve().parents[2]),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )


def _ensure_shared_daemon(timeout_sec: float = 20.0) -> None:
    if _daemon_healthz_ok():
        return
    DAEMON_LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    with DAEMON_LOCK_PATH.open("a+", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            if not _daemon_healthz_ok():
                _replace_incompatible_daemon()
                _spawn_daemon()
            deadline = time.monotonic() + timeout_sec
            while time.monotonic() < deadline:
                if _daemon_healthz_ok():
                    lock_file.seek(0)
                    lock_file.truncate()
                    lock_file.write(json.dumps({"url": DAEMON_URL, "started_at": time.time()}) + "\n")
                    lock_file.flush()
                    return
                time.sleep(0.5)
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
    raise RuntimeError(f"Timed out waiting for ida-hybrid-manager daemon at {DAEMON_URL}")


def _daemon_request_sync(op_name: str, payload: dict[str, Any]) -> Any:
    req = urllib.request.Request(
        f"{DAEMON_URL}/api/ops/{quote(op_name)}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            response = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8")
            response = json.loads(body) if body else {}
        except Exception:
            response = {"ok": False, "error": str(exc)}
        raise RuntimeError(response.get("error") or str(exc)) from exc
    if not response.get("ok"):
        raise RuntimeError(response.get("error") or f"daemon operation failed: {op_name}")
    return response.get("result")


async def _daemon_request_async(op_name: str, payload: dict[str, Any]) -> Any:
    return await asyncio.to_thread(_daemon_request_sync, op_name, payload)


def _local_list_alive_sessions(client_id: str | None = None) -> dict[str, Any]:
    return {"sessions": _serialize_sessions_for_client(registry.list_sessions(include_dead=False), client_id)}


def _local_current_session(client_id: str | None = None) -> dict[str, Any]:
    session_id = _client_get_current_session_id(client_id)
    record = registry.get_session(session_id)
    return {"session": _session_to_client_dict(record, client_id) if record else None}


def _local_select_session(session_id: str, client_id: str | None = None) -> dict[str, Any]:
    record = registry.get_session(session_id)
    if record is None:
        return {"ok": False, "error": f"Unknown session: {session_id}"}
    _client_set_current_session(client_id, session_id)
    return {"ok": True, "current_session_id": record.session_id}


def _local_attach_to_gui(binary_name: str = "", binary_path: str = "", client_id: str | None = None) -> dict[str, Any]:
    normalized_path = normalize_path(binary_path).windows_path if binary_path else ""
    matches = registry.find_candidates(engine="gui", binary_name=binary_name or None, binary_path=normalized_path or None)
    if len(matches) == 1:
        _client_set_current_session(client_id, matches[0].session_id)
        return {
            "matches": _serialize_sessions_for_client(matches, client_id),
            "auto_selected": True,
            "current_session_id": matches[0].session_id,
        }
    return {"matches": _serialize_sessions_for_client(matches, client_id), "auto_selected": False}


def _local_open_binary(path: str, mode: str = "auto", reuse: bool = True, client_id: str | None = None) -> dict[str, Any]:
    normalized = normalize_path(path)
    if reuse:
        preferred_engine = None if mode == "auto" else mode
        candidate_paths = {normalized.input_path, normalized.windows_path, normalized.wsl_path}
        matches = []
        for candidate_path in candidate_paths:
            if not candidate_path:
                continue
            matches = registry.find_candidates(engine=preferred_engine, binary_path=candidate_path)
            if matches:
                break
        if matches:
            _client_set_current_session(client_id, matches[0].session_id)
            return {
                "ok": True,
                "session_id": matches[0].session_id,
                "engine": matches[0].engine,
                "status": matches[0].status,
                "selected": True,
                "reused": True,
            }

    if mode == "gui":
        pending = launcher.launch_gui(path)
        registry.register_pending_launch(pending)
        record = _wait_for_session(pending)
        if record is None:
            return {"ok": False, "error": f"Timed out waiting for {pending.engine} session", "pending": pending.to_dict()}
    else:
        launcher.terminate_untracked_idat(_tracked_headless_pids())
        pending = launcher.launch_headless(path, manager_url())
        record = _attach_managed_headless(pending)
    if not _backend_ready(record):
        if record.closable and record.owner_pid is not None:
            try:
                launcher.terminate_process(record.owner_pid)
            except Exception:
                pass
            registry.unregister(record.session_id, "backend_unreachable")
        return {
            "ok": False,
            "error": f"{record.engine} session registered but backend was unreachable",
            "session_id": record.session_id,
            "endpoint_candidates": _backend_candidates(record),
        }
    if record.engine == "headless":
        try:
            tools_info = asyncio.run(list_backend_tools_any(_backend_candidates(record)))
            capabilities = [tool.get("name") for tool in tools_info.get("tools", []) if tool.get("name")]
        except Exception:
            capabilities = []
        listener_pid = launcher.lookup_listener_pid(record.endpoint.get("url", ""))
        registry.update_managed_session(
            record.session_id,
            status="ready",
            capabilities=capabilities,
            owner_pid=listener_pid or record.owner_pid,
        )
    _client_set_current_session(client_id, record.session_id)
    return {
        "ok": True,
        "session_id": record.session_id,
        "engine": record.engine,
        "status": "ready",
        "selected": True,
        "reused": False,
    }


def _local_close_session(session_id: str, save: bool = True, client_id: str | None = None) -> dict[str, Any]:
    record = registry.get_session(session_id)
    if record is None:
        return {"ok": False, "error": f"Unknown session: {session_id}"}
    if not record.closable:
        return {"ok": False, "error": "GUI sessions are attach-only in v1 and are not closed by the manager"}
    if save and "save_database" in record.capabilities:
        asyncio.run(call_backend_tool_any(_backend_candidates(record), "save_database", {}))
    if record.owner_pid is not None:
        launcher.terminate_process(record.owner_pid)
    cleanup = {}
    staged_dir = str(record.metadata.get("staged_dir") or "")
    if staged_dir:
        cleanup["staged_dir"] = staged_dir
        cleanup["deleted"] = launcher.cleanup_staged_dir(staged_dir)
    registry.unregister(record.session_id, "manager_close")
    _client_clear_session_references(record.session_id)
    return {"ok": True, "closed_session_id": record.session_id, "cleanup": cleanup}


async def _local_list_session_tools(session_id: str = "", client_id: str | None = None) -> dict[str, Any]:
    record = _current_or_explicit(session_id or None, client_id=client_id)
    return await list_backend_tools_any(_backend_candidates(record))


async def _local_call_session_tool(tool_name: str, arguments: Any = None, session_id: str = "", client_id: str | None = None) -> dict[str, Any]:
    record = _current_or_explicit(session_id or None, client_id=client_id)
    return await call_backend_tool_any(_backend_candidates(record), tool_name, _coerce_tool_arguments(arguments))


async def _local_write_session_tool_output(
    path: str,
    tool_name: str,
    arguments: Any = None,
    session_id: str = "",
    output_format: str = "text",
    overwrite: bool = True,
    client_id: str | None = None,
) -> dict[str, Any]:
    if output_format not in {"text", "json"}:
        raise ValueError("output_format must be 'text' or 'json'")
    result = await _local_call_session_tool(tool_name, arguments=arguments, session_id=session_id, client_id=client_id)
    target = _resolve_output_path(path)
    if target.exists() and not overwrite:
        return {"ok": False, "error": f"File already exists: {target}"}
    target.parent.mkdir(parents=True, exist_ok=True)
    rendered = _render_tool_result(result, output_format)
    target.write_text(rendered, encoding="utf-8")
    return {
        "ok": True,
        "path": str(target),
        "tool_name": tool_name,
        "session_id": _current_or_explicit(session_id or None, client_id=client_id).session_id,
        "output_format": output_format,
        "bytes_written": len(rendered.encode("utf-8")),
    }


def _dispatch_operation(op_name: str, payload: dict[str, Any]) -> Any:
    client_id = payload.get("client_id")
    op_map = {
        "connect_client": lambda **kwargs: _client_connect(**kwargs),
        "list_alive_sessions": lambda **kwargs: _local_list_alive_sessions(client_id=client_id),
        "current_session": lambda **kwargs: _local_current_session(client_id=client_id),
        "select_session": lambda **kwargs: _local_select_session(kwargs["session_id"], client_id=client_id),
        "attach_to_gui": lambda **kwargs: _local_attach_to_gui(kwargs.get("binary_name", ""), kwargs.get("binary_path", ""), client_id=client_id),
        "open_binary": lambda **kwargs: _local_open_binary(kwargs["path"], kwargs.get("mode", "auto"), kwargs.get("reuse", True), client_id=client_id),
        "close_session": lambda **kwargs: _local_close_session(kwargs["session_id"], kwargs.get("save", True), client_id=client_id),
        "list_session_tools": lambda **kwargs: _local_list_session_tools(kwargs.get("session_id", ""), client_id=client_id),
        "call_session_tool": lambda **kwargs: _local_call_session_tool(kwargs["tool_name"], kwargs.get("arguments"), kwargs.get("session_id", ""), client_id=client_id),
        "decompile": lambda **kwargs: _local_call_session_tool("decompile", {"addr": kwargs["addr"]}, kwargs.get("session_id", ""), client_id=client_id),
        "lookup_funcs": lambda **kwargs: _local_call_session_tool("lookup_funcs", {"queries": kwargs["queries"]}, kwargs.get("session_id", ""), client_id=client_id),
        "xrefs_to": lambda **kwargs: _local_call_session_tool("xrefs_to", {"addrs": kwargs["addrs"], "limit": kwargs.get("limit", 100)}, kwargs.get("session_id", ""), client_id=client_id),
        "rename": lambda **kwargs: _local_call_session_tool("rename", {"batch": kwargs["batch"]}, kwargs.get("session_id", ""), client_id=client_id),
        "set_comments": lambda **kwargs: _local_call_session_tool("set_comments", {"items": kwargs["items"]}, kwargs.get("session_id", ""), client_id=client_id),
        "write_session_tool_output": lambda **kwargs: _local_write_session_tool_output(
            path=kwargs["path"],
            tool_name=kwargs["tool_name"],
            arguments=kwargs.get("arguments"),
            session_id=kwargs.get("session_id", ""),
            output_format=kwargs.get("output_format", "text"),
            overwrite=kwargs.get("overwrite", True),
            client_id=client_id,
        ),
    }
    operation = op_map.get(op_name)
    if operation is None:
        raise ValueError(f"Unknown operation: {op_name}")
    result = operation(**payload)
    if asyncio.iscoroutine(result):
        return asyncio.run(result)
    return result


@mcp.tool(description="List alive IDA sessions discovered by the manager.")
def list_alive_sessions() -> dict[str, Any]:
    if ACTIVE_BACKEND == "daemon":
        return _daemon_request_sync("list_alive_sessions", {"client_id": CLIENT_ID})
    return _local_list_alive_sessions(CLIENT_ID)


@mcp.tool(description="Return the currently selected IDA session.")
def current_session() -> dict[str, Any]:
    if ACTIVE_BACKEND == "daemon":
        return _daemon_request_sync("current_session", {"client_id": CLIENT_ID})
    return _local_current_session(CLIENT_ID)


@mcp.tool(description="Select an alive IDA session by its session_id.")
def select_session(session_id: str) -> dict[str, Any]:
    if ACTIVE_BACKEND == "daemon":
        return _daemon_request_sync("select_session", {"session_id": session_id, "client_id": CLIENT_ID})
    return _local_select_session(session_id, CLIENT_ID)


@mcp.tool(description="Attach to an already-open GUI IDA session, optionally filtering by binary name or path.")
def attach_to_gui(binary_name: str = "", binary_path: str = "") -> dict[str, Any]:
    if ACTIVE_BACKEND == "daemon":
        return _daemon_request_sync("attach_to_gui", {"binary_name": binary_name, "binary_path": binary_path, "client_id": CLIENT_ID})
    return _local_attach_to_gui(binary_name=binary_name, binary_path=binary_path, client_id=CLIENT_ID)


@mcp.tool(description="Open a binary in headless mode, GUI mode, or auto mode and select the resulting session.")
def open_binary(path: str, mode: str = "auto", reuse: bool = True) -> dict[str, Any]:
    if ACTIVE_BACKEND == "daemon":
        return _daemon_request_sync("open_binary", {"path": path, "mode": mode, "reuse": reuse, "client_id": CLIENT_ID})
    return _local_open_binary(path=path, mode=mode, reuse=reuse, client_id=CLIENT_ID)


@mcp.tool(description="Close a manager-owned headless session.")
def close_session(session_id: str, save: bool = True) -> dict[str, Any]:
    if ACTIVE_BACKEND == "daemon":
        return _daemon_request_sync("close_session", {"session_id": session_id, "save": save, "client_id": CLIENT_ID})
    return _local_close_session(session_id=session_id, save=save, client_id=CLIENT_ID)


@mcp.tool(description="List backend tools exposed by the selected or explicit session.")
async def list_session_tools(session_id: str = "") -> dict[str, Any]:
    if ACTIVE_BACKEND == "daemon":
        return await _daemon_request_async("list_session_tools", {"session_id": session_id, "client_id": CLIENT_ID})
    return await _local_list_session_tools(session_id=session_id, client_id=CLIENT_ID)


@mcp.tool(description="Call any backend MCP tool on the selected or explicit session.")
async def call_session_tool(tool_name: str, arguments: Any = None, session_id: str = "") -> dict[str, Any]:
    if ACTIVE_BACKEND == "daemon":
        return await _daemon_request_async(
            "call_session_tool",
            {"tool_name": tool_name, "arguments": arguments, "session_id": session_id, "client_id": CLIENT_ID},
        )
    return await _local_call_session_tool(tool_name=tool_name, arguments=arguments, session_id=session_id, client_id=CLIENT_ID)


@mcp.tool(description="Run any backend tool and write the result to a WSL-accessible file path.")
async def write_session_tool_output(
    path: str,
    tool_name: str,
    arguments: Any = None,
    session_id: str = "",
    output_format: str = "text",
    overwrite: bool = True,
) -> dict[str, Any]:
    if ACTIVE_BACKEND == "daemon":
        return await _daemon_request_async(
            "write_session_tool_output",
            {
                "path": path,
                "tool_name": tool_name,
                "arguments": arguments,
                "session_id": session_id,
                "output_format": output_format,
                "overwrite": overwrite,
                "client_id": CLIENT_ID,
            },
        )
    return await _local_write_session_tool_output(
        path=path,
        tool_name=tool_name,
        arguments=arguments,
        session_id=session_id,
        output_format=output_format,
        overwrite=overwrite,
        client_id=CLIENT_ID,
    )


@mcp.tool(description="Decompile a function in the selected session.")
async def decompile(addr: str, session_id: str = "") -> dict[str, Any]:
    if ACTIVE_BACKEND == "daemon":
        return await _daemon_request_async("decompile", {"addr": addr, "session_id": session_id, "client_id": CLIENT_ID})
    return await _local_call_session_tool("decompile", {"addr": addr}, session_id=session_id, client_id=CLIENT_ID)


@mcp.tool(description="Lookup one or more functions in the selected session.")
async def lookup_funcs(queries: list[str] | str, session_id: str = "") -> dict[str, Any]:
    if ACTIVE_BACKEND == "daemon":
        return await _daemon_request_async("lookup_funcs", {"queries": queries, "session_id": session_id, "client_id": CLIENT_ID})
    return await _local_call_session_tool("lookup_funcs", {"queries": queries}, session_id=session_id, client_id=CLIENT_ID)


@mcp.tool(description="Find xrefs to one or more addresses in the selected session.")
async def xrefs_to(addrs: list[str] | str, limit: int = 100, session_id: str = "") -> dict[str, Any]:
    if ACTIVE_BACKEND == "daemon":
        return await _daemon_request_async(
            "xrefs_to",
            {"addrs": addrs, "limit": limit, "session_id": session_id, "client_id": CLIENT_ID},
        )
    return await _local_call_session_tool("xrefs_to", {"addrs": addrs, "limit": limit}, session_id=session_id, client_id=CLIENT_ID)


@mcp.tool(description="Rename functions, globals, locals, or stack variables in the selected session.")
async def rename(batch: dict[str, Any], session_id: str = "") -> dict[str, Any]:
    if ACTIVE_BACKEND == "daemon":
        return await _daemon_request_async("rename", {"batch": batch, "session_id": session_id, "client_id": CLIENT_ID})
    return await _local_call_session_tool("rename", {"batch": batch}, session_id=session_id, client_id=CLIENT_ID)


@mcp.tool(description="Set comments in the selected session.")
async def set_comments(items: dict[str, Any] | list[dict[str, Any]], session_id: str = "") -> dict[str, Any]:
    if ACTIVE_BACKEND == "daemon":
        return await _daemon_request_async("set_comments", {"items": items, "session_id": session_id, "client_id": CLIENT_ID})
    return await _local_call_session_tool("set_comments", {"items": items}, session_id=session_id, client_id=CLIENT_ID)


def _run_daemon() -> None:
    manager_api = ManagerApiServer(
        registry=registry,
        host=DAEMON_HOST,
        port=DAEMON_PORT,
        op_dispatcher=_dispatch_operation,
    )
    manager_api.start()
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        manager_api.stop()


def main() -> None:
    global ACTIVE_BACKEND, CLIENT_ID

    parser = argparse.ArgumentParser(description="Run the IDA Hybrid Manager MCP server")
    parser.add_argument("--transport", default="streamable-http", choices=["stdio", "streamable-http", "sse", "daemon"])
    args = parser.parse_args()

    if args.transport == "daemon":
        ACTIVE_BACKEND = "local"
        _run_daemon()
        return

    if args.transport == "stdio":
        ACTIVE_BACKEND = "daemon"
        _ensure_shared_daemon()
        connect_info = _daemon_request_sync(
            "connect_client",
            {
                "client_name": os.getenv("CODEX_AGENT_NAME", "codex-stdio"),
                "client_pid": os.getpid(),
            },
        )
        CLIENT_ID = connect_info.get("client_id")
        mcp.run("stdio")
        return

    ACTIVE_BACKEND = "local"
    manager_api = ManagerApiServer(
        registry=registry,
        host=DAEMON_HOST,
        port=DAEMON_PORT,
        op_dispatcher=_dispatch_operation,
    )
    manager_api.start()
    try:
        mcp.run(args.transport)
    finally:
        manager_api.stop()


if __name__ == "__main__":
    main()
