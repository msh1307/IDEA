from __future__ import annotations

import argparse
import asyncio
from contextlib import AsyncExitStack, contextmanager
from datetime import datetime
import fcntl
import hashlib
from io import TextIOWrapper
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import traceback
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit
import uuid

import anyio
import mcp.types as mcp_types
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.session import ServerSession
from mcp.shared.message import SessionMessage
from mcp.shared.session import RequestResponder

from .backend import BackendToolError, BackendUnavailableError, call_backend_tool_any, list_backend_tools_any
from .launch import IdaLauncher
from .manager_api import ManagerApiServer
from .models import PendingLaunch, utc_now
from .pathing import normalize_path
from .registry import SessionRegistry


DAEMON_HOST = "127.0.0.1"
DAEMON_PORT = 18080
DAEMON_API_VERSION = 5
DAEMON_URL = f"http://{DAEMON_HOST}:{DAEMON_PORT}"
DAEMON_LOCK_PATH = Path("/tmp/ida-hybrid-manager-daemon.lock")
DAEMON_LOG_PATH = Path("/tmp/ida-hybrid-manager-daemon.log")
STDIO_DEBUG_PATH = Path("/tmp/ida-hybrid-manager-stdio.log")
MCP_ARTIFACT_DIR = Path(os.getenv("IDA_MCP_ARTIFACT_DIR", "/tmp/ida-hybrid-manager-artifacts")).expanduser()


def _env_int(name: str, default: int, minimum: int = 1) -> int:
    try:
        return max(minimum, int(os.getenv(name, str(default))))
    except (TypeError, ValueError):
        return default


MCP_INLINE_RESULT_BYTES = _env_int("IDA_MCP_MAX_INLINE_BYTES", 32 * 1024, minimum=1024)
MCP_ARTIFACT_READ_BYTES = _env_int("IDA_MCP_MAX_ARTIFACT_READ_BYTES", 16 * 1024, minimum=1024)
MCP_ARTIFACT_TTL_SEC = _env_int("IDA_MCP_ARTIFACT_TTL_SEC", 30 * 60, minimum=60)
MCP_ARTIFACT_MAX_BYTES = _env_int("IDA_MCP_ARTIFACT_MAX_BYTES", 256 * 1024 * 1024, minimum=1024 * 1024)
MCP_ARTIFACT_CLEANUP_INTERVAL_SEC = _env_int("IDA_MCP_ARTIFACT_CLEANUP_INTERVAL_SEC", 60, minimum=1)
MCP_ARTIFACT_TMP_TTL_SEC = max(60, min(MCP_ARTIFACT_TTL_SEC, 5 * 60))
MCP_LOG_MAX_BYTES = _env_int("IDA_MCP_LOG_MAX_BYTES", 8 * 1024 * 1024, minimum=64 * 1024)
_artifact_cleanup_lock = threading.RLock()
_artifact_cleanup_last_at = 0.0
_log_write_lock = threading.RLock()
DAEMON_BUILD_FILES = (
    Path(__file__).resolve(),
    Path(__file__).with_name("launch.py"),
    Path(__file__).with_name("registry.py"),
    Path(__file__).with_name("models.py"),
    Path(__file__).with_name("backend.py"),
    Path(__file__).with_name("manager_api.py"),
    # Headless IDA processes load this bundled overlay. Include the package
    # itself in the token so backend edits force a daemon compatibility check;
    # already-running IDA processes still need a normal IDA restart to reload
    # their in-memory Python modules.
    Path(__file__).resolve().parents[2] / "plugin_overlay" / "idea_ida_backend",
)

registry = SessionRegistry()
ACTIVE_BACKEND = "local"
CLIENT_ID: str | None = None
CLIENT_LAST_SESSION_ID: str | None = None
_client_lock = threading.RLock()
_client_current_sessions: dict[str, str | None] = {}
_client_last_seen: dict[str, float] = {}
_client_cwds: dict[str, str] = {}
_client_infos: dict[str, dict[str, Any]] = {}
_launcher: IdaLauncher | None = None
_open_binary_lock = threading.RLock()
_operation_progress_lock = threading.RLock()
_operation_progress: dict[str, dict[str, Any]] = {}
_cancelled_operation_progress: dict[str, float] = {}
OPERATION_PROGRESS_TTL_SEC = 3600.0
MUTATING_BACKEND_TOOLS = {
    "apply_decl",
    "apply_struct",
    "apply_struct_to_many",
    "bulk_recover_and_name",
    "create_struct",
    "create_padded_struct_from_map",
    "declare_stack",
    "declare_type",
    "define",
    "define_code",
    "define_func",
    "delete_stack",
    "import_header",
    "make_array",
    "nop_range",
    "patch_bytes",
    "reanalyze_function",
    "revert_patch",
    "repair_function_analysis",
    "rename",
    "save_database",
    "set_comments",
    "set_function_options",
    "set_sp_delta",
    "set_type",
    "type_workflow",
    "undefine",
    "upsert_struct",
}
ANALYSIS_DEPENDENT_BACKEND_TOOLS = MUTATING_BACKEND_TOOLS | {
    "basic_blocks",
    "callees",
    "decompile",
    "diagnose_function",
    "disasm_function",
    "export_decompiled_c",
    "field_xrefs_for_struct",
    "find_immediates",
    "find_insns",
    "find_regex",
    "find_text",
    "get_decompile_line_map",
    "get_enclosing_function",
    "get_function",
    "get_xrefs_from",
    "get_xrefs_to",
    "imports",
    "inspect",
    "inspect_addr",
    "jump",
    "list_functions",
    "list_globals",
    "list_strings",
    "lookup_funcs",
    "search",
    "stack_frame",
    "typed_decompile_export",
    "xrefs",
    "xrefs_to",
    "xrefs_to_field",
}
ANALYSIS_INVALIDATING_BACKEND_TOOLS = MUTATING_BACKEND_TOOLS - {"save_database"}

mcp = FastMCP(
    "IDA Hybrid Manager",
    instructions="Manage and route live IDA GUI or manager-owned headless sessions.",
    host="0.0.0.0",
    port=18081,
)

LITE_MCP_TOOLS = {
    "list_alive_sessions",
    "current_session",
    "select_session",
    "attach_to_gui",
    "inspect_environment",
    "open_binary",
    "load_idb",
    "close_session",
    "prune_alive_sessions",
    "list_session_tools",
    "describe_session_tool",
    "call_session_tool",
    "read_artifact",
    "write_session_tool_output",
}
_DISCOVERED_TOOL_SCHEMAS: dict[str, dict[str, Any]] = {}


def _capture_tool_schemas() -> None:
    for tool in mcp._tool_manager.list_tools():
        if tool.name not in _DISCOVERED_TOOL_SCHEMAS:
            _DISCOVERED_TOOL_SCHEMAS[tool.name] = {
                "name": tool.name,
                "description": tool.description or "",
                "inputSchema": dict(tool.parameters or {}),
            }


def _apply_mcp_profile(profile: str) -> str:
    normalized = str(profile or "full").strip().lower() or "full"
    if normalized not in {"full", "lite"}:
        raise ValueError(f"Unknown MCP profile: {profile}")
    _capture_tool_schemas()
    if normalized == "lite":
        registered = list(mcp._tool_manager.list_tools())
        for tool in registered:
            if tool.name not in LITE_MCP_TOOLS:
                mcp.remove_tool(tool.name)
    return normalized


def _stdio_debug(message: str) -> None:
    if not os.getenv("IDA_HYBRID_STDIO_DEBUG"):
        return
    _append_bounded_log(STDIO_DEBUG_PATH, message)


def _daemon_debug(message: str) -> None:
    _append_bounded_log(DAEMON_LOG_PATH, message)


def _append_bounded_log(path: Path, message: str) -> None:
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        with _log_write_lock:
            if path.exists() and path.stat().st_size >= MCP_LOG_MAX_BYTES:
                rotated = path.with_name(f"{path.name}.1")
                try:
                    rotated.unlink()
                except FileNotFoundError:
                    pass
                os.replace(path, rotated)
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as handle:
                handle.write(f"[{timestamp}] {message}\n")
    except Exception:
        pass


def _prune_operation_progress_locked(now: float) -> None:
    stale = [
        operation_id
        for operation_id, entry in _operation_progress.items()
        if now - float(entry.get("updated_at") or now) >= OPERATION_PROGRESS_TTL_SEC
    ]
    for operation_id in stale:
        _operation_progress.pop(operation_id, None)
    cancelled_stale = [
        operation_id
        for operation_id, cancelled_at in _cancelled_operation_progress.items()
        if now - cancelled_at >= OPERATION_PROGRESS_TTL_SEC
    ]
    for operation_id in cancelled_stale:
        _cancelled_operation_progress.pop(operation_id, None)


def _set_operation_progress(
    operation_id: str | None,
    *,
    operation: str,
    stage: str,
    progress: float,
    message: str,
    analysis: dict[str, Any] | None = None,
) -> None:
    operation_id = str(operation_id or "").strip()
    if not operation_id:
        return
    now = time.time()
    with _operation_progress_lock:
        _prune_operation_progress_locked(now)
        if operation_id in _cancelled_operation_progress:
            return
        previous = _operation_progress.get(operation_id, {})
        monotonic_progress = max(float(previous.get("progress") or 0.0), float(progress))
        entry: dict[str, Any] = {
            "operation_id": operation_id,
            "operation": operation,
            "stage": stage,
            "progress": round(max(0.0, min(100.0, monotonic_progress)), 2),
            "total": 100.0,
            "message": message,
            "revision": int(previous.get("revision") or 0) + 1,
            "updated_at": now,
        }
        if analysis is not None:
            entry["analysis"] = analysis
        _operation_progress[operation_id] = entry


def _get_operation_progress(operation_id: str | None) -> dict[str, Any]:
    operation_id = str(operation_id or "").strip()
    if not operation_id:
        return {"found": False, "operation_id": ""}
    now = time.time()
    with _operation_progress_lock:
        _prune_operation_progress_locked(now)
        entry = _operation_progress.get(operation_id)
        if entry is None:
            return {"found": False, "operation_id": operation_id}
        return {"found": True, **dict(entry)}


def _clear_operation_progress(operation_id: str | None) -> dict[str, Any]:
    operation_id = str(operation_id or "").strip()
    with _operation_progress_lock:
        _cancelled_operation_progress.pop(operation_id, None)
        removed = _operation_progress.pop(operation_id, None) if operation_id else None
    return {"ok": True, "operation_id": operation_id, "removed": removed is not None}


def _cancel_operation_progress(operation_id: str | None) -> None:
    normalized = str(operation_id or "").strip()
    if not normalized:
        return
    with _operation_progress_lock:
        _cancelled_operation_progress[normalized] = time.time()
        _operation_progress.pop(normalized, None)


def _get_launcher() -> IdaLauncher:
    global _launcher
    if _launcher is None:
        _launcher = IdaLauncher()
    return _launcher


def _compute_daemon_build_token() -> str:
    digest = hashlib.sha256()
    for path in DAEMON_BUILD_FILES:
        paths = sorted(path.rglob("*.py")) if path.is_dir() else [path]
        for source in paths:
            try:
                digest.update(str(source.relative_to(path if path.is_dir() else source.parent)).encode("utf-8"))
                digest.update(source.read_bytes())
            except OSError:
                digest.update(str(source).encode("utf-8"))
    return digest.hexdigest()[:16]


DAEMON_BUILD_TOKEN = _compute_daemon_build_token()
STDIO_IDLE_TIMEOUT_SEC = max(0, int(os.getenv("IDA_MCP_STDIO_IDLE_TIMEOUT_SEC", "600") or 0))
STDIO_PING_TIMEOUT_SEC = max(1.0, float(os.getenv("IDA_MCP_STDIO_PING_TIMEOUT_SEC", "10") or 10.0))
STDIO_PING_FAILURES_BEFORE_EXIT = max(1, int(os.getenv("IDA_MCP_STDIO_PING_FAILURES_BEFORE_EXIT", "3") or 3))
STDIO_IDLE_CHECK_INTERVAL_SEC = max(5.0, min(60.0, float(os.getenv("IDA_MCP_STDIO_IDLE_CHECK_INTERVAL_SEC", "30") or 30.0)))
STDIO_DISCONNECT_TIMEOUT_SEC = max(1.0, float(os.getenv("IDA_MCP_STDIO_DISCONNECT_TIMEOUT_SEC", "60") or 60.0))
STDIO_FORCE_EXIT_GRACE_SEC = max(0.1, float(os.getenv("IDA_MCP_STDIO_FORCE_EXIT_GRACE_SEC", "3") or 3.0))
STDIO_PARENT_CHECK_INTERVAL_SEC = max(1.0, min(30.0, float(os.getenv("IDA_MCP_STDIO_PARENT_CHECK_INTERVAL_SEC", "5") or 5.0)))
CLIENT_LEASE_TIMEOUT_SEC = max(60.0, float(os.getenv("IDA_MCP_CLIENT_LEASE_TIMEOUT_SEC", str(max(900, STDIO_IDLE_TIMEOUT_SEC * 2))) or 900.0))
CLIENT_LEASE_SWEEP_INTERVAL_SEC = max(10.0, min(120.0, float(os.getenv("IDA_MCP_CLIENT_LEASE_SWEEP_INTERVAL_SEC", "30") or 30.0)))
AUTO_PRUNE_HEADLESS_ENABLED = os.getenv("IDA_MCP_AUTO_PRUNE_HEADLESS", "1").strip().lower() not in {"0", "false", "no", "off"}
AUTO_PRUNE_HEADLESS_KEEP = max(1, int(os.getenv("IDA_MCP_AUTO_PRUNE_HEADLESS_KEEP", "3") or 3))
DAEMON_REQUEST_TIMEOUT_SEC = max(30.0, float(os.getenv("IDA_MCP_DAEMON_REQUEST_TIMEOUT_SEC", "120") or 120.0))
LONG_DAEMON_REQUEST_TIMEOUT_SEC = max(
    DAEMON_REQUEST_TIMEOUT_SEC,
    float(os.getenv("IDA_MCP_LONG_DAEMON_REQUEST_TIMEOUT_SEC", "1800") or 1800.0),
)
EXPORT_BACKEND_TIMEOUT_SEC = max(60.0, float(os.getenv("IDA_MCP_EXPORT_BACKEND_TIMEOUT_SEC", "3600") or 3600.0))
SAVE_BACKEND_TIMEOUT_SEC = max(30.0, float(os.getenv("IDA_MCP_SAVE_BACKEND_TIMEOUT_SEC", "180") or 180.0))
LONG_ANALYSIS_DAEMON_OPERATIONS = {
    "call_session_tool",
    "decompile",
    "decompile_line_map",
    "diagnose_function",
    "disasm_function",
    "export_decompiled_c",
    "get_enclosing_function",
    "inspect",
    "inspect_addr",
    "jump",
    "search",
    "write_session_tool_output",
    "xrefs",
}


def _stdio_client_connect_payload() -> dict[str, Any]:
    return {
        "client_name": os.getenv("CODEX_AGENT_NAME", "codex-stdio"),
        "client_pid": os.getpid(),
        "client_cwd": os.getcwd(),
        "client_scope": os.getenv("IDA_MCP_AGENT_SCOPE") or os.getenv("CODEX_AGENT_NAME") or f"pid:{os.getpid()}",
    }


def _connect_stdio_client(reason: str = "connect") -> dict[str, Any]:
    global CLIENT_ID
    connect_info = _daemon_request_sync("connect_client", _stdio_client_connect_payload())
    CLIENT_ID = connect_info.get("client_id")
    _stdio_debug(f"connect_client ok reason={reason} client_id={CLIENT_ID}")
    return connect_info


def _remember_client_session(result: Any) -> None:
    global CLIENT_LAST_SESSION_ID
    if not isinstance(result, dict):
        return
    closed_session_id = str(result.get("closed_session_id") or "").strip()
    if closed_session_id and closed_session_id == CLIENT_LAST_SESSION_ID:
        CLIENT_LAST_SESSION_ID = None
        return
    session_id = str(result.get("current_session_id") or result.get("session_id") or "").strip()
    meta = result.get("meta")
    if not session_id and isinstance(meta, dict):
        session_id = str(meta.get("session_id") or "").strip()
    session = result.get("session")
    if not session_id and isinstance(session, dict):
        session_id = str(session.get("session_id") or "").strip()
    if session_id:
        CLIENT_LAST_SESSION_ID = session_id


def _restore_stdio_current_session() -> bool:
    if not CLIENT_ID or not CLIENT_LAST_SESSION_ID:
        return False
    try:
        result = _daemon_request_sync_once(
            "select_session",
            {"session_id": CLIENT_LAST_SESSION_ID, "client_id": CLIENT_ID},
            timeout_sec=DAEMON_REQUEST_TIMEOUT_SEC,
            retry_unknown_client=False,
        )
        if isinstance(result, dict) and result.get("ok") is False:
            return False
        _stdio_debug(f"restored current session client_id={CLIENT_ID} session_id={CLIENT_LAST_SESSION_ID}")
        return True
    except Exception as exc:
        _stdio_debug(f"restore current session failed client_id={CLIENT_ID} session_id={CLIENT_LAST_SESSION_ID}: {exc!r}")
        return False


def _disconnect_stdio_client(reason: str) -> None:
    global CLIENT_ID, CLIENT_LAST_SESSION_ID
    client_id = CLIENT_ID
    CLIENT_ID = None
    CLIENT_LAST_SESSION_ID = None
    if not client_id:
        return
    try:
        _stdio_debug(f"disconnect_client start reason={reason} client_id={client_id}")
        _daemon_request_sync(
            "disconnect_client",
            {"client_id": client_id, "async_close": True, "reason": reason},
            timeout_sec=STDIO_DISCONNECT_TIMEOUT_SEC,
        )
        _stdio_debug(f"disconnect_client ok reason={reason} client_id={client_id}")
    except Exception as exc:
        _stdio_debug(f"disconnect_client failed reason={reason}: {exc!r}")


async def _force_exit_stdio(reason: str) -> None:
    _stdio_debug(f"stdio forced exit start reason={reason}")
    try:
        with anyio.move_on_after(STDIO_FORCE_EXIT_GRACE_SEC) as scope:
            await anyio.to_thread.run_sync(_disconnect_stdio_client, reason, abandon_on_cancel=True)
        if scope.cancel_called:
            _stdio_debug(f"disconnect_client grace timeout reason={reason} grace_sec={STDIO_FORCE_EXIT_GRACE_SEC}")
    except Exception as exc:
        _stdio_debug(f"disconnect_client grace failed reason={reason}: {exc!r}")
    _stdio_debug(f"stdio forced exit now reason={reason}")
    os._exit(0)


async def _run_stdio_server() -> None:
    _stdio_debug("stdio bootstrap start")
    initial_parent_pid = os.getppid()
    stdin = anyio.wrap_file(TextIOWrapper(sys.stdin.buffer, encoding="utf-8"))
    stdout = anyio.wrap_file(TextIOWrapper(sys.stdout.buffer, encoding="utf-8"))
    read_stream_writer, read_stream = anyio.create_memory_object_stream[SessionMessage | Exception](0)
    write_stream, write_stream_reader = anyio.create_memory_object_stream[SessionMessage](0)
    last_activity_at = time.monotonic()
    active_requests = 0

    async def stdin_reader() -> None:
        nonlocal last_activity_at
        _stdio_debug("stdin_reader start")
        try:
            async with read_stream_writer:
                async for line in stdin:
                    last_activity_at = time.monotonic()
                    _stdio_debug(f"stdin line: {line[:200]!r}")
                    try:
                        message = mcp_types.JSONRPCMessage.model_validate_json(line)
                    except Exception as exc:
                        _stdio_debug(f"stdin parse error: {exc!r}")
                        await read_stream_writer.send(exc)
                        continue
                    await read_stream_writer.send(SessionMessage(message))
                _stdio_debug("stdin_reader eof")
        except Exception as exc:
            _stdio_debug(f"stdin_reader exception: {exc!r}")
            _stdio_debug(traceback.format_exc())
            raise
        finally:
            _stdio_debug("stdin_reader stop")
            await _force_exit_stdio("stdin_eof")

    async def stdout_writer() -> None:
        _stdio_debug("stdout_writer start")
        try:
            async with write_stream_reader:
                async for session_message in write_stream_reader:
                    payload = session_message.message.model_dump_json(by_alias=True, exclude_none=True)
                    _stdio_debug(f"stdout line: {payload[:200]!r}")
                    await stdout.write(payload + "\n")
                    await stdout.flush()
        except Exception as exc:
            _stdio_debug(f"stdout_writer exception: {exc!r}")
            _stdio_debug(traceback.format_exc())
            raise
        finally:
            _stdio_debug("stdout_writer stop")

    async with AsyncExitStack() as stack:
        lifespan_context = await stack.enter_async_context(mcp._mcp_server.lifespan(mcp._mcp_server))
        session = await stack.enter_async_context(
            ServerSession(
                read_stream,
                write_stream,
                mcp._mcp_server.create_initialization_options(),
            )
        )
        task_support = mcp._mcp_server._experimental_handlers.task_support if mcp._mcp_server._experimental_handlers else None
        if task_support is not None:
            task_support.configure_session(session)
            await stack.enter_async_context(task_support.run())

        async def handle_message(
            message: RequestResponder[mcp_types.ClientRequest, mcp_types.ServerResult] | mcp_types.ClientNotification | Exception,
        ) -> None:
            nonlocal active_requests, last_activity_at
            is_request = isinstance(message, RequestResponder)
            if is_request:
                active_requests += 1
            try:
                await mcp._mcp_server._handle_message(
                    message,
                    session,
                    lifespan_context,
                    False,
                )
            finally:
                last_activity_at = time.monotonic()
                if is_request:
                    active_requests = max(0, active_requests - 1)

        async def idle_monitor() -> None:
            nonlocal last_activity_at
            ping_failures = 0
            _stdio_debug(
                "idle monitor start "
                f"timeout={STDIO_IDLE_TIMEOUT_SEC}s ping_timeout={STDIO_PING_TIMEOUT_SEC}s "
                f"interval={STDIO_IDLE_CHECK_INTERVAL_SEC}s failures_before_exit={STDIO_PING_FAILURES_BEFORE_EXIT}"
            )
            if STDIO_IDLE_TIMEOUT_SEC <= 0:
                return
            while True:
                await anyio.sleep(STDIO_IDLE_CHECK_INTERVAL_SEC)
                if active_requests > 0:
                    continue
                idle_for = time.monotonic() - last_activity_at
                if idle_for < STDIO_IDLE_TIMEOUT_SEC:
                    continue
                if session.client_params is None:
                    _stdio_debug(f"idle pre-initialize timeout idle_sec={idle_for:.1f}")
                    await _force_exit_stdio("pre_initialize_idle_timeout")
                _stdio_debug(f"idle heartbeat start idle_sec={idle_for:.1f}")
                try:
                    with anyio.fail_after(STDIO_PING_TIMEOUT_SEC):
                        await session.send_ping()
                    if CLIENT_ID:
                        await anyio.to_thread.run_sync(
                            lambda: _daemon_request_sync(
                                "heartbeat_client",
                                {"client_id": CLIENT_ID},
                                timeout_sec=STDIO_DISCONNECT_TIMEOUT_SEC,
                            )
                        )
                    ping_failures = 0
                    last_activity_at = time.monotonic()
                    _stdio_debug("idle heartbeat ok")
                except Exception as exc:
                    ping_failures += 1
                    _stdio_debug(f"idle heartbeat failed count={ping_failures}: {exc!r}")
                    if ping_failures >= STDIO_PING_FAILURES_BEFORE_EXIT:
                        await _force_exit_stdio("heartbeat_failed")

        async def parent_monitor() -> None:
            _stdio_debug(f"parent monitor start initial_parent_pid={initial_parent_pid}")
            if initial_parent_pid <= 1:
                _stdio_debug(f"stdio started orphaned initial_parent_pid={initial_parent_pid}")
                await _force_exit_stdio("orphaned_at_start")
                return
            while True:
                await anyio.sleep(STDIO_PARENT_CHECK_INTERVAL_SEC)
                current_parent_pid = os.getppid()
                if current_parent_pid != initial_parent_pid:
                    _stdio_debug(
                        "parent changed; exiting stdio "
                        f"initial_parent_pid={initial_parent_pid} current_parent_pid={current_parent_pid}"
                    )
                    await _force_exit_stdio("parent_process_exited")

        async with anyio.create_task_group() as tg:
            tg.start_soon(stdin_reader)
            tg.start_soon(stdout_writer)
            tg.start_soon(idle_monitor)
            tg.start_soon(parent_monitor)
            _stdio_debug("stdio transport ready")
            try:
                async for message in session.incoming_messages:
                    last_activity_at = time.monotonic()
                    tg.start_soon(handle_message, message)
            except Exception as exc:
                _stdio_debug(f"stdio server exception: {exc!r}")
                _stdio_debug(traceback.format_exc())
                raise


def manager_url() -> str:
    return DAEMON_URL


def _serialize_sessions(records) -> list[dict[str, Any]]:
    return [record.to_dict() for record in records]


def _normalize_agent_scope(client_name: str = "", client_pid: int | None = None, client_scope: str = "") -> str:
    scope = str(client_scope or "").strip()
    if scope:
        return scope
    name = str(client_name or "").strip()
    if name and name != "codex-stdio":
        return f"name:{name}"
    if client_pid is not None:
        return f"pid:{client_pid}"
    return "unknown"


def _client_connect(
    client_name: str = "",
    client_pid: int | None = None,
    client_cwd: str = "",
    client_scope: str = "",
) -> dict[str, Any]:
    client_id = f"client-{uuid.uuid4().hex[:12]}"
    normalized_scope = _normalize_agent_scope(client_name, client_pid, client_scope)
    info = {
        "client_id": client_id,
        "client_name": client_name,
        "client_pid": client_pid,
        "client_cwd": client_cwd,
        "client_scope": normalized_scope,
    }
    with _client_lock:
        _client_current_sessions[client_id] = None
        _client_last_seen[client_id] = time.monotonic()
        _client_infos[client_id] = info
        if client_cwd:
            _client_cwds[client_id] = client_cwd
    return info


def _client_touch(client_id: str | None) -> bool:
    if not client_id:
        return False
    with _client_lock:
        if client_id in _client_current_sessions:
            _client_last_seen[client_id] = time.monotonic()
            return True
    return False


@contextmanager
def _client_lease_renewal(client_id: str | None):
    if not client_id or not _client_is_connected(client_id):
        yield
        return
    stop = threading.Event()

    def renew() -> None:
        interval = max(5.0, min(30.0, CLIENT_LEASE_TIMEOUT_SEC / 3.0))
        while not stop.wait(interval):
            if not _client_touch(client_id):
                return

    thread = threading.Thread(target=renew, name=f"ida-client-lease-{client_id}", daemon=True)
    thread.start()
    try:
        _client_touch(client_id)
        yield
    finally:
        _client_touch(client_id)
        stop.set()
        thread.join(timeout=1.0)


def _client_is_connected(client_id: str | None) -> bool:
    if not client_id:
        return False
    with _client_lock:
        return client_id in _client_current_sessions


def _client_get_cwd(client_id: str | None) -> str:
    if not client_id:
        return ""
    with _client_lock:
        return _client_cwds.get(client_id, "")


def _client_get_info(client_id: str | None) -> dict[str, Any]:
    if not client_id:
        return {}
    with _client_lock:
        return dict(_client_infos.get(client_id, {}))


def _mark_pending_owner(pending: PendingLaunch, client_id: str | None) -> None:
    if client_id:
        client_info = _client_get_info(client_id)
        pending.metadata["owner_client_id"] = client_id
        if client_info.get("client_scope"):
            pending.metadata["owner_agent_scope"] = client_info["client_scope"]
        if client_info.get("client_name"):
            pending.metadata["owner_client_name"] = client_info["client_name"]
        if client_info.get("client_pid") is not None:
            pending.metadata["owner_client_pid"] = client_info["client_pid"]
        client_cwd = str(client_info.get("client_cwd") or _client_get_cwd(client_id))
        if client_cwd:
            pending.metadata["owner_agent_cwd"] = client_cwd


def _on_session_registered(record) -> None:
    owner_client_id = str(record.metadata.get("owner_client_id") or "")
    if not owner_client_id:
        return
    if _client_is_connected(owner_client_id):
        registry.attach_client(record.session_id, owner_client_id, refresh_snapshot=True)
        return
    if record.engine != "headless" or record.source != "manager_created" or not record.closable:
        return
    closable, error = registry.begin_close(record.session_id, force=True)
    if error is not None or closable is None:
        _daemon_debug(f"registered session owner disconnected but close failed session_id={record.session_id} error={error}")
        return
    try:
        _terminate_session_record(closable, save=True, reason="owner_client_disconnected_before_register")
    except Exception as exc:
        registry.cancel_close(record.session_id)
        _daemon_debug(f"registered session owner disconnected cleanup failed session_id={record.session_id}: {exc!r}")


def _restore_disconnect_cleanup_retry(
    client_id: str | None,
    client_info: dict[str, Any],
    failed_session_ids: list[str],
    detached_session_id: str | None,
) -> None:
    if not client_id or not failed_session_ids:
        return
    with _client_lock:
        if client_id not in _client_current_sessions:
            _client_current_sessions[client_id] = detached_session_id if detached_session_id in failed_session_ids else failed_session_ids[0]
        _client_last_seen[client_id] = time.monotonic()
        _client_infos[client_id] = client_info
        client_cwd = str(client_info.get("client_cwd") or "")
        if client_cwd:
            _client_cwds[client_id] = client_cwd
    for session_id in failed_session_ids:
        registry.attach_client(session_id, client_id, refresh_snapshot=False)


def _close_detached_client_sessions(
    detached_records: list[Any],
    client_info: dict[str, Any],
    *,
    reason: str,
) -> tuple[list[str], list[dict[str, Any]]]:
    auto_closed: list[str] = []
    auto_close_errors: list[dict[str, Any]] = []
    for record in detached_records:
        if record.status == "dead":
            continue
        if record.engine != "headless" or record.source != "manager_created" or not record.closable:
            continue
        closable, error = registry.begin_close(record.session_id)
        if error is not None or closable is None:
            auto_close_errors.append({"session_id": record.session_id, "error": str(error or "begin_close_failed")})
            continue
        record_agent_cwd = str(
            client_info.get("client_cwd")
            or record.metadata.get("owner_agent_cwd")
            or ""
        )
        try:
            _terminate_session_record(
                closable,
                save=True,
                reason=reason,
                idb_output_dir=None,
                agent_cwd=record_agent_cwd,
            )
        except Exception as exc:
            registry.cancel_close(record.session_id)
            auto_close_errors.append({"session_id": record.session_id, "error": str(exc)})
            continue
        auto_closed.append(record.session_id)
    return auto_closed, auto_close_errors


def _client_disconnect(client_id: str | None, *, async_close: bool = False, reason: str = "disconnect_client") -> dict[str, Any]:
    detached_session_id = None
    client_info: dict[str, Any] = {}
    with _client_lock:
        if client_id:
            detached_session_id = _client_current_sessions.pop(client_id, None)
            _client_last_seen.pop(client_id, None)
            client_info = _client_infos.pop(client_id, {})
            _client_cwds.pop(client_id, None)
    detached_records = registry.detach_client(client_id)
    close_candidates = [
        record
        for record in detached_records
        if record.status != "dead"
        and record.engine == "headless"
        and record.source == "manager_created"
        and record.closable
    ]
    if async_close and close_candidates:
        def close_worker() -> None:
            auto_closed, auto_close_errors = _close_detached_client_sessions(
                close_candidates,
                client_info,
                reason=reason,
            )
            if auto_close_errors:
                _restore_disconnect_cleanup_retry(
                    client_id,
                    client_info,
                    [str(item.get("session_id") or "") for item in auto_close_errors if item.get("session_id")],
                    detached_session_id,
                )
            if auto_closed or auto_close_errors:
                _daemon_debug(
                    "async disconnect cleanup done "
                    f"client_id={client_id} closed={auto_closed} errors={auto_close_errors}"
                )

        thread = threading.Thread(
            target=close_worker,
            name=f"ida-disconnect-cleanup-{client_id or 'unknown'}",
            daemon=True,
        )
        thread.start()
        return {
            "ok": True,
            "client_id": client_id,
            "detached_session_id": detached_session_id,
            "auto_close_pending_session_ids": [record.session_id for record in close_candidates],
            "auto_closed_session_ids": [],
            "auto_close_errors": [],
        }
    auto_closed, auto_close_errors = _close_detached_client_sessions(
        close_candidates,
        client_info,
        reason=reason,
    )
    if auto_close_errors:
        _restore_disconnect_cleanup_retry(
            client_id,
            client_info,
            [str(item.get("session_id") or "") for item in auto_close_errors if item.get("session_id")],
            detached_session_id,
        )
    return {
        "ok": True,
        "client_id": client_id,
        "detached_session_id": detached_session_id,
        "auto_closed_session_ids": auto_closed,
        "auto_close_errors": auto_close_errors,
    }


def _sweep_stale_clients() -> dict[str, Any]:
    now = time.monotonic()
    stale: list[str] = []
    with _client_lock:
        for client_id, last_seen in list(_client_last_seen.items()):
            if now - last_seen >= CLIENT_LEASE_TIMEOUT_SEC:
                stale.append(client_id)
    closed: list[str] = []
    errors: list[dict[str, Any]] = []
    for client_id in stale:
        result = _client_disconnect(client_id)
        closed.extend(result.get("auto_closed_session_ids") or [])
        errors.extend(result.get("auto_close_errors") or [])
    return {"stale_client_ids": stale, "auto_closed_session_ids": closed, "auto_close_errors": errors}


def _close_detached_inactive_headless_session(session_id: str, *, reason: str) -> dict[str, Any] | None:
    record = registry.get_session(session_id)
    if record is None:
        return None
    if record.engine != "headless" or record.source != "manager_created" or not record.closable:
        return None
    if record.status == "dead" or record.closing:
        return None
    if record.attached_clients or record.active_ops > 0:
        return None
    closable, error = registry.begin_close(record.session_id)
    if error is not None or closable is None:
        _daemon_debug(f"detached inactive close skipped session_id={session_id} error={error}")
        return None
    try:
        return _terminate_session_record(closable, save=True, reason=reason)
    except Exception as exc:
        registry.cancel_close(session_id)
        _daemon_debug(f"detached inactive close failed session_id={session_id}: {exc!r}")
        return None


@contextmanager
def _track_session_operation(session_id: str):
    try:
        with registry.track_operation(session_id) as record:
            yield record
    finally:
        _close_detached_inactive_headless_session(
            session_id,
            reason="last_client_detached_after_operation",
        )


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
            return
        _client_current_sessions[client_id] = session_id


def _client_clear_session_references(session_id: str) -> None:
    with _client_lock:
        for client_id, current in list(_client_current_sessions.items()):
            if current == session_id:
                _client_current_sessions[client_id] = None


def _client_session_refresh_state(record, client_id: str | None) -> dict[str, Any]:
    if not client_id:
        return {"attached": False, "snapshot_txid": None, "requires_refresh": False}
    attachment = record.attached_clients.get(client_id) or {}
    snapshot_txid = attachment.get("last_seen_txid")
    requires_refresh = snapshot_txid is not None and int(snapshot_txid) != int(record.txid)
    return {
        "attached": bool(client_id in record.attached_clients),
        "snapshot_txid": snapshot_txid,
        "requires_refresh": requires_refresh,
    }


def _session_revision_payload(record, client_id: str | None) -> dict[str, Any]:
    refresh_state = _client_session_refresh_state(record, client_id)
    return {
        "txid": int(record.txid),
        "snapshot_txid": refresh_state["snapshot_txid"],
        "requires_refresh": refresh_state["requires_refresh"],
        "attached_client_count": len(record.attached_clients),
        "last_writer_client_id": record.last_writer_client_id,
    }


def _session_to_client_dict(record, client_id: str | None) -> dict[str, Any]:
    autoanalysis = _cached_session_autoanalysis(record)
    data = record.to_dict()
    for key in (
        "txid",
        "attached_client_count",
        "last_writer_client_id",
        "capabilities",
        "endpoint",
        "owner_pid",
        "metadata",
        "created_at",
        "last_seen",
        "last_write_at",
        "active_ops",
    ):
        data.pop(key, None)
    data["current"] = bool(client_id and record.session_id == _client_get_current_session_id(client_id))
    data["revision"] = _session_revision_payload(record, client_id)
    if autoanalysis:
        data["analysis"] = autoanalysis
        data["analysis_ready"] = autoanalysis.get("autoanalysis_complete") is True
    if client_id:
        data["attached"] = bool(client_id in record.attached_clients)
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


def _cleanup_untracked_headless_before_launch_enabled() -> bool:
    return os.getenv("IDA_MCP_CLEAN_UNTRACKED_HEADLESS_BEFORE_LAUNCH", "0").strip().lower() in {"1", "true", "yes"}


def _wait_for_session(pending: PendingLaunch, timeout_sec: float = 90.0):
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        sessions = registry.list_sessions(include_dead=False)
        for record in sessions:
            if record.metadata.get("launch_token") == pending.launch_token:
                return record
            if pending.engine == "gui" and record.engine == "gui" and record.binary_path.lower() == pending.binary_path.lower():
                return record
        time.sleep(1.0)
    return None


def _current_or_explicit(session_id: str | None, client_id: str | None = None):
    _sweep_unreachable_sessions()
    if client_id and not _client_is_connected(client_id):
        raise ValueError(f"Unknown client_id: {client_id}")
    if session_id is None:
        session_id = _client_get_current_session_id(client_id)
    record = registry.get_session(session_id)
    if record is None:
        raise ValueError("No active session selected")
    if record.status not in {"ready", "busy"}:
        raise ValueError(f"Session {record.session_id} is not available: {record.status}")
    attached = registry.attach_client(record.session_id, client_id)
    if attached is not None:
        record = attached
    return record


def _backend_candidates(record) -> list[dict[str, str]]:
    transport = str(record.endpoint.get("transport") or "streamable-http")
    raw_candidates = record.metadata.get("endpoint_candidates")
    urls: list[str] = []
    if isinstance(raw_candidates, list):
        for item in raw_candidates:
            if isinstance(item, str) and item:
                urls.append(item)
            elif isinstance(item, dict) and item.get("url"):
                urls.append(str(item["url"]))
    endpoint_url = str(record.endpoint.get("url") or "")
    if endpoint_url and endpoint_url not in urls:
        urls.append(endpoint_url)
    return [{"transport": transport, "url": url} for url in urls]


def _backend_tool_timeout_sec(tool_name: str) -> float:
    if tool_name == "export_decompiled_c":
        return EXPORT_BACKEND_TIMEOUT_SEC
    if tool_name == "save_database":
        return SAVE_BACKEND_TIMEOUT_SEC
    return 30.0


def _normalize_export_fallback(value: str) -> str:
    fallback = str(value or "comment").strip().lower()
    if fallback not in {"comment", "none", "disasm", "asm"}:
        raise ValueError("fallback must be one of: comment, none, disasm, asm")
    return fallback


def _analysis_timeout_value(value: Any = None) -> float:
    if value is None or value == "":
        value = os.getenv("IDA_AUTOANALYSIS_TIMEOUT_SEC", "120")
    numeric = float(value)
    if numeric <= 0:
        numeric = float(os.getenv("IDA_AUTOANALYSIS_TIMEOUT_SEC", "120") or 120.0)
    return max(1.0, numeric)


def _launch_timeout_value(value: Any = None) -> float:
    if value is None or value == "":
        value = os.getenv("IDA_SESSION_LAUNCH_TIMEOUT_SEC", "90")
    numeric = float(value)
    if numeric <= 0:
        numeric = float(os.getenv("IDA_SESSION_LAUNCH_TIMEOUT_SEC", "90") or 90.0)
    return max(1.0, numeric)


def _backend_ready_timeout_value(value: Any = None) -> float:
    if value is None or value == "":
        value = os.getenv("IDA_BACKEND_READY_TIMEOUT_SEC", "20")
    numeric = float(value)
    if numeric <= 0:
        numeric = float(os.getenv("IDA_BACKEND_READY_TIMEOUT_SEC", "20") or 20.0)
    return max(1.0, numeric)


def _request_timeout_value(value: Any = None, *, default: float) -> float:
    if value is None or value == "":
        return default
    numeric = float(value)
    if numeric <= 0:
        return default
    return max(1.0, numeric)


def _run_coroutine_sync(coro):
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    result: dict[str, Any] = {}

    def runner() -> None:
        try:
            result["value"] = asyncio.run(coro)
        except BaseException as exc:
            result["error"] = exc

    thread = threading.Thread(target=runner, name="ida-sync-async-runner", daemon=True)
    thread.start()
    thread.join()
    if "error" in result:
        raise result["error"]
    return result.get("value")


def _backend_structured_content(result: Any) -> dict[str, Any]:
    if not isinstance(result, dict):
        return {}
    payload = result.get("structuredContent", result)
    if isinstance(payload, dict) and "structuredContent" in payload:
        nested = payload.get("structuredContent")
        if isinstance(nested, dict):
            payload = nested
    return payload if isinstance(payload, dict) else {}


def _compact_session_autoanalysis(status: dict[str, Any], *, source: str) -> dict[str, Any]:
    phase = status.get("phase") if isinstance(status.get("phase"), dict) else {}
    current = status.get("current") if isinstance(status.get("current"), dict) else {}
    executable_segments = status.get("executable_segments") if isinstance(status.get("executable_segments"), list) else []
    return {
        "autoanalysis_complete": bool(status.get("autoanalysis_complete")),
        "status": str(status.get("status") or ("complete" if status.get("autoanalysis_complete") else "analyzing")),
        "message": str(status.get("message") or ""),
        "progress_percent": float(status.get("progress_percent") or (100.0 if status.get("autoanalysis_complete") else 0.0)),
        "phase": {
            "name": phase.get("name"),
            "label": phase.get("label"),
        },
        "current": {
            "address": current.get("address"),
            "rva": current.get("rva"),
            "segment": current.get("segment"),
            "segment_percent": current.get("segment_percent"),
        },
        "function_total": int(status.get("function_total") or 0),
        "text_segments": [
            segment
            for segment in executable_segments
            if isinstance(segment, dict) and segment.get("text_like")
        ],
        "source": source,
        "checked_at": utc_now().isoformat(),
        "checked_at_epoch": time.time(),
    }


def _update_session_autoanalysis(session_id: str, status: dict[str, Any], *, source: str) -> dict[str, Any]:
    snapshot = _compact_session_autoanalysis(status, source=source)
    registry.update_managed_session(
        session_id,
        status="ready" if snapshot["autoanalysis_complete"] else "busy",
        metadata={"autoanalysis": snapshot},
    )
    return snapshot


def _invalidate_session_autoanalysis(session_id: str, *, reason: str) -> None:
    registry.update_managed_session(
        session_id,
        status="busy",
        metadata={
            "autoanalysis": {
                "autoanalysis_complete": False,
                "status": "needs_recheck",
                "message": f"Analysis readiness must be rechecked after {reason}",
                "progress_percent": 0.0,
                "phase": {"name": None, "label": None},
                "current": {"address": None, "rva": None, "segment": None, "segment_percent": None},
                "function_total": 0,
                "text_segments": [],
                "source": "manager_invalidation",
                "checked_at": utc_now().isoformat(),
                "checked_at_epoch": time.time(),
            }
        },
    )


def _cached_session_autoanalysis(record) -> dict[str, Any]:
    cached = record.metadata.get("autoanalysis") if isinstance(record.metadata, dict) else None
    return dict(cached) if isinstance(cached, dict) else {}


def _compact_analysis_sample(status: dict[str, Any], elapsed_sec: float) -> dict[str, Any]:
    phase = status.get("phase") if isinstance(status.get("phase"), dict) else {}
    current = status.get("current") if isinstance(status.get("current"), dict) else {}
    return {
        "elapsed_sec": round(elapsed_sec, 3),
        "progress_percent": float(status.get("progress_percent") or 0.0),
        "phase": phase.get("name"),
        "address": current.get("address"),
        "segment": current.get("segment"),
        "segment_percent": current.get("segment_percent"),
        "function_total": int(status.get("function_total") or 0),
    }


def _analysis_operation_progress(status: dict[str, Any]) -> float:
    estimated = max(0.0, min(100.0, float(status.get("progress_percent") or 0.0)))
    return 25.0 + estimated * 0.7


def _maybe_wait_for_autoanalysis(
    record,
    *,
    operation: str,
    wait_for_analysis: bool,
    analysis_timeout_sec: Any = None,
    progress_id: str | None = None,
) -> dict[str, Any]:
    if record.engine != "headless":
        return {"waited": False, "reason": "not_headless", "autoanalysis_complete": None}
    if not wait_for_analysis:
        return {"waited": False, "reason": "disabled", "autoanalysis_complete": None}

    timeout_sec = _analysis_timeout_value(analysis_timeout_sec)
    started = time.monotonic()
    deadline = started + timeout_sec
    samples: list[dict[str, Any]] = []
    last_status: dict[str, Any] = {}
    last_sample_percent = -10.0
    last_sample_phase = ""
    consecutive_stalls = 0
    _set_operation_progress(
        progress_id,
        operation=operation,
        stage="autoanalysis",
        progress=25.0,
        message="Waiting for IDA autoanalysis queues",
    )
    _daemon_debug(f"{operation} wait_for_autoanalysis start session_id={record.session_id} timeout_sec={timeout_sec}")

    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            work_slice_sec = min(0.75, remaining)
            analysis_result = _run_coroutine_sync(
                call_backend_tool_any(
                    _backend_candidates(record),
                    "wait_for_autoanalysis",
                    {
                        "timeout_sec": remaining,
                        "max_work_sec": work_slice_sec,
                        "include_coverage": remaining <= work_slice_sec,
                    },
                    # Older installed backends ignore max_work_sec and call the
                    # blocking auto_wait(), so retain the full remaining timeout.
                    timeout_sec=remaining + 10.0,
                )
            )
            status = _backend_structured_content(analysis_result)
            if status:
                last_status = status
                _update_session_autoanalysis(record.session_id, status, source=f"{operation}_wait")
            elapsed = time.monotonic() - started
            phase = status.get("phase") if isinstance(status.get("phase"), dict) else {}
            phase_name = str(phase.get("name") or "")
            percent = float(status.get("progress_percent") or 0.0)
            if not samples or percent >= last_sample_percent + 5.0 or phase_name != last_sample_phase or bool(status.get("autoanalysis_complete")):
                samples.append(_compact_analysis_sample(status, elapsed))
                if len(samples) > 40:
                    samples.pop(1)
                last_sample_percent = percent
                last_sample_phase = phase_name

            _set_operation_progress(
                progress_id,
                operation=operation,
                stage="autoanalysis",
                progress=_analysis_operation_progress(status),
                message=str(status.get("message") or "IDA autoanalysis in progress"),
                analysis=status,
            )
            if bool(status.get("autoanalysis_complete")):
                break
            if bool(status.get("stalled")):
                consecutive_stalls += 1
                if consecutive_stalls >= 3:
                    break
            else:
                consecutive_stalls = 0

        complete = bool(last_status.get("autoanalysis_complete"))
        if not complete:
            try:
                final_result = _run_coroutine_sync(
                    call_backend_tool_any(
                        _backend_candidates(record),
                        "analysis_status",
                        {"include_coverage": True},
                        timeout_sec=10.0,
                    )
                )
                final_status = _backend_structured_content(final_result)
                if final_status:
                    last_status = final_status
                    complete = bool(last_status.get("autoanalysis_complete"))
                    _update_session_autoanalysis(record.session_id, final_status, source=f"{operation}_final_probe")
            except Exception:
                pass

        waited_sec = round(time.monotonic() - started, 3)
        executable_segments = (
            last_status.get("executable_segments")
            if isinstance(last_status.get("executable_segments"), list)
            else []
        )
        result = {
            "waited": True,
            "ok": complete,
            "autoanalysis_complete": complete,
            "timed_out": not complete and time.monotonic() >= deadline,
            "stalled": not complete and consecutive_stalls >= 3,
            "timeout_sec": timeout_sec,
            "waited_sec": waited_sec,
            "function_total": int(last_status.get("function_total") or 0),
            "progress": last_status,
            "samples": samples,
            "executable_segments": executable_segments,
            "text_segments": [
                segment
                for segment in executable_segments
                if isinstance(segment, dict) and segment.get("text_like")
            ],
        }
        if not complete:
            result["warning"] = (
                "IDA autoanalysis did not complete; downstream function/decompile results may be incomplete. "
                "Inspect progress.executable_segments for an unexplored .text tail."
            )
        _daemon_debug(
            f"{operation} wait_for_autoanalysis done session_id={record.session_id} "
            f"complete={complete} waited_sec={waited_sec} status={last_status}"
        )
        return result
    except Exception as exc:
        waited_sec = round(time.monotonic() - started, 3)
        _daemon_debug(f"{operation} wait_for_autoanalysis failed session_id={record.session_id}: {exc!r}")
        return {
            "waited": True,
            "ok": False,
            "autoanalysis_complete": False,
            "timeout_sec": timeout_sec,
            "waited_sec": waited_sec,
            "progress": last_status,
            "samples": samples,
            "error": str(exc),
            "warning": "IDA autoanalysis wait failed; downstream analysis may be incomplete.",
        }


async def _ensure_session_autoanalysis_ready(
    record,
    *,
    tool_name: str,
    analysis_timeout_sec: Any = None,
) -> dict[str, Any]:
    if record.engine != "headless" or tool_name not in ANALYSIS_DEPENDENT_BACKEND_TOOLS:
        return {
            "required": False,
            "ok": True,
            "autoanalysis_complete": None,
            "tool_name": tool_name,
        }

    required_backend_tools = {"analysis_status", "wait_for_autoanalysis"}
    capabilities = {str(name) for name in (record.capabilities or [])}
    missing_backend_tools = sorted(required_backend_tools - capabilities) if capabilities else []
    if missing_backend_tools:
        return {
            "required": True,
            "ok": False,
            "cached": False,
            "waited": False,
            "autoanalysis_complete": False,
            "tool_name": tool_name,
            "error": "autoanalysis_backend_outdated",
            "missing_backend_tools": missing_backend_tools,
            "status": _cached_session_autoanalysis(record),
            "message": (
                "This running IDA backend cannot verify autoanalysis readiness. "
                "Reload the updated plugin or reopen the IDA session."
            ),
        }

    cached = _cached_session_autoanalysis(record)
    if cached.get("autoanalysis_complete") is True:
        return {
            "required": True,
            "ok": True,
            "cached": True,
            "waited": False,
            "autoanalysis_complete": True,
            "tool_name": tool_name,
            "status": cached,
        }

    timeout_sec = _analysis_timeout_value(analysis_timeout_sec)
    started = time.monotonic()
    deadline = started + timeout_sec
    endpoints = _backend_candidates(record)
    last_status: dict[str, Any] = {}
    consecutive_stalls = 0

    try:
        probe_result = await call_backend_tool_any(
            endpoints,
            "analysis_status",
            {"include_coverage": False},
            timeout_sec=10.0,
        )
    except BackendToolError as exc:
        return {
            "required": True,
            "ok": False,
            "cached": False,
            "waited": False,
            "autoanalysis_complete": False,
            "tool_name": tool_name,
            "error": "autoanalysis_backend_outdated",
            "status": cached,
            "message": f"Unable to query IDA autoanalysis readiness: {exc}. Reload the updated plugin or reopen the IDA session.",
        }
    if _backend_tool_is_error(probe_result):
        probe_error = _backend_structured_content(probe_result)
        return {
            "required": True,
            "ok": False,
            "cached": False,
            "waited": False,
            "autoanalysis_complete": False,
            "tool_name": tool_name,
            "error": "autoanalysis_status_failed",
            "status": cached,
            "message": str(probe_error.get("error") or "IDA analysis_status returned an error"),
        }
    probe_status = _backend_structured_content(probe_result)
    if probe_status:
        last_status = probe_status
        cached = _update_session_autoanalysis(record.session_id, probe_status, source=f"gate_probe:{tool_name}")
    if bool(last_status.get("autoanalysis_complete")):
        return {
            "required": True,
            "ok": True,
            "cached": False,
            "waited": False,
            "autoanalysis_complete": True,
            "tool_name": tool_name,
            "waited_sec": round(time.monotonic() - started, 3),
            "status": cached,
        }

    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        work_slice_sec = min(0.75, remaining)
        wait_result = await call_backend_tool_any(
            endpoints,
            "wait_for_autoanalysis",
            {
                "timeout_sec": remaining,
                "max_work_sec": work_slice_sec,
                "include_coverage": remaining <= work_slice_sec,
            },
            timeout_sec=remaining + 10.0,
        )
        if _backend_tool_is_error(wait_result):
            wait_error = _backend_structured_content(wait_result)
            return {
                "required": True,
                "ok": False,
                "cached": False,
                "waited": True,
                "autoanalysis_complete": False,
                "tool_name": tool_name,
                "timeout_sec": timeout_sec,
                "waited_sec": round(time.monotonic() - started, 3),
                "error": "autoanalysis_wait_failed",
                "status": cached,
                "message": str(wait_error.get("error") or "IDA wait_for_autoanalysis returned an error"),
            }
        status = _backend_structured_content(wait_result)
        if status:
            last_status = status
            cached = _update_session_autoanalysis(record.session_id, status, source=f"gate_wait:{tool_name}")
        if bool(last_status.get("autoanalysis_complete")):
            return {
                "required": True,
                "ok": True,
                "cached": False,
                "waited": True,
                "autoanalysis_complete": True,
                "tool_name": tool_name,
                "waited_sec": round(time.monotonic() - started, 3),
                "status": cached,
            }
        if bool(status.get("stalled")):
            consecutive_stalls += 1
            if consecutive_stalls >= 3:
                break
        else:
            consecutive_stalls = 0

    return {
        "required": True,
        "ok": False,
        "cached": False,
        "waited": True,
        "autoanalysis_complete": False,
        "tool_name": tool_name,
        "timeout_sec": timeout_sec,
        "waited_sec": round(time.monotonic() - started, 3),
        "timed_out": time.monotonic() >= deadline,
        "stalled": consecutive_stalls >= 3,
        "status": cached or _compact_session_autoanalysis(last_status, source=f"gate_failed:{tool_name}"),
        "error": "autoanalysis_incomplete",
        "message": (
            f"Refusing to run {tool_name} before IDA autoanalysis completes; "
            "function/decompile/xref results would be an incomplete snapshot."
        ),
    }


def _backend_ready(record, timeout_sec: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        for candidate in _backend_candidates(record):
            parsed = urlsplit(candidate["url"])
            host = parsed.hostname
            port = parsed.port
            if not host or not port:
                continue
            try:
                with socket.create_connection((host, port), timeout=2):
                    _daemon_debug(f"backend_ready ok session_id={record.session_id} url={candidate['url']}")
                    return True
            except OSError:
                continue
        time.sleep(2.0)
    _daemon_debug(f"backend_ready timeout session_id={record.session_id} candidates={_backend_candidates(record)}")
    return False


def _owner_pid_alive(pid: int | None) -> bool:
    return _get_launcher().is_process_alive(pid)


def _terminate_managed_pid(pid: int | None, *, launch_token: str, errors: list[dict[str, Any]], step: str) -> bool:
    if pid is None:
        return False
    launcher = _get_launcher()
    if not launcher.is_managed_headless_process(int(pid), launch_token=launch_token):
        errors.append({"step": step, "pid": int(pid), "error": "pid does not match managed headless launch token"})
        return False
    try:
        launcher.terminate_process(int(pid))
        return True
    except Exception as exc:
        errors.append({"step": step, "pid": int(pid), "error": str(exc)})
        return False


def _terminate_pending_launch(pending: PendingLaunch | None, *, step: str) -> list[dict[str, Any]]:
    errors: list[dict[str, Any]] = []
    if pending is not None:
        terminated = _terminate_managed_pid(
            pending.pid,
            launch_token=str(pending.launch_token or ""),
            errors=errors,
            step=step,
        )
        still_alive = False
        if pending.pid is not None:
            try:
                still_alive = _owner_pid_alive(pending.pid)
            except Exception as exc:
                errors.append({"step": "verify_pending_process_exit", "pid": pending.pid, "error": str(exc)})
        # A launch that never registered a session should be removed once its
        # process is gone. Keep it in the registry when termination is
        # ambiguous so a later cleanup can still recover the owner PID.
        if pending.pid is None or terminated or not still_alive:
            registry.pop_pending_launch(str(pending.launch_token or ""))
    return errors


def _terminate_session_owner_if_managed(record, *, step: str) -> list[dict[str, Any]]:
    errors: list[dict[str, Any]] = []
    if not record.closable or record.owner_pid is None:
        return errors
    if record.engine == "headless" and record.source == "manager_created":
        _terminate_managed_pid(
            int(record.owner_pid),
            launch_token=str(record.metadata.get("launch_token") or ""),
            errors=errors,
            step=step,
        )
    else:
        try:
            _get_launcher().terminate_process(int(record.owner_pid))
        except Exception as exc:
            errors.append({"step": step, "pid": int(record.owner_pid), "error": str(exc)})
    return errors


def _unregister_managed_session(record, reason: str, *, step: str) -> bool:
    errors = _terminate_session_owner_if_managed(record, step=step)
    if record.owner_pid is not None and _owner_pid_alive(record.owner_pid):
        registry.update_managed_session(
            record.session_id,
            metadata={
                "last_unregister_blocked_reason": reason,
                "last_unregister_blocked_at": utc_now().isoformat(),
                "last_unregister_errors": errors,
            },
        )
        _daemon_debug(f"unregister blocked: managed owner still alive session_id={record.session_id} pid={record.owner_pid} reason={reason} errors={errors}")
        return False
    registry.unregister(record.session_id, reason)
    _client_clear_session_references(record.session_id)
    return True


def _sweep_unreachable_sessions(probe_timeout_sec: float = 1.0, max_failures: int = 3) -> None:
    for record in registry.list_sessions(include_dead=False):
        if record.engine != "headless" or record.source != "manager_created":
            continue
        if record.status not in {"ready", "busy", "starting"}:
            continue
        if record.owner_pid is not None and not _owner_pid_alive(record.owner_pid):
            registry.unregister(record.session_id, "owner_pid_exited")
            _client_clear_session_references(record.session_id)
            continue
        if _backend_ready(record, timeout_sec=probe_timeout_sec):
            if int(record.metadata.get("backend_probe_failures", 0)) > 0:
                registry.update_managed_session(
                    record.session_id,
                    metadata={"backend_probe_failures": 0, "last_backend_probe_failed_at": ""},
                )
            continue
        failures = int(record.metadata.get("backend_probe_failures", 0)) + 1
        registry.update_managed_session(
            record.session_id,
            metadata={
                "backend_probe_failures": failures,
                "last_backend_probe_failed_at": utc_now().isoformat(),
            },
        )
        if failures < max_failures:
            continue
        _unregister_managed_session(record, "backend_unreachable", step="backend_unreachable_sweep")


def _session_matches_any_path(record, candidate_paths: set[str]) -> bool:
    normalized_candidates = {item.lower() for item in candidate_paths if item}
    if not normalized_candidates:
        return False
    possible_paths = {
        str(record.binary_path or "").lower(),
        str(record.idb_path or "").lower(),
        str(record.metadata.get("source_input_path") or "").lower(),
        str(record.metadata.get("source_windows_path") or "").lower(),
        str(record.metadata.get("source_wsl_path") or "").lower(),
        str(record.metadata.get("source_binary_windows_path") or "").lower(),
        str(record.metadata.get("source_binary_wsl_path") or "").lower(),
        str(record.metadata.get("source_idb_wsl_path") or "").lower(),
        str(record.metadata.get("staged_binary_path") or "").lower(),
        str(record.metadata.get("staged_idb_path") or "").lower(),
    }
    possible_paths.discard("")
    return bool(possible_paths & normalized_candidates)


def _session_reuse_score(
    record,
    *,
    candidate_paths: set[str],
    candidate_hash: str = "",
    candidate_idb_fingerprint: tuple[int, int] | None = None,
    operation: str,
) -> tuple[int, int, float, str] | None:
    """Rank reusable sessions so canonical IDBs beat stale staged copies.

    Registry order is name-based and therefore not a safe tie breaker when
    multiple sessions represent the same binary.  Explicit IDB loads prefer a
    session created from the requested IDB; binary opens prefer the canonical
    source binary path, then fall back to the newest matching hash.
    """
    normalized_candidates = {str(item).lower() for item in candidate_paths if item}
    metadata = record.metadata if isinstance(record.metadata, dict) else {}
    source_kind = str(metadata.get("source_input_kind") or "").strip().lower()
    fingerprint_match = False
    if candidate_idb_fingerprint is not None:
        try:
            fingerprint_match = (
                int(metadata.get("source_idb_size")) == candidate_idb_fingerprint[0]
                and int(metadata.get("source_idb_mtime_ns")) == candidate_idb_fingerprint[1]
            )
        except (TypeError, ValueError):
            fingerprint_match = False
    staged_paths = {
        str(metadata.get("staged_binary_path") or "").lower(),
        str(metadata.get("staged_idb_path") or "").lower(),
    }
    staged_paths.discard("")
    source_paths = {
        str(metadata.get(key) or "").lower()
        for key in (
            "source_input_path",
            "source_windows_path",
            "source_wsl_path",
            "source_idb_wsl_path",
            "source_binary_windows_path",
            "source_binary_wsl_path",
        )
    }
    source_paths.discard("")
    record_paths = {
        str(record.binary_path or "").lower(),
        str(record.idb_path or "").lower(),
    }
    record_paths.discard("")
    all_paths = source_paths | staged_paths | record_paths
    path_hits = normalized_candidates & all_paths
    hash_hit = bool(candidate_hash and str(record.binary_hash or "") == candidate_hash)
    if not path_hits and not hash_hit:
        return None

    source_hits = normalized_candidates & source_paths
    staged_hits = normalized_candidates & staged_paths
    record_hits = normalized_candidates & record_paths
    if operation == "load_idb":
        if fingerprint_match and source_hits:
            tier = 0
        elif source_kind == "idb" and source_hits:
            tier = 1
        elif source_hits:
            tier = 2
        elif record_hits and not staged_hits:
            tier = 3
        elif staged_hits:
            tier = 4
        else:
            tier = 5
    else:
        if source_hits:
            tier = 0
        elif record_hits and not staged_hits:
            tier = 1
        elif staged_hits:
            tier = 2
        elif hash_hit:
            tier = 3
        else:
            tier = 4

    status_penalty = 0 if str(record.status) == "ready" else 1
    timestamps = []
    for value in (getattr(record, "created_at", None), getattr(record, "last_seen", None)):
        try:
            timestamps.append(float(value.timestamp()))
        except (AttributeError, TypeError, ValueError):
            continue
    recency = max(timestamps, default=0.0)
    return tier, status_penalty, -recency, str(record.session_id)


def _sort_reuse_matches(
    records: list[Any],
    *,
    candidate_paths: set[str],
    candidate_hash: str = "",
    candidate_idb_fingerprint: tuple[int, int] | None = None,
    operation: str,
) -> list[Any]:
    ranked = []
    for record in records:
        score = _session_reuse_score(
            record,
            candidate_paths=candidate_paths,
            candidate_hash=candidate_hash,
            candidate_idb_fingerprint=candidate_idb_fingerprint,
            operation=operation,
        )
        if score is not None:
            ranked.append((score, record))
    ranked.sort(key=lambda item: item[0])
    return [record for _score, record in ranked]


def _compute_input_binary_hash(normalized_path) -> str:
    candidates = [normalized_path.wsl_path, normalized_path.input_path]
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate)
        if not path.exists() or not path.is_file():
            continue
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return f"sha256:{digest.hexdigest()}"
    return ""


def _compute_idb_fingerprint(normalized_path) -> tuple[int, int] | None:
    try:
        path = Path(normalized_path.wsl_path)
        stat_result = path.stat()
    except (OSError, AttributeError):
        return None
    if not path.is_file():
        return None
    return int(stat_result.st_size), int(stat_result.st_mtime_ns)


def _remove_adjacent_idb(normalized_path) -> dict[str, Any]:
    source_wsl = Path(normalized_path.wsl_path)
    if source_wsl.suffix.lower() == ".i64":
        if not source_wsl.exists():
            return {"removed": False, "path": str(source_wsl), "reason": "missing"}
        source_wsl.unlink()
        return {"removed": True, "path": str(source_wsl)}
    source_idb = source_wsl.with_name(f"{source_wsl.name}.i64")
    if not source_idb.exists():
        return {"removed": False, "path": str(source_idb), "reason": "missing"}
    source_idb.unlink()
    return {"removed": True, "path": str(source_idb)}


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


def _normalize_tool_arguments(tool_name: str, arguments: Any) -> dict[str, Any]:
    payload = _coerce_tool_arguments(arguments)
    if tool_name != "set_type":
        return payload

    edits = payload.get("edits", payload)
    wrapped = False
    if isinstance(edits, dict):
        edits = [dict(edits)]
        wrapped = "edits" in payload
    elif isinstance(edits, list):
        edits = [dict(item) if isinstance(item, dict) else item for item in edits]
    else:
        return payload

    for edit in edits:
        if not isinstance(edit, dict):
            continue
        alias_value = str(edit.get("type") or "").strip()
        if not alias_value:
            continue
        if "signature" not in edit and "ty" not in edit:
            if "(" in alias_value and ")" in alias_value:
                edit["signature"] = alias_value
                edit.setdefault("kind", "function")
            else:
                edit["ty"] = alias_value

    if wrapped:
        normalized = dict(payload)
        normalized["edits"] = edits
        return normalized
    if len(edits) == 1 and isinstance(edits[0], dict):
        return edits[0]
    return {"edits": edits}


def _merge_payload(arguments: Any = None, **explicit: Any) -> dict[str, Any]:
    payload = _coerce_tool_arguments(arguments)
    for key, value in explicit.items():
        if value in (None, ""):
            continue
        payload[key] = value
    return payload


def _merge_payload_with_defaults(arguments: Any = None, defaults: dict[str, Any] | None = None, **explicit: Any) -> dict[str, Any]:
    payload = _coerce_tool_arguments(arguments)
    defaults = defaults or {}
    for key, value in explicit.items():
        if value in (None, ""):
            continue
        if key in payload and key in defaults and value == defaults[key]:
            continue
        payload[key] = value
    return payload


def _merge_detail_payload(arguments: Any = None, *, full: bool = False, detail: str = "", **explicit: Any) -> dict[str, Any]:
    payload = _merge_payload(arguments, **explicit)
    normalized_detail = str(detail or "").strip().lower()
    if full:
        payload["full"] = True
    if normalized_detail:
        payload["detail"] = normalized_detail
    return payload


def _resolve_output_path(path: str) -> Path:
    normalized = normalize_path(path)
    target = Path(normalized.wsl_path).expanduser()
    if not target.is_absolute():
        target = (Path.cwd() / target).resolve()
    return target


def _resolve_agent_output_dir(output_dir: str | None = None, agent_cwd: str | None = None) -> Path:
    base = Path(str(agent_cwd or Path.cwd())).expanduser()
    if not base.is_absolute():
        base = (Path.cwd() / base).resolve()
    if not output_dir:
        return base
    normalized = normalize_path(str(output_dir))
    target = Path(normalized.wsl_path).expanduser()
    if not target.is_absolute():
        target = (base / target).resolve()
    return target


def _session_persistent_idb_target(record: Any) -> Path | None:
    source_kind = str(record.metadata.get("source_input_kind") or "").strip().lower()
    if source_kind == "idb":
        source_idb_path = str(record.metadata.get("source_idb_wsl_path") or "").strip()
        return Path(source_idb_path) if source_idb_path else None
    source_wsl_path = str(record.metadata.get("source_wsl_path") or "").strip()
    if not source_wsl_path:
        return None
    source_path = Path(source_wsl_path)
    target_name = f"{source_path.name}.i64"
    return source_path.with_name(target_name)


def _session_staged_idb_path(record: Any) -> Path | None:
    staged_idb_path = str(record.metadata.get("staged_idb_path") or "").strip()
    if staged_idb_path:
        return Path(staged_idb_path)
    staged_binary_path = str(record.metadata.get("staged_binary_path") or "").strip()
    if not staged_binary_path:
        return None
    staged_path = Path(staged_binary_path)
    return staged_path.with_name(f"{staged_path.name}.i64")


def _safe_output_stem(value: str) -> str:
    stem = Path(str(value or "")).stem or "ida_session"
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", stem).strip("._")
    return cleaned or "ida_session"


def _session_output_idb_target(record: Any, output_dir: str | None = None, agent_cwd: str | None = None) -> Path:
    root = _resolve_agent_output_dir(output_dir, agent_cwd)
    persistent = _session_persistent_idb_target(record)
    staged = _session_staged_idb_path(record)
    source_name = ""
    if persistent is not None:
        source_name = persistent.name
    elif staged is not None:
        source_name = staged.name
    elif record.idb_path:
        source_name = Path(str(normalize_path(record.idb_path).wsl_path)).name
    else:
        source_name = f"{record.display_name or record.session_id}.i64"
    stem = _safe_output_stem(source_name)
    return root / f"{stem}_{record.session_id}.i64"


def _session_idb_status(record: Any) -> dict[str, Any]:
    source_kind = str(record.metadata.get("source_input_kind") or "").strip().lower()
    source_idb_path = str(record.metadata.get("source_idb_wsl_path") or "").strip()
    source_idb_exists = bool(record.metadata.get("source_idb_exists")) or source_kind == "idb" or bool(source_idb_path)
    staged_from_existing = bool(record.metadata.get("staged_from_existing_idb"))
    staged_idb = _session_staged_idb_path(record)
    persistent_idb = _session_persistent_idb_target(record)
    idb_path = ""
    if persistent_idb is not None:
        idb_path = str(persistent_idb)
    elif record.idb_path:
        idb_path = str(normalize_path(record.idb_path).wsl_path)
    return {
        "idb_loaded": source_idb_exists or staged_from_existing,
        "idb_path": idb_path,
        "idb_source_path": source_idb_path or idb_path,
    }


def _persist_staged_idb(record: Any, output_dir: str | None = None, agent_cwd: str | None = None) -> dict[str, Any]:
    staged_idb = _session_staged_idb_path(record)
    persistent_idb = _session_output_idb_target(record, output_dir, agent_cwd) if output_dir or agent_cwd else _session_persistent_idb_target(record)
    if staged_idb is None or persistent_idb is None:
        return {"copied": False, "reason": "no_staged_or_source_path"}
    if not staged_idb.exists():
        return {"copied": False, "reason": "staged_idb_missing", "staged_idb": str(staged_idb)}
    persistent_idb.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(staged_idb, persistent_idb)
    return {
        "copied": True,
        "staged_idb": str(staged_idb),
        "persistent_idb": str(persistent_idb),
    }


def _tail_text_file(path: str, max_lines: int = 40, max_chars: int = 4000) -> str:
    try:
        data = Path(path).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""
    text = "\n".join(data.splitlines()[-max_lines:]).strip()
    if len(text) > max_chars:
        text = text[-max_chars:]
    return text


def _pending_log_summary(pending: PendingLaunch) -> dict[str, Any]:
    logs: dict[str, Any] = {}
    for key in ("stdout_log_path", "stderr_log_path", "idat_log_path"):
        path = str(pending.metadata.get(key) or "")
        if not path:
            continue
        entry: dict[str, Any] = {"path": path}
        tail = _tail_text_file(path)
        if tail:
            entry["tail"] = tail
        logs[key] = entry
    return logs


def _augment_session_meta(
    result: dict[str, Any],
    record,
    *,
    client_id: str | None = None,
    warning: str = "",
    analysis_gate: dict[str, Any] | None = None,
) -> dict[str, Any]:
    revision = _session_revision_payload(record, client_id)
    meta = dict(result.get("meta") or {})
    meta.update(
        {
            "session_id": record.session_id,
            "revision": revision,
        }
    )
    if warning:
        meta["warning"] = warning
    if analysis_gate and analysis_gate.get("required"):
        meta["analysis_gate"] = analysis_gate
    result["meta"] = meta
    return result


def _render_tool_result(result: dict[str, Any], output_format: str) -> str:
    if output_format == "json":
        return json.dumps(result, ensure_ascii=False, indent=2)
    meta = result.get("meta")
    if isinstance(meta, dict) and meta.get("content_mode") == "summary":
        structured = result.get("structuredContent")
        if structured is not None:
            return json.dumps(structured, ensure_ascii=False, indent=2) + "\n"
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


def _trim_summary_text(text: str, limit: int = 120) -> str:
    normalized = str(text or "").strip().replace("\n", " ")
    if not normalized:
        return "result"
    if len(normalized) <= limit:
        return normalized
    return normalized[: max(1, limit - 3)] + "..."


def _summary_text(payload: Any) -> str:
    if isinstance(payload, dict):
        if payload.get("truncated") and payload.get("artifact_id"):
            size = payload.get("bytes")
            suffix = f" bytes={size}" if size is not None else ""
            return _trim_summary_text(f"result truncated artifact={payload.get('artifact_id')}{suffix}")
        session_id = str(payload.get("session_id") or "").strip()
        engine = str(payload.get("engine") or "").strip()
        status = str(payload.get("status") or "").strip()
        if session_id and engine:
            bits = [engine, session_id]
            if status:
                bits.append(status)
            return _trim_summary_text(" ".join(bits))
        if "session" in payload and isinstance(payload.get("session"), dict):
            return _summary_text(payload.get("session") or {})
        if "sessions" in payload and isinstance(payload.get("sessions"), list):
            return _trim_summary_text(f"sessions={len(payload.get('sessions') or [])}")
        if "matches" in payload and isinstance(payload.get("matches"), list):
            return _trim_summary_text(f"matches={len(payload.get('matches') or [])}")
        if "ok" in payload:
            parts = [f"ok={bool(payload.get('ok'))}"]
            if session_id:
                parts.append(f"session_id={session_id}")
            if status:
                parts.append(f"status={status}")
            if payload.get("error"):
                parts.append(f"error={payload.get('error')}")
            return _trim_summary_text(" ".join(parts))
        keys = [key for key in payload.keys() if key not in {"content", "structuredContent", "meta"}]
        preview = ", ".join(keys[:4])
        return _trim_summary_text(f"result {{{preview}}}" if preview else "result")
    if isinstance(payload, list):
        return _trim_summary_text(f"results={len(payload)}")
    if isinstance(payload, str):
        return _trim_summary_text(payload)
    return _trim_summary_text(str(payload))


def _artifact_json_bytes(payload: Any) -> bytes:
    return json.dumps(payload, ensure_ascii=False, indent=2, default=str).encode("utf-8")


def _artifact_id_path(artifact_id: str) -> Path:
    normalized = str(artifact_id or "").strip()
    if not re.fullmatch(r"art_[0-9a-f]{32}", normalized):
        raise ValueError("Invalid artifact_id")
    return MCP_ARTIFACT_DIR / f"{normalized}.json"


def _cleanup_artifacts(*, force: bool = False) -> dict[str, Any]:
    global _artifact_cleanup_last_at
    now = time.time()
    with _artifact_cleanup_lock:
        if not force and now - _artifact_cleanup_last_at < MCP_ARTIFACT_CLEANUP_INTERVAL_SEC:
            return {"deleted": 0, "bytes_deleted": 0, "skipped": True}
        _artifact_cleanup_last_at = now
        root = MCP_ARTIFACT_DIR
        if not root.exists():
            return {"deleted": 0, "bytes_deleted": 0, "skipped": False}
        try:
            root.chmod(0o700)
        except OSError:
            pass

        candidates: list[tuple[float, int, Path]] = []
        deleted = 0
        bytes_deleted = 0
        try:
            children = list(root.iterdir())
        except OSError:
            return {"deleted": 0, "bytes_deleted": 0, "skipped": False}
        for path in children:
            if path.is_file() and re.fullmatch(r"\.art_[0-9a-f]{32}\.[0-9]+\.tmp", path.name):
                try:
                    stat_result = path.stat()
                    if now - stat_result.st_mtime >= MCP_ARTIFACT_TMP_TTL_SEC:
                        path.unlink()
                except OSError:
                    pass
                continue
            if not path.is_file() or not re.fullmatch(r"art_[0-9a-f]{32}\.json", path.name):
                continue
            try:
                stat_result = path.stat()
            except OSError:
                continue
            age = max(0.0, now - stat_result.st_mtime)
            if age >= MCP_ARTIFACT_TTL_SEC:
                try:
                    path.unlink()
                    deleted += 1
                    bytes_deleted += int(stat_result.st_size)
                except OSError:
                    continue
                continue
            candidates.append((stat_result.st_mtime, int(stat_result.st_size), path))

        total_bytes = sum(size for _mtime, size, _path in candidates)
        if total_bytes > MCP_ARTIFACT_MAX_BYTES:
            for _mtime, size, path in sorted(candidates):
                if total_bytes <= MCP_ARTIFACT_MAX_BYTES:
                    break
                try:
                    path.unlink()
                    total_bytes -= size
                    deleted += 1
                    bytes_deleted += size
                except OSError:
                    continue
        return {"deleted": deleted, "bytes_deleted": bytes_deleted, "skipped": False}


def _artifact_session_id(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ""
    direct = str(payload.get("session_id") or "").strip()
    if direct:
        return direct
    meta = payload.get("meta")
    if isinstance(meta, dict):
        return str(meta.get("session_id") or "").strip()
    return ""


def _artifact_preview(payload: Any) -> dict[str, Any]:
    if isinstance(payload, dict):
        preview: dict[str, Any] = {}
        for key in (
            "addr",
            "name",
            "mode",
            "status",
            "found",
            "total",
            "count",
            "offset",
            "session_id",
        ):
            if key in payload and not isinstance(payload.get(key), (dict, list)):
                preview[key] = payload.get(key)
        if isinstance(payload.get("items"), list):
            preview["item_count"] = len(payload["items"])
        if isinstance(payload.get("instructions"), list):
            preview["instruction_count"] = len(payload["instructions"])
        if isinstance(payload.get("code"), str):
            preview["code_chars"] = len(payload["code"])
        return preview
    if isinstance(payload, list):
        return {"item_count": len(payload)}
    return {"type": type(payload).__name__}


def _externalize_result(payload: Any) -> tuple[Any, dict[str, Any] | None]:
    """Store oversized JSON results losslessly and return a compact handle.

    The model-facing response is bounded, but the original structured payload is
    retained byte-for-byte as formatted JSON and can be read in chunks through
    read_artifact().
    """
    _cleanup_artifacts()
    try:
        raw = _artifact_json_bytes(payload)
    except Exception:
        return payload, None
    if len(raw) <= MCP_INLINE_RESULT_BYTES:
        return payload, None

    artifact_id = f"art_{uuid.uuid4().hex}"
    path = _artifact_id_path(artifact_id)
    temp_path: Path | None = None
    try:
        with _artifact_cleanup_lock:
            MCP_ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
            try:
                MCP_ARTIFACT_DIR.chmod(0o700)
            except OSError:
                pass
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=MCP_ARTIFACT_DIR,
                prefix=f".{artifact_id}.",
                suffix=f".{os.getpid()}.tmp",
                delete=False,
            ) as handle:
                temp_path = Path(handle.name)
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            temp_path.chmod(0o600)
            os.replace(temp_path, path)
            temp_path = None
    except OSError:
        if temp_path is not None:
            try:
                temp_path.unlink()
            except OSError:
                pass
        return payload, None
    artifact = {
        "ok": True,
        "truncated": True,
        "artifact_id": artifact_id,
        "path": str(path),
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "preview": _artifact_preview(payload),
    }
    session_id = _artifact_session_id(payload)
    if session_id:
        artifact["session_id"] = session_id
    return artifact, artifact


def _artifact_field(payload: Any, field: str) -> Any:
    value = payload
    for part in [item for item in str(field or "").split(".") if item]:
        if isinstance(value, dict):
            if part not in value:
                raise ValueError(f"Artifact field not found: {field}")
            value = value[part]
        elif isinstance(value, list) and part.isdigit():
            index = int(part)
            if index >= len(value):
                raise ValueError(f"Artifact field index out of range: {field}")
            value = value[index]
        else:
            raise ValueError(f"Artifact field not found: {field}")
    return value


def _artifact_lines(value: Any) -> list[str]:
    if isinstance(value, str):
        return value.splitlines() or [""]
    if isinstance(value, list):
        return [
            item if isinstance(item, str) else json.dumps(item, ensure_ascii=False, separators=(",", ":"))
            for item in value
        ] or [""]
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, indent=2, default=str).splitlines() or [""]
    return [str(value)]


def _artifact_line_window(
    lines: list[str],
    *,
    start_line: int,
    line_count: int,
    pattern: str = "",
    context_lines: int = 2,
    ignore_case: bool = False,
) -> tuple[list[dict[str, Any]], list[int]]:
    total = len(lines)
    if pattern:
        flags = re.IGNORECASE if ignore_case else 0
        try:
            expression = re.compile(pattern, flags)
        except re.error as exc:
            raise ValueError(f"Invalid artifact pattern: {exc}") from exc
        matches = [index for index, line in enumerate(lines) if expression.search(line)]
        if not matches:
            return [], []
        context = max(0, min(int(context_lines), 20))
        selected: set[int] = set()
        for index in matches:
            selected.update(range(max(0, index - context), min(total, index + context + 1)))
        selected_indexes = sorted(selected)
    else:
        first = max(1, int(start_line)) - 1
        selected_indexes = list(range(max(0, first), min(total, first + max(1, int(line_count)))))
        matches = []

    max_lines = max(1, int(line_count))
    if len(selected_indexes) > max_lines:
        selected_indexes = selected_indexes[:max_lines]
    return [{"line": index + 1, "text": lines[index]} for index in selected_indexes], [index + 1 for index in matches]


def _tool_result(payload: Any, *, is_error: bool = False) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": _summary_text(payload)}],
        "structuredContent": payload,
        "meta": {"content_mode": "summary"},
        "isError": is_error,
    }


def _tool_error(message: str, **extra: Any) -> dict[str, Any]:
    payload = {"ok": False, "error": message}
    payload.update(extra)
    return _tool_result(payload, is_error=True)


def _mcp_error_result(message: str, **payload: Any) -> mcp_types.CallToolResult:
    body = {"ok": False, "error": message}
    body.update(payload)
    return mcp_types.CallToolResult(
        content=[mcp_types.TextContent(type="text", text=_summary_text(body), _meta={"content_mode": "summary"})],
        structuredContent=body,
        isError=True,
        _meta={"content_mode": "summary"},
    )


def _mcp_result(payload: Any) -> mcp_types.CallToolResult:
    if isinstance(payload, mcp_types.CallToolResult):
        return payload
    if isinstance(payload, dict) and {"content", "structuredContent", "isError"} <= set(payload.keys()):
        structured = payload.get("structuredContent")
        bounded_structured, artifact = _externalize_result(structured)
        if artifact is not None:
            outer_meta = dict(payload.get("meta") or {}) if isinstance(payload.get("meta"), dict) else {}
            outer_meta.update({"content_mode": "summary", "externalized": True, "artifact_id": artifact["artifact_id"]})
            return mcp_types.CallToolResult(
                content=[mcp_types.TextContent(type="text", text=_summary_text(bounded_structured), _meta={"content_mode": "summary"})],
                structuredContent=bounded_structured if isinstance(bounded_structured, dict) else {"result": bounded_structured},
                isError=bool(payload.get("isError")),
                _meta=outer_meta,
            )
        content_items: list[mcp_types.TextContent] = []
        for item in payload.get("content") or []:
            if not isinstance(item, dict) or item.get("type") != "text":
                continue
            content_items.append(
                mcp_types.TextContent(
                    type="text",
                    text=str(item.get("text") or ""),
                    annotations=item.get("annotations"),
                    _meta=item.get("meta"),
                )
            )
        if structured is None:
            structured_payload: dict[str, Any] = {}
        elif isinstance(structured, dict):
            structured_payload = structured
        else:
            structured_payload = {"result": structured}
        return mcp_types.CallToolResult(
            content=content_items or [mcp_types.TextContent(type="text", text=_summary_text(structured_payload))],
            structuredContent=structured_payload,
            isError=bool(payload.get("isError")),
            _meta=payload.get("meta"),
        )
    if isinstance(payload, dict):
        bounded_payload, artifact = _externalize_result(payload)
        if artifact is not None:
            return mcp_types.CallToolResult(
                content=[mcp_types.TextContent(type="text", text=_summary_text(bounded_payload), _meta={"content_mode": "summary"})],
                structuredContent=bounded_payload if isinstance(bounded_payload, dict) else {"result": bounded_payload},
                isError=False,
                _meta={"content_mode": "summary", "externalized": True, "artifact_id": artifact["artifact_id"]},
            )
        return mcp_types.CallToolResult(
            content=[mcp_types.TextContent(type="text", text=_summary_text(payload), _meta={"content_mode": "summary"})],
            structuredContent=payload,
            isError=False,
            _meta={"content_mode": "summary"},
        )
    return mcp_types.CallToolResult(
        content=[mcp_types.TextContent(type="text", text=_summary_text(payload), _meta={"content_mode": "summary"})],
        structuredContent={"result": payload},
        isError=False,
        _meta={"content_mode": "summary"},
    )

def _backend_tool_is_error(result: dict[str, Any]) -> bool:
    if bool(result.get("isError")):
        return True
    structured = result.get("structuredContent")
    return isinstance(structured, dict) and bool(structured.get("isError"))


def _backend_mutation_changed_db(result: dict[str, Any]) -> bool:
    if _backend_tool_is_error(result):
        return False
    payload = result.get("structuredContent")
    if isinstance(payload, dict) and "structuredContent" in payload and {"content", "structuredContent", "isError", "meta"} >= set(payload.keys()):
        payload = payload.get("structuredContent")
    if isinstance(payload, dict):
        if "db_changed" in payload:
            return bool(payload.get("db_changed"))
        if "changed_count" in payload:
            return int(payload.get("changed_count") or 0) > 0
        if "ok" in payload:
            return bool(payload.get("ok"))
        if "ok_count" in payload:
            return int(payload.get("ok_count") or 0) > 0
        for value in payload.values():
            if isinstance(value, list) and _backend_mutation_changed_db({"structuredContent": value}):
                return True
        return False
    if isinstance(payload, list):
        saw_status = False
        for item in payload:
            if not isinstance(item, dict):
                continue
            if "db_changed" in item:
                saw_status = True
                if bool(item.get("db_changed")):
                    return True
            elif "ok" in item:
                saw_status = True
                if bool(item.get("ok")):
                    return True
            elif "ok_count" in item:
                saw_status = True
                if int(item.get("ok_count") or 0) > 0:
                    return True
        return not saw_status
    return False


def _bool_payload_value(payload: dict[str, Any], key: str, default: bool = False) -> bool:
    if key not in payload:
        return default
    value = payload.get(key)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() not in {"", "0", "false", "no", "off"}
    if value is None:
        return False
    return bool(value)


def _backend_tool_may_mutate(tool_name: str, payload: dict[str, Any]) -> bool:
    if tool_name not in MUTATING_BACKEND_TOOLS:
        return False
    if tool_name in {"patch_bytes", "nop_range"} and _bool_payload_value(payload, "dry_run", True):
        return False
    if tool_name == "revert_patch" and _bool_payload_value(payload, "dry_run", False):
        return False
    return True


def _daemon_healthz_ok(timeout_sec: float = 2.0) -> bool:
    req = urllib.request.Request(f"{DAEMON_URL}/healthz", method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        return (
            bool(payload.get("ok"))
            and payload.get("service") == "ida-hybrid-manager"
            and int(payload.get("daemon_api_version", 0)) >= DAEMON_API_VERSION
            and str(payload.get("build_token") or "") == DAEMON_BUILD_TOKEN
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


def _cleanup_incompatible_daemon_sessions() -> bool:
    all_closed = True
    try:
        result = _daemon_request_sync_once("list_alive_sessions", {}, timeout_sec=10.0, retry_unknown_client=False)
    except Exception as exc:
        _daemon_debug(f"incompatible daemon session listing failed before replacement: {exc!r}")
        return False
    sessions = result.get("sessions") if isinstance(result, dict) else []
    if not isinstance(sessions, list):
        return False
    for session in sessions:
        if not isinstance(session, dict):
            continue
        if session.get("engine") != "headless" or not session.get("closable") or session.get("status") == "dead":
            continue
        session_id = str(session.get("session_id") or "").strip()
        if not session_id:
            continue
        try:
            close_result = _daemon_request_sync_once(
                "close_session",
                {"session_id": session_id, "save": True, "force": True},
                timeout_sec=max(60.0, SAVE_BACKEND_TIMEOUT_SEC + 30.0),
                retry_unknown_client=False,
            )
            _daemon_debug(f"incompatible daemon pre-replacement close session_id={session_id} result={close_result}")
            if not isinstance(close_result, dict) or not close_result.get("ok") or close_result.get("cleanup_errors"):
                all_closed = False
        except Exception as exc:
            _daemon_debug(f"incompatible daemon pre-replacement close failed session_id={session_id}: {exc!r}")
            all_closed = False
    return all_closed


def _replace_incompatible_daemon() -> None:
    pid = _listener_pid_for_port(DAEMON_PORT)
    if pid is None:
        return
    cmdline = _process_command(pid)
    if "ida_hybrid_manager.server" not in cmdline:
        raise RuntimeError(f"Port {DAEMON_PORT} is occupied by another process: {cmdline or pid}")
    if not _cleanup_incompatible_daemon_sessions():
        raise RuntimeError("Existing daemon sessions could not be closed safely; refusing to replace the daemon")
    _terminate_local_process(pid)


def _spawn_daemon() -> subprocess.Popen[Any]:
    env = os.environ.copy()
    DAEMON_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with DAEMON_LOG_PATH.open("ab") as log_file:
        return subprocess.Popen(
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
    spawned: subprocess.Popen[Any] | None = None
    with DAEMON_LOCK_PATH.open("a+", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            if not _daemon_healthz_ok():
                _replace_incompatible_daemon()
                spawned = _spawn_daemon()
            deadline = time.monotonic() + timeout_sec
            while time.monotonic() < deadline:
                if _daemon_healthz_ok():
                    lock_file.seek(0)
                    lock_file.truncate()
                    lock_file.write(json.dumps({"url": DAEMON_URL, "started_at": time.time(), "build_token": DAEMON_BUILD_TOKEN}) + "\n")
                    lock_file.flush()
                    return
                time.sleep(0.5)
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
    if spawned is not None and spawned.poll() is None:
        _terminate_local_process(spawned.pid)
    raise RuntimeError(f"Timed out waiting for ida-hybrid-manager daemon at {DAEMON_URL}")


def _daemon_operation_timeout_sec(op_name: str) -> float:
    if op_name in {"open_binary", "load_idb"} or op_name in LONG_ANALYSIS_DAEMON_OPERATIONS:
        return LONG_DAEMON_REQUEST_TIMEOUT_SEC
    return DAEMON_REQUEST_TIMEOUT_SEC


def _daemon_request_sync(op_name: str, payload: dict[str, Any], *, timeout_sec: float | None = None) -> Any:
    if timeout_sec is None:
        timeout_sec = _daemon_operation_timeout_sec(op_name)
    return _daemon_request_sync_once(op_name, payload, timeout_sec=timeout_sec, retry_unknown_client=True)


def _daemon_request_sync_once(op_name: str, payload: dict[str, Any], *, timeout_sec: float, retry_unknown_client: bool = False) -> Any:
    req = urllib.request.Request(
        f"{DAEMON_URL}/api/ops/{quote(op_name)}",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            response = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode("utf-8")
            response = json.loads(body) if body else {}
        except Exception:
            response = {"ok": False, "error": str(exc)}
        error = response.get("error") or str(exc)
        if retry_unknown_client and _should_retry_unknown_client(op_name, payload, str(error)):
            refreshed_payload = dict(payload)
            refreshed_payload["client_id"] = CLIENT_ID
            _stdio_debug(f"retrying daemon op after reconnect op={op_name} client_id={CLIENT_ID}")
            return _daemon_request_sync_once(op_name, refreshed_payload, timeout_sec=timeout_sec, retry_unknown_client=False)
        raise RuntimeError(error) from exc
    if not response.get("ok"):
        error = response.get("error") or f"daemon operation failed: {op_name}"
        if retry_unknown_client and _should_retry_unknown_client(op_name, payload, str(error)):
            refreshed_payload = dict(payload)
            refreshed_payload["client_id"] = CLIENT_ID
            _stdio_debug(f"retrying daemon op after reconnect op={op_name} client_id={CLIENT_ID}")
            return _daemon_request_sync_once(op_name, refreshed_payload, timeout_sec=timeout_sec, retry_unknown_client=False)
        raise RuntimeError(error)
    result = response.get("result")
    _remember_client_session(result)
    return result


def _should_retry_unknown_client(op_name: str, payload: dict[str, Any], error: str) -> bool:
    if op_name in {"connect_client", "disconnect_client"}:
        return False
    stale_client_id = payload.get("client_id")
    if not stale_client_id or stale_client_id != CLIENT_ID:
        return False
    if "Unknown client_id:" not in error:
        return False
    try:
        _stdio_debug(f"unknown client_id reconnect start op={op_name} stale_client_id={stale_client_id}")
        _connect_stdio_client("unknown_client_retry")
        _restore_stdio_current_session()
        return bool(CLIENT_ID)
    except Exception as exc:
        _stdio_debug(f"unknown client_id reconnect failed op={op_name}: {exc!r}")
        return False


async def _daemon_request_async(op_name: str, payload: dict[str, Any]) -> Any:
    return await asyncio.to_thread(_daemon_request_sync, op_name, payload, timeout_sec=_daemon_operation_timeout_sec(op_name))


def _local_list_alive_sessions(client_id: str | None = None) -> dict[str, Any]:
    _sweep_unreachable_sessions()
    return {"sessions": _serialize_sessions_for_client(registry.list_sessions(include_dead=False), client_id)}


def _local_current_session(client_id: str | None = None) -> dict[str, Any]:
    _sweep_unreachable_sessions()
    session_id = _client_get_current_session_id(client_id)
    record = registry.get_session(session_id)
    return {"session": _session_to_client_dict(record, client_id) if record else None}


def _local_select_session(session_id: str, client_id: str | None = None) -> dict[str, Any]:
    _sweep_unreachable_sessions()
    record = registry.get_session(session_id)
    if record is None:
        return {"ok": False, "error": f"Unknown session: {session_id}"}
    if record.status not in {"ready", "busy"}:
        return {"ok": False, "error": f"Session {record.session_id} is not available: {record.status}", "session": _session_to_client_dict(record, client_id)}
    attached = registry.attach_client(record.session_id, client_id, refresh_snapshot=True) or record
    _client_set_current_session(client_id, session_id)
    return {
        "ok": True,
        "current_session_id": attached.session_id,
        "session": _session_to_client_dict(attached, client_id),
        "revision": _session_revision_payload(attached, client_id),
    }


def _local_attach_to_gui(binary_name: str = "", binary_path: str = "", client_id: str | None = None) -> dict[str, Any]:
    normalized_path = normalize_path(binary_path).windows_path if binary_path else ""
    matches = registry.find_candidates(engine="gui", binary_name=binary_name or None, binary_path=normalized_path or None)
    if len(matches) == 1:
        registry.attach_client(matches[0].session_id, client_id, refresh_snapshot=True)
        _client_set_current_session(client_id, matches[0].session_id)
        return {
            "matches": _serialize_sessions_for_client(matches, client_id),
            "auto_selected": True,
            "current_session_id": matches[0].session_id,
        }
    return {"matches": _serialize_sessions_for_client(matches, client_id), "auto_selected": False}


def _local_inspect_environment() -> dict[str, Any]:
    launcher = _get_launcher()
    return {"ok": True, "environment": launcher.inspect_environment()}


def _local_open_binary(
    path: str,
    mode: str = "auto",
    reuse: bool = True,
    remove_previous_idb: bool = False,
    wait_for_analysis: bool = True,
    analysis_timeout_sec: Any = None,
    launch_timeout_sec: Any = None,
    backend_ready_timeout_sec: Any = None,
    progress_id: str = "",
    client_id: str | None = None,
) -> dict[str, Any]:
    with _open_binary_lock:
        _set_operation_progress(
            progress_id,
            operation="open_binary",
            stage="preparing",
            progress=1.0,
            message="Preparing binary launch",
        )
        launch_timeout = _launch_timeout_value(launch_timeout_sec)
        backend_ready_timeout = _backend_ready_timeout_value(backend_ready_timeout_sec)
        _sweep_unreachable_sessions()
        normalized = normalize_path(path)
        candidate_paths = {normalized.input_path, normalized.windows_path, normalized.wsl_path}
        if remove_previous_idb:
            reuse = False
        candidate_hash = _compute_input_binary_hash(normalized) if reuse else ""
        removed_idb = _remove_adjacent_idb(normalized) if remove_previous_idb else None
        _daemon_debug(
            "open_binary start "
            f"path={path!r} mode={mode} reuse={reuse} remove_previous_idb={remove_previous_idb} "
            f"wait_for_analysis={wait_for_analysis} launch_timeout_sec={launch_timeout} "
            f"backend_ready_timeout_sec={backend_ready_timeout} client_id={client_id}"
        )
        if reuse:
            preferred_engine = None if mode == "auto" else mode
            matches = [
                record
                for record in registry.list_sessions(include_dead=False)
                if record.status in {"ready", "busy"}
                and (preferred_engine is None or record.engine == preferred_engine)
                and (
                    _session_matches_any_path(record, candidate_paths)
                    or (candidate_hash and record.binary_hash == candidate_hash)
                )
            ]
            matches = _sort_reuse_matches(
                matches,
                candidate_paths=candidate_paths,
                candidate_hash=candidate_hash,
                operation="open_binary",
            )
            if matches:
                _daemon_debug(f"open_binary reuse-hit session_id={matches[0].session_id}")
                attached = registry.attach_client(matches[0].session_id, client_id, refresh_snapshot=True) or matches[0]
                _client_set_current_session(client_id, matches[0].session_id)
                analysis_wait = _maybe_wait_for_autoanalysis(
                    attached,
                    operation="open_binary",
                    wait_for_analysis=wait_for_analysis,
                    analysis_timeout_sec=analysis_timeout_sec,
                    progress_id=progress_id,
                )
                response_status = (
                    "analysis_pending"
                    if analysis_wait.get("waited") and not analysis_wait.get("autoanalysis_complete")
                    else attached.status
                )
                _set_operation_progress(
                    progress_id,
                    operation="open_binary",
                    stage="complete",
                    progress=100.0,
                    message=(
                        "Reused session; IDA autoanalysis complete"
                        if analysis_wait.get("autoanalysis_complete")
                        else (
                            "Reused session, but IDA autoanalysis is incomplete"
                            if analysis_wait.get("waited")
                            else "Reused existing IDA session"
                        )
                    ),
                    analysis=analysis_wait.get("progress") if isinstance(analysis_wait.get("progress"), dict) else None,
                )
                return {
                    "ok": True,
                    "session_id": attached.session_id,
                    "engine": attached.engine,
                    "status": response_status,
                    "revision": _session_revision_payload(attached, client_id),
                    "selected": True,
                    "reused": True,
                    "remove_previous_idb": False,
                    "removed_previous_idb": None,
                    "analysis": analysis_wait,
                    "analysis_complete": analysis_wait.get("autoanalysis_complete"),
                    **_session_idb_status(attached),
                }

        if mode == "gui":
            _set_operation_progress(
                progress_id,
                operation="open_binary",
                stage="launching",
                progress=5.0,
                message="Launching IDA GUI",
            )
            launcher = _get_launcher()
            environment = launcher.inspect_environment()
            if not environment.get("gui_plugin_installed"):
                return {
                    "ok": False,
                    "error": "GUI mode requires the native Windows plugin bundle, but it does not appear to be installed.",
                    "environment": environment,
                }
            try:
                pending = launcher.launch_gui(path, allow_existing_idb=not remove_previous_idb)
            except Exception as exc:
                return {
                    "ok": False,
                    "error": f"Failed to launch GUI IDA: {exc}",
                    "environment": environment,
                }
            _mark_pending_owner(pending, client_id)
            registry.register_pending_launch(pending)
            _daemon_debug(f"open_binary launched gui launch_token={pending.launch_token} pid={pending.pid}")
            record = _wait_for_session(pending, timeout_sec=launch_timeout)
            if record is None:
                _daemon_debug(f"open_binary wait timeout launch_token={pending.launch_token}")
                return {
                    "ok": False,
                    "error": f"Timed out waiting for {pending.engine} session",
                    "pending": pending.to_dict(),
                    "environment": environment,
                }
        else:
            _set_operation_progress(
                progress_id,
                operation="open_binary",
                stage="launching",
                progress=5.0,
                message="Launching headless IDA",
            )
            launcher = _get_launcher()
            attempts = max(1, int(os.getenv("IDA_HEADLESS_LAUNCH_ATTEMPTS", "3")))
            last_failure: dict[str, Any] | None = None
            record = None
            pending = None
            for attempt in range(1, attempts + 1):
                if _cleanup_untracked_headless_before_launch_enabled():
                    launcher.terminate_untracked_idat(_tracked_headless_pids())
                try:
                    pending = launcher.launch_headless(path, manager_url(), allow_existing_idb=not remove_previous_idb)
                except Exception as exc:
                    last_failure = {
                        "ok": False,
                        "error": f"Failed to launch headless IDA: {exc}",
                        "environment": launcher.inspect_environment(),
                        "attempt": attempt,
                        "attempts": attempts,
                    }
                    if attempt >= attempts:
                        return last_failure
                    continue

                _mark_pending_owner(pending, client_id)
                registry.register_pending_launch(pending)
                _set_operation_progress(
                    progress_id,
                    operation="open_binary",
                    stage="waiting_for_session",
                    progress=10.0,
                    message="Waiting for the IDA session to register",
                )
                _daemon_debug(
                    "open_binary launched headless "
                    f"launch_token={pending.launch_token} pid={pending.pid} port={pending.port} attempt={attempt}/{attempts}"
                )
                record = _wait_for_session(pending, timeout_sec=launch_timeout)
                if record is None:
                    _daemon_debug(
                        "open_binary wait timeout "
                        f"launch_token={pending.launch_token} attempt={attempt}/{attempts}"
                    )
                    cleanup_errors = _terminate_pending_launch(pending, step="open_binary_timeout_terminate")
                    last_failure = {
                        "ok": False,
                        "error": f"Timed out waiting for {pending.engine} session",
                        "pending": pending.to_dict(),
                        "environment": launcher.inspect_environment(),
                        "logs": _pending_log_summary(pending),
                        "cleanup_errors": cleanup_errors,
                        "attempt": attempt,
                        "attempts": attempts,
                    }
                    if attempt >= attempts:
                        return last_failure
                    continue

                _daemon_debug(
                    "open_binary session-linked "
                    f"session_id={record.session_id} status={record.status} endpoint={record.endpoint} attempt={attempt}/{attempts}"
                )
                if _backend_ready(record, timeout_sec=backend_ready_timeout):
                    break

                _daemon_debug(f"open_binary backend_unreachable session_id={record.session_id} attempt={attempt}/{attempts}")
                cleanup_errors = _terminate_session_owner_if_managed(record, step="open_binary_backend_unreachable_terminate")
                if record.closable and record.owner_pid is not None:
                    registry.unregister(record.session_id, "backend_unreachable")
                last_failure = {
                    "ok": False,
                    "error": f"{record.engine} session registered but backend was unreachable",
                    "session_id": record.session_id,
                    "endpoint_candidates": _backend_candidates(record),
                    "environment": _get_launcher().inspect_environment(),
                    "logs": _pending_log_summary(pending),
                    "cleanup_errors": cleanup_errors,
                    "attempt": attempt,
                    "attempts": attempts,
                }
                record = None
                if attempt >= attempts:
                    return last_failure
            if record is None:
                return last_failure or {
                    "ok": False,
                    "error": "Failed to launch headless IDA",
                    "environment": launcher.inspect_environment(),
                }
        if mode == "gui":
            _daemon_debug(f"open_binary session-linked session_id={record.session_id} status={record.status} endpoint={record.endpoint}")
        _set_operation_progress(
            progress_id,
            operation="open_binary",
            stage="backend_ready",
            progress=20.0,
            message="IDA backend is reachable",
        )
        if mode == "gui" and not _backend_ready(record, timeout_sec=backend_ready_timeout):
            _daemon_debug(f"open_binary backend_unreachable session_id={record.session_id}")
            cleanup_errors = _terminate_session_owner_if_managed(record, step="open_binary_gui_backend_unreachable_terminate")
            if record.closable and record.owner_pid is not None:
                registry.unregister(record.session_id, "backend_unreachable")
            return {
                "ok": False,
                "error": f"{record.engine} session registered but backend was unreachable",
                "session_id": record.session_id,
                "endpoint_candidates": _backend_candidates(record),
                "environment": _get_launcher().inspect_environment(),
                "logs": _pending_log_summary(pending) if record.engine == "headless" else {},
                "cleanup_errors": cleanup_errors,
            }
        analysis_wait = _maybe_wait_for_autoanalysis(
            record,
            operation="open_binary",
            wait_for_analysis=wait_for_analysis,
            analysis_timeout_sec=analysis_timeout_sec,
            progress_id=progress_id,
        )
        if record.engine == "headless":
            try:
                _daemon_debug(f"open_binary list_backend_tools start session_id={record.session_id}")
                tools_info = asyncio.run(list_backend_tools_any(_backend_candidates(record)))
                capabilities = [tool.get("name") for tool in tools_info.get("tools", []) if tool.get("name")]
                _daemon_debug(f"open_binary list_backend_tools done session_id={record.session_id} count={len(capabilities)}")
            except Exception:
                capabilities = []
                _daemon_debug(f"open_binary list_backend_tools failed session_id={record.session_id}")
            _daemon_debug(f"open_binary lookup_listener_pid start session_id={record.session_id}")
            listener_pid = _get_launcher().lookup_listener_pid(record.endpoint.get("url", ""))
            _daemon_debug(f"open_binary lookup_listener_pid done session_id={record.session_id} listener_pid={listener_pid}")
            registry.update_managed_session(
                record.session_id,
                status=(
                    "ready"
                    if analysis_wait.get("autoanalysis_complete") is True
                    else ("busy" if analysis_wait.get("autoanalysis_complete") is False else None)
                ),
                capabilities=capabilities,
                owner_pid=listener_pid or record.owner_pid,
                metadata=pending.metadata if pending is not None else None,
            )
        _daemon_debug(f"open_binary done session_id={record.session_id}")
        attached = registry.attach_client(record.session_id, client_id, refresh_snapshot=True) or record
        _client_set_current_session(client_id, record.session_id)
        analysis_complete = analysis_wait.get("autoanalysis_complete")
        response_status = (
            "analysis_pending"
            if analysis_complete is False or (analysis_complete is None and attached.status == "busy")
            else "ready"
        )
        _set_operation_progress(
            progress_id,
            operation="open_binary",
            stage="complete",
            progress=100.0,
            message=(
                "IDA autoanalysis complete"
                if analysis_complete
                else (
                    "IDA session opened, but autoanalysis is incomplete"
                    if analysis_wait.get("waited")
                    else "IDA session ready"
                )
            ),
            analysis=analysis_wait.get("progress") if isinstance(analysis_wait.get("progress"), dict) else None,
        )
        return {
            "ok": True,
            "session_id": attached.session_id,
            "engine": attached.engine,
            "status": response_status,
            "revision": _session_revision_payload(attached, client_id),
            "selected": True,
            "reused": False,
            "remove_previous_idb": remove_previous_idb,
            "removed_previous_idb": removed_idb,
            "analysis": analysis_wait,
            "analysis_complete": analysis_complete,
            "timeouts": {
                "launch_timeout_sec": launch_timeout,
                "backend_ready_timeout_sec": backend_ready_timeout,
                "analysis_timeout_sec": _analysis_timeout_value(analysis_timeout_sec) if wait_for_analysis else None,
            },
            **_session_idb_status(attached),
        }


def _local_load_idb(
    path: str,
    mode: str = "headless",
    reuse: bool = True,
    wait_for_analysis: bool = True,
    analysis_timeout_sec: Any = None,
    launch_timeout_sec: Any = None,
    backend_ready_timeout_sec: Any = None,
    progress_id: str = "",
    client_id: str | None = None,
) -> dict[str, Any]:
    with _open_binary_lock:
        _set_operation_progress(
            progress_id,
            operation="load_idb",
            stage="preparing",
            progress=1.0,
            message="Preparing IDB load",
        )
        launch_timeout = _launch_timeout_value(launch_timeout_sec)
        backend_ready_timeout = _backend_ready_timeout_value(backend_ready_timeout_sec)
        _sweep_unreachable_sessions()
        normalized = normalize_path(path)
        if not str(normalized.wsl_path).lower().endswith(".i64"):
            return {"ok": False, "error": "load_idb expects a .i64 path"}
        idb_fingerprint = _compute_idb_fingerprint(normalized)
        if idb_fingerprint is None:
            return {"ok": False, "error": f"Input IDB not found: {path}"}
        candidate_paths = {normalized.input_path, normalized.windows_path, normalized.wsl_path}
        _daemon_debug(
            "load_idb start "
            f"path={path!r} mode={mode} reuse={reuse} wait_for_analysis={wait_for_analysis} "
            f"launch_timeout_sec={launch_timeout} backend_ready_timeout_sec={backend_ready_timeout} client_id={client_id}"
        )
        if reuse:
            preferred_engine = None if mode == "auto" else mode
            matches = [
                record
                for record in registry.list_sessions(include_dead=False)
                if record.status in {"ready", "busy"}
                and (preferred_engine is None or record.engine == preferred_engine)
                and _session_matches_any_path(record, candidate_paths)
            ]
            matches = _sort_reuse_matches(
                matches,
                candidate_paths=candidate_paths,
                candidate_idb_fingerprint=idb_fingerprint,
                operation="load_idb",
            )
            if matches:
                _daemon_debug(f"load_idb reuse-hit session_id={matches[0].session_id}")
                attached = registry.attach_client(matches[0].session_id, client_id, refresh_snapshot=True) or matches[0]
                _client_set_current_session(client_id, matches[0].session_id)
                analysis_wait = _maybe_wait_for_autoanalysis(
                    attached,
                    operation="load_idb",
                    wait_for_analysis=wait_for_analysis,
                    analysis_timeout_sec=analysis_timeout_sec,
                    progress_id=progress_id,
                )
                response_status = (
                    "analysis_pending"
                    if analysis_wait.get("waited") and not analysis_wait.get("autoanalysis_complete")
                    else attached.status
                )
                _set_operation_progress(
                    progress_id,
                    operation="load_idb",
                    stage="complete",
                    progress=100.0,
                    message=(
                        "Reused IDB session; IDA autoanalysis complete"
                        if analysis_wait.get("autoanalysis_complete")
                        else (
                            "Reused IDB session, but IDA autoanalysis is incomplete"
                            if analysis_wait.get("waited")
                            else "Reused existing IDB session"
                        )
                    ),
                    analysis=analysis_wait.get("progress") if isinstance(analysis_wait.get("progress"), dict) else None,
                )
                return {
                    "ok": True,
                    "session_id": attached.session_id,
                    "engine": attached.engine,
                    "status": response_status,
                    "revision": _session_revision_payload(attached, client_id),
                    "selected": True,
                    "reused": True,
                    "analysis": analysis_wait,
                    "analysis_complete": analysis_wait.get("autoanalysis_complete"),
                    **_session_idb_status(attached),
                }

        launcher = _get_launcher()
        if mode == "gui":
            _set_operation_progress(
                progress_id,
                operation="load_idb",
                stage="launching",
                progress=5.0,
                message="Launching IDA GUI with the IDB",
            )
            environment = launcher.inspect_environment()
            if not environment.get("gui_plugin_installed"):
                return {
                    "ok": False,
                    "error": "GUI mode requires the native Windows plugin bundle, but it does not appear to be installed.",
                    "environment": environment,
                }
            try:
                pending = launcher.launch_gui_idb(path)
            except Exception as exc:
                return {
                    "ok": False,
                    "error": f"Failed to load GUI IDA database: {exc}",
                    "environment": environment,
                }
            _mark_pending_owner(pending, client_id)
            registry.register_pending_launch(pending)
            _daemon_debug(f"load_idb launched gui launch_token={pending.launch_token} pid={pending.pid}")
            record = _wait_for_session(pending, timeout_sec=launch_timeout)
            if record is None:
                _daemon_debug(f"load_idb wait timeout launch_token={pending.launch_token}")
                return {
                    "ok": False,
                    "error": f"Timed out waiting for {pending.engine} session",
                    "pending": pending.to_dict(),
                    "environment": environment,
                }
        else:
            _set_operation_progress(
                progress_id,
                operation="load_idb",
                stage="launching",
                progress=5.0,
                message="Launching headless IDA with the IDB",
            )
            attempts = max(1, int(os.getenv("IDA_HEADLESS_LAUNCH_ATTEMPTS", "3")))
            last_failure: dict[str, Any] | None = None
            record = None
            pending = None
            for attempt in range(1, attempts + 1):
                if _cleanup_untracked_headless_before_launch_enabled():
                    launcher.terminate_untracked_idat(_tracked_headless_pids())
                try:
                    pending = launcher.launch_headless_idb(path, manager_url())
                except Exception as exc:
                    last_failure = {
                        "ok": False,
                        "error": f"Failed to load headless IDA database: {exc}",
                        "environment": launcher.inspect_environment(),
                        "attempt": attempt,
                        "attempts": attempts,
                    }
                    if attempt >= attempts:
                        return last_failure
                    continue

                _mark_pending_owner(pending, client_id)
                registry.register_pending_launch(pending)
                _set_operation_progress(
                    progress_id,
                    operation="load_idb",
                    stage="waiting_for_session",
                    progress=10.0,
                    message="Waiting for the IDB session to register",
                )
                _daemon_debug(
                    "load_idb launched headless "
                    f"launch_token={pending.launch_token} pid={pending.pid} port={pending.port} attempt={attempt}/{attempts}"
                )
                record = _wait_for_session(pending, timeout_sec=launch_timeout)
                if record is None:
                    _daemon_debug(
                        "load_idb wait timeout "
                        f"launch_token={pending.launch_token} attempt={attempt}/{attempts}"
                    )
                    cleanup_errors = _terminate_pending_launch(pending, step="load_idb_timeout_terminate")
                    last_failure = {
                        "ok": False,
                        "error": f"Timed out waiting for {pending.engine} session",
                        "pending": pending.to_dict(),
                        "environment": launcher.inspect_environment(),
                        "logs": _pending_log_summary(pending),
                        "cleanup_errors": cleanup_errors,
                        "attempt": attempt,
                        "attempts": attempts,
                    }
                    if attempt >= attempts:
                        return last_failure
                    continue

                _daemon_debug(
                    "load_idb session-linked "
                    f"session_id={record.session_id} status={record.status} endpoint={record.endpoint} attempt={attempt}/{attempts}"
                )
                if _backend_ready(record, timeout_sec=backend_ready_timeout):
                    break

                _daemon_debug(f"load_idb backend_unreachable session_id={record.session_id} attempt={attempt}/{attempts}")
                cleanup_errors = _terminate_session_owner_if_managed(record, step="load_idb_backend_unreachable_terminate")
                if record.closable and record.owner_pid is not None:
                    registry.unregister(record.session_id, "backend_unreachable")
                last_failure = {
                    "ok": False,
                    "error": f"{record.engine} session registered but backend was unreachable",
                    "session_id": record.session_id,
                    "endpoint_candidates": _backend_candidates(record),
                    "environment": _get_launcher().inspect_environment(),
                    "logs": _pending_log_summary(pending),
                    "cleanup_errors": cleanup_errors,
                    "attempt": attempt,
                    "attempts": attempts,
                }
                record = None
                if attempt >= attempts:
                    return last_failure
            if record is None:
                return last_failure or {
                    "ok": False,
                    "error": "Failed to load headless IDA database",
                    "environment": launcher.inspect_environment(),
                }

        if mode == "gui":
            _daemon_debug(f"load_idb session-linked session_id={record.session_id} status={record.status} endpoint={record.endpoint}")
        _set_operation_progress(
            progress_id,
            operation="load_idb",
            stage="backend_ready",
            progress=20.0,
            message="IDA backend is reachable",
        )
        if mode == "gui" and not _backend_ready(record, timeout_sec=backend_ready_timeout):
            _daemon_debug(f"load_idb backend_unreachable session_id={record.session_id}")
            cleanup_errors = _terminate_session_owner_if_managed(record, step="load_idb_gui_backend_unreachable_terminate")
            if record.closable and record.owner_pid is not None:
                registry.unregister(record.session_id, "backend_unreachable")
            return {
                "ok": False,
                "error": f"{record.engine} session registered but backend was unreachable",
                "session_id": record.session_id,
                "endpoint_candidates": _backend_candidates(record),
                "environment": _get_launcher().inspect_environment(),
                "logs": _pending_log_summary(pending) if record.engine == "headless" else {},
                "cleanup_errors": cleanup_errors,
            }
        analysis_wait = _maybe_wait_for_autoanalysis(
            record,
            operation="load_idb",
            wait_for_analysis=wait_for_analysis,
            analysis_timeout_sec=analysis_timeout_sec,
            progress_id=progress_id,
        )
        if record.engine == "headless":
            try:
                _daemon_debug(f"load_idb list_backend_tools start session_id={record.session_id}")
                tools_info = asyncio.run(list_backend_tools_any(_backend_candidates(record)))
                capabilities = [tool.get("name") for tool in tools_info.get("tools", []) if tool.get("name")]
                _daemon_debug(f"load_idb list_backend_tools done session_id={record.session_id} count={len(capabilities)}")
            except Exception:
                capabilities = []
                _daemon_debug(f"load_idb list_backend_tools failed session_id={record.session_id}")
            _daemon_debug(f"load_idb lookup_listener_pid start session_id={record.session_id}")
            listener_pid = _get_launcher().lookup_listener_pid(record.endpoint.get("url", ""))
            _daemon_debug(f"load_idb lookup_listener_pid done session_id={record.session_id} listener_pid={listener_pid}")
            registry.update_managed_session(
                record.session_id,
                status=(
                    "ready"
                    if analysis_wait.get("autoanalysis_complete") is True
                    else ("busy" if analysis_wait.get("autoanalysis_complete") is False else None)
                ),
                capabilities=capabilities,
                owner_pid=listener_pid or record.owner_pid,
                metadata=pending.metadata if pending is not None else None,
            )
        _daemon_debug(f"load_idb done session_id={record.session_id}")
        attached = registry.attach_client(record.session_id, client_id, refresh_snapshot=True) or record
        _client_set_current_session(client_id, record.session_id)
        analysis_complete = analysis_wait.get("autoanalysis_complete")
        response_status = (
            "analysis_pending"
            if analysis_complete is False or (analysis_complete is None and attached.status == "busy")
            else "ready"
        )
        _set_operation_progress(
            progress_id,
            operation="load_idb",
            stage="complete",
            progress=100.0,
            message=(
                "IDA autoanalysis complete"
                if analysis_complete
                else (
                    "IDB session opened, but autoanalysis is incomplete"
                    if analysis_wait.get("waited")
                    else "IDB session ready"
                )
            ),
            analysis=analysis_wait.get("progress") if isinstance(analysis_wait.get("progress"), dict) else None,
        )
        return {
            "ok": True,
            "session_id": attached.session_id,
            "engine": attached.engine,
            "status": response_status,
            "revision": _session_revision_payload(attached, client_id),
            "selected": True,
            "reused": False,
            "analysis": analysis_wait,
            "analysis_complete": analysis_complete,
            "timeouts": {
                "launch_timeout_sec": launch_timeout,
                "backend_ready_timeout_sec": backend_ready_timeout,
                "analysis_timeout_sec": _analysis_timeout_value(analysis_timeout_sec) if wait_for_analysis else None,
            },
            **_session_idb_status(attached),
        }


def _terminate_session_record(
    record,
    *,
    save: bool,
    reason: str,
    force: bool = False,
    idb_output_dir: str | None = None,
    agent_cwd: str | None = None,
) -> dict[str, Any]:
    cleanup: dict[str, Any] = {}
    errors: list[dict[str, Any]] = []
    launch_token = str(record.metadata.get("launch_token") or "")
    if save:
        try:
            save_result = _run_coroutine_sync(
                call_backend_tool_any(_backend_candidates(record), "save_database", {}, timeout_sec=SAVE_BACKEND_TIMEOUT_SEC)
            )
            cleanup["save_database"] = save_result
            if isinstance(save_result, dict) and save_result.get("ok") is False:
                errors.append({"step": "save_database", "error": str(save_result.get("error") or "save_database returned ok=false")})
        except Exception as exc:
            errors.append({"step": "save_database", "error": str(exc)})
        if errors and not force:
            raise RuntimeError(f"save_database failed; close aborted to avoid data loss: {errors[-1]['error']}")

    launcher = _get_launcher()
    kill_pids: list[int] = []
    if record.owner_pid is not None:
        kill_pids.append(int(record.owner_pid))
    listener_pid = launcher.lookup_listener_pid(record.endpoint.get("url", ""))
    if listener_pid is not None and listener_pid not in kill_pids:
        kill_pids.append(listener_pid)
    validated_kill_pids: list[int] = []
    for pid in kill_pids:
        if record.engine == "headless" and record.source == "manager_created":
            if not launcher.is_managed_headless_process(pid, launch_token=launch_token):
                errors.append({"step": "validate_process_owner", "pid": pid, "error": "pid does not match managed headless launch token"})
                continue
        validated_kill_pids.append(pid)
    cleanup["kill_pids"] = validated_kill_pids
    cleanup["owner_pid"] = record.owner_pid
    cleanup["listener_pid"] = listener_pid
    for pid in validated_kill_pids:
        try:
            launcher.terminate_process(pid)
        except Exception as exc:
            errors.append({"step": "terminate_process", "pid": pid, "error": str(exc)})

    remaining_pids: list[int] = []
    for pid in kill_pids:
        try:
            if launcher.is_process_alive(pid):
                remaining_pids.append(pid)
        except Exception as exc:
            errors.append({"step": "verify_process_exit", "pid": pid, "error": str(exc)})
    if remaining_pids:
        cleanup["remaining_pids"] = remaining_pids
        errors.append({"step": "process_still_alive", "pids": remaining_pids})
        # Never discard the registry record or staged files while an owner is
        # still alive.  A failed/ambiguous kill must remain recoverable after a
        # WSL or daemon restart instead of becoming an orphaned IDA process.
        registry.cancel_close(record.session_id)
        return {
            "ok": False,
            "error": "close_process_still_alive",
            "session_id": record.session_id,
            "cleanup": cleanup,
            "cleanup_errors": errors,
        }

    if save:
        try:
            cleanup["idb_persist"] = _persist_staged_idb(
                record,
                output_dir=idb_output_dir,
                agent_cwd=agent_cwd if idb_output_dir else None,
            )
        except Exception as exc:
            errors.append({"step": "idb_persist", "error": str(exc)})
    staged_dir = str(record.metadata.get("staged_dir") or "")
    if staged_dir:
        cleanup["staged_dir"] = staged_dir
        try:
            cleanup["deleted"] = launcher.cleanup_staged_dir(staged_dir)
        except Exception as exc:
            cleanup["deleted"] = False
            errors.append({"step": "cleanup_staged_dir", "error": str(exc)})
    registry.unregister(record.session_id, reason)
    _client_clear_session_references(record.session_id)
    return {"ok": True, "closed_session_id": record.session_id, "cleanup": cleanup, "cleanup_errors": errors}


def _timestamp_or_none(value: Any) -> float | None:
    if value is None:
        return None
    if hasattr(value, "timestamp"):
        return float(value.timestamp())
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value).timestamp()
        except ValueError:
            return None
    return None


def _session_recency_key(record) -> tuple[float, float, str]:
    # record.last_seen is liveness state and is touched by backend probes; keep
    # pruning order tied to actual client access/write activity.
    candidates = [record.last_write_at, record.created_at]
    for attachment in getattr(record, "attached_clients", {}).values():
        if isinstance(attachment, dict):
            candidates.append(attachment.get("last_seen"))
    timestamps = [timestamp for item in candidates if (timestamp := _timestamp_or_none(item)) is not None]
    newest = max(timestamps) if timestamps else 0.0
    created_at = _timestamp_or_none(record.created_at) or 0.0
    return (newest, created_at, record.session_id)


def _session_agent_scope(record) -> str:
    metadata = getattr(record, "metadata", {}) or {}
    scope = str(metadata.get("owner_agent_scope") or "").strip()
    if scope:
        return scope
    client_name = str(metadata.get("owner_client_name") or "").strip()
    if client_name and client_name != "codex-stdio":
        return f"name:{client_name}"
    client_pid = metadata.get("owner_client_pid")
    if client_pid is not None:
        return f"pid:{client_pid}"
    client_id = str(metadata.get("owner_client_id") or "").strip()
    if client_id:
        return f"client:{client_id}"
    return "unowned"


def _attached_clients_for_agent_scope(record, agent_scope: str) -> set[str]:
    allowed: set[str] = set()
    for attached_client_id in record.attached_clients:
        client_info = _client_get_info(attached_client_id)
        if str(client_info.get("client_scope") or "") == agent_scope:
            allowed.add(attached_client_id)
    return allowed


def _prune_session_summary(record, agent_scope: str) -> dict[str, Any]:
    return {
        "session_id": record.session_id,
        "display_name": record.display_name,
        "agent_scope": agent_scope,
    }


def _local_prune_alive_sessions(
    keep: int = 3,
    output_dir: str = "",
    save: bool = True,
    force: bool = False,
    client_id: str | None = None,
    agent_cwd: str | None = None,
    per_agent: bool = True,
    agent_scope: str = "",
) -> dict[str, Any]:
    keep = max(0, int(keep))
    _sweep_unreachable_sessions()
    records = [
        record
        for record in registry.list_sessions(include_dead=False)
        if record.engine == "headless"
        and record.source == "manager_created"
        and record.closable
        and record.status in {"ready", "busy", "starting"}
    ]
    requested_scope = str(agent_scope or "").strip()
    grouped: dict[str, list[Any]] = {}
    if per_agent:
        for record in records:
            scope = _session_agent_scope(record)
            if requested_scope and scope != requested_scope:
                continue
            grouped.setdefault(scope, []).append(record)
    else:
        grouped["all"] = records
    closed: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    kept: list[dict[str, Any]] = []
    groups: list[dict[str, Any]] = []
    for scope, group_records in sorted(grouped.items()):
        group_records.sort(key=_session_recency_key, reverse=True)
        group_kept = group_records[:keep]
        targets = group_records[keep:]
        kept.extend(_prune_session_summary(record, scope) for record in group_kept)
        group_closed_before = len(closed)
        group_skipped_before = len(skipped)
        for record in targets:
            record_agent_cwd = agent_cwd or str(record.metadata.get("owner_agent_cwd") or "")
            target_output_dir = str(_resolve_agent_output_dir(output_dir, record_agent_cwd)) if output_dir else ""
            allowed_client_ids = _attached_clients_for_agent_scope(record, scope) if per_agent else None
            closable, error = registry.begin_close(
                record.session_id,
                client_id=client_id,
                allowed_client_ids=allowed_client_ids,
                force=force,
            )
            if error is not None or closable is None:
                skipped.append({
                    **_prune_session_summary(record, scope),
                    "reason": error or "begin_close_failed",
                })
                continue
            try:
                result = _terminate_session_record(
                    closable,
                    save=save,
                    reason="prune_alive_sessions",
                    force=force,
                    idb_output_dir=target_output_dir or None,
                    agent_cwd=record_agent_cwd,
                )
            except Exception as exc:
                registry.cancel_close(record.session_id)
                skipped.append({**_prune_session_summary(record, scope), "reason": str(exc)})
                continue
            closed.append({
                **_prune_session_summary(record, scope),
                "output_dir": target_output_dir or "source_path",
                **result,
            })
        groups.append({
            "agent_scope": scope,
            "candidate_count": len(group_records),
            "kept_count": len(group_kept),
            "closed_count": len(closed) - group_closed_before,
            "skipped_count": len(skipped) - group_skipped_before,
        })
    return {
        "ok": True,
        "mode": "prune_alive_sessions",
        "keep": keep,
        "per_agent": bool(per_agent),
        "agent_scope": requested_scope,
        "output_dir": str(_resolve_agent_output_dir(output_dir, agent_cwd)) if output_dir else "source_path",
        "candidate_count": len(records),
        "kept_count": len(kept),
        "closed_count": len(closed),
        "skipped_count": len(skipped),
        "groups": groups,
        "kept": kept,
        "closed": closed,
        "skipped": skipped,
    }


def _auto_prune_headless_sessions() -> dict[str, Any]:
    if not AUTO_PRUNE_HEADLESS_ENABLED:
        return {"ok": True, "enabled": False}
    return _local_prune_alive_sessions(
        keep=AUTO_PRUNE_HEADLESS_KEEP,
        output_dir="",
        save=True,
        force=False,
        client_id=None,
        agent_cwd=None,
        per_agent=True,
    )


def _local_close_session(
    session_id: str,
    save: bool = True,
    force: bool = False,
    client_id: str | None = None,
    idb_output_dir: str | None = None,
    agent_cwd: str | None = None,
) -> dict[str, Any]:
    record = registry.get_session(session_id)
    if record is None:
        return {"ok": False, "error": f"Unknown session: {session_id}"}
    if not record.closable:
        return {"ok": False, "error": "GUI sessions are attach-only in v1 and are not closed by the manager"}
    closable, error = registry.begin_close(
        session_id,
        client_id=client_id,
        force=force,
        require_client_attached=True,
    )
    if error is not None or closable is None:
        return error or {"ok": False, "error": f"Unknown session: {session_id}"}
    try:
        return _terminate_session_record(
            closable,
            save=save,
            reason="manager_close",
            force=force,
            idb_output_dir=idb_output_dir,
            agent_cwd=agent_cwd,
        )
    except Exception as exc:
        registry.cancel_close(session_id)
        return {"ok": False, "error": "close_session_failed", "detail": str(exc), "session_id": session_id}


def _filter_session_tools_payload(result: Any, *, names_only: bool = False, filter_text: str = "") -> Any:
    if not isinstance(result, dict):
        return result
    tools = result.get("tools")
    if not isinstance(tools, list):
        return result
    needles = [item for item in re.split(r"[|,\\s]+", str(filter_text or "").strip().lower()) if item]
    filtered = []
    for item in tools:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "")
        description = str(item.get("description") or "")
        haystack = f"{name}\n{description}".lower()
        if needles and not any(needle in haystack for needle in needles):
            continue
        filtered.append(name if names_only else item)
    compact = dict(result)
    compact["tools"] = filtered
    compact["count"] = len(filtered)
    compact["names_only"] = bool(names_only)
    if needles:
        compact["filter"] = filter_text
    return compact


async def _local_list_session_tools(session_id: str = "", client_id: str | None = None, names_only: bool = False, filter_text: str = "") -> dict[str, Any]:
    record = _current_or_explicit(session_id or None, client_id=client_id)
    with _track_session_operation(record.session_id):
        with record.write_lock:
            latest = registry.get_session(record.session_id)
            if latest is None:
                raise ValueError(f"Unknown session: {record.session_id}")
            result = await list_backend_tools_any(_backend_candidates(latest))
            result = _filter_session_tools_payload(result, names_only=names_only, filter_text=filter_text)
            touched = registry.touch_client(latest.session_id, client_id) or latest
            if isinstance(result, dict):
                return _augment_session_meta(dict(result), touched, client_id=client_id)
            return result


async def _local_describe_session_tool(tool_name: str, session_id: str = "", client_id: str | None = None) -> dict[str, Any]:
    normalized_name = str(tool_name or "").strip()
    if not normalized_name:
        raise ValueError("tool_name is required")
    result = await _local_list_session_tools(session_id=session_id, client_id=client_id, names_only=False, filter_text=normalized_name)
    tools = result.get("tools") if isinstance(result, dict) else None
    match = next(
        (item for item in tools or [] if isinstance(item, dict) and str(item.get("name") or "") == normalized_name),
        None,
    )
    if match is None:
        raise ValueError(f"Unknown backend tool: {normalized_name}")
    descriptor = dict(match)
    cached_schema = _DISCOVERED_TOOL_SCHEMAS.get(normalized_name)
    if cached_schema:
        for key in ("description", "inputSchema"):
            if key in cached_schema:
                descriptor[key] = cached_schema[key]
    return {
        "ok": True,
        "tool": descriptor,
        "schema_available": "inputSchema" in descriptor or "input_schema" in descriptor,
        "session_id": result.get("session_id", "") if isinstance(result, dict) else "",
    }


async def _local_call_session_tool(tool_name: str, arguments: Any = None, session_id: str = "", client_id: str | None = None) -> dict[str, Any]:
    record = _current_or_explicit(session_id or None, client_id=client_id)
    with _track_session_operation(record.session_id):
        payload = _normalize_tool_arguments(tool_name, arguments)
        attachment = registry.get_client_attachment(record.session_id, client_id) or {}
        expected_txid = payload.get("expected_txid")
        force_write = bool(payload.get("force", False))
        warning = ""
        backend_payload = dict(payload)
        backend_payload.pop("expected_txid", None)
        backend_payload.pop("force", None)
        analysis_timeout_sec = backend_payload.pop("analysis_timeout_sec", None)
        allow_incomplete_analysis = _bool_payload_value(backend_payload, "allow_incomplete_analysis", False)
        backend_payload.pop("allow_incomplete_analysis", None)
        with record.write_lock:
            latest = registry.get_session(record.session_id)
            if latest is None:
                raise ValueError(f"Unknown session: {record.session_id}")
            may_mutate = _backend_tool_may_mutate(tool_name, backend_payload)
            if may_mutate:
                current_txid = latest.txid
                seen_txid = attachment.get("last_seen_txid")
                if expected_txid is not None and int(expected_txid) != current_txid:
                    return _augment_session_meta(
                        {
                            "ok": False,
                            "error": "stale_session_revision",
                            "expected_txid": int(expected_txid),
                            "current_txid": current_txid,
                            "session_id": latest.session_id,
                        },
                        latest,
                        client_id=client_id,
                    )
                if expected_txid is None and seen_txid is not None and seen_txid != current_txid and not force_write:
                    warning = f"session_txid changed from {seen_txid} to {current_txid} before {tool_name}"

            if allow_incomplete_analysis:
                analysis_gate = {
                    "required": tool_name in ANALYSIS_DEPENDENT_BACKEND_TOOLS,
                    "ok": True,
                    "bypassed": True,
                    "autoanalysis_complete": False,
                    "tool_name": tool_name,
                    "warning": "Caller explicitly allowed an analysis-incomplete result.",
                }
            else:
                analysis_gate = await _ensure_session_autoanalysis_ready(
                    latest,
                    tool_name=tool_name,
                    analysis_timeout_sec=analysis_timeout_sec,
                )
            latest = registry.get_session(record.session_id) or latest
            if not analysis_gate.get("ok"):
                touched = registry.touch_client(latest.session_id, client_id) or latest
                return _augment_session_meta(
                    _tool_error(
                        str(analysis_gate.get("error") or "autoanalysis_incomplete"),
                        detail=analysis_gate.get("message"),
                        analysis=analysis_gate.get("status"),
                        tool_name=tool_name,
                        timed_out=bool(analysis_gate.get("timed_out")),
                        stalled=bool(analysis_gate.get("stalled")),
                    ),
                    touched,
                    client_id=client_id,
                    warning=warning,
                    analysis_gate=analysis_gate,
                )

            if may_mutate:
                try:
                    result = await call_backend_tool_any(
                        _backend_candidates(latest),
                        tool_name,
                        backend_payload,
                        timeout_sec=_backend_tool_timeout_sec(tool_name),
                    )
                except BackendUnavailableError:
                    _daemon_debug(f"backend unavailable during mutating tool session_id={latest.session_id} tool={tool_name}")
                    raise
                if not _backend_mutation_changed_db(result):
                    touched = registry.touch_client(latest.session_id, client_id) or latest
                    return _augment_session_meta(
                        result,
                        touched,
                        client_id=client_id,
                        warning=warning,
                        analysis_gate=analysis_gate,
                    )
                updated = registry.bump_txid(latest.session_id, client_id, tool_name) or latest
                if tool_name in ANALYSIS_INVALIDATING_BACKEND_TOOLS:
                    _invalidate_session_autoanalysis(latest.session_id, reason=tool_name)
                    updated = registry.get_session(latest.session_id) or updated
                return _augment_session_meta(
                    result,
                    updated,
                    client_id=client_id,
                    warning=warning,
                    analysis_gate=analysis_gate,
                )
            try:
                result = await call_backend_tool_any(
                    _backend_candidates(latest),
                    tool_name,
                    backend_payload,
                    timeout_sec=_backend_tool_timeout_sec(tool_name),
                )
                touched = registry.touch_client(latest.session_id, client_id) or latest
                return _augment_session_meta(
                    result,
                    touched,
                    client_id=client_id,
                    analysis_gate=analysis_gate,
                )
            except BackendUnavailableError:
                _daemon_debug(f"backend unavailable during read-only tool session_id={latest.session_id} tool={tool_name}")
                raise


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
    if client_id and op_name not in {"connect_client", "disconnect_client"} and not _client_touch(client_id):
        raise ValueError(f"Unknown client_id: {client_id}")
    op_map = {
        "connect_client": lambda **kwargs: _client_connect(**kwargs),
        "heartbeat_client": lambda **kwargs: {"ok": bool(_client_touch(kwargs.get("client_id"))), "client_id": kwargs.get("client_id")},
        "disconnect_client": lambda **kwargs: _client_disconnect(
            kwargs.get("client_id"),
            async_close=bool(kwargs.get("async_close", False)),
            reason=str(kwargs.get("reason") or "disconnect_client"),
        ),
        "get_operation_progress": lambda **kwargs: _get_operation_progress(kwargs.get("operation_id")),
        "clear_operation_progress": lambda **kwargs: _clear_operation_progress(kwargs.get("operation_id")),
        "inspect_environment": lambda **kwargs: _local_inspect_environment(),
        "list_alive_sessions": lambda **kwargs: _local_list_alive_sessions(client_id=client_id),
        "current_session": lambda **kwargs: _local_current_session(client_id=client_id),
        "select_session": lambda **kwargs: _local_select_session(kwargs["session_id"], client_id=client_id),
        "attach_to_gui": lambda **kwargs: _local_attach_to_gui(kwargs.get("binary_name", ""), kwargs.get("binary_path", ""), client_id=client_id),
        "open_binary": lambda **kwargs: _local_open_binary(
            path=kwargs["path"],
            mode=kwargs.get("mode", "auto"),
            reuse=kwargs.get("reuse", True),
            remove_previous_idb=kwargs.get("remove_previous_idb", False),
            wait_for_analysis=kwargs.get("wait_for_analysis", True),
            analysis_timeout_sec=kwargs.get("analysis_timeout_sec"),
            launch_timeout_sec=kwargs.get("launch_timeout_sec"),
            backend_ready_timeout_sec=kwargs.get("backend_ready_timeout_sec"),
            progress_id=kwargs.get("progress_id", ""),
            client_id=client_id,
        ),
        "load_idb": lambda **kwargs: _local_load_idb(
            path=kwargs["path"],
            mode=kwargs.get("mode", "headless"),
            reuse=kwargs.get("reuse", True),
            wait_for_analysis=kwargs.get("wait_for_analysis", True),
            analysis_timeout_sec=kwargs.get("analysis_timeout_sec"),
            launch_timeout_sec=kwargs.get("launch_timeout_sec"),
            backend_ready_timeout_sec=kwargs.get("backend_ready_timeout_sec"),
            progress_id=kwargs.get("progress_id", ""),
            client_id=client_id,
        ),
        "close_session": lambda **kwargs: _local_close_session(
            kwargs["session_id"],
            kwargs.get("save", True),
            kwargs.get("force", False),
            client_id=client_id,
            idb_output_dir=kwargs.get("idb_output_dir") or kwargs.get("output_dir"),
            agent_cwd=kwargs.get("agent_cwd"),
        ),
        "prune_alive_sessions": lambda **kwargs: _local_prune_alive_sessions(
            kwargs.get("keep", 3),
            kwargs.get("output_dir", ""),
            kwargs.get("save", True),
            kwargs.get("force", False),
            client_id=client_id,
            agent_cwd=kwargs.get("agent_cwd"),
            per_agent=kwargs.get("per_agent", True),
            agent_scope=kwargs.get("agent_scope", ""),
        ),
        "list_session_tools": lambda **kwargs: _local_list_session_tools(
            kwargs.get("session_id", ""),
            client_id=client_id,
            names_only=bool(kwargs.get("names_only", False)),
            filter_text=str(kwargs.get("filter", "") or kwargs.get("query", "") or ""),
        ),
        "describe_session_tool": lambda **kwargs: _local_describe_session_tool(
            kwargs["tool_name"], kwargs.get("session_id", ""), client_id=client_id
        ),
        "call_session_tool": lambda **kwargs: _local_call_session_tool(kwargs["tool_name"], kwargs.get("arguments"), kwargs.get("session_id", ""), client_id=client_id),
        "inspect": lambda **kwargs: _local_call_session_tool(
            "inspect",
            _merge_detail_payload(
                kwargs.get("arguments"),
                full=bool(kwargs.get("full", False)),
                detail=str(kwargs.get("detail", "")),
                addr=kwargs["addr"],
            ),
            kwargs.get("session_id", ""),
            client_id=client_id,
        ),
        "read": lambda **kwargs: _local_call_session_tool(
            "read",
            _merge_detail_payload(
                kwargs.get("arguments"),
                full=bool(kwargs.get("full", False)),
                detail=str(kwargs.get("detail", "")),
                kind=kwargs["kind"],
                addr=kwargs.get("addr", ""),
            ),
            kwargs.get("session_id", ""),
            client_id=client_id,
        ),
        "search": lambda **kwargs: _local_call_session_tool(
            "search",
            _merge_detail_payload(
                kwargs.get("arguments"),
                full=bool(kwargs.get("full", False)),
                detail=str(kwargs.get("detail", "")),
                kind=kwargs["kind"],
                query=kwargs.get("query", ""),
            ),
            kwargs.get("session_id", ""),
            client_id=client_id,
        ),
        "xrefs": lambda **kwargs: _local_call_session_tool(
            "xrefs",
            _merge_detail_payload(
                kwargs.get("arguments"),
                full=bool(kwargs.get("full", False)),
                detail=str(kwargs.get("detail", "")),
                direction=kwargs.get("direction", "to"),
                addr=kwargs.get("addr", ""),
            ),
            kwargs.get("session_id", ""),
            client_id=client_id,
        ),
        "define": lambda **kwargs: _local_call_session_tool(
            "define",
            _merge_payload(kwargs.get("arguments"), kind=kwargs["kind"], addr=kwargs.get("addr", "")),
            kwargs.get("session_id", ""),
            client_id=client_id,
        ),
        "inspect_addr": lambda **kwargs: _local_call_session_tool("inspect_addr", {"addr": kwargs["addr"]}, kwargs.get("session_id", ""), client_id=client_id),
        "jump": lambda **kwargs: _local_call_session_tool(
            "jump",
            _merge_payload_with_defaults(
                kwargs.get("arguments"),
                {"addr": "", "rva": "", "symbol": "", "mode": "decompile", "max_instructions": 400, "fallback": "disasm"},
                addr=kwargs.get("addr", ""),
                rva=kwargs.get("rva", ""),
                symbol=kwargs.get("symbol", ""),
                mode=kwargs.get("mode", "decompile"),
                max_instructions=kwargs.get("max_instructions", 400),
                fallback=kwargs.get("fallback", "disasm"),
            ),
            kwargs.get("session_id", ""),
            client_id=client_id,
        ),
        "diagnose_function": lambda **kwargs: _local_call_session_tool(
            "diagnose_function",
            _merge_payload_with_defaults(
                kwargs.get("arguments"),
                {"addr": "", "rva": "", "symbol": "", "max_items": 200},
                addr=kwargs.get("addr", ""),
                rva=kwargs.get("rva", ""),
                symbol=kwargs.get("symbol", ""),
                max_items=kwargs.get("max_items", 200),
            ),
            kwargs.get("session_id", ""),
            client_id=client_id,
        ),
        "get_enclosing_function": lambda **kwargs: _local_call_session_tool("get_enclosing_function", {"addr": kwargs["addr"]}, kwargs.get("session_id", ""), client_id=client_id),
        "decompile": lambda **kwargs: _local_call_session_tool(
            "decompile",
            _merge_detail_payload(
                None,
                full=bool(kwargs.get("full", False)),
                detail=str(kwargs.get("detail", "")),
                addr=kwargs["addr"],
                include_line_map=kwargs.get("include_line_map", False),
                view=str(kwargs.get("view", "")),
            ),
            kwargs.get("session_id", ""),
            client_id=client_id,
        ),
        "export_decompiled_c": lambda **kwargs: _local_call_session_tool(
            "export_decompiled_c",
            {
                "path": kwargs.get("path", ""),
                "include_extern": kwargs.get("include_extern", False),
                "include_thunks": kwargs.get("include_thunks", False),
                "filter": kwargs.get("filter", ""),
                "fallback": _normalize_export_fallback(kwargs.get("fallback", "comment")),
                "max_functions": kwargs.get("max_functions", 0),
                "return_code": kwargs.get("return_code", False),
                "max_return_bytes": kwargs.get("max_return_bytes", 256 * 1024),
                "include_structs": kwargs.get("include_structs", False),
                "header_path": kwargs.get("header_path", ""),
                "struct_names": kwargs.get("struct_names", kwargs.get("header_structs", [])),
            },
            kwargs.get("session_id", ""),
            client_id=client_id,
        ),
        "decompile_line_map": lambda **kwargs: _local_call_session_tool("get_decompile_line_map", {"addr": kwargs["addr"]}, kwargs.get("session_id", ""), client_id=client_id),
        "disasm_function": lambda **kwargs: _local_call_session_tool(
            "disasm_function",
            _merge_detail_payload(None, full=bool(kwargs.get("full", False)), detail=str(kwargs.get("detail", "")), addr=kwargs["addr"], max_instructions=kwargs.get("max_instructions", 4000)),
            kwargs.get("session_id", ""),
            client_id=client_id,
        ),
        "apply_decl": lambda **kwargs: _local_call_session_tool(
            "apply_decl",
            {"addr": kwargs.get("addr", ""), "symbol": kwargs.get("symbol", ""), "decl": kwargs["decl"], "supporting_decls": kwargs.get("supporting_decls")},
            kwargs.get("session_id", ""),
            client_id=client_id,
        ),
        "export_header": lambda **kwargs: _local_call_session_tool(
            "export_header",
            {
                "path": kwargs.get("path", ""),
                "struct_names": kwargs.get("struct_names", kwargs.get("names", [])),
                "return_header": kwargs.get("return_header", False),
                "include_guard": kwargs.get("include_guard", True),
                "auto_order": kwargs.get("auto_order", True),
                "forward_decls": kwargs.get("forward_decls", True),
            },
            kwargs.get("session_id", ""),
            client_id=client_id,
        ),
        "import_header": lambda **kwargs: _local_call_session_tool(
            "import_header",
            {
                "path": kwargs.get("path", ""),
                "header": kwargs.get("header", kwargs.get("decl", kwargs.get("text", ""))),
            },
            kwargs.get("session_id", ""),
            client_id=client_id,
        ),
        "reanalyze_function": lambda **kwargs: _local_call_session_tool("reanalyze_function", {"addr": kwargs["addr"]}, kwargs.get("session_id", ""), client_id=client_id),
        "repair_function_analysis": lambda **kwargs: _local_call_session_tool(
            "repair_function_analysis",
            _merge_payload_with_defaults(
                kwargs.get("arguments"),
                {
                    "addr": "",
                    "rva": "",
                    "symbol": "",
                    "name": "",
                    "new_name": "",
                    "function_name": "",
                    "end": "",
                    "end_rva": "",
                    "size": 0,
                    "undefine": False,
                    "define_code": True,
                    "make_function": True,
                    "decl": "",
                    "signature": "",
                    "supporting_decls": None,
                    "frame_size": "",
                    "saved_regs_size": "",
                    "args_size": "",
                    "purged_bytes": "",
                    "fpd": "",
                    "flags": "",
                    "decompile": True,
                    "fallback": "disasm",
                },
                addr=kwargs.get("addr", ""),
                rva=kwargs.get("rva", ""),
                symbol=kwargs.get("symbol", ""),
                name=kwargs.get("name", ""),
                new_name=kwargs.get("new_name", ""),
                function_name=kwargs.get("function_name", ""),
                end=kwargs.get("end", ""),
                end_rva=kwargs.get("end_rva", ""),
                size=kwargs.get("size", 0),
                undefine=kwargs.get("undefine", False),
                define_code=kwargs.get("define_code", True),
                make_function=kwargs.get("make_function", True),
                decl=kwargs.get("decl", ""),
                signature=kwargs.get("signature", ""),
                supporting_decls=kwargs.get("supporting_decls"),
                frame_size=kwargs.get("frame_size", ""),
                saved_regs_size=kwargs.get("saved_regs_size", ""),
                args_size=kwargs.get("args_size", ""),
                purged_bytes=kwargs.get("purged_bytes", ""),
                fpd=kwargs.get("fpd", ""),
                flags=kwargs.get("flags", ""),
                decompile=kwargs.get("decompile", True),
                fallback=kwargs.get("fallback", "disasm"),
            ),
            kwargs.get("session_id", ""),
            client_id=client_id,
        ),
        "bulk_recover_and_name": lambda **kwargs: _local_call_session_tool(
            "bulk_recover_and_name",
            _merge_payload_with_defaults(
                kwargs.get("arguments"),
                {"items": [], "define_code": True, "make_function": True, "reanalyze": True, "apply_comments": True},
                items=kwargs.get("items", []),
                define_code=kwargs.get("define_code", True),
                make_function=kwargs.get("make_function", True),
                reanalyze=kwargs.get("reanalyze", True),
                apply_comments=kwargs.get("apply_comments", True),
                expected_txid=kwargs.get("expected_txid"),
                force=kwargs.get("force"),
            ),
            kwargs.get("session_id", ""),
            client_id=client_id,
        ),
        "set_function_options": lambda **kwargs: _local_call_session_tool(
            "set_function_options",
            _merge_payload_with_defaults(
                kwargs.get("arguments"),
                {
                    "addr": "",
                    "rva": "",
                    "symbol": "",
                    "end": "",
                    "end_rva": "",
                    "create": False,
                    "frame_size": "",
                    "saved_regs_size": "",
                    "args_size": "",
                    "purged_bytes": "",
                    "fpd": "",
                    "flags": "",
                    "reanalyze": True,
                },
                addr=kwargs.get("addr", ""),
                rva=kwargs.get("rva", ""),
                symbol=kwargs.get("symbol", ""),
                end=kwargs.get("end", ""),
                end_rva=kwargs.get("end_rva", ""),
                create=kwargs.get("create", False),
                frame_size=kwargs.get("frame_size", ""),
                saved_regs_size=kwargs.get("saved_regs_size", ""),
                args_size=kwargs.get("args_size", ""),
                purged_bytes=kwargs.get("purged_bytes", ""),
                fpd=kwargs.get("fpd", ""),
                flags=kwargs.get("flags", ""),
                reanalyze=kwargs.get("reanalyze", True),
            ),
            kwargs.get("session_id", ""),
            client_id=client_id,
        ),
        "set_sp_delta": lambda **kwargs: _local_call_session_tool(
            "set_sp_delta",
            _merge_payload_with_defaults(
                kwargs.get("arguments"),
                {"addr": "", "rva": "", "symbol": "", "delta": 0, "reanalyze": True},
                addr=kwargs.get("addr", ""),
                rva=kwargs.get("rva", ""),
                symbol=kwargs.get("symbol", ""),
                delta=kwargs.get("delta", 0),
                reanalyze=kwargs.get("reanalyze", True),
            ),
            kwargs.get("session_id", ""),
            client_id=client_id,
        ),
        "patch_bytes": lambda **kwargs: _local_call_session_tool(
            "patch_bytes",
            _merge_payload_with_defaults(
                kwargs.get("arguments"),
                {"addr": "", "rva": "", "symbol": "", "bytes": "", "dry_run": True, "reanalyze": True, "max_bytes": 4096},
                addr=kwargs.get("addr", ""),
                rva=kwargs.get("rva", ""),
                symbol=kwargs.get("symbol", ""),
                bytes=kwargs.get("data", kwargs.get("bytes", "")),
                dry_run=kwargs.get("dry_run", True),
                reanalyze=kwargs.get("reanalyze", True),
                max_bytes=kwargs.get("max_bytes", 4096),
                expected_txid=kwargs.get("expected_txid"),
                force=kwargs.get("force"),
            ),
            kwargs.get("session_id", ""),
            client_id=client_id,
        ),
        "revert_patch": lambda **kwargs: _local_call_session_tool(
            "revert_patch",
            _merge_payload_with_defaults(
                kwargs.get("arguments"),
                {"addr": "", "rva": "", "symbol": "", "original": "", "dry_run": False, "reanalyze": True, "max_bytes": 4096},
                addr=kwargs.get("addr", ""),
                rva=kwargs.get("rva", ""),
                symbol=kwargs.get("symbol", ""),
                original=kwargs.get("original", kwargs.get("original_bytes", "")),
                dry_run=kwargs.get("dry_run", False),
                reanalyze=kwargs.get("reanalyze", True),
                max_bytes=kwargs.get("max_bytes", 4096),
                expected_txid=kwargs.get("expected_txid"),
                force=kwargs.get("force"),
            ),
            kwargs.get("session_id", ""),
            client_id=client_id,
        ),
        "nop_range": lambda **kwargs: _local_call_session_tool(
            "nop_range",
            _merge_payload_with_defaults(
                kwargs.get("arguments"),
                {
                    "addr": "",
                    "rva": "",
                    "symbol": "",
                    "end": "",
                    "end_rva": "",
                    "size": 0,
                    "nop_byte": 0x90,
                    "dry_run": True,
                    "reanalyze": True,
                    "max_bytes": 4096,
                },
                addr=kwargs.get("addr", ""),
                rva=kwargs.get("rva", ""),
                symbol=kwargs.get("symbol", ""),
                end=kwargs.get("end", ""),
                end_rva=kwargs.get("end_rva", ""),
                size=kwargs.get("size", 0),
                nop_byte=kwargs.get("nop_byte", 0x90),
                dry_run=kwargs.get("dry_run", True),
                reanalyze=kwargs.get("reanalyze", True),
                max_bytes=kwargs.get("max_bytes", 4096),
                expected_txid=kwargs.get("expected_txid"),
                force=kwargs.get("force"),
            ),
            kwargs.get("session_id", ""),
            client_id=client_id,
        ),
        "lookup_funcs": lambda **kwargs: _local_call_session_tool("lookup_funcs", {"queries": kwargs["queries"]}, kwargs.get("session_id", ""), client_id=client_id),
        "xrefs_to": lambda **kwargs: _local_call_session_tool("xrefs_to", {"addrs": kwargs["addrs"], "limit": kwargs.get("limit", 100)}, kwargs.get("session_id", ""), client_id=client_id),
        "rename": lambda **kwargs: _local_call_session_tool(
            "rename",
            {
                "batch": kwargs["batch"],
                **({"expected_txid": kwargs["expected_txid"]} if kwargs.get("expected_txid") is not None else {}),
                **({"force": kwargs["force"]} if kwargs.get("force") is not None else {}),
            },
            kwargs.get("session_id", ""),
            client_id=client_id,
        ),
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
    with _client_lease_renewal(client_id):
        result = operation(**payload)
        if asyncio.iscoroutine(result):
            return asyncio.run(result)
        return result


@mcp.tool(description="List alive IDA sessions discovered by the manager.", structured_output=False)
def list_alive_sessions() -> mcp_types.CallToolResult:
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(_daemon_request_sync("list_alive_sessions", {"client_id": CLIENT_ID}))
    return _mcp_result(_local_list_alive_sessions(CLIENT_ID))


@mcp.tool(description="Return the currently selected IDA session.", structured_output=False)
def current_session() -> mcp_types.CallToolResult:
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(_daemon_request_sync("current_session", {"client_id": CLIENT_ID}))
    return _mcp_result(_local_current_session(CLIENT_ID))


@mcp.tool(description="Select an alive IDA session by its session_id.", structured_output=False)
def select_session(session_id: str) -> mcp_types.CallToolResult:
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(_daemon_request_sync("select_session", {"session_id": session_id, "client_id": CLIENT_ID}))
    return _mcp_result(_local_select_session(session_id, CLIENT_ID))


@mcp.tool(description="Attach to an already-open GUI IDA session, optionally filtering by binary name or path.", structured_output=False)
def attach_to_gui(binary_name: str = "", binary_path: str = "") -> mcp_types.CallToolResult:
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(_daemon_request_sync("attach_to_gui", {"binary_name": binary_name, "binary_path": binary_path, "client_id": CLIENT_ID}))
    return _mcp_result(_local_attach_to_gui(binary_name=binary_name, binary_path=binary_path, client_id=CLIENT_ID))


@mcp.tool(description="Inspect Windows IDA paths, plugin install state, and headless bootstrap availability.", structured_output=False)
def inspect_environment() -> mcp_types.CallToolResult:
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(_daemon_request_sync("inspect_environment", {"client_id": CLIENT_ID}))
    return _mcp_result(_local_inspect_environment())


async def _run_operation_with_mcp_progress(
    ctx: Context,
    *,
    operation: str,
    daemon_payload: dict[str, Any],
    local_call,
    request_timeout_sec: float,
) -> Any:
    progress_id = f"progress-{uuid.uuid4().hex}"
    payload = dict(daemon_payload)
    payload["progress_id"] = progress_id
    await ctx.report_progress(0.0, 100.0, f"Starting {operation}")

    if ACTIVE_BACKEND == "daemon":
        task = asyncio.create_task(
            asyncio.to_thread(
                _daemon_request_sync,
                operation,
                payload,
                timeout_sec=request_timeout_sec,
            )
        )

        async def fetch_progress() -> dict[str, Any]:
            return await asyncio.to_thread(
                _daemon_request_sync_once,
                "get_operation_progress",
                {"operation_id": progress_id},
                timeout_sec=5.0,
                retry_unknown_client=False,
            )

        async def clear_progress() -> None:
            try:
                await asyncio.to_thread(
                    _daemon_request_sync_once,
                    "clear_operation_progress",
                    {"operation_id": progress_id},
                    timeout_sec=5.0,
                    retry_unknown_client=False,
                )
            except Exception:
                pass
    else:
        task = asyncio.create_task(asyncio.to_thread(local_call, progress_id))

        async def fetch_progress() -> dict[str, Any]:
            return _get_operation_progress(progress_id)

        async def clear_progress() -> None:
            _clear_operation_progress(progress_id)

    last_revision = -1
    last_progress = 0.0
    last_message = f"Starting {operation}"
    try:
        while not task.done():
            try:
                entry = await fetch_progress()
                revision = int(entry.get("revision") or -1)
                if entry.get("found") and revision != last_revision:
                    last_revision = revision
                    last_progress = max(last_progress, float(entry.get("progress") or 0.0))
                    last_message = str(entry.get("message") or last_message)
                    await ctx.report_progress(last_progress, 100.0, last_message)
            except Exception as exc:
                _stdio_debug(f"{operation} progress poll failed progress_id={progress_id}: {exc!r}")
            await asyncio.sleep(0.25)

        result = await task
        try:
            entry = await fetch_progress()
            if entry.get("found"):
                last_progress = max(last_progress, float(entry.get("progress") or 0.0))
                last_message = str(entry.get("message") or last_message)
        except Exception:
            pass

        if isinstance(result, dict) and result.get("ok") is False:
            await ctx.report_progress(last_progress, 100.0, str(result.get("error") or f"{operation} failed"))
        else:
            analysis = result.get("analysis") if isinstance(result, dict) and isinstance(result.get("analysis"), dict) else {}
            if analysis.get("waited") and not analysis.get("autoanalysis_complete"):
                message = str(analysis.get("warning") or "IDA autoanalysis is still incomplete")
            else:
                message = last_message if last_progress >= 100.0 else f"{operation} complete"
            await ctx.report_progress(100.0, 100.0, message)
        return result
    except BaseException:
        if not task.done():
            # asyncio cannot stop work already running in a worker thread. Mark
            # this progress id cancelled so late worker updates cannot recreate
            # a stale entry after the MCP caller has disconnected.
            _cancel_operation_progress(progress_id)
        if task.done():
            try:
                await task
            except BaseException:
                pass
        raise
    finally:
        if task.done():
            await clear_progress()


@mcp.tool(description="Open a binary in headless mode, GUI mode, or auto mode and select the resulting session. Headless launches wait for IDA autoanalysis by default and emit live phase/address/segment progress; set wait_for_analysis=false for the old backend-ready-only behavior.", structured_output=False)
async def open_binary(
    ctx: Context,
    path: str,
    mode: str = "auto",
    reuse: bool = True,
    remove_previous_idb: bool = False,
    wait_for_analysis: bool = True,
    analysis_timeout_sec: float = 120.0,
    launch_timeout_sec: float = 90.0,
    backend_ready_timeout_sec: float = 20.0,
    request_timeout_sec: float = 0.0,
) -> mcp_types.CallToolResult:
    if str(path or "").strip().lower().endswith(".i64"):
        return _mcp_error_result("open_binary expects the original binary path. Use load_idb() to open an existing .i64 database.")
    payload = {
        "path": path,
        "mode": mode,
        "reuse": reuse,
        "remove_previous_idb": remove_previous_idb,
        "wait_for_analysis": wait_for_analysis,
        "analysis_timeout_sec": analysis_timeout_sec,
        "launch_timeout_sec": launch_timeout_sec,
        "backend_ready_timeout_sec": backend_ready_timeout_sec,
        "client_id": CLIENT_ID,
    }
    timeout = _request_timeout_value(request_timeout_sec, default=_daemon_operation_timeout_sec("open_binary"))
    if ACTIVE_BACKEND == "daemon":
        result = await _run_operation_with_mcp_progress(
            ctx,
            operation="open_binary",
            daemon_payload=payload,
            local_call=None,
            request_timeout_sec=timeout,
        )
    else:
        result = await _run_operation_with_mcp_progress(
            ctx,
            operation="open_binary",
            daemon_payload=payload,
            local_call=lambda progress_id: _local_open_binary(
                path=path,
                mode=mode,
                reuse=reuse,
                remove_previous_idb=remove_previous_idb,
                wait_for_analysis=wait_for_analysis,
                analysis_timeout_sec=analysis_timeout_sec,
                launch_timeout_sec=launch_timeout_sec,
                backend_ready_timeout_sec=backend_ready_timeout_sec,
                progress_id=progress_id,
                client_id=CLIENT_ID,
            ),
            request_timeout_sec=timeout,
        )
    return _mcp_result(result)


@mcp.tool(description="Load an existing .i64 database in headless or GUI mode and select the resulting session. Headless loads wait for IDA autoanalysis by default and emit live phase/address/segment progress; the final response includes executable-segment tail coverage.", structured_output=False)
async def load_idb(
    ctx: Context,
    path: str,
    mode: str = "headless",
    reuse: bool = True,
    wait_for_analysis: bool = True,
    analysis_timeout_sec: float = 120.0,
    launch_timeout_sec: float = 90.0,
    backend_ready_timeout_sec: float = 20.0,
    request_timeout_sec: float = 0.0,
) -> mcp_types.CallToolResult:
    payload = {
        "path": path,
        "mode": mode,
        "reuse": reuse,
        "wait_for_analysis": wait_for_analysis,
        "analysis_timeout_sec": analysis_timeout_sec,
        "launch_timeout_sec": launch_timeout_sec,
        "backend_ready_timeout_sec": backend_ready_timeout_sec,
        "client_id": CLIENT_ID,
    }
    timeout = _request_timeout_value(request_timeout_sec, default=_daemon_operation_timeout_sec("load_idb"))
    if ACTIVE_BACKEND == "daemon":
        result = await _run_operation_with_mcp_progress(
            ctx,
            operation="load_idb",
            daemon_payload=payload,
            local_call=None,
            request_timeout_sec=timeout,
        )
    else:
        result = await _run_operation_with_mcp_progress(
            ctx,
            operation="load_idb",
            daemon_payload=payload,
            local_call=lambda progress_id: _local_load_idb(
                path=path,
                mode=mode,
                reuse=reuse,
                wait_for_analysis=wait_for_analysis,
                analysis_timeout_sec=analysis_timeout_sec,
                launch_timeout_sec=launch_timeout_sec,
                backend_ready_timeout_sec=backend_ready_timeout_sec,
                progress_id=progress_id,
                client_id=CLIENT_ID,
            ),
            request_timeout_sec=timeout,
        )
    return _mcp_result(result)


@mcp.tool(description="Close a manager-owned headless session.", structured_output=False)
def close_session(session_id: str, save: bool = True, force: bool = False, idb_output_dir: str = "") -> mcp_types.CallToolResult:
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(_daemon_request_sync(
            "close_session",
            {
                "session_id": session_id,
                "save": save,
                "force": force,
                "idb_output_dir": idb_output_dir,
                "agent_cwd": os.getcwd(),
                "client_id": CLIENT_ID,
            },
        ))
    return _mcp_result(_local_close_session(
        session_id=session_id,
        save=save,
        force=force,
        client_id=CLIENT_ID,
        idb_output_dir=idb_output_dir,
        agent_cwd=os.getcwd(),
    ))


@mcp.tool(description="Keep only the most recent manager-owned headless sessions alive per agent scope by default; save and close older sessions. Set per_agent=false for a global cap. By default saved .i64 data is persisted back to the original/source-adjacent IDB path; pass output_dir only when you explicitly want an additional copy in a chosen directory.", structured_output=False)
def prune_alive_sessions(
    keep: int = 3,
    output_dir: str = "",
    save: bool = True,
    force: bool = False,
    per_agent: bool = True,
    agent_scope: str = "",
) -> mcp_types.CallToolResult:
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(_daemon_request_sync(
            "prune_alive_sessions",
            {
                "keep": keep,
                "output_dir": output_dir,
                "save": save,
                "force": force,
                "per_agent": per_agent,
                "agent_scope": agent_scope,
                "agent_cwd": os.getcwd(),
                "client_id": CLIENT_ID,
            },
        ))
    return _mcp_result(_local_prune_alive_sessions(
        keep=keep,
        output_dir=output_dir,
        save=save,
        force=force,
        client_id=CLIENT_ID,
        agent_cwd=os.getcwd(),
        per_agent=per_agent,
        agent_scope=agent_scope,
    ))


@mcp.tool(description="List backend tools exposed by a session. Use names_only=true and/or filter='rename|struct|export' to avoid large tool-list responses.", structured_output=False)
async def list_session_tools(session_id: str = "", names_only: bool = False, filter: str = "") -> mcp_types.CallToolResult:
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(await _daemon_request_async("list_session_tools", {"session_id": session_id, "names_only": names_only, "filter": filter, "client_id": CLIENT_ID}))
    return _mcp_result(await _local_list_session_tools(session_id=session_id, client_id=CLIENT_ID, names_only=names_only, filter_text=filter))


@mcp.tool(description="Describe one backend tool after discovery. Only the selected tool definition is returned; use names_only=true on list_session_tools first.", structured_output=False)
async def describe_session_tool(tool_name: str, session_id: str = "") -> mcp_types.CallToolResult:
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(await _daemon_request_async("describe_session_tool", {"tool_name": tool_name, "session_id": session_id, "client_id": CLIENT_ID}))
    return _mcp_result(await _local_describe_session_tool(tool_name, session_id=session_id, client_id=CLIENT_ID))


@mcp.tool(description="Call any backend raw tool on the explicit session_id, or on the current selected session when session_id is omitted.", structured_output=False)
async def call_session_tool(tool_name: str, arguments: Any = None, session_id: str = "") -> mcp_types.CallToolResult:
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(await _daemon_request_async(
            "call_session_tool",
            {"tool_name": tool_name, "arguments": arguments, "session_id": session_id, "client_id": CLIENT_ID},
        ))
    return _mcp_result(await _local_call_session_tool(tool_name=tool_name, arguments=arguments, session_id=session_id, client_id=CLIENT_ID))


@mcp.tool(description="High-level address inspection with optional decompile/disasm payloads.", structured_output=False)
async def inspect(
    addr: str,
    session_id: str = "",
    include_decompile: bool = False,
    include_disasm: bool = False,
    include_line_map: bool = False,
    max_instructions: int = 200,
    full: bool = False,
    detail: str = "",
    arguments: Any = None,
) -> mcp_types.CallToolResult:
    payload = _merge_detail_payload(
        arguments,
        full=full,
        detail=detail,
        addr=addr,
        include_decompile=include_decompile,
        include_disasm=include_disasm,
        include_line_map=include_line_map,
        max_instructions=max_instructions,
    )
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(await _daemon_request_async("inspect", {"session_id": session_id, "client_id": CLIENT_ID, "arguments": payload, "addr": addr}))
    return _mcp_result(await _local_call_session_tool("inspect", payload, session_id=session_id, client_id=CLIENT_ID))


@mcp.tool(description="High-level read API for bytes/int/string/struct/array/global.", structured_output=False)
async def read(kind: str, addr: str = "", session_id: str = "", full: bool = False, detail: str = "", arguments: Any = None) -> mcp_types.CallToolResult:
    payload = _merge_detail_payload(arguments, full=full, detail=detail, kind=kind, addr=addr)
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(await _daemon_request_async("read", {"kind": kind, "addr": addr, "full": full, "detail": detail, "arguments": payload, "session_id": session_id, "client_id": CLIENT_ID}))
    return _mcp_result(await _local_call_session_tool("read", payload, session_id=session_id, client_id=CLIENT_ID))


@mcp.tool(description="High-level search API for text/regex/bytes/immediates/instructions.", structured_output=False)
async def search(kind: str, query: str = "", session_id: str = "", full: bool = False, detail: str = "", arguments: Any = None) -> mcp_types.CallToolResult:
    payload = _merge_detail_payload(arguments, full=full, detail=detail, kind=kind, query=query)
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(await _daemon_request_async("search", {"kind": kind, "query": query, "full": full, "detail": detail, "arguments": payload, "session_id": session_id, "client_id": CLIENT_ID}))
    return _mcp_result(await _local_call_session_tool("search", payload, session_id=session_id, client_id=CLIENT_ID))


@mcp.tool(description="High-level xref API for to/from or struct-field lookups.", structured_output=False)
async def xrefs(direction: str = "to", addr: str = "", session_id: str = "", full: bool = False, detail: str = "", arguments: Any = None) -> mcp_types.CallToolResult:
    payload = _merge_detail_payload(arguments, full=full, detail=detail, direction=direction, addr=addr)
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(await _daemon_request_async("xrefs", {"direction": direction, "addr": addr, "full": full, "detail": detail, "arguments": payload, "session_id": session_id, "client_id": CLIENT_ID}))
    return _mcp_result(await _local_call_session_tool("xrefs", payload, session_id=session_id, client_id=CLIENT_ID))


@mcp.tool(description="High-level define API for function/code/type/struct/array/stack/undefine.", structured_output=False)
async def define(kind: str, addr: str = "", session_id: str = "", arguments: Any = None) -> mcp_types.CallToolResult:
    payload = _merge_payload(arguments, kind=kind, addr=addr)
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(await _daemon_request_async("define", {"kind": kind, "addr": addr, "arguments": payload, "session_id": session_id, "client_id": CLIENT_ID}))
    return _mcp_result(await _local_call_session_tool("define", payload, session_id=session_id, client_id=CLIENT_ID))


@mcp.tool(description="Inspect an address and return code/data/function context.", structured_output=False)
async def inspect_addr(addr: str, session_id: str = "") -> mcp_types.CallToolResult:
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(await _daemon_request_async("inspect_addr", {"addr": addr, "session_id": session_id, "client_id": CLIENT_ID}))
    return _mcp_result(await _local_call_session_tool("inspect_addr", {"addr": addr}, session_id=session_id, client_id=CLIENT_ID))


@mcp.tool(description="Resolve a VA, RVA, or symbol and return decompile/disasm/function/inspect context without modifying the database. Use rva for image-relative addresses like 0x1234.", structured_output=False)
async def jump(
    addr: str = "",
    rva: str = "",
    symbol: str = "",
    mode: str = "decompile",
    session_id: str = "",
    max_instructions: int = 400,
    fallback: str = "disasm",
    arguments: Any = None,
) -> mcp_types.CallToolResult:
    payload = _merge_payload_with_defaults(
        arguments,
        {"addr": "", "rva": "", "symbol": "", "mode": "decompile", "max_instructions": 400, "fallback": "disasm"},
        addr=addr,
        rva=rva,
        symbol=symbol,
        mode=mode,
        max_instructions=max_instructions,
        fallback=fallback,
    )
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(await _daemon_request_async("jump", {**payload, "session_id": session_id, "client_id": CLIENT_ID}))
    return _mcp_result(await _local_call_session_tool("jump", payload, session_id=session_id, client_id=CLIENT_ID))


@mcp.tool(description="Read-only function diagnosis for decompile failures, CFG anomalies, orphan blocks, and indirect control flow. This does not deobfuscate; it only reports analysis symptoms.", structured_output=False)
async def diagnose_function(
    addr: str = "",
    rva: str = "",
    symbol: str = "",
    session_id: str = "",
    max_items: int = 200,
    arguments: Any = None,
) -> mcp_types.CallToolResult:
    payload = _merge_payload_with_defaults(
        arguments,
        {"addr": "", "rva": "", "symbol": "", "max_items": 200},
        addr=addr,
        rva=rva,
        symbol=symbol,
        max_items=max_items,
    )
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(await _daemon_request_async("diagnose_function", {**payload, "session_id": session_id, "client_id": CLIENT_ID}))
    return _mcp_result(await _local_call_session_tool("diagnose_function", payload, session_id=session_id, client_id=CLIENT_ID))


@mcp.tool(description="Return the function containing the queried address.", structured_output=False)
async def get_enclosing_function(addr: str, session_id: str = "") -> mcp_types.CallToolResult:
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(await _daemon_request_async("get_enclosing_function", {"addr": addr, "session_id": session_id, "client_id": CLIENT_ID}))
    return _mcp_result(await _local_call_session_tool("get_enclosing_function", {"addr": addr}, session_id=session_id, client_id=CLIENT_ID))


@mcp.tool(description="Read a bounded line window or grep-like match from a large MCP result artifact without returning the full result to the model.", structured_output=False)
def read_artifact(
    artifact_id: str,
    field: str = "",
    pattern: str = "",
    start_line: int = 1,
    line_count: int = 120,
    context_lines: int = 2,
    ignore_case: bool = False,
) -> mcp_types.CallToolResult:
    try:
        _cleanup_artifacts()
        path = _artifact_id_path(artifact_id)
        if not path.exists():
            return _mcp_error_result(f"Artifact not found: {artifact_id}")
        raw = path.read_bytes()
        payload = json.loads(raw.decode("utf-8"))
        selected = _artifact_field(payload, field) if field else payload
        lines = _artifact_lines(selected)
        rows, matches = _artifact_line_window(
            lines,
            start_line=start_line,
            line_count=min(max(1, int(line_count)), 400),
            pattern=pattern,
            context_lines=context_lines,
            ignore_case=ignore_case,
        )
        while len(rows) > 1:
            candidate = {"lines": rows, "matches": matches[:200]}
            if len(_artifact_json_bytes(candidate)) <= MCP_ARTIFACT_READ_BYTES:
                break
            rows = rows[: max(1, len(rows) // 2)]
        result = {
            "ok": True,
            "artifact_id": artifact_id,
            "field": field,
            "pattern": pattern,
            "total_lines": len(lines),
            "match_count": len(matches),
            "matches": matches[:200],
            "lines": rows,
            "eof": bool(rows) and rows[-1]["line"] >= len(lines),
        }
        return _mcp_result(result)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return _mcp_error_result(str(exc))


@mcp.tool(description="Run any backend tool and write the result to a WSL-accessible file path.", structured_output=False)
async def write_session_tool_output(
    path: str,
    tool_name: str,
    arguments: Any = None,
    session_id: str = "",
    output_format: str = "text",
    overwrite: bool = True,
) -> mcp_types.CallToolResult:
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(await _daemon_request_async(
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
        ))
    return _mcp_result(await _local_write_session_tool_output(
        path=path,
        tool_name=tool_name,
        arguments=arguments,
        session_id=session_id,
        output_format=output_format,
        overwrite=overwrite,
        client_id=CLIENT_ID,
    ))


@mcp.tool(description="Decompile a function. Default view=compact returns the signature/body with safe boilerplate local declarations removed. Use view=header for the prototype/declarations, or view=full/detail=full for the exact Hex-Rays text. include_line_map=true returns full text with the raw address map.", structured_output=False)
async def decompile(addr: str, session_id: str = "", full: bool = False, detail: str = "", view: str = "compact", include_line_map: bool = False) -> mcp_types.CallToolResult:
    payload = _merge_detail_payload(None, full=full, detail=detail, addr=addr, view=view, include_line_map=include_line_map)
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(await _daemon_request_async("decompile", {**payload, "session_id": session_id, "client_id": CLIENT_ID}))
    return _mcp_result(await _local_call_session_tool("decompile", payload, session_id=session_id, client_id=CLIENT_ID))


@mcp.tool(description="Export all or filtered functions from the current IDB as one .c file. Prefer this over manually copying per-function decompile output. Can also write a paired .h with include_structs/header_path/struct_names. filter is a simple case-insensitive substring match on function name or 0x address; omit filter for full export and use max_functions to cap size. fallback must be one of: comment, none, disasm, asm.", structured_output=False)
async def export_decompiled_c(
    path: str = "",
    session_id: str = "",
    include_extern: bool = False,
    include_thunks: bool = False,
    filter: str = "",
    fallback: str = "comment",
    max_functions: int = 0,
    return_code: bool = False,
    max_return_bytes: int = 262144,
    include_structs: bool = False,
    header_path: str = "",
    struct_names: list[str] | str | None = None,
) -> mcp_types.CallToolResult:
    payload = {
        "path": path,
        "include_extern": include_extern,
        "include_thunks": include_thunks,
        "filter": filter,
        "fallback": _normalize_export_fallback(fallback),
        "max_functions": max_functions,
        "return_code": return_code,
        "max_return_bytes": max_return_bytes,
        "include_structs": include_structs,
        "header_path": header_path,
        "struct_names": struct_names or [],
    }
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(await _daemon_request_async("export_decompiled_c", {**payload, "session_id": session_id, "client_id": CLIENT_ID}))
    return _mcp_result(await _local_call_session_tool("export_decompiled_c", payload, session_id=session_id, client_id=CLIENT_ID))


@mcp.tool(description="Return pseudocode lines with best-effort disassembly address mapping from the explicit session_id, or from the current selected session when session_id is omitted.", structured_output=False)
async def decompile_line_map(addr: str, session_id: str = "") -> mcp_types.CallToolResult:
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(await _daemon_request_async("decompile_line_map", {"addr": addr, "session_id": session_id, "client_id": CLIENT_ID}))
    return _mcp_result(await _local_call_session_tool("get_decompile_line_map", {"addr": addr}, session_id=session_id, client_id=CLIENT_ID))


@mcp.tool(description="Disassemble the full containing function for an address in the explicit session_id, or in the current selected session when session_id is omitted.", structured_output=False)
async def disasm_function(addr: str, session_id: str = "", max_instructions: int = 4000, full: bool = False, detail: str = "") -> mcp_types.CallToolResult:
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(await _daemon_request_async(
            "disasm_function",
            {"addr": addr, "session_id": session_id, "max_instructions": max_instructions, "full": full, "detail": detail, "client_id": CLIENT_ID},
        ))
    return _mcp_result(await _local_call_session_tool(
        "disasm_function",
        _merge_detail_payload(None, full=full, detail=detail, addr=addr, max_instructions=max_instructions),
        session_id=session_id,
        client_id=CLIENT_ID,
    ))


@mcp.tool(description="Apply a C declaration to a symbol or address like the GUI Y command.", structured_output=False)
async def apply_decl(
    decl: str,
    session_id: str = "",
    addr: str = "",
    symbol: str = "",
    supporting_decls: list[str] | str | None = None,
) -> mcp_types.CallToolResult:
    payload = {"decl": decl, "session_id": session_id, "client_id": CLIENT_ID}
    if addr:
        payload["addr"] = addr
    if symbol:
        payload["symbol"] = symbol
    if supporting_decls:
        payload["supporting_decls"] = supporting_decls
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(await _daemon_request_async("apply_decl", payload))
    return _mcp_result(await _local_call_session_tool("apply_decl", payload, session_id=session_id, client_id=CLIENT_ID))


@mcp.tool(description="Export one or more named structs from the current IDB into a reusable .h file. Defaults to dependency ordering plus forward declarations.", structured_output=False)
async def export_header(
    struct_names: list[str] | str,
    path: str = "",
    session_id: str = "",
    return_header: bool = False,
    include_guard: bool = True,
    auto_order: bool = True,
    forward_decls: bool = True,
) -> mcp_types.CallToolResult:
    payload = {
        "struct_names": struct_names,
        "path": path,
        "session_id": session_id,
        "return_header": return_header,
        "include_guard": include_guard,
        "auto_order": auto_order,
        "forward_decls": forward_decls,
        "client_id": CLIENT_ID,
    }
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(await _daemon_request_async("export_header", payload))
    return _mcp_result(await _local_call_session_tool("export_header", payload, session_id=session_id, client_id=CLIENT_ID))


@mcp.tool(description="Import C declarations from a .h file or raw header text into IDA's type system.", structured_output=False)
async def import_header(
    path: str = "",
    header: str = "",
    session_id: str = "",
) -> mcp_types.CallToolResult:
    payload = {"path": path, "header": header, "session_id": session_id, "client_id": CLIENT_ID}
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(await _daemon_request_async("import_header", payload))
    return _mcp_result(await _local_call_session_tool("import_header", payload, session_id=session_id, client_id=CLIENT_ID))


@mcp.tool(description="Create or reanalyze the function containing an address.", structured_output=False)
async def reanalyze_function(addr: str, session_id: str = "") -> mcp_types.CallToolResult:
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(await _daemon_request_async("reanalyze_function", {"addr": addr, "session_id": session_id, "client_id": CLIENT_ID}))
    return _mcp_result(await _local_call_session_tool("reanalyze_function", {"addr": addr}, session_id=session_id, client_id=CLIENT_ID))


@mcp.tool(description="Explicit IDA analysis repair workflow: optional undefine, define instruction, create function, rename with name/new_name/function_name, apply declaration, set function options, reanalyze, then decompile. Mutates the IDB and participates in txid stale-write checks.", structured_output=False)
async def repair_function_analysis(
    addr: str = "",
    rva: str = "",
    symbol: str = "",
    name: str = "",
    new_name: str = "",
    function_name: str = "",
    session_id: str = "",
    end: str = "",
    end_rva: str = "",
    size: int = 0,
    undefine: bool = False,
    define_code: bool = True,
    make_function: bool = True,
    decl: str = "",
    signature: str = "",
    supporting_decls: list[str] | str | None = None,
    frame_size: str = "",
    saved_regs_size: str = "",
    args_size: str = "",
    purged_bytes: str = "",
    fpd: str = "",
    flags: str = "",
    decompile: bool = True,
    fallback: str = "disasm",
    arguments: Any = None,
) -> mcp_types.CallToolResult:
    payload = _merge_payload_with_defaults(
        arguments,
        {
            "addr": "",
            "rva": "",
            "symbol": "",
            "name": "",
            "new_name": "",
            "function_name": "",
            "end": "",
            "end_rva": "",
            "size": 0,
            "undefine": False,
            "define_code": True,
            "make_function": True,
            "decl": "",
            "signature": "",
            "supporting_decls": None,
            "frame_size": "",
            "saved_regs_size": "",
            "args_size": "",
            "purged_bytes": "",
            "fpd": "",
            "flags": "",
            "decompile": True,
            "fallback": "disasm",
        },
        addr=addr,
        rva=rva,
        symbol=symbol,
        name=name,
        new_name=new_name,
        function_name=function_name,
        end=end,
        end_rva=end_rva,
        size=size,
        undefine=undefine,
        define_code=define_code,
        make_function=make_function,
        decl=decl,
        signature=signature,
        supporting_decls=supporting_decls,
        frame_size=frame_size,
        saved_regs_size=saved_regs_size,
        args_size=args_size,
        purged_bytes=purged_bytes,
        fpd=fpd,
        flags=flags,
        decompile=decompile,
        fallback=fallback,
    )
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(await _daemon_request_async("repair_function_analysis", {**payload, "session_id": session_id, "client_id": CLIENT_ID}))
    return _mcp_result(await _local_call_session_tool("repair_function_analysis", payload, session_id=session_id, client_id=CLIENT_ID))


@mcp.tool(description="Compact bulk workflow for [{addr|rva,name,decl,comment}]: define code/function, rename, apply declaration, comment, and reanalyze. Returns summary only, no decompiled code.", structured_output=False)
async def bulk_recover_and_name(
    items: list[dict[str, Any]],
    session_id: str = "",
    define_code: bool = True,
    make_function: bool = True,
    reanalyze: bool = True,
    apply_comments: bool = True,
    expected_txid: int = -1,
    force: bool = False,
    arguments: Any = None,
) -> mcp_types.CallToolResult:
    payload = _merge_payload_with_defaults(
        arguments,
        {"items": [], "define_code": True, "make_function": True, "reanalyze": True, "apply_comments": True},
        items=items,
        define_code=define_code,
        make_function=make_function,
        reanalyze=reanalyze,
        apply_comments=apply_comments,
    )
    if expected_txid >= 0:
        payload["expected_txid"] = expected_txid
    if force:
        payload["force"] = True
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(await _daemon_request_async("bulk_recover_and_name", {**payload, "session_id": session_id, "client_id": CLIENT_ID}))
    return _mcp_result(await _local_call_session_tool("bulk_recover_and_name", payload, session_id=session_id, client_id=CLIENT_ID))


@mcp.tool(description="Set function bounds or selected IDA function attributes such as frame_size, saved_regs_size, args_size/purged_bytes, fpd, or numeric flags. Mutates the IDB.", structured_output=False)
async def set_function_options(
    addr: str = "",
    rva: str = "",
    symbol: str = "",
    session_id: str = "",
    end: str = "",
    end_rva: str = "",
    create: bool = False,
    frame_size: str = "",
    saved_regs_size: str = "",
    args_size: str = "",
    purged_bytes: str = "",
    fpd: str = "",
    flags: str = "",
    reanalyze: bool = True,
    arguments: Any = None,
) -> mcp_types.CallToolResult:
    payload = _merge_payload_with_defaults(
        arguments,
        {
            "addr": "",
            "rva": "",
            "symbol": "",
            "end": "",
            "end_rva": "",
            "create": False,
            "frame_size": "",
            "saved_regs_size": "",
            "args_size": "",
            "purged_bytes": "",
            "fpd": "",
            "flags": "",
            "reanalyze": True,
        },
        addr=addr,
        rva=rva,
        symbol=symbol,
        end=end,
        end_rva=end_rva,
        create=create,
        frame_size=frame_size,
        saved_regs_size=saved_regs_size,
        args_size=args_size,
        purged_bytes=purged_bytes,
        fpd=fpd,
        flags=flags,
        reanalyze=reanalyze,
    )
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(await _daemon_request_async("set_function_options", {**payload, "session_id": session_id, "client_id": CLIENT_ID}))
    return _mcp_result(await _local_call_session_tool("set_function_options", payload, session_id=session_id, client_id=CLIENT_ID))


@mcp.tool(description="Set a user stack-pointer delta at an instruction when IDA exposes the API. Use only for explicit SP-depth repair after inspecting disassembly. Mutates the IDB.", structured_output=False)
async def set_sp_delta(
    delta: int = 0,
    addr: str = "",
    rva: str = "",
    symbol: str = "",
    session_id: str = "",
    reanalyze: bool = True,
    arguments: Any = None,
) -> mcp_types.CallToolResult:
    payload = _merge_payload_with_defaults(
        arguments,
        {"addr": "", "rva": "", "symbol": "", "delta": 0, "reanalyze": True},
        addr=addr,
        rva=rva,
        symbol=symbol,
        delta=delta,
        reanalyze=reanalyze,
    )
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(await _daemon_request_async("set_sp_delta", {**payload, "session_id": session_id, "client_id": CLIENT_ID}))
    return _mcp_result(await _local_call_session_tool("set_sp_delta", payload, session_id=session_id, client_id=CLIENT_ID))


@mcp.tool(description="Patch bytes at a VA/RVA/symbol. dry_run defaults to true and returns original/patched bytes without changing txid; set dry_run=false to mutate the IDB.", structured_output=False)
async def patch_bytes(
    bytes: str = "",
    data: str = "",
    addr: str = "",
    rva: str = "",
    symbol: str = "",
    session_id: str = "",
    dry_run: bool = True,
    reanalyze: bool = True,
    max_bytes: int = 4096,
    expected_txid: int = -1,
    force: bool = False,
    arguments: Any = None,
) -> mcp_types.CallToolResult:
    byte_text = bytes or data
    payload = _merge_payload_with_defaults(
        arguments,
        {"addr": "", "rva": "", "symbol": "", "bytes": "", "dry_run": True, "reanalyze": True, "max_bytes": 4096},
        addr=addr,
        rva=rva,
        symbol=symbol,
        bytes=byte_text,
        dry_run=dry_run,
        reanalyze=reanalyze,
        max_bytes=max_bytes,
    )
    if expected_txid >= 0:
        payload["expected_txid"] = expected_txid
    if force:
        payload["force"] = True
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(await _daemon_request_async("patch_bytes", {**payload, "session_id": session_id, "client_id": CLIENT_ID}))
    return _mcp_result(await _local_call_session_tool("patch_bytes", payload, session_id=session_id, client_id=CLIENT_ID))


@mcp.tool(description="Revert a patch by restoring bytes from patch_bytes.original/original_bytes. dry_run defaults to false because this tool is explicitly for rollback.", structured_output=False)
async def revert_patch(
    original: str = "",
    addr: str = "",
    rva: str = "",
    symbol: str = "",
    session_id: str = "",
    dry_run: bool = False,
    reanalyze: bool = True,
    max_bytes: int = 4096,
    expected_txid: int = -1,
    force: bool = False,
    arguments: Any = None,
) -> mcp_types.CallToolResult:
    payload = _merge_payload_with_defaults(
        arguments,
        {"addr": "", "rva": "", "symbol": "", "original": "", "dry_run": False, "reanalyze": True, "max_bytes": 4096},
        addr=addr,
        rva=rva,
        symbol=symbol,
        original=original,
        dry_run=dry_run,
        reanalyze=reanalyze,
        max_bytes=max_bytes,
    )
    if expected_txid >= 0:
        payload["expected_txid"] = expected_txid
    if force:
        payload["force"] = True
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(await _daemon_request_async("revert_patch", {**payload, "session_id": session_id, "client_id": CLIENT_ID}))
    return _mcp_result(await _local_call_session_tool("revert_patch", payload, session_id=session_id, client_id=CLIENT_ID))


@mcp.tool(description="NOP a VA/RVA/symbol range. dry_run defaults to true; pass size or end/end_rva. Set dry_run=false to mutate the IDB.", structured_output=False)
async def nop_range(
    addr: str = "",
    rva: str = "",
    symbol: str = "",
    session_id: str = "",
    size: int = 0,
    end: str = "",
    end_rva: str = "",
    nop_byte: int = 0x90,
    dry_run: bool = True,
    reanalyze: bool = True,
    max_bytes: int = 4096,
    expected_txid: int = -1,
    force: bool = False,
    arguments: Any = None,
) -> mcp_types.CallToolResult:
    payload = _merge_payload_with_defaults(
        arguments,
        {
            "addr": "",
            "rva": "",
            "symbol": "",
            "size": 0,
            "end": "",
            "end_rva": "",
            "nop_byte": 0x90,
            "dry_run": True,
            "reanalyze": True,
            "max_bytes": 4096,
        },
        addr=addr,
        rva=rva,
        symbol=symbol,
        size=size,
        end=end,
        end_rva=end_rva,
        nop_byte=nop_byte,
        dry_run=dry_run,
        reanalyze=reanalyze,
        max_bytes=max_bytes,
    )
    if expected_txid >= 0:
        payload["expected_txid"] = expected_txid
    if force:
        payload["force"] = True
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(await _daemon_request_async("nop_range", {**payload, "session_id": session_id, "client_id": CLIENT_ID}))
    return _mcp_result(await _local_call_session_tool("nop_range", payload, session_id=session_id, client_id=CLIENT_ID))


@mcp.tool(description="Lookup one or more functions by name, VA, or RVA. Bare hex values are checked as VA and image-base-relative RVA.", structured_output=False)
async def lookup_funcs(queries: list[str] | str, session_id: str = "") -> mcp_types.CallToolResult:
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(await _daemon_request_async("lookup_funcs", {"queries": queries, "session_id": session_id, "client_id": CLIENT_ID}))
    return _mcp_result(await _local_call_session_tool("lookup_funcs", {"queries": queries}, session_id=session_id, client_id=CLIENT_ID))


@mcp.tool(description="Find xrefs to one or more addresses in the explicit session_id, or in the current selected session when session_id is omitted.", structured_output=False)
async def xrefs_to(addrs: list[str] | str, limit: int = 100, session_id: str = "") -> mcp_types.CallToolResult:
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(await _daemon_request_async(
            "xrefs_to",
            {"addrs": addrs, "limit": limit, "session_id": session_id, "client_id": CLIENT_ID},
        ))
    return _mcp_result(await _local_call_session_tool("xrefs_to", {"addrs": addrs, "limit": limit}, session_id=session_id, client_id=CLIENT_ID))


@mcp.tool(description="Rename functions, globals, local variables, or stack variables in the explicit session_id, or in the current selected session when session_id is omitted.", structured_output=False)
async def rename(batch: dict[str, Any], session_id: str = "", expected_txid: int = -1, force: bool = False) -> mcp_types.CallToolResult:
    payload = {"batch": batch}
    if expected_txid >= 0:
        payload["expected_txid"] = expected_txid
    if force:
        payload["force"] = True
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(await _daemon_request_async("rename", {**payload, "session_id": session_id, "client_id": CLIENT_ID}))
    return _mcp_result(await _local_call_session_tool("rename", payload, session_id=session_id, client_id=CLIENT_ID))


@mcp.tool(description="Set comments in the explicit session_id, or in the current selected session when session_id is omitted.", structured_output=False)
async def set_comments(items: dict[str, Any] | list[dict[str, Any]], session_id: str = "") -> mcp_types.CallToolResult:
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(await _daemon_request_async("set_comments", {"items": items, "session_id": session_id, "client_id": CLIENT_ID}))
    return _mcp_result(await _local_call_session_tool("set_comments", {"items": items}, session_id=session_id, client_id=CLIENT_ID))


def _run_daemon() -> None:
    stop_maintenance = threading.Event()

    def maintenance_loop() -> None:
        while not stop_maintenance.wait(CLIENT_LEASE_SWEEP_INTERVAL_SEC):
            result = _sweep_stale_clients()
            if result["stale_client_ids"] or result["auto_close_errors"]:
                _daemon_debug(f"client lease sweep result={result}")
            prune_result = _auto_prune_headless_sessions()
            if prune_result.get("closed_count") or prune_result.get("skipped_count"):
                _daemon_debug(f"auto prune result={prune_result}")

    maintenance_thread = threading.Thread(target=maintenance_loop, name="ida-hybrid-manager-client-lease", daemon=True)
    maintenance_thread.start()
    manager_api = ManagerApiServer(
        registry=registry,
        host=DAEMON_HOST,
        port=DAEMON_PORT,
        api_version=DAEMON_API_VERSION,
        build_token=DAEMON_BUILD_TOKEN,
        op_dispatcher=_dispatch_operation,
        session_registered_callback=_on_session_registered,
    )
    manager_api.start()
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        stop_maintenance.set()
        manager_api.stop()
        maintenance_thread.join(timeout=2.0)


def main() -> None:
    global ACTIVE_BACKEND, CLIENT_ID

    parser = argparse.ArgumentParser(description="Run the IDA Hybrid Manager MCP server")
    parser.add_argument("--transport", default="streamable-http", choices=["stdio", "streamable-http", "sse", "daemon"])
    parser.add_argument("--profile", default=os.getenv("IDA_MCP_PROFILE", "full"), choices=["full", "lite"], help="Model-facing MCP tool profile (default: full)")
    args = parser.parse_args()
    _cleanup_artifacts(force=True)

    if args.transport == "daemon":
        ACTIVE_BACKEND = "local"
        _capture_tool_schemas()
        _run_daemon()
        return

    if args.transport == "stdio":
        ACTIVE_BACKEND = "daemon"
        _apply_mcp_profile(args.profile)
        _stdio_debug("stdio main start")
        _ensure_shared_daemon()
        _stdio_debug("shared daemon ready")
        _connect_stdio_client("stdio_start")
        try:
            anyio.run(_run_stdio_server)
        finally:
            _disconnect_stdio_client("stdio_shutdown")
        return

    ACTIVE_BACKEND = "local"
    _apply_mcp_profile(args.profile)
    manager_api = ManagerApiServer(
        registry=registry,
        host=DAEMON_HOST,
        port=DAEMON_PORT,
        build_token=DAEMON_BUILD_TOKEN,
        op_dispatcher=_dispatch_operation,
        session_registered_callback=_on_session_registered,
    )
    manager_api.start()
    try:
        mcp.run(args.transport)
    finally:
        manager_api.stop()


if __name__ == "__main__":
    main()
