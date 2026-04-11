from __future__ import annotations

import argparse
import asyncio
from contextlib import AsyncExitStack
import fcntl
import hashlib
from io import TextIOWrapper
import json
import os
import shutil
import socket
import subprocess
import sys
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
from mcp.server.fastmcp import FastMCP
from mcp.server.session import ServerSession
from mcp.shared.message import SessionMessage
from mcp.shared.session import RequestResponder

from .backend import BackendUnavailableError, call_backend_tool_any, list_backend_tools_any
from .launch import IdaLauncher
from .manager_api import ManagerApiServer
from .models import PendingLaunch, utc_now
from .pathing import normalize_path
from .registry import SessionRegistry


DAEMON_HOST = "127.0.0.1"
DAEMON_PORT = 18080
DAEMON_API_VERSION = 4
DAEMON_URL = f"http://{DAEMON_HOST}:{DAEMON_PORT}"
DAEMON_LOCK_PATH = Path("/tmp/ida-hybrid-manager-daemon.lock")
DAEMON_LOG_PATH = Path("/tmp/ida-hybrid-manager-daemon.log")
STDIO_DEBUG_PATH = Path("/tmp/ida-hybrid-manager-stdio.log")
DAEMON_BUILD_FILES = (
    Path(__file__).resolve(),
    Path(__file__).with_name("launch.py"),
    Path(__file__).with_name("registry.py"),
    Path(__file__).with_name("models.py"),
    Path(__file__).with_name("backend.py"),
    Path(__file__).with_name("manager_api.py"),
)

registry = SessionRegistry()
ACTIVE_BACKEND = "local"
CLIENT_ID: str | None = None
_client_lock = threading.RLock()
_client_current_sessions: dict[str, str | None] = {}
_launcher: IdaLauncher | None = None
_open_binary_lock = threading.RLock()
MUTATING_BACKEND_TOOLS = {
    "apply_decl",
    "apply_struct",
    "apply_struct_to_many",
    "create_struct",
    "create_padded_struct_from_map",
    "declare_stack",
    "declare_type",
    "define",
    "define_code",
    "define_func",
    "delete_stack",
    "make_array",
    "reanalyze_function",
    "rename",
    "save_database",
    "set_comments",
    "set_type",
    "type_workflow",
    "undefine",
    "upsert_struct",
}

mcp = FastMCP(
    "IDA Hybrid Manager",
    instructions="Manage and route live IDA GUI or manager-owned headless sessions.",
    host="0.0.0.0",
    port=18081,
)


def _stdio_debug(message: str) -> None:
    if not os.getenv("IDA_HYBRID_STDIO_DEBUG"):
        return
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        with STDIO_DEBUG_PATH.open("a", encoding="utf-8") as handle:
            handle.write(f"[{timestamp}] {message}\n")
    except Exception:
        pass


def _daemon_debug(message: str) -> None:
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        with DAEMON_LOG_PATH.open("a", encoding="utf-8") as handle:
            handle.write(f"[{timestamp}] {message}\n")
    except Exception:
        pass


def _get_launcher() -> IdaLauncher:
    global _launcher
    if _launcher is None:
        _launcher = IdaLauncher()
    return _launcher


def _compute_daemon_build_token() -> str:
    digest = hashlib.sha256()
    for path in DAEMON_BUILD_FILES:
        try:
            digest.update(path.read_bytes())
        except OSError:
            digest.update(str(path).encode("utf-8"))
    return digest.hexdigest()[:16]


DAEMON_BUILD_TOKEN = _compute_daemon_build_token()
STDIO_IDLE_TIMEOUT_SEC = max(0, int(os.getenv("IDA_MCP_STDIO_IDLE_TIMEOUT_SEC", "600") or 0))
STDIO_PING_TIMEOUT_SEC = max(1.0, float(os.getenv("IDA_MCP_STDIO_PING_TIMEOUT_SEC", "10") or 10.0))
STDIO_IDLE_CHECK_INTERVAL_SEC = max(5.0, min(60.0, float(os.getenv("IDA_MCP_STDIO_IDLE_CHECK_INTERVAL_SEC", "30") or 30.0)))


async def _run_stdio_server() -> None:
    _stdio_debug("stdio bootstrap start")
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
        except Exception as exc:
            _stdio_debug(f"stdin_reader exception: {exc!r}")
            _stdio_debug(traceback.format_exc())
            raise
        finally:
            _stdio_debug("stdin_reader stop")

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
            if STDIO_IDLE_TIMEOUT_SEC <= 0:
                return
            while True:
                await anyio.sleep(STDIO_IDLE_CHECK_INTERVAL_SEC)
                if active_requests > 0:
                    continue
                if session.client_params is None:
                    continue
                idle_for = time.monotonic() - last_activity_at
                if idle_for < STDIO_IDLE_TIMEOUT_SEC:
                    continue
                _stdio_debug(f"idle heartbeat start idle_sec={idle_for:.1f}")
                try:
                    with anyio.fail_after(STDIO_PING_TIMEOUT_SEC):
                        await session.send_ping()
                    last_activity_at = time.monotonic()
                    _stdio_debug("idle heartbeat ok")
                except Exception as exc:
                    _stdio_debug(f"idle heartbeat failed: {exc!r}")
                    raise

        async with anyio.create_task_group() as tg:
            tg.start_soon(stdin_reader)
            tg.start_soon(stdout_writer)
            tg.start_soon(idle_monitor)
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


def _client_connect(client_name: str = "", client_pid: int | None = None) -> dict[str, Any]:
    client_id = f"client-{uuid.uuid4().hex[:12]}"
    with _client_lock:
        _client_current_sessions[client_id] = None
    return {"client_id": client_id, "client_name": client_name, "client_pid": client_pid}


def _client_disconnect(client_id: str | None) -> dict[str, Any]:
    detached_session_id = None
    with _client_lock:
        if client_id:
            detached_session_id = _client_current_sessions.pop(client_id, None)
    detached_records = registry.detach_client(client_id)
    auto_closed: list[str] = []
    auto_close_errors: list[dict[str, Any]] = []
    for record in detached_records:
        if record.status == "dead":
            continue
        if record.engine != "headless" or record.source != "manager_created" or not record.closable:
            continue
        closable, error = registry.begin_close(record.session_id)
        if error is not None or closable is None:
            continue
        try:
            _terminate_session_record(closable, save=True, reason="last_client_detached")
        except Exception as exc:
            registry.cancel_close(record.session_id)
            auto_close_errors.append({"session_id": record.session_id, "error": str(exc)})
            continue
        auto_closed.append(record.session_id)
    return {
        "ok": True,
        "client_id": client_id,
        "detached_session_id": detached_session_id,
        "auto_closed_session_ids": auto_closed,
        "auto_close_errors": auto_close_errors,
    }


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
        registry.unregister(record.session_id, "backend_unreachable")
        _client_clear_session_references(record.session_id)


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


def _persist_staged_idb(record: Any) -> dict[str, Any]:
    staged_idb = _session_staged_idb_path(record)
    persistent_idb = _session_persistent_idb_target(record)
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


def _augment_session_meta(result: dict[str, Any], record, *, client_id: str | None = None, warning: str = "") -> dict[str, Any]:
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
        structured = payload.get("structuredContent")
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
            if "ok" in item:
                saw_status = True
                if bool(item.get("ok")):
                    return True
            elif "ok_count" in item:
                saw_status = True
                if int(item.get("ok_count") or 0) > 0:
                    return True
        return not saw_status
    return False


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
                    lock_file.write(json.dumps({"url": DAEMON_URL, "started_at": time.time(), "build_token": DAEMON_BUILD_TOKEN}) + "\n")
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
    client_id: str | None = None,
) -> dict[str, Any]:
    with _open_binary_lock:
        _sweep_unreachable_sessions()
        normalized = normalize_path(path)
        candidate_paths = {normalized.input_path, normalized.windows_path, normalized.wsl_path}
        if remove_previous_idb:
            reuse = False
        candidate_hash = _compute_input_binary_hash(normalized) if reuse else ""
        removed_idb = _remove_adjacent_idb(normalized) if remove_previous_idb else None
        _daemon_debug(
            "open_binary start "
            f"path={path!r} mode={mode} reuse={reuse} remove_previous_idb={remove_previous_idb} client_id={client_id}"
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
            if matches:
                _daemon_debug(f"open_binary reuse-hit session_id={matches[0].session_id}")
                attached = registry.attach_client(matches[0].session_id, client_id, refresh_snapshot=True) or matches[0]
                _client_set_current_session(client_id, matches[0].session_id)
                return {
                    "ok": True,
                    "session_id": attached.session_id,
                    "engine": attached.engine,
                    "status": attached.status,
                    "revision": _session_revision_payload(attached, client_id),
                    "selected": True,
                    "reused": True,
                    "remove_previous_idb": False,
                    "removed_previous_idb": None,
                    **_session_idb_status(attached),
                }

        if mode == "gui":
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
            registry.register_pending_launch(pending)
            _daemon_debug(f"open_binary launched gui launch_token={pending.launch_token} pid={pending.pid}")
            record = _wait_for_session(pending)
            if record is None:
                _daemon_debug(f"open_binary wait timeout launch_token={pending.launch_token}")
                return {
                    "ok": False,
                    "error": f"Timed out waiting for {pending.engine} session",
                    "pending": pending.to_dict(),
                    "environment": environment,
                }
        else:
            launcher = _get_launcher()
            attempts = max(1, int(os.getenv("IDA_HEADLESS_LAUNCH_ATTEMPTS", "3")))
            last_failure: dict[str, Any] | None = None
            record = None
            pending = None
            for attempt in range(1, attempts + 1):
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

                registry.register_pending_launch(pending)
                _daemon_debug(
                    "open_binary launched headless "
                    f"launch_token={pending.launch_token} pid={pending.pid} port={pending.port} attempt={attempt}/{attempts}"
                )
                record = _wait_for_session(pending)
                if record is None:
                    _daemon_debug(
                        "open_binary wait timeout "
                        f"launch_token={pending.launch_token} attempt={attempt}/{attempts}"
                    )
                    if pending.pid is not None:
                        try:
                            launcher.terminate_process(pending.pid)
                        except Exception:
                            pass
                    last_failure = {
                        "ok": False,
                        "error": f"Timed out waiting for {pending.engine} session",
                        "pending": pending.to_dict(),
                        "environment": launcher.inspect_environment(),
                        "logs": _pending_log_summary(pending),
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
                if _backend_ready(record):
                    break

                _daemon_debug(f"open_binary backend_unreachable session_id={record.session_id} attempt={attempt}/{attempts}")
                if record.closable and record.owner_pid is not None:
                    try:
                        _get_launcher().terminate_process(record.owner_pid)
                    except Exception:
                        pass
                    registry.unregister(record.session_id, "backend_unreachable")
                last_failure = {
                    "ok": False,
                    "error": f"{record.engine} session registered but backend was unreachable",
                    "session_id": record.session_id,
                    "endpoint_candidates": _backend_candidates(record),
                    "environment": _get_launcher().inspect_environment(),
                    "logs": _pending_log_summary(pending),
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
        if mode == "gui" and not _backend_ready(record):
            _daemon_debug(f"open_binary backend_unreachable session_id={record.session_id}")
            if record.closable and record.owner_pid is not None:
                try:
                    _get_launcher().terminate_process(record.owner_pid)
                except Exception:
                    pass
                registry.unregister(record.session_id, "backend_unreachable")
            return {
                "ok": False,
                "error": f"{record.engine} session registered but backend was unreachable",
                "session_id": record.session_id,
                "endpoint_candidates": _backend_candidates(record),
                "environment": _get_launcher().inspect_environment(),
                "logs": _pending_log_summary(pending) if record.engine == "headless" else {},
            }
        if record.engine == "headless":
            try:
                _daemon_debug(f"open_binary wait_for_autoanalysis start session_id={record.session_id}")
                analysis_result = asyncio.run(
                    call_backend_tool_any(
                        _backend_candidates(record),
                        "wait_for_autoanalysis",
                        {"timeout_sec": float(os.getenv("IDA_AUTOANALYSIS_TIMEOUT_SEC", "120"))},
                        timeout_sec=float(os.getenv("IDA_AUTOANALYSIS_TIMEOUT_SEC", "120")) + 10.0,
                    )
                )
                _daemon_debug(
                    "open_binary wait_for_autoanalysis done "
                    f"session_id={record.session_id} result={analysis_result.get('structuredContent', analysis_result)}"
                )
            except Exception:
                _daemon_debug(f"open_binary wait_for_autoanalysis failed session_id={record.session_id}")
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
                status="ready",
                capabilities=capabilities,
                owner_pid=listener_pid or record.owner_pid,
                metadata=pending.metadata if pending is not None else None,
            )
        _daemon_debug(f"open_binary done session_id={record.session_id}")
        attached = registry.attach_client(record.session_id, client_id, refresh_snapshot=True) or record
        _client_set_current_session(client_id, record.session_id)
        return {
            "ok": True,
            "session_id": attached.session_id,
            "engine": attached.engine,
            "status": "ready",
            "revision": _session_revision_payload(attached, client_id),
            "selected": True,
            "reused": False,
            "remove_previous_idb": remove_previous_idb,
            "removed_previous_idb": removed_idb,
            **_session_idb_status(attached),
        }


def _local_load_idb(
    path: str,
    mode: str = "headless",
    reuse: bool = True,
    client_id: str | None = None,
) -> dict[str, Any]:
    with _open_binary_lock:
        _sweep_unreachable_sessions()
        normalized = normalize_path(path)
        if not str(normalized.wsl_path).lower().endswith(".i64"):
            return {"ok": False, "error": "load_idb expects a .i64 path"}
        candidate_paths = {normalized.input_path, normalized.windows_path, normalized.wsl_path}
        _daemon_debug(
            "load_idb start "
            f"path={path!r} mode={mode} reuse={reuse} client_id={client_id}"
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
            if matches:
                _daemon_debug(f"load_idb reuse-hit session_id={matches[0].session_id}")
                attached = registry.attach_client(matches[0].session_id, client_id, refresh_snapshot=True) or matches[0]
                _client_set_current_session(client_id, matches[0].session_id)
                return {
                    "ok": True,
                    "session_id": attached.session_id,
                    "engine": attached.engine,
                    "status": attached.status,
                    "revision": _session_revision_payload(attached, client_id),
                    "selected": True,
                    "reused": True,
                    **_session_idb_status(attached),
                }

        launcher = _get_launcher()
        if mode == "gui":
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
            registry.register_pending_launch(pending)
            _daemon_debug(f"load_idb launched gui launch_token={pending.launch_token} pid={pending.pid}")
            record = _wait_for_session(pending)
            if record is None:
                _daemon_debug(f"load_idb wait timeout launch_token={pending.launch_token}")
                return {
                    "ok": False,
                    "error": f"Timed out waiting for {pending.engine} session",
                    "pending": pending.to_dict(),
                    "environment": environment,
                }
        else:
            attempts = max(1, int(os.getenv("IDA_HEADLESS_LAUNCH_ATTEMPTS", "3")))
            last_failure: dict[str, Any] | None = None
            record = None
            pending = None
            for attempt in range(1, attempts + 1):
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

                registry.register_pending_launch(pending)
                _daemon_debug(
                    "load_idb launched headless "
                    f"launch_token={pending.launch_token} pid={pending.pid} port={pending.port} attempt={attempt}/{attempts}"
                )
                record = _wait_for_session(pending)
                if record is None:
                    _daemon_debug(
                        "load_idb wait timeout "
                        f"launch_token={pending.launch_token} attempt={attempt}/{attempts}"
                    )
                    if pending.pid is not None:
                        try:
                            launcher.terminate_process(pending.pid)
                        except Exception:
                            pass
                    last_failure = {
                        "ok": False,
                        "error": f"Timed out waiting for {pending.engine} session",
                        "pending": pending.to_dict(),
                        "environment": launcher.inspect_environment(),
                        "logs": _pending_log_summary(pending),
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
                if _backend_ready(record):
                    break

                _daemon_debug(f"load_idb backend_unreachable session_id={record.session_id} attempt={attempt}/{attempts}")
                if record.closable and record.owner_pid is not None:
                    try:
                        _get_launcher().terminate_process(record.owner_pid)
                    except Exception:
                        pass
                    registry.unregister(record.session_id, "backend_unreachable")
                last_failure = {
                    "ok": False,
                    "error": f"{record.engine} session registered but backend was unreachable",
                    "session_id": record.session_id,
                    "endpoint_candidates": _backend_candidates(record),
                    "environment": _get_launcher().inspect_environment(),
                    "logs": _pending_log_summary(pending),
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
        if mode == "gui" and not _backend_ready(record):
            _daemon_debug(f"load_idb backend_unreachable session_id={record.session_id}")
            if record.closable and record.owner_pid is not None:
                try:
                    _get_launcher().terminate_process(record.owner_pid)
                except Exception:
                    pass
                registry.unregister(record.session_id, "backend_unreachable")
            return {
                "ok": False,
                "error": f"{record.engine} session registered but backend was unreachable",
                "session_id": record.session_id,
                "endpoint_candidates": _backend_candidates(record),
                "environment": _get_launcher().inspect_environment(),
                "logs": _pending_log_summary(pending) if record.engine == "headless" else {},
            }
        if record.engine == "headless":
            try:
                _daemon_debug(f"load_idb wait_for_autoanalysis start session_id={record.session_id}")
                analysis_result = asyncio.run(
                    call_backend_tool_any(
                        _backend_candidates(record),
                        "wait_for_autoanalysis",
                        {"timeout_sec": float(os.getenv("IDA_AUTOANALYSIS_TIMEOUT_SEC", "120"))},
                        timeout_sec=float(os.getenv("IDA_AUTOANALYSIS_TIMEOUT_SEC", "120")) + 10.0,
                    )
                )
                _daemon_debug(
                    "load_idb wait_for_autoanalysis done "
                    f"session_id={record.session_id} result={analysis_result.get('structuredContent', analysis_result)}"
                )
            except Exception:
                _daemon_debug(f"load_idb wait_for_autoanalysis failed session_id={record.session_id}")
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
                status="ready",
                capabilities=capabilities,
                owner_pid=listener_pid or record.owner_pid,
                metadata=pending.metadata if pending is not None else None,
            )
        _daemon_debug(f"load_idb done session_id={record.session_id}")
        attached = registry.attach_client(record.session_id, client_id, refresh_snapshot=True) or record
        _client_set_current_session(client_id, record.session_id)
        return {
            "ok": True,
            "session_id": attached.session_id,
            "engine": attached.engine,
            "status": "ready",
            "revision": _session_revision_payload(attached, client_id),
            "selected": True,
            "reused": False,
            **_session_idb_status(attached),
        }


def _terminate_session_record(record, *, save: bool, reason: str) -> dict[str, Any]:
    if save and "save_database" in record.capabilities:
        asyncio.run(call_backend_tool_any(_backend_candidates(record), "save_database", {}))
    if record.owner_pid is not None:
        _get_launcher().terminate_process(record.owner_pid)
    cleanup = {}
    if save:
        cleanup["idb_persist"] = _persist_staged_idb(record)
    staged_dir = str(record.metadata.get("staged_dir") or "")
    if staged_dir:
        cleanup["staged_dir"] = staged_dir
        cleanup["deleted"] = _get_launcher().cleanup_staged_dir(staged_dir)
    registry.unregister(record.session_id, reason)
    _client_clear_session_references(record.session_id)
    return {"ok": True, "closed_session_id": record.session_id, "cleanup": cleanup}


def _local_close_session(session_id: str, save: bool = True, force: bool = False, client_id: str | None = None) -> dict[str, Any]:
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
        return _terminate_session_record(closable, save=save, reason="manager_close")
    except Exception as exc:
        registry.cancel_close(session_id)
        return {"ok": False, "error": "close_session_failed", "detail": str(exc), "session_id": session_id}


async def _local_list_session_tools(session_id: str = "", client_id: str | None = None) -> dict[str, Any]:
    record = _current_or_explicit(session_id or None, client_id=client_id)
    with registry.track_operation(record.session_id):
        with record.write_lock:
            latest = registry.get_session(record.session_id)
            if latest is None:
                raise ValueError(f"Unknown session: {record.session_id}")
            result = await list_backend_tools_any(_backend_candidates(latest))
            touched = registry.touch_client(latest.session_id, client_id) or latest
            if isinstance(result, dict):
                return _augment_session_meta(dict(result), touched, client_id=client_id)
            return result


async def _local_call_session_tool(tool_name: str, arguments: Any = None, session_id: str = "", client_id: str | None = None) -> dict[str, Any]:
    record = _current_or_explicit(session_id or None, client_id=client_id)
    with registry.track_operation(record.session_id):
        payload = _normalize_tool_arguments(tool_name, arguments)
        attachment = registry.get_client_attachment(record.session_id, client_id) or {}
        expected_txid = payload.get("expected_txid")
        force_write = bool(payload.get("force", False))
        warning = ""
        backend_payload = dict(payload)
        backend_payload.pop("expected_txid", None)
        backend_payload.pop("force", None)
        with record.write_lock:
            latest = registry.get_session(record.session_id)
            if latest is None:
                raise ValueError(f"Unknown session: {record.session_id}")
            if tool_name in MUTATING_BACKEND_TOOLS:
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
                try:
                    result = await call_backend_tool_any(_backend_candidates(latest), tool_name, backend_payload)
                except BackendUnavailableError:
                    if latest.engine == "headless" and latest.source == "manager_created":
                        registry.unregister(latest.session_id, "backend_unreachable")
                        _client_clear_session_references(latest.session_id)
                    raise
                if not _backend_mutation_changed_db(result):
                    touched = registry.touch_client(latest.session_id, client_id) or latest
                    return _augment_session_meta(result, touched, client_id=client_id, warning=warning)
                updated = registry.bump_txid(latest.session_id, client_id, tool_name) or latest
                return _augment_session_meta(result, updated, client_id=client_id, warning=warning)
            try:
                result = await call_backend_tool_any(_backend_candidates(latest), tool_name, backend_payload)
                touched = registry.touch_client(latest.session_id, client_id) or latest
                return _augment_session_meta(result, touched, client_id=client_id)
            except BackendUnavailableError:
                if latest.engine == "headless" and latest.source == "manager_created":
                    registry.unregister(latest.session_id, "backend_unreachable")
                    _client_clear_session_references(latest.session_id)
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
    op_map = {
        "connect_client": lambda **kwargs: _client_connect(**kwargs),
        "disconnect_client": lambda **kwargs: _client_disconnect(kwargs.get("client_id")),
        "inspect_environment": lambda **kwargs: _local_inspect_environment(),
        "list_alive_sessions": lambda **kwargs: _local_list_alive_sessions(client_id=client_id),
        "current_session": lambda **kwargs: _local_current_session(client_id=client_id),
        "select_session": lambda **kwargs: _local_select_session(kwargs["session_id"], client_id=client_id),
        "attach_to_gui": lambda **kwargs: _local_attach_to_gui(kwargs.get("binary_name", ""), kwargs.get("binary_path", ""), client_id=client_id),
        "open_binary": lambda **kwargs: _local_open_binary(
            kwargs["path"],
            kwargs.get("mode", "auto"),
            kwargs.get("reuse", True),
            kwargs.get("remove_previous_idb", False),
            client_id=client_id,
        ),
        "load_idb": lambda **kwargs: _local_load_idb(
            kwargs["path"],
            kwargs.get("mode", "headless"),
            kwargs.get("reuse", True),
            client_id=client_id,
        ),
        "close_session": lambda **kwargs: _local_close_session(kwargs["session_id"], kwargs.get("save", True), kwargs.get("force", False), client_id=client_id),
        "list_session_tools": lambda **kwargs: _local_list_session_tools(kwargs.get("session_id", ""), client_id=client_id),
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
        "get_enclosing_function": lambda **kwargs: _local_call_session_tool("get_enclosing_function", {"addr": kwargs["addr"]}, kwargs.get("session_id", ""), client_id=client_id),
        "decompile": lambda **kwargs: _local_call_session_tool(
            "decompile",
            _merge_detail_payload(None, full=bool(kwargs.get("full", False)), detail=str(kwargs.get("detail", "")), addr=kwargs["addr"]),
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
        "reanalyze_function": lambda **kwargs: _local_call_session_tool("reanalyze_function", {"addr": kwargs["addr"]}, kwargs.get("session_id", ""), client_id=client_id),
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


@mcp.tool(description="Open a binary in headless mode, GUI mode, or auto mode and select the resulting session. By default this reuses an existing live session when possible and reuses an adjacent .i64 when launching fresh. Set remove_previous_idb=true to force a fresh launch without reusing the adjacent .i64.", structured_output=False)
def open_binary(path: str, mode: str = "auto", reuse: bool = True, remove_previous_idb: bool = False) -> mcp_types.CallToolResult:
    if str(path or "").strip().lower().endswith(".i64"):
        return _mcp_error_result("open_binary expects the original binary path. Use load_idb() to open an existing .i64 database.")
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(_daemon_request_sync(
            "open_binary",
            {"path": path, "mode": mode, "reuse": reuse, "remove_previous_idb": remove_previous_idb, "client_id": CLIENT_ID},
        ))
    return _mcp_result(_local_open_binary(
        path=path,
        mode=mode,
        reuse=reuse,
        remove_previous_idb=remove_previous_idb,
        client_id=CLIENT_ID,
    ))


@mcp.tool(description="Load an existing .i64 database in headless or GUI mode and select the resulting session.", structured_output=False)
def load_idb(path: str, mode: str = "headless", reuse: bool = True) -> mcp_types.CallToolResult:
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(_daemon_request_sync(
            "load_idb",
            {"path": path, "mode": mode, "reuse": reuse, "client_id": CLIENT_ID},
        ))
    return _mcp_result(_local_load_idb(
        path=path,
        mode=mode,
        reuse=reuse,
        client_id=CLIENT_ID,
    ))


@mcp.tool(description="Close a manager-owned headless session.", structured_output=False)
def close_session(session_id: str, save: bool = True, force: bool = False) -> mcp_types.CallToolResult:
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(_daemon_request_sync("close_session", {"session_id": session_id, "save": save, "force": force, "client_id": CLIENT_ID}))
    return _mcp_result(_local_close_session(session_id=session_id, save=save, force=force, client_id=CLIENT_ID))


@mcp.tool(description="List backend tools exposed by the explicit session_id, or by the current selected session when session_id is omitted.", structured_output=False)
async def list_session_tools(session_id: str = "") -> mcp_types.CallToolResult:
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(await _daemon_request_async("list_session_tools", {"session_id": session_id, "client_id": CLIENT_ID}))
    return _mcp_result(await _local_list_session_tools(session_id=session_id, client_id=CLIENT_ID))


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


@mcp.tool(description="Return the function containing the queried address.", structured_output=False)
async def get_enclosing_function(addr: str, session_id: str = "") -> mcp_types.CallToolResult:
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(await _daemon_request_async("get_enclosing_function", {"addr": addr, "session_id": session_id, "client_id": CLIENT_ID}))
    return _mcp_result(await _local_call_session_tool("get_enclosing_function", {"addr": addr}, session_id=session_id, client_id=CLIENT_ID))


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


@mcp.tool(description="Decompile a function in the explicit session_id, or in the current selected session when session_id is omitted.", structured_output=False)
async def decompile(addr: str, session_id: str = "", full: bool = False, detail: str = "") -> mcp_types.CallToolResult:
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(await _daemon_request_async("decompile", {"addr": addr, "full": full, "detail": detail, "session_id": session_id, "client_id": CLIENT_ID}))
    return _mcp_result(await _local_call_session_tool("decompile", _merge_detail_payload(None, full=full, detail=detail, addr=addr), session_id=session_id, client_id=CLIENT_ID))


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


@mcp.tool(description="Create or reanalyze the function containing an address.", structured_output=False)
async def reanalyze_function(addr: str, session_id: str = "") -> mcp_types.CallToolResult:
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(await _daemon_request_async("reanalyze_function", {"addr": addr, "session_id": session_id, "client_id": CLIENT_ID}))
    return _mcp_result(await _local_call_session_tool("reanalyze_function", {"addr": addr}, session_id=session_id, client_id=CLIENT_ID))


@mcp.tool(description="Lookup one or more functions in the explicit session_id, or in the current selected session when session_id is omitted.", structured_output=False)
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
async def rename(batch: dict[str, Any], session_id: str = "") -> mcp_types.CallToolResult:
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(await _daemon_request_async("rename", {"batch": batch, "session_id": session_id, "client_id": CLIENT_ID}))
    return _mcp_result(await _local_call_session_tool("rename", {"batch": batch}, session_id=session_id, client_id=CLIENT_ID))


@mcp.tool(description="Set comments in the explicit session_id, or in the current selected session when session_id is omitted.", structured_output=False)
async def set_comments(items: dict[str, Any] | list[dict[str, Any]], session_id: str = "") -> mcp_types.CallToolResult:
    if ACTIVE_BACKEND == "daemon":
        return _mcp_result(await _daemon_request_async("set_comments", {"items": items, "session_id": session_id, "client_id": CLIENT_ID}))
    return _mcp_result(await _local_call_session_tool("set_comments", {"items": items}, session_id=session_id, client_id=CLIENT_ID))


def _run_daemon() -> None:
    manager_api = ManagerApiServer(
        registry=registry,
        host=DAEMON_HOST,
        port=DAEMON_PORT,
        api_version=DAEMON_API_VERSION,
        build_token=DAEMON_BUILD_TOKEN,
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
        _stdio_debug("stdio main start")
        _ensure_shared_daemon()
        _stdio_debug("shared daemon ready")
        connect_info = _daemon_request_sync(
            "connect_client",
            {
                "client_name": os.getenv("CODEX_AGENT_NAME", "codex-stdio"),
                "client_pid": os.getpid(),
            },
        )
        CLIENT_ID = connect_info.get("client_id")
        _stdio_debug(f"connect_client ok client_id={CLIENT_ID}")
        try:
            anyio.run(_run_stdio_server)
        finally:
            if CLIENT_ID:
                try:
                    _daemon_request_sync("disconnect_client", {"client_id": CLIENT_ID})
                except Exception as exc:
                    _stdio_debug(f"disconnect_client failed: {exc!r}")
        return

    ACTIVE_BACKEND = "local"
    manager_api = ManagerApiServer(
        registry=registry,
        host=DAEMON_HOST,
        port=DAEMON_PORT,
        build_token=DAEMON_BUILD_TOKEN,
        op_dispatcher=_dispatch_operation,
    )
    manager_api.start()
    try:
        mcp.run(args.transport)
    finally:
        manager_api.stop()


if __name__ == "__main__":
    main()
