from __future__ import annotations

import argparse
import socket
import time
from typing import Any
from urllib.parse import urlsplit

from mcp.server.fastmcp import FastMCP

from .backend import call_backend_tool_any, list_backend_tools_any
from .launch import IdaLauncher
from .manager_api import ManagerApiServer
from .models import PendingLaunch
from .pathing import normalize_path
from .registry import SessionRegistry


registry = SessionRegistry()
launcher = IdaLauncher()
manager_api = ManagerApiServer(registry=registry, host="0.0.0.0", port=18080)


def manager_url() -> str:
    return "http://127.0.0.1:18080"

mcp = FastMCP(
    "IDA Hybrid Manager",
    instructions="Manage and route live IDA GUI or manager-owned headless sessions.",
    host="0.0.0.0",
    port=18081,
)


def _serialize_sessions(records) -> list[dict[str, Any]]:
    return [record.to_dict() for record in records]


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


def _current_or_explicit(session_id: str | None):
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


def _attach_managed_headless(pending: PendingLaunch):
    display_name = pending.binary_path.rsplit("\\", 1)[-1]
    return registry.register_managed_session(
        engine="headless",
        display_name=display_name,
        binary_path=pending.binary_path,
        idb_path=pending.idb_path,
        owner_pid=pending.pid,
        endpoint_url=f"http://127.0.0.1:13337/mcp",
    )


@mcp.tool(description="List alive IDA sessions discovered by the manager.")
def list_alive_sessions() -> dict[str, Any]:
    return {"sessions": _serialize_sessions(registry.list_sessions(include_dead=False))}


@mcp.tool(description="Return the currently selected IDA session.")
def current_session() -> dict[str, Any]:
    record = registry.get_session(None)
    return {"session": record.to_dict() if record else None}


@mcp.tool(description="Select an alive IDA session by its session_id.")
def select_session(session_id: str) -> dict[str, Any]:
    record = registry.select_session(session_id)
    if record is None:
        return {"ok": False, "error": f"Unknown session: {session_id}"}
    return {"ok": True, "current_session_id": record.session_id}


@mcp.tool(description="Attach to an already-open GUI IDA session, optionally filtering by binary name or path.")
def attach_to_gui(binary_name: str = "", binary_path: str = "") -> dict[str, Any]:
    normalized_path = normalize_path(binary_path).windows_path if binary_path else ""
    matches = registry.find_candidates(engine="gui", binary_name=binary_name or None, binary_path=normalized_path or None)
    if len(matches) == 1:
        registry.select_session(matches[0].session_id)
        return {
            "matches": _serialize_sessions(matches),
            "auto_selected": True,
            "current_session_id": matches[0].session_id,
        }
    return {"matches": _serialize_sessions(matches), "auto_selected": False}


@mcp.tool(description="Open a binary in headless mode, GUI mode, or auto mode and select the resulting session.")
def open_binary(path: str, mode: str = "auto", reuse: bool = True) -> dict[str, Any]:
    normalized = normalize_path(path)
    if reuse:
        preferred_engine = None if mode == "auto" else mode
        matches = registry.find_candidates(engine=preferred_engine, binary_path=normalized.windows_path)
        if matches:
            registry.select_session(matches[0].session_id)
            return {
                "ok": True,
                "session_id": matches[0].session_id,
                "engine": matches[0].engine,
                "status": matches[0].status,
                "selected": True,
                "reused": True,
            }

    if mode == "gui":
        pending = launcher.launch_gui(normalized.windows_path)
        registry.register_pending_launch(pending)
        record = _wait_for_session(pending)
        if record is None:
            return {"ok": False, "error": f"Timed out waiting for {pending.engine} session", "pending": pending.to_dict()}
    else:
        pending = launcher.launch_headless(normalized.windows_path, manager_url())
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
            import asyncio

            tools_info = asyncio.run(list_backend_tools_any(_backend_candidates(record)))
            capabilities = [tool.get("name") for tool in tools_info.get("tools", []) if tool.get("name")]
        except Exception:
            capabilities = []
        registry.update_managed_session(record.session_id, status="ready", capabilities=capabilities)
    return {
        "ok": True,
        "session_id": record.session_id,
        "engine": record.engine,
        "status": "ready",
        "selected": True,
        "reused": False,
    }


@mcp.tool(description="Close a manager-owned headless session.")
def close_session(session_id: str, save: bool = True) -> dict[str, Any]:
    record = registry.get_session(session_id)
    if record is None:
        return {"ok": False, "error": f"Unknown session: {session_id}"}
    if not record.closable:
        return {"ok": False, "error": "GUI sessions are attach-only in v1 and are not closed by the manager"}
    if save and "save_database" in record.capabilities:
        import asyncio

        asyncio.run(call_backend_tool_any(_backend_candidates(record), "save_database", {}))
    if record.owner_pid is not None:
        launcher.terminate_process(record.owner_pid)
    registry.unregister(record.session_id, "manager_close")
    return {"ok": True, "closed_session_id": record.session_id}


@mcp.tool(description="List backend tools exposed by the selected or explicit session.")
async def list_session_tools(session_id: str = "") -> dict[str, Any]:
    record = _current_or_explicit(session_id or None)
    return await list_backend_tools_any(_backend_candidates(record))


@mcp.tool(description="Call any backend MCP tool on the selected or explicit session.")
async def call_session_tool(tool_name: str, arguments: dict[str, Any] | None = None, session_id: str = "") -> dict[str, Any]:
    record = _current_or_explicit(session_id or None)
    return await call_backend_tool_any(_backend_candidates(record), tool_name, arguments or {})


@mcp.tool(description="Decompile a function in the selected session.")
async def decompile(addr: str, session_id: str = "") -> dict[str, Any]:
    return await call_session_tool("decompile", {"addr": addr}, session_id=session_id)


@mcp.tool(description="Lookup one or more functions in the selected session.")
async def lookup_funcs(queries: list[str] | str, session_id: str = "") -> dict[str, Any]:
    return await call_session_tool("lookup_funcs", {"queries": queries}, session_id=session_id)


@mcp.tool(description="Find xrefs to one or more addresses in the selected session.")
async def xrefs_to(addrs: list[str] | str, limit: int = 100, session_id: str = "") -> dict[str, Any]:
    return await call_session_tool("xrefs_to", {"addrs": addrs, "limit": limit}, session_id=session_id)


@mcp.tool(description="Rename functions, globals, locals, or stack variables in the selected session.")
async def rename(batch: dict[str, Any], session_id: str = "") -> dict[str, Any]:
    return await call_session_tool("rename", {"batch": batch}, session_id=session_id)


@mcp.tool(description="Set comments in the selected session.")
async def set_comments(items: dict[str, Any] | list[dict[str, Any]], session_id: str = "") -> dict[str, Any]:
    return await call_session_tool("set_comments", {"items": items}, session_id=session_id)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the IDA Hybrid Manager MCP server")
    parser.add_argument("--transport", default="streamable-http", choices=["stdio", "streamable-http", "sse"])
    args = parser.parse_args()
    manager_api.start()
    try:
        mcp.run(args.transport)
    finally:
        manager_api.stop()


if __name__ == "__main__":
    main()
