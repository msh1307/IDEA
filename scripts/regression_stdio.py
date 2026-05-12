#!/usr/bin/env python3

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sys
import time
from typing import Any

import anyio
from ida_hybrid_manager.networking import discover_windows_host
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


DEFAULT_TARGET = "/mnt/c/Windows/System32/notepad.exe"
REQUIRED_MANAGER_TOOLS = {
    "inspect",
    "read",
    "search",
    "xrefs",
    "define",
    "lookup_funcs",
    "get_enclosing_function",
    "inspect_addr",
    "disasm_function",
    "list_session_tools",
    "call_session_tool",
    "open_binary",
    "load_idb",
    "close_session",
    "export_decompiled_c",
}

REQUIRED_BACKEND_TOOLS = {
    "declare_type",
    "define_code",
    "undefine",
    "list_functions",
    "list_strings",
    "imports",
    "export_decompiled_c",
}


class RegressionFailure(RuntimeError):
    pass


def _json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2)


def _outer_structured(payload: dict[str, Any]) -> Any:
    return payload.get("structuredContent")


def _content_text(payload: dict[str, Any]) -> str:
    chunks: list[str] = []
    for item in payload.get("content") or []:
        if isinstance(item, dict) and item.get("type") == "text":
            chunks.append(str(item.get("text") or ""))
    return "\n".join(chunk for chunk in chunks if chunk).strip()


def _inner_structured(payload: dict[str, Any]) -> Any:
    structured = payload.get("structuredContent")
    if isinstance(structured, dict) and "structuredContent" in structured:
        structured = structured["structuredContent"]
    if isinstance(structured, dict) and "result" in structured and len(structured) == 1:
        return structured["result"]
    return structured


def _outer_meta(payload: dict[str, Any]) -> dict[str, Any]:
    meta = payload.get("meta")
    if isinstance(meta, dict):
        return meta
    return {}


def _meta_revision(meta: dict[str, Any]) -> dict[str, Any]:
    revision = meta.get("revision")
    return revision if isinstance(revision, dict) else {}


def _meta_txid(meta: dict[str, Any]) -> int:
    revision = _meta_revision(meta)
    return int(revision.get("txid") or 0)


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise RegressionFailure(message)


def _first(items: list[dict[str, Any]], message: str) -> dict[str, Any]:
    if not items:
        raise RegressionFailure(message)
    return items[0]


def _pick_function(functions: list[dict[str, Any]]) -> dict[str, Any]:
    for item in functions:
        if item.get("segment", "").lower() != "extern":
            return item
    raise RegressionFailure("No non-extern function available")


def _pick_local_name_from_code(code: str) -> str:
    patterns = [
        r"\b(v\d+)\b",
        r"\b(a\d+)\b",
        r"\b(result)\b",
    ]
    for pattern in patterns:
        match = re.search(pattern, code)
        if match:
            return match.group(1)
    raise RegressionFailure("No renameable local variable candidate found in decompiled code")


def _pick_string(strings: list[dict[str, Any]]) -> dict[str, Any]:
    for item in strings:
        value = str(item.get("value") or "")
        if len(value.strip()) >= 6:
            return item
    raise RegressionFailure("No usable string available")


def _slice_query(text: str) -> str:
    value = text.strip()
    if len(value) < 4:
        raise RegressionFailure("String too short to build a text-search query")
    return value[: min(len(value), 12)]


def _hex_to_int(value: str) -> int:
    return int(str(value), 16)


def _normalize_test_path(path: str) -> str:
    text = str(path or "").strip()
    match = re.match(r"^(?P<drive>[a-zA-Z]):\\(?P<rest>.*)$", text)
    if match:
        rest = match.group("rest").replace("\\", "/")
        return f"/mnt/{match.group('drive').lower()}/{rest}"
    return text


async def call_tool(session: ClientSession, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    result = await session.call_tool(name, arguments)
    payload = result.model_dump(mode="json")
    if payload.get("isError"):
        raise RegressionFailure(f"{name} failed: {_json(payload)}")
    return payload


async def main(target: str) -> int:
    idb_target = os.getenv("IDA_REGRESSION_IDB_TARGET", "").strip()
    connect_host = os.getenv("IDA_MCP_CONNECT_HOST", "").strip() or discover_windows_host()
    params = StdioServerParameters(
        command=os.path.join(os.getcwd(), ".venv/bin/python"),
        args=["-m", "ida_hybrid_manager.server", "--transport", "stdio"],
        cwd=os.getcwd(),
        env={"IDA_MCP_CONNECT_HOST": connect_host},
    )

    session_id = ""

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            started = time.perf_counter()
            init = await session.initialize()
            print(f"INIT {time.perf_counter() - started:.2f}s {init.serverInfo.name}")

            tools = await session.list_tools()
            tool_names = {tool.name for tool in tools.tools}
            missing = sorted(REQUIRED_MANAGER_TOOLS - tool_names)
            _assert(not missing, f"Missing manager tools: {missing}")
            print(f"TOOLS ok count={len(tool_names)}")

            misuse_resp = (await session.call_tool("open_binary", {"path": "/tmp/example.i64", "mode": "headless"})).model_dump(mode="json")
            misuse_data = _outer_structured(misuse_resp) or {}
            _assert(misuse_resp.get("isError") is True, f"open_binary(.i64) should be an MCP error: {_json(misuse_resp)}")
            _assert(misuse_data.get("ok") is False and "load_idb" in str(misuse_data.get("error") or ""), f"open_binary(.i64) error payload unexpected: {_json(misuse_resp)}")
            print("OPEN misuse error ok")

            opened = await call_tool(session, "open_binary", {"path": target, "mode": "headless", "reuse": False})
            open_data = _outer_structured(opened) or {}
            open_text = _content_text(opened)
            open_meta = _outer_meta(opened)
            _assert(open_data.get("ok") is True, f"open_binary failed: {_json(open_data)}")
            session_id = str(open_data.get("session_id") or "")
            _assert(session_id, "open_binary did not return a session_id")
            _assert(open_meta.get("content_mode") == "summary", f"open_binary missing summary mode: {_json(opened)}")
            _assert(open_text and len(open_text) < 120 and "{" not in open_text, f"open_binary content is not a short summary: {_json(opened)}")
            open_revision = open_data.get("revision") or {}
            _assert(int(open_revision.get("txid") or 0) == 0, f"open_binary revision mismatch: {_json(open_data)}")
            _assert(int(open_revision.get("snapshot_txid") or 0) == int(open_revision.get("txid") or 0), f"open_binary snapshot mismatch: {_json(open_data)}")
            for field in ("txid", "snapshot_txid", "requires_refresh", "attached_client_count", "last_writer_client_id"):
                _assert(field not in open_data, f"open_binary leaked flat revision field {field}: {_json(open_data)}")
            print(f"OPEN ok session_id={session_id}")

            observer_stale_txid = int(open_revision.get("txid") or 0)
            try:
                async with stdio_client(params) as (read2, write2):
                    async with ClientSession(read2, write2) as observer:
                        observer_init = await observer.initialize()
                        print(f"OBSERVER init ok {observer_init.serverInfo.name}")
                        observer_select = await call_tool(observer, "select_session", {"session_id": session_id})
                        observer_select_data = _outer_structured(observer_select) or {}
                        _assert(observer_select_data.get("ok") is True, f"observer select_session failed: {_json(observer_select_data)}")
                        observer_select_revision = observer_select_data.get("revision") or {}
                        _assert(int(observer_select_revision.get("txid") or 0) == observer_stale_txid, f"observer select revision mismatch: {_json(observer_select_data)}")
                        observer_current = await call_tool(observer, "current_session", {})
                        observer_current_data = _outer_structured(observer_current) or {}
                        observer_session = observer_current_data.get("session") or {}
                        _assert(observer_session.get("session_id") == session_id, f"observer current_session mismatch: {_json(observer_current_data)}")
                        observer_revision = observer_session.get("revision") or {}
                        _assert(int(observer_revision.get("txid") or 0) == observer_stale_txid, f"observer revision mismatch: {_json(observer_current_data)}")
                        observer_stale_txid = int(observer_revision.get("txid") or observer_stale_txid)
                        print(f"OBSERVER attach ok txid={observer_stale_txid}")

                        session_tools = await call_tool(session, "list_session_tools", {"session_id": session_id})
                        backend_tools = _inner_structured(session_tools) or {}
                        exposed = {item.get("name") for item in backend_tools.get("tools", []) if isinstance(item, dict)}
                        missing_backend = sorted(REQUIRED_BACKEND_TOOLS - exposed)
                        _assert(not missing_backend, f"Missing backend tools: {missing_backend}")
                        print(f"SESSION_TOOLS ok count={len(exposed)}")

                        metadata_resp = await call_tool(
                            session,
                            "call_session_tool",
                            {"session_id": session_id, "tool_name": "get_metadata", "arguments": {}},
                        )
                        metadata = _inner_structured(metadata_resp) or {}
                        image_base = str(metadata.get("image_base") or "")
                        _assert(image_base.startswith("0x"), f"Unexpected metadata: {_json(metadata)}")
                        print(f"METADATA ok image_base={image_base}")

                        functions_resp = await call_tool(
                            session,
                            "call_session_tool",
                            {"session_id": session_id, "tool_name": "list_functions", "arguments": {"count": 32}},
                        )
                        functions = _inner_structured(functions_resp) or {}
                        function_items = functions.get("items") or []
                        func = _pick_function(function_items)
                        func_addr = str(func.get("address") or "")
                        func_name = str(func.get("name") or "")
                        print(f"FUNCTION ok {func_name} @ {func_addr}")

                        decompile_preview_resp = await call_tool(session, "decompile", {"session_id": session_id, "addr": func_addr})
                        decompile_preview = _outer_structured(decompile_preview_resp) or {}
                        decompile_preview_meta = _outer_meta(decompile_preview_resp)
                        decompile_preview_text = _content_text(decompile_preview_resp)
                        preview_code = str(decompile_preview.get("code") or "")
                        _assert(decompile_preview_meta.get("content_mode") == "summary", f"decompile missing summary mode: {_json(decompile_preview_resp)}")
                        _assert(decompile_preview.get("mode") == "decompile" and preview_code, f"decompile missing code payload: {_json(decompile_preview)}")
                        _assert(
                            decompile_preview_text.startswith("decompile ") and len(decompile_preview_text) < min(len(preview_code), 160),
                            f"decompile content is not slim summary text: {_json(decompile_preview_resp)}",
                        )
                        _assert("session_txid" not in decompile_preview_meta, f"decompile leaked legacy flat meta: {_json(decompile_preview_meta)}")
                        print("DECOMPILE envelope ok")

                        decompile_full_resp = await call_tool(session, "decompile", {"session_id": session_id, "addr": func_addr, "detail": "full"})
                        decompile_full = _inner_structured(decompile_full_resp) or {}
                        _assert(isinstance(decompile_full.get("line_map"), dict), f"decompile(detail=full) missing line_map: {_json(decompile_full)}")
                        print("DECOMPILE full ok")

                        lookup_resp = await call_tool(session, "lookup_funcs", {"session_id": session_id, "queries": [func_name]})
                        lookup_outer = _outer_structured(lookup_resp) or {}
                        _assert(isinstance(lookup_outer, dict) and isinstance(lookup_outer.get("result"), list), f"lookup_funcs should wrap list payloads under structuredContent.result: {_json(lookup_resp)}")
                        lookup = _inner_structured(lookup_resp) or []
                        first_lookup = _first(lookup, "lookup_funcs returned no rows")
                        lookup_matches = first_lookup.get("matches") or []
                        _assert(lookup_matches, f"lookup_funcs failed for {func_name}")
                        print(f"LOOKUP ok matches={len(lookup_matches)}")

                        inspect_resp = await call_tool(
                            session,
                            "inspect",
                            {"session_id": session_id, "addr": func_addr, "include_disasm": True, "max_instructions": 16},
                        )
                        inspect_payload = _inner_structured(inspect_resp) or {}
                        disasm_payload = inspect_payload.get("disasm") or {}
                        instructions = disasm_payload.get("instructions") or []
                        _assert(instructions, f"inspect returned no disassembly: {_json(inspect_payload)}")
                        print(f"INSPECT ok instructions={len(instructions)}")

                        inspect_full_resp = await call_tool(session, "inspect", {"session_id": session_id, "addr": func_addr, "detail": "full", "max_instructions": 12})
                        inspect_full = _inner_structured(inspect_full_resp) or {}
                        _assert(isinstance(inspect_full.get("decompile"), dict), f"inspect(detail=full) missing decompile payload: {_json(inspect_full)}")
                        _assert(isinstance(inspect_full.get("disasm"), dict), f"inspect(detail=full) missing disasm payload: {_json(inspect_full)}")
                        _assert(isinstance(inspect_full.get("line_map"), dict), f"inspect(detail=full) missing line_map payload: {_json(inspect_full)}")
                        print("INSPECT full ok")

                        enclosing_resp = await call_tool(session, "get_enclosing_function", {"session_id": session_id, "addr": func_addr})
                        enclosing = _inner_structured(enclosing_resp) or {}
                        _assert(enclosing.get("found") is True, f"get_enclosing_function failed: {_json(enclosing)}")
                        print("ENCLOSING ok")

                        disasm_func_resp = await call_tool(
                            session,
                            "disasm_function",
                            {"session_id": session_id, "addr": func_addr, "max_instructions": 32},
                        )
                        disasm_func = _inner_structured(disasm_func_resp) or {}
                        func_instructions = disasm_func.get("instructions") or []
                        _assert(len(func_instructions) >= 2, "disasm_function did not return enough instructions")
                        print(f"DISASM_FUNCTION ok instructions={len(func_instructions)}")

                        strings_resp = await call_tool(
                            session,
                            "call_session_tool",
                            {"session_id": session_id, "tool_name": "list_strings", "arguments": {"count": 64}},
                        )
                        strings = _inner_structured(strings_resp) or {}
                        string_item = _pick_string(strings.get("items") or [])
                        string_addr = str(string_item.get("address") or "")
                        string_value = str(string_item.get("value") or "")
                        _assert("length" not in string_item and "type" not in string_item, f"list_strings default is not slim: {_json(string_item)}")
                        _assert((strings.get("count") or 0) == len(strings.get("items") or []), f"list_strings count mismatch: {_json(strings)}")
                        print(f"STRING ok {string_addr} value={string_value[:32]!r}")

                        strings_full_resp = await call_tool(
                            session,
                            "call_session_tool",
                            {"session_id": session_id, "tool_name": "list_strings", "arguments": {"count": 8, "full": True}},
                        )
                        strings_full = _inner_structured(strings_full_resp) or {}
                        string_full_item = _pick_string(strings_full.get("items") or [])
                        _assert("length" in string_full_item and "type" in string_full_item, f"list_strings full missing metadata: {_json(string_full_item)}")
                        print("LIST_STRINGS full ok")

                        read_string_resp = await call_tool(session, "read", {"session_id": session_id, "kind": "string", "addr": string_addr})
                        read_string = _inner_structured(read_string_resp) or []
                        first_string = _first(read_string, "read(string) returned no rows")
                        _assert(first_string.get("value"), f"read(string) returned empty value: {_json(read_string)}")
                        print("READ string ok")

                        read_bytes_resp = await call_tool(
                            session,
                            "read",
                            {"session_id": session_id, "kind": "bytes", "addr": image_base, "arguments": {"size": 8}},
                        )
                        read_bytes = _inner_structured(read_bytes_resp) or {}
                        _assert(str(read_bytes.get("hex") or "").lower().startswith("4d5a"), f"read(bytes) unexpected: {_json(read_bytes)}")
                        print("READ bytes ok")

                        read_int_resp = await call_tool(
                            session,
                            "read",
                            {"session_id": session_id, "kind": "int", "addr": image_base, "arguments": {"ty": "u16"}},
                        )
                        read_int = _inner_structured(read_int_resp) or []
                        first_int = _first(read_int, "read(int) returned no rows")
                        _assert(int(first_int.get("value") or 0) == 0x5A4D, f"read(int) unexpected: {_json(read_int)}")
                        print("READ int ok")

                        search_text_resp = await call_tool(
                            session,
                            "search",
                            {
                                "session_id": session_id,
                                "kind": "text",
                                "query": _slice_query(string_value),
                                "arguments": {"kinds": ["strings"], "limit": 5},
                            },
                        )
                        search_text = _inner_structured(search_text_resp) or {}
                        _assert((search_text.get("count") or 0) >= 1, f"search(text) returned nothing: {_json(search_text)}")
                        first_search_item = _first(search_text.get("items") or [], "search(text) returned no items")
                        _assert("segment" not in first_search_item and "name" not in first_search_item, f"search(text) default is not slim: {_json(first_search_item)}")
                        print("SEARCH text ok")

                        search_text_full_resp = await call_tool(
                            session,
                            "search",
                            {
                                "session_id": session_id,
                                "kind": "text",
                                "query": _slice_query(string_value),
                                "arguments": {"kinds": ["strings"], "limit": 5, "full": True},
                            },
                        )
                        search_text_full = _inner_structured(search_text_full_resp) or {}
                        first_search_full_item = _first(search_text_full.get("items") or [], "search(text, full) returned no items")
                        _assert("segment" in first_search_full_item and "name" in first_search_full_item, f"search(text, full) missing metadata: {_json(first_search_full_item)}")
                        print("SEARCH text full ok")

                        search_text_detail_resp = await call_tool(
                            session,
                            "search",
                            {
                                "session_id": session_id,
                                "kind": "text",
                                "query": _slice_query(string_value),
                                "detail": "full",
                                "arguments": {"kinds": ["strings"], "limit": 5},
                            },
                        )
                        search_text_detail = _inner_structured(search_text_detail_resp) or {}
                        first_search_detail_item = _first(search_text_detail.get("items") or [], "search(text, detail=full) returned no items")
                        _assert("segment" in first_search_detail_item and "name" in first_search_detail_item, f"search(text, detail=full) missing metadata: {_json(first_search_detail_item)}")
                        print("SEARCH detail full ok")

                        regex_pattern = re.escape(_slice_query(string_value))
                        search_regex_resp = await call_tool(
                            session,
                            "search",
                            {"session_id": session_id, "kind": "regex", "query": regex_pattern, "arguments": {"limit": 5}},
                        )
                        search_regex = _inner_structured(search_regex_resp) or {}
                        _assert("count" in search_regex and search_regex.get("count", 0) >= 1, f"search(regex) missing count or matches: {_json(search_regex)}")
                        first_regex_item = _first(search_regex.get("matches") or [], "search(regex) returned no items")
                        _assert("segment" not in first_regex_item and "name" not in first_regex_item, f"search(regex) default is not slim: {_json(first_regex_item)}")
                        print("SEARCH regex ok")

                        search_regex_full_resp = await call_tool(
                            session,
                            "search",
                            {"session_id": session_id, "kind": "regex", "query": regex_pattern, "arguments": {"limit": 5, "full": True}},
                        )
                        search_regex_full = _inner_structured(search_regex_full_resp) or {}
                        first_regex_full_item = _first(search_regex_full.get("matches") or [], "search(regex, full) returned no items")
                        _assert("segment" in first_regex_full_item and "name" in first_regex_full_item, f"search(regex, full) missing metadata: {_json(first_regex_full_item)}")
                        print("SEARCH regex full ok")

                        search_bytes_resp = await call_tool(
                            session,
                            "search",
                            {"session_id": session_id, "kind": "bytes", "query": "4D 5A", "arguments": {"limit": 1}},
                        )
                        search_bytes = _inner_structured(search_bytes_resp) or []
                        first_pattern = _first(search_bytes, "search(bytes) returned no rows")
                        matches = first_pattern.get("matches") or []
                        _assert(matches, f"search(bytes) returned no matches: {_json(search_bytes)}")
                        _assert("segment" not in matches[0] and "name" not in matches[0], f"search(bytes) default is not slim: {_json(matches[0])}")
                        print("SEARCH bytes ok")

                        search_bytes_full_resp = await call_tool(
                            session,
                            "search",
                            {"session_id": session_id, "kind": "bytes", "query": "4D 5A", "arguments": {"limit": 1, "full": True}},
                        )
                        search_bytes_full = _inner_structured(search_bytes_full_resp) or []
                        first_pattern_full = _first(search_bytes_full, "search(bytes, full) returned no rows")
                        first_byte_full_match = _first(first_pattern_full.get("matches") or [], "search(bytes, full) returned no matches")
                        _assert("segment" in first_byte_full_match and "name" in first_byte_full_match, f"search(bytes, full) missing metadata: {_json(first_byte_full_match)}")
                        print("SEARCH bytes full ok")

                        imports_resp = await call_tool(
                            session,
                            "call_session_tool",
                            {"session_id": session_id, "tool_name": "imports", "arguments": {"count": 16}},
                        )
                        imports_data = _inner_structured(imports_resp) or {}
                        import_item = _first(imports_data.get("items") or [], "imports returned no rows")
                        import_addr = str(import_item.get("address") or "")
                        xrefs_resp = await call_tool(
                            session,
                            "xrefs",
                            {"session_id": session_id, "direction": "to", "addr": import_addr, "arguments": {"limit": 16}},
                        )
                        xrefs_data = _inner_structured(xrefs_resp) or {}
                        _assert("items" in xrefs_data, f"xrefs(to) unexpected: {_json(xrefs_data)}")
                        print(f"XREFS ok import={import_item.get('imported_name')}")

                        declare_type_resp = await call_tool(
                            session,
                            "define",
                            {"session_id": session_id, "kind": "type", "arguments": {"decl": "typedef unsigned __int64 regression_u64;"}},
                        )
                        declare_type_outer = _outer_structured(declare_type_resp) or {}
                        _assert(isinstance(declare_type_outer, dict) and isinstance(declare_type_outer.get("result"), list), f"define(type) should wrap list payloads under structuredContent.result: {_json(declare_type_resp)}")
                        declare_type = _inner_structured(declare_type_resp) or []
                        first_decl = _first(declare_type, "define(type decl) returned no rows")
                        _assert(first_decl.get("ok") is True, f"define(type decl) failed: {_json(declare_type)}")
                        declare_meta = _outer_meta(declare_type_resp)
                        _assert(isinstance(declare_meta.get("revision"), dict), f"define(type) missing revision meta: {_json(declare_meta)}")
                        _assert("session_txid" not in declare_meta, f"define(type) leaked legacy flat revision meta: {_json(declare_meta)}")
                        current_txid = _meta_txid(declare_meta)
                        _assert(current_txid > observer_stale_txid, f"txid did not advance after mutation: {_json(declare_meta)}")
                        print(f"DEFINE type ok txid={current_txid}")

                        apply_decl_resp = await call_tool(
                            session,
                            "call_session_tool",
                            {
                                "session_id": session_id,
                                "tool_name": "apply_decl",
                                "arguments": {
                                    "addr": func_addr,
                                    "decl": "regression_apply_u64 __fastcall regression_apply_fn(regression_apply_u64 a1);",
                                    "supporting_decls": ["typedef unsigned __int64 regression_apply_u64;"],
                                },
                            },
                        )
                        apply_decl_data = _inner_structured(apply_decl_resp) or {}
                        _assert(apply_decl_data.get("ok") is True, f"apply_decl with supporting_decls failed: {_json(apply_decl_data)}")
                        supporting_decl_rows = apply_decl_data.get("supporting_decls") or []
                        first_supporting_decl = _first(supporting_decl_rows, f"apply_decl missing supporting declarations: {_json(apply_decl_data)}")
                        _assert(first_supporting_decl.get("ok") is True, f"apply_decl supporting declaration failed: {_json(apply_decl_data)}")
                        apply_decl_meta = _outer_meta(apply_decl_resp)
                        current_txid = _meta_txid(apply_decl_meta) or current_txid
                        print("APPLY_DECL supporting_decls ok")

                        observer_stale_state_resp = await call_tool(observer, "current_session", {})
                        observer_stale_state = _outer_structured(observer_stale_state_resp) or {}
                        observer_stale_session = observer_stale_state.get("session") or {}
                        observer_stale_revision = observer_stale_session.get("revision") or {}
                        _assert(observer_stale_revision.get("requires_refresh") is True, f"observer session did not report stale snapshot: {_json(observer_stale_state)}")
                        _assert(int(observer_stale_revision.get("snapshot_txid") or 0) == observer_stale_txid, f"observer snapshot txid drifted unexpectedly: {_json(observer_stale_state)}")
                        print("REFRESH state flagged ok")

                        stale_write_resp = await call_tool(
                            observer,
                            "define",
                            {
                                "session_id": session_id,
                                "kind": "type",
                                "arguments": {"decl": "typedef unsigned __int64 regression_u64_observer;", "expected_txid": observer_stale_txid},
                            },
                        )
                        stale_write_data = _outer_structured(stale_write_resp) or {}
                        _assert(stale_write_data.get("ok") is False and stale_write_data.get("error") == "stale_session_revision", f"stale write was not rejected: {_json(stale_write_data)}")
                        print("STALE txid rejection ok")

                        observer_refresh_resp = await call_tool(
                            observer,
                            "call_session_tool",
                            {"session_id": session_id, "tool_name": "get_metadata", "arguments": {}},
                        )
                        observer_refresh_meta = _outer_meta(observer_refresh_resp)
                        _assert(_meta_txid(observer_refresh_meta) == current_txid, f"observer refresh did not pick up new txid: {_json(observer_refresh_meta)}")
                        observer_refreshed_state_resp = await call_tool(observer, "current_session", {})
                        observer_refreshed_state = _outer_structured(observer_refreshed_state_resp) or {}
                        observer_refreshed_session = observer_refreshed_state.get("session") or {}
                        observer_refreshed_revision = observer_refreshed_session.get("revision") or {}
                        _assert(observer_refreshed_revision.get("requires_refresh") is False, f"observer session stayed stale after refresh: {_json(observer_refreshed_state)}")
                        print("REFRESH clear ok")

                        observer_reuse_resp = await call_tool(
                            observer,
                            "open_binary",
                            {"path": target, "mode": "headless", "reuse": True},
                        )
                        observer_reuse = _outer_structured(observer_reuse_resp) or {}
                        _assert(observer_reuse.get("ok") is True and observer_reuse.get("reused") is True, f"observer reuse open failed: {_json(observer_reuse)}")
                        observer_reuse_revision = observer_reuse.get("revision") or {}
                        _assert(int(observer_reuse_revision.get("txid") or 0) == current_txid, f"observer reuse revision mismatch: {_json(observer_reuse)}")
                        _assert(int(observer_reuse_revision.get("snapshot_txid") or 0) == current_txid, f"observer reuse snapshot mismatch: {_json(observer_reuse)}")
                        print("OPEN reuse refresh ok")

                        observer_close_resp = await call_tool(observer, "close_session", {"session_id": session_id, "save": False})
                        observer_close_data = _outer_structured(observer_close_resp) or {}
                        _assert(observer_close_data.get("ok") is False, f"observer close_session should have been rejected: {_json(observer_close_data)}")
                        print("CLOSE guard ok")

                        struct_name = f"regression_struct_{int(time.time())}"
                        define_struct_resp = await call_tool(
                            session,
                            "define",
                            {
                                "session_id": session_id,
                                "kind": "struct",
                                "arguments": {
                                    "name": struct_name,
                                    "fields": [
                                        {"type": "unsigned int", "name": "size"},
                                        {"type": "unsigned short", "name": "tag"},
                                    ],
                                },
                            },
                        )
                        define_struct = _inner_structured(define_struct_resp) or {}
                        _assert(define_struct.get("ok") is True, f"define(struct) failed: {_json(define_struct)}")
                        define_struct_meta = _outer_meta(define_struct_resp)
                        next_txid = _meta_txid(define_struct_meta)
                        _assert(next_txid > current_txid, f"define(struct) did not advance txid: {_json(define_struct_meta)}")
                        current_txid = next_txid
                        print(f"DEFINE struct ok {struct_name}")

                        duplicate_struct_resp = await call_tool(
                            session,
                            "define",
                            {
                                "session_id": session_id,
                                "kind": "struct",
                                "arguments": {
                                    "name": struct_name,
                                    "fields": [
                                        {"type": "unsigned int", "name": "size"},
                                    ],
                                },
                            },
                        )
                        duplicate_struct = _inner_structured(duplicate_struct_resp) or {}
                        _assert(duplicate_struct.get("ok") is False, f"duplicate define(struct) unexpectedly succeeded: {_json(duplicate_struct)}")
                        duplicate_struct_meta = _outer_meta(duplicate_struct_resp)
                        _assert(_meta_txid(duplicate_struct_meta) == current_txid, f"failed mutator incorrectly advanced txid: {_json(duplicate_struct_meta)}")
                        print("FAILED mutator no-bump ok")

                        padded_struct_name = f"regression_padded_{int(time.time())}"
                        padded_struct_resp = await call_tool(
                            session,
                            "call_session_tool",
                            {
                                "session_id": session_id,
                                "tool_name": "create_padded_struct_from_map",
                                "arguments": {
                                    "name": padded_struct_name,
                                    "fields": [
                                        {"offset": 0, "name": "magic", "type": "unsigned int"},
                                        {"offset": 8, "name": "tag", "type": "unsigned short"},
                                    ],
                                    "size": 12,
                                },
                            },
                        )
                        padded_struct = _inner_structured(padded_struct_resp) or {}
                        _assert(padded_struct.get("ok") is True, f"create_padded_struct_from_map failed: {_json(padded_struct)}")
                        _assert("__pad_" in str(padded_struct.get("decl") or ""), f"create_padded_struct_from_map did not add padding: {_json(padded_struct)}")
                        padded_struct_meta = _outer_meta(padded_struct_resp)
                        next_txid = _meta_txid(padded_struct_meta)
                        _assert(next_txid > current_txid, f"create_padded_struct_from_map did not advance txid: {_json(padded_struct_meta)}")
                        current_txid = next_txid
                        print(f"CREATE_PADDED_STRUCT ok {padded_struct_name}")

                        upsert_struct_resp = await call_tool(
                            session,
                            "call_session_tool",
                            {
                                "session_id": session_id,
                                "tool_name": "upsert_struct",
                                "arguments": {
                                    "name": padded_struct_name,
                                    "fields": [{"offset": 10, "name": "flags", "type": "unsigned short"}],
                                    "size": 12,
                                },
                            },
                        )
                        upsert_struct = _inner_structured(upsert_struct_resp) or {}
                        _assert(upsert_struct.get("ok") is True, f"upsert_struct failed: {_json(upsert_struct)}")
                        upsert_struct_meta = _outer_meta(upsert_struct_resp)
                        next_txid = _meta_txid(upsert_struct_meta)
                        _assert(next_txid > current_txid, f"upsert_struct did not advance txid: {_json(upsert_struct_meta)}")
                        current_txid = next_txid
                        print("UPSERT_STRUCT ok")

                        apply_many_resp = await call_tool(
                            session,
                            "call_session_tool",
                            {
                                "session_id": session_id,
                                "tool_name": "apply_struct_to_many",
                                "arguments": {"struct_name": padded_struct_name, "items": [{"kind": "address", "addr": string_addr}]},
                            },
                        )
                        apply_many = _inner_structured(apply_many_resp) or {}
                        _assert((apply_many.get("ok_count") or 0) >= 1, f"apply_struct_to_many failed: {_json(apply_many)}")
                        apply_many_meta = _outer_meta(apply_many_resp)
                        next_txid = _meta_txid(apply_many_meta)
                        _assert(next_txid > current_txid, f"apply_struct_to_many did not advance txid: {_json(apply_many_meta)}")
                        current_txid = next_txid
                        print("APPLY_STRUCT_TO_MANY ok")

                        read_struct_resp = await call_tool(
                            session,
                            "read",
                            {"session_id": session_id, "kind": "struct", "addr": string_addr, "arguments": {"struct_name": padded_struct_name}},
                        )
                        read_struct = _inner_structured(read_struct_resp) or {}
                        read_struct_member = _first(read_struct.get("members") or [], "read(struct) returned no members")
                        _assert("bytes" not in read_struct_member, f"read(struct) default is not slim: {_json(read_struct_member)}")
                        print("READ struct ok")

                        read_struct_full_resp = await call_tool(
                            session,
                            "read",
                            {"session_id": session_id, "kind": "struct", "addr": string_addr, "detail": "full", "arguments": {"struct_name": padded_struct_name}},
                        )
                        read_struct_full = _inner_structured(read_struct_full_resp) or {}
                        read_struct_full_member = _first(read_struct_full.get("members") or [], "read(struct, full) returned no members")
                        _assert("bytes" in read_struct_full_member, f"read(struct, detail=full) missing bytes metadata: {_json(read_struct_full_member)}")
                        print("READ struct full ok")

                        raw_stale_mutator_resp = await call_tool(
                            observer,
                            "call_session_tool",
                            {
                                "session_id": session_id,
                                "tool_name": "upsert_struct",
                                "arguments": {
                                    "name": padded_struct_name,
                                    "fields": [{"offset": 14, "name": "late_flag", "type": "unsigned short"}],
                                    "size": 16,
                                    "expected_txid": observer_stale_txid,
                                },
                            },
                        )
                        raw_stale_mutator = _outer_structured(raw_stale_mutator_resp) or {}
                        _assert(raw_stale_mutator.get("ok") is False and raw_stale_mutator.get("error") == "stale_session_revision", f"raw stale mutator was not rejected: {_json(raw_stale_mutator)}")
                        print("RAW stale mutator rejection ok")

                        workflow_decl_name = f"workflow_u64_{int(time.time())}"
                        workflow_partial_resp = await call_tool(
                            session,
                            "call_session_tool",
                            {
                                "session_id": session_id,
                                "tool_name": "type_workflow",
                                "arguments": {
                                    "decls": [f"typedef unsigned __int64 {workflow_decl_name};"],
                                    "exports": [{"struct_name": "__missing_struct__"}],
                                },
                            },
                        )
                        workflow_partial = _inner_structured(workflow_partial_resp) or {}
                        _assert(workflow_partial.get("ok") is False, f"type_workflow partial expected overall false: {_json(workflow_partial)}")
                        _assert(workflow_partial.get("db_changed") is True, f"type_workflow partial missing db_changed: {_json(workflow_partial)}")
                        workflow_partial_meta = _outer_meta(workflow_partial_resp)
                        next_txid = _meta_txid(workflow_partial_meta)
                        _assert(next_txid > current_txid, f"type_workflow partial success did not advance txid: {_json(workflow_partial_meta)}")
                        current_txid = next_txid
                        print("TYPE_WORKFLOW partial bump ok")

                        workflow_fail_resp = await call_tool(
                            session,
                            "call_session_tool",
                            {
                                "session_id": session_id,
                                "tool_name": "type_workflow",
                                "arguments": {
                                    "decls": ["typedef struct {"],
                                },
                            },
                        )
                        workflow_fail = _inner_structured(workflow_fail_resp) or {}
                        _assert(workflow_fail.get("ok") is False and workflow_fail.get("db_changed") is False, f"type_workflow fail expected no db change: {_json(workflow_fail)}")
                        workflow_fail_meta = _outer_meta(workflow_fail_resp)
                        _assert(_meta_txid(workflow_fail_meta) == current_txid, f"type_workflow fail incorrectly advanced txid: {_json(workflow_fail_meta)}")
                        print("TYPE_WORKFLOW fail no-bump ok")

                        export_struct_resp = await call_tool(
                            session,
                            "call_session_tool",
                            {
                                "session_id": session_id,
                                "tool_name": "export_struct",
                                "arguments": {"struct_name": padded_struct_name, "format": "json"},
                            },
                        )
                        export_struct = _inner_structured(export_struct_resp) or {}
                        exported_header = str(export_struct.get("header") or "")
                        _assert(export_struct.get("name") == padded_struct_name and exported_header, f"export_struct failed: {_json(export_struct)}")
                        print("EXPORT_STRUCT ok")

                        export_struct_file_resp = await call_tool(
                            session,
                            "call_session_tool",
                            {
                                "session_id": session_id,
                                "tool_name": "export_struct",
                                "arguments": {
                                    "struct_name": padded_struct_name,
                                    "format": "json",
                                    "path": f"/mnt/c/Windows/Temp/{padded_struct_name}.json",
                                },
                            },
                        )
                        export_struct_file = _inner_structured(export_struct_file_resp) or {}
                        export_path = str(export_struct_file.get("path") or "")
                        _assert(export_path.endswith(f"{padded_struct_name}.json"), f"export_struct path missing: {_json(export_struct_file)}")
                        with open(_normalize_test_path(export_path), "r", encoding="utf-8") as handle:
                            exported_file_payload = json.load(handle)
                        _assert(exported_file_payload.get("name") == padded_struct_name, f"export_struct file contents unexpected: {_json(exported_file_payload)}")
                        print("EXPORT_STRUCT file ok")

                        struct_diff_resp = await call_tool(
                            session,
                            "call_session_tool",
                            {
                                "session_id": session_id,
                                "tool_name": "struct_diff",
                                "arguments": {"struct_name": padded_struct_name, "decl": exported_header},
                            },
                        )
                        struct_diff = _inner_structured(struct_diff_resp) or {}
                        _assert(struct_diff.get("identical") is True, f"struct_diff expected identical: {_json(struct_diff)}")
                        print("STRUCT_DIFF ok")

                        field_xrefs_resp = await call_tool(
                            session,
                            "call_session_tool",
                            {
                                "session_id": session_id,
                                "tool_name": "field_xrefs_for_struct",
                                "arguments": {"struct_name": padded_struct_name},
                            },
                        )
                        field_xrefs = _inner_structured(field_xrefs_resp) or {}
                        _assert((field_xrefs.get("field_count") or 0) >= 1, f"field_xrefs_for_struct failed: {_json(field_xrefs)}")
                        print("FIELD_XREFS_FOR_STRUCT ok")

                        typed_export_resp = await call_tool(
                            session,
                            "call_session_tool",
                            {
                                "session_id": session_id,
                                "tool_name": "typed_decompile_export",
                                "arguments": {"addr": func_addr, "include_line_map": True, "format": "json"},
                            },
                        )
                        typed_export = _inner_structured(typed_export_resp) or {}
                        _assert(str(typed_export.get("code") or ""), f"typed_decompile_export returned empty code: {_json(typed_export)}")
                        _assert("line_map" in typed_export, f"typed_decompile_export missing line_map: {_json(typed_export)}")
                        print("TYPED_DECOMPILE_EXPORT ok")

                        full_c_path = f"/mnt/c/Windows/Temp/regression_full_decompile_{int(time.time())}.c"
                        full_c_resp = await call_tool(
                            session,
                            "export_decompiled_c",
                            {
                                "session_id": session_id,
                                "path": full_c_path,
                                "max_functions": 2,
                                "fallback": "comment",
                            },
                        )
                        full_c_export = _outer_structured(full_c_resp) or {}
                        full_c_meta = _outer_meta(full_c_resp)
                        full_c_text_summary = _content_text(full_c_resp)
                        full_c_export_path = str(full_c_export.get("path") or "")
                        _assert(full_c_export.get("ok") is True, f"export_decompiled_c failed: {_json(full_c_export)}")
                        _assert(full_c_export.get("selected_count") == 2, f"export_decompiled_c selected_count mismatch: {_json(full_c_export)}")
                        _assert(full_c_export_path.endswith(".c"), f"export_decompiled_c path missing .c: {_json(full_c_export)}")
                        _assert(full_c_meta.get("content_mode") == "summary", f"export_decompiled_c missing summary mode: {_json(full_c_resp)}")
                        _assert("code" not in full_c_export, f"export_decompiled_c default leaked code payload: {_json(full_c_export)}")
                        _assert(full_c_text_summary and len(full_c_text_summary) < 160, f"export_decompiled_c content is not slim: {_json(full_c_resp)}")
                        with open(_normalize_test_path(full_c_export_path), "r", encoding="utf-8") as handle:
                            full_c_text = handle.read()
                        _assert("IDA decompiled C export" in full_c_text, "export_decompiled_c file missing header")
                        _assert("=====" in full_c_text, "export_decompiled_c file missing function separator")
                        print("EXPORT_DECOMPILED_C ok")

                        write_output_path = f"/mnt/c/Windows/Temp/regression_decompile_{int(time.time())}.txt"
                        write_output_resp = await call_tool(
                            session,
                            "write_session_tool_output",
                            {
                                "session_id": session_id,
                                "path": write_output_path,
                                "tool_name": "decompile",
                                "arguments": {"addr": func_addr},
                                "output_format": "text",
                                "overwrite": True,
                            },
                        )
                        write_output_data = _outer_structured(write_output_resp) or {}
                        rendered_path = _normalize_test_path(str(write_output_data.get("path") or write_output_path))
                        with open(rendered_path, "r", encoding="utf-8") as handle:
                            rendered_text = handle.read()
                        _assert('"mode": "decompile"' in rendered_text and '"code": ' in rendered_text, "write_session_tool_output(text) did not render the full structured payload")
                        _assert(rendered_text.strip() != decompile_preview_text.strip(), "write_session_tool_output(text) unexpectedly rendered only the slim summary")
                        print("WRITE_SESSION_TOOL_OUTPUT ok")

                        second = func_instructions[1]
                        third = func_instructions[2] if len(func_instructions) > 2 else None
                        undef_addr = str(second.get("address") or "")
                        undef_size = max(1, _hex_to_int(str(third.get("address"))) - _hex_to_int(undef_addr)) if third else 1
                        undefine_resp = await call_tool(
                            session,
                            "define",
                            {"session_id": session_id, "kind": "undefine", "addr": undef_addr, "arguments": {"size": undef_size}},
                        )
                        undefine_data = _inner_structured(undefine_resp) or []
                        first_undefine = _first(undefine_data, "define(undefine) returned no rows")
                        _assert(first_undefine.get("ok") is True, f"define(undefine) failed: {_json(undefine_data)}")
                        print(f"UNDEFINE ok addr={undef_addr} size={undef_size}")

                        define_code_resp = await call_tool(session, "define", {"session_id": session_id, "kind": "code", "addr": undef_addr})
                        define_code = _inner_structured(define_code_resp) or []
                        first_define_code = _first(define_code, "define(code) returned no rows")
                        _assert(first_define_code.get("ok") is True, f"define(code) failed: {_json(define_code)}")
                        print("DEFINE code ok")

                        inspect_after_resp = await call_tool(session, "inspect_addr", {"session_id": session_id, "addr": undef_addr})
                        inspect_after = _inner_structured(inspect_after_resp) or {}
                        _assert(inspect_after.get("is_code") is True, f"inspect_addr after define(code) failed: {_json(inspect_after)}")
                        print("POST-CODE inspect ok")

                        stack_frame_resp = await call_tool(
                            session,
                            "call_session_tool",
                            {"session_id": session_id, "tool_name": "stack_frame", "arguments": {"addr": func_addr}},
                        )
                        stack_frames = _inner_structured(stack_frame_resp) or []
                        first_stack_frame = _first(stack_frames, "stack_frame returned no rows")
                        stack_vars = first_stack_frame.get("vars") or []
                        renamed_stack = False
                        renamed_stack_name = ""
                        for stack_var in stack_vars:
                            old_stack_name = str(stack_var.get("name") or "").strip()
                            if not old_stack_name or old_stack_name.startswith("arg_"):
                                continue
                            new_stack_name = f"reg_stack_{int(time.time())}"
                            rename_stack_resp = await call_tool(
                                session,
                                "rename",
                                {
                                    "session_id": session_id,
                                    "batch": {"stack": [{"func_addr": func_addr, "old": old_stack_name, "new": new_stack_name}]},
                                },
                            )
                            rename_stack = _inner_structured(rename_stack_resp) or {}
                            stack_results = rename_stack.get("stack") or []
                            if not stack_results or not stack_results[0].get("ok"):
                                continue
                            stack_frame_after_resp = await call_tool(
                                session,
                                "call_session_tool",
                                {"session_id": session_id, "tool_name": "stack_frame", "arguments": {"addr": func_addr}},
                            )
                            stack_frame_after = _inner_structured(stack_frame_after_resp) or []
                            first_stack_after = _first(stack_frame_after, "stack_frame after rename returned no rows")
                            renamed_names = {str(item.get("name") or "") for item in (first_stack_after.get("vars") or [])}
                            _assert(new_stack_name in renamed_names, f"stack rename not visible in frame: {_json(first_stack_after)}")
                            print(f"RENAME stack ok {old_stack_name}->{new_stack_name}")
                            renamed_stack = True
                            renamed_stack_name = new_stack_name
                            break
                        _assert(renamed_stack, "No stack variable candidate could be renamed end-to-end")

                        apply_many_stack_resp = await call_tool(
                            session,
                            "call_session_tool",
                            {
                                "session_id": session_id,
                                "tool_name": "apply_struct_to_many",
                                "arguments": {"struct_name": padded_struct_name, "items": [{"kind": "stack", "func_addr": func_addr, "name": renamed_stack_name}]},
                            },
                        )
                        apply_many_stack = _inner_structured(apply_many_stack_resp) or {}
                        _assert((apply_many_stack.get("ok_count") or 0) >= 1, f"apply_struct_to_many(stack) failed: {_json(apply_many_stack)}")
                        print("APPLY_STRUCT_TO_MANY stack ok")

                        local_rename_verified = False
                        renamed_local_name = ""
                        renamed_local_func_addr = ""
                        for candidate in function_items[:24]:
                            candidate_addr = str(candidate.get("address") or "")
                            if not candidate_addr:
                                continue
                            decompile_resp = await call_tool(session, "decompile", {"session_id": session_id, "addr": candidate_addr})
                            decompile_data = _inner_structured(decompile_resp) or {}
                            if decompile_data.get("mode") != "decompile":
                                continue
                            code = str(decompile_data.get("code") or "")
                            try:
                                old_local_name = _pick_local_name_from_code(code)
                            except RegressionFailure:
                                continue
                            new_local_name = f"reg_local_{int(time.time())}"
                            rename_local_resp = await call_tool(
                                session,
                                "rename",
                                {
                                    "session_id": session_id,
                                    "batch": {"local": [{"func_addr": candidate_addr, "old": old_local_name, "new": new_local_name}]},
                                },
                            )
                            rename_local = _inner_structured(rename_local_resp) or {}
                            local_results = rename_local.get("local") or []
                            if not local_results or not local_results[0].get("ok"):
                                continue
                            decompile_after_resp = await call_tool(session, "decompile", {"session_id": session_id, "addr": candidate_addr})
                            decompile_after = _inner_structured(decompile_after_resp) or {}
                            code_after = str(decompile_after.get("code") or "")
                            _assert(new_local_name in code_after, f"local rename not visible in decompile output: {_json(decompile_after)}")
                            print(f"RENAME local ok {old_local_name}->{new_local_name}")
                            local_rename_verified = True
                            renamed_local_name = new_local_name
                            renamed_local_func_addr = candidate_addr
                            break
                        _assert(local_rename_verified, "No local variable candidate could be renamed end-to-end")

                        apply_many_local_resp = await call_tool(
                            session,
                            "call_session_tool",
                            {
                                "session_id": session_id,
                                "tool_name": "apply_struct_to_many",
                                "arguments": {"struct_name": padded_struct_name, "items": [{"kind": "local", "func_addr": renamed_local_func_addr, "name": renamed_local_name}]},
                            },
                        )
                        apply_many_local = _inner_structured(apply_many_local_resp) or {}
                        _assert((apply_many_local.get("ok_count") or 0) >= 1, f"apply_struct_to_many(local) failed: {_json(apply_many_local)}")
                        print("APPLY_STRUCT_TO_MANY local ok")
            finally:
                if session_id:
                    closed = await call_tool(session, "close_session", {"session_id": session_id, "save": False, "force": True})
                    close_data = _outer_structured(closed) or {}
                    _assert(close_data.get("ok") is True, f"close_session failed: {_json(close_data)}")
                    print("CLOSE ok")

            if idb_target and not Path(_normalize_test_path(idb_target)).exists():
                print(f"LOAD_IDB skip missing target={idb_target}")
            elif idb_target:
                load_idb_resp = await call_tool(session, "load_idb", {"path": idb_target, "mode": "headless", "reuse": False})
                load_idb_data = _outer_structured(load_idb_resp) or {}
                _assert(load_idb_data.get("ok") is True, f"load_idb failed: {_json(load_idb_data)}")
                _assert(bool(load_idb_data.get("idb_loaded")), f"load_idb did not mark idb_loaded: {_json(load_idb_data)}")
                load_idb_session_id = str(load_idb_data.get("session_id") or "")
                _assert(load_idb_session_id, f"load_idb did not return a session_id: {_json(load_idb_data)}")
                print(f"LOAD_IDB ok session_id={load_idb_session_id}")
                closed_idb = await call_tool(session, "close_session", {"session_id": load_idb_session_id, "save": False, "force": True})
                closed_idb_data = _outer_structured(closed_idb) or {}
                _assert(closed_idb_data.get("ok") is True, f"load_idb close_session failed: {_json(closed_idb_data)}")
                print("LOAD_IDB close ok")

    print("REGRESSION ok")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(anyio.run(main, sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGET))
    except RegressionFailure as exc:
        print(f"REGRESSION failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
