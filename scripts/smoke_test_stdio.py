#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import sys
import time

import anyio
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


DEFAULT_TARGET = "/mnt/c/Users/USER/Downloads/for_user (48)/deploy/board_server"


async def call_tool(session: ClientSession, name: str, arguments: dict) -> dict:
    result = await session.call_tool(name, arguments)
    return result.model_dump(mode="json")


async def main(target: str) -> int:
    params = StdioServerParameters(
        command=os.path.join(os.getcwd(), ".venv/bin/python"),
        args=["-m", "ida_hybrid_manager.server", "--transport", "stdio"],
        cwd=os.getcwd(),
        env={"IDA_MCP_CONNECT_HOST": os.getenv("IDA_MCP_CONNECT_HOST", "172.31.96.1")},
    )

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            t0 = time.time()
            init = await session.initialize()
            print(f"INIT {time.time() - t0:.2f}s {init.serverInfo.name}")

            tools = await session.list_tools()
            print(f"TOOLS {len(tools.tools)}")

            t1 = time.time()
            opened = await call_tool(session, "open_binary", {"path": target, "mode": "headless", "reuse": True})
            print(f"OPEN {time.time() - t1:.2f}s")
            print(json.dumps(opened, indent=2))
            session_id = opened.get("structuredContent", {}).get("session_id")
            if not session_id:
                return 2

            t2 = time.time()
            current = await call_tool(session, "current_session", {})
            print(f"CURRENT {time.time() - t2:.2f}s")
            print(json.dumps(current, indent=2))

            t3 = time.time()
            metadata = await call_tool(
                session,
                "call_session_tool",
                {"session_id": session_id, "tool_name": "get_metadata", "arguments": {}},
            )
            print(f"METADATA {time.time() - t3:.2f}s")
            print(json.dumps(metadata, indent=2))

            t4 = time.time()
            text_matches = await call_tool(
                session,
                "call_session_tool",
                {"session_id": session_id, "tool_name": "find_text", "arguments": {"text": "/report", "kinds": ["strings"]}},
            )
            print(f"FIND_TEXT {time.time() - t4:.2f}s")
            print(json.dumps(text_matches, indent=2)[:4000])

            t4b = time.time()
            invalid_decompile = await call_tool(
                session,
                "call_session_tool",
                {"session_id": session_id, "tool_name": "decompile", "arguments": {"addr": "0x1"}},
            )
            print(f"INVALID_DECOMPILE {time.time() - t4b:.2f}s")
            print(json.dumps(invalid_decompile, indent=2)[:4000])

            t4c = time.time()
            metadata_after_invalid = await call_tool(
                session,
                "call_session_tool",
                {"session_id": session_id, "tool_name": "get_metadata", "arguments": {}},
            )
            print(f"METADATA_AFTER_INVALID {time.time() - t4c:.2f}s")
            print(json.dumps(metadata_after_invalid, indent=2))

            t5 = time.time()
            reopened = await call_tool(session, "open_binary", {"path": target, "mode": "headless", "reuse": True})
            print(f"REOPEN {time.time() - t5:.2f}s")
            print(json.dumps(reopened, indent=2))

            t6 = time.time()
            closed = await call_tool(session, "close_session", {"session_id": session_id, "save": False})
            print(f"CLOSE {time.time() - t6:.2f}s")
            print(json.dumps(closed, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(anyio.run(main, sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGET))
