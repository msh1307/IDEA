from __future__ import annotations

from typing import Any

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


async def list_backend_tools(endpoint_url: str) -> dict[str, Any]:
    async with streamablehttp_client(endpoint_url, timeout=10) as (read_stream, write_stream, _):
        async with ClientSession(read_stream, write_stream) as session:
            result = await session.initialize()
            tools = await session.list_tools()
            return {
                "server": result.serverInfo.model_dump(mode="json"),
                "tools": [tool.model_dump(mode="json") for tool in tools.tools],
            }


async def call_backend_tool(endpoint_url: str, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    async with streamablehttp_client(endpoint_url, timeout=10) as (read_stream, write_stream, _):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            result = await session.call_tool(name, arguments or {})
            return result.model_dump(mode="json")


async def list_backend_tools_any(endpoint_urls: list[str]) -> dict[str, Any]:
    last_error: Exception | None = None
    for endpoint_url in endpoint_urls:
        try:
            return await list_backend_tools(endpoint_url)
        except Exception as exc:
            last_error = exc
    raise RuntimeError(f"Unable to reach backend via any endpoint: {endpoint_urls}") from last_error


async def call_backend_tool_any(endpoint_urls: list[str], name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    last_error: Exception | None = None
    for endpoint_url in endpoint_urls:
        try:
            return await call_backend_tool(endpoint_url, name, arguments)
        except Exception as exc:
            last_error = exc
    raise RuntimeError(f"Unable to reach backend via any endpoint: {endpoint_urls}") from last_error
