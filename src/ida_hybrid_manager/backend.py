from __future__ import annotations

import asyncio
import json
from typing import Any
from urllib import error, request

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


class BackendError(RuntimeError):
    pass


class BackendUnavailableError(BackendError):
    pass


class BackendToolError(BackendError):
    pass


def _normalize_endpoint(endpoint: str | dict[str, Any]) -> dict[str, str]:
    if isinstance(endpoint, str):
        return {"transport": "streamable-http", "url": endpoint}
    transport = str(endpoint.get("transport") or "streamable-http")
    url = str(endpoint.get("url") or "")
    if not url:
        raise ValueError(f"Backend endpoint missing URL: {endpoint}")
    return {"transport": transport, "url": url}


def _native_url(endpoint_url: str, path: str) -> str:
    return endpoint_url.rstrip("/") + path


def _native_get_json(endpoint_url: str, path: str) -> dict[str, Any]:
    req = request.Request(_native_url(endpoint_url, path), method="GET")
    with request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _native_post_json(endpoint_url: str, path: str, payload: dict[str, Any], timeout_sec: float = 30.0) -> dict[str, Any]:
    req = request.Request(
        _native_url(endpoint_url, path),
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with request.urlopen(req, timeout=timeout_sec) as resp:
        return json.loads(resp.read().decode("utf-8"))


async def list_backend_tools(endpoint: str | dict[str, Any]) -> dict[str, Any]:
    normalized = _normalize_endpoint(endpoint)
    if normalized["transport"] == "native-http":
        try:
            response = await asyncio.to_thread(_native_get_json, normalized["url"], "/api/tools/list")
        except error.HTTPError as exc:
            try:
                body = exc.read().decode("utf-8")
                response = json.loads(body) if body else {}
            except Exception:
                response = {"ok": False, "error": str(exc)}
        except (error.URLError, TimeoutError, OSError) as exc:
            raise BackendUnavailableError(str(exc)) from exc
        if not response.get("ok"):
            raise BackendToolError(response.get("error") or f"native backend list failed: {normalized['url']}")
        return {"server": response.get("server", {}), "tools": response.get("tools", [])}

    endpoint_url = normalized["url"]
    async with streamablehttp_client(endpoint_url, timeout=10) as (read_stream, write_stream, _):
        async with ClientSession(read_stream, write_stream) as session:
            result = await session.initialize()
            tools = await session.list_tools()
            return {
                "server": result.serverInfo.model_dump(mode="json"),
                "tools": [tool.model_dump(mode="json") for tool in tools.tools],
            }


async def call_backend_tool(
    endpoint: str | dict[str, Any],
    name: str,
    arguments: dict[str, Any] | None = None,
    *,
    timeout_sec: float = 30.0,
) -> dict[str, Any]:
    normalized = _normalize_endpoint(endpoint)
    if normalized["transport"] == "native-http":
        payload = {"tool_name": name, "arguments": arguments or {}}
        try:
            response = await asyncio.to_thread(_native_post_json, normalized["url"], "/api/tools/call", payload, timeout_sec)
        except error.HTTPError as exc:
            try:
                body = exc.read().decode("utf-8")
                response = json.loads(body) if body else {}
            except Exception:
                response = {"ok": False, "error": str(exc)}
        except (error.URLError, TimeoutError, OSError) as exc:
            raise BackendUnavailableError(str(exc)) from exc
        if not response.get("ok"):
            raise BackendToolError(response.get("error") or f"native backend call failed: {name}")
        result = response.get("result")
        if isinstance(result, dict):
            return result
        raise BackendToolError(f"Native backend returned invalid tool result for {name}")

    endpoint_url = normalized["url"]
    async with streamablehttp_client(endpoint_url, timeout=10) as (read_stream, write_stream, _):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            result = await session.call_tool(name, arguments or {})
            return result.model_dump(mode="json")


async def list_backend_tools_any(endpoints: list[str | dict[str, Any]]) -> dict[str, Any]:
    last_error: Exception | None = None
    for endpoint in endpoints:
        try:
            return await list_backend_tools(endpoint)
        except BackendToolError:
            raise
        except Exception as exc:
            last_error = exc
    if last_error is not None:
        raise BackendUnavailableError(f"Unable to reach backend via any endpoint: {endpoints}") from last_error
    raise BackendUnavailableError(f"Unable to reach backend via any endpoint: {endpoints}")


async def call_backend_tool_any(
    endpoints: list[str | dict[str, Any]],
    name: str,
    arguments: dict[str, Any] | None = None,
    *,
    timeout_sec: float = 30.0,
) -> dict[str, Any]:
    last_error: Exception | None = None
    for endpoint in endpoints:
        try:
            return await call_backend_tool(endpoint, name, arguments, timeout_sec=timeout_sec)
        except BackendToolError:
            raise
        except Exception as exc:
            last_error = exc
    if last_error is not None:
        raise BackendUnavailableError(f"Unable to reach backend via any endpoint: {endpoints}") from last_error
    raise BackendUnavailableError(f"Unable to reach backend via any endpoint: {endpoints}")
