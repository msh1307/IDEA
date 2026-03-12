from __future__ import annotations

import os
import subprocess
from urllib.parse import urlsplit, urlunsplit


def discover_windows_host() -> str:
    env = os.getenv("IDA_MCP_CONNECT_HOST", "").strip()
    if env:
        return env

    commands = [
        ["sh", "-lc", "ip route show default | awk '/default/ {print $3; exit}'"],
        ["sh", "-lc", "awk '/nameserver/ {print $2; exit}' /etc/resolv.conf"],
    ]
    for cmd in commands:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        value = result.stdout.strip()
        if value:
            return value
    return "127.0.0.1"


def rewrite_endpoint_url(url: str, host: str) -> str:
    parsed = urlsplit(url)
    netloc = parsed.netloc
    if ":" in netloc:
        _, port = netloc.rsplit(":", 1)
        netloc = f"{host}:{port}"
    else:
        netloc = host
    return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))


def candidate_endpoint_urls(url: str) -> list[str]:
    parsed = urlsplit(url)
    hosts: list[str] = []

    env = os.getenv("IDA_MCP_CONNECT_HOST", "").strip()
    if env:
        # Codex deployments can pin the known-good Windows/WSL reachability path
        # in config via IDA_MCP_CONNECT_HOST. Keep the fallback probes below
        # because localhost vs gateway behavior differs across WSL setups.
        for item in env.split(","):
            item = item.strip()
            if item:
                hosts.append(item)

    hosts.append("127.0.0.1")
    gateway = discover_windows_host()
    if gateway:
        hosts.append(gateway)

    original_host = parsed.hostname or ""
    if original_host and original_host not in {"0.0.0.0", "::"}:
        hosts.append(original_host)

    urls: list[str] = []
    seen: set[str] = set()
    for host in hosts:
        candidate = rewrite_endpoint_url(url, host)
        if candidate not in seen:
            seen.add(candidate)
            urls.append(candidate)
    return urls
