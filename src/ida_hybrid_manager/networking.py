from __future__ import annotations

import os
import subprocess
from urllib.parse import urlsplit, urlunsplit


def _split_hosts(value: str) -> list[str]:
    hosts: list[str] = []
    for item in value.split(","):
        candidate = item.strip()
        if candidate:
            hosts.append(candidate)
    return hosts


def candidate_windows_hosts(*, include_loopback: bool = True) -> list[str]:
    hosts: list[str] = []
    seen: set[str] = set()

    def add(host: str) -> None:
        candidate = host.strip()
        if not candidate or candidate in seen:
            return
        seen.add(candidate)
        hosts.append(candidate)

    env = os.getenv("IDA_MCP_CONNECT_HOST", "").strip()
    for host in _split_hosts(env):
        add(host)

    commands = [
        ["sh", "-lc", "ip route show default | awk '/default/ {print $3; exit}'"],
        ["sh", "-lc", "awk '/nameserver/ {print $2; exit}' /etc/resolv.conf"],
    ]
    for cmd in commands:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        value = result.stdout.strip()
        if value:
            add(value)

    if include_loopback:
        add("127.0.0.1")
    return hosts


def discover_windows_host() -> str:
    candidates = candidate_windows_hosts()
    return candidates[0] if candidates else "127.0.0.1"


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
    hosts.extend(candidate_windows_hosts())

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
