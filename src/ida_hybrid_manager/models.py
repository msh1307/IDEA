from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def isoformat(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


@dataclass
class SessionRecord:
    session_id: str
    engine: str
    display_name: str
    binary_path: str
    idb_path: str
    binary_hash: str
    status: str
    source: str
    capabilities: list[str] = field(default_factory=list)
    endpoint: dict[str, Any] = field(default_factory=dict)
    owner_pid: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=utc_now)
    last_seen: datetime = field(default_factory=utc_now)
    current: bool = False
    closable: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "engine": self.engine,
            "display_name": self.display_name,
            "binary_path": self.binary_path,
            "idb_path": self.idb_path,
            "binary_hash": self.binary_hash,
            "status": self.status,
            "source": self.source,
            "capabilities": list(self.capabilities),
            "endpoint": dict(self.endpoint),
            "owner_pid": self.owner_pid,
            "metadata": dict(self.metadata),
            "created_at": isoformat(self.created_at),
            "last_seen": isoformat(self.last_seen),
            "current": self.current,
            "closable": self.closable,
        }


@dataclass
class PendingLaunch:
    launch_token: str
    binary_path: str
    idb_path: str
    engine: str
    port: int | None
    pid: int | None
    created_at: datetime = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "launch_token": self.launch_token,
            "binary_path": self.binary_path,
            "idb_path": self.idb_path,
            "engine": self.engine,
            "port": self.port,
            "pid": self.pid,
            "created_at": isoformat(self.created_at),
        }
