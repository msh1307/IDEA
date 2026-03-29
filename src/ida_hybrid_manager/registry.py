from __future__ import annotations

import threading
import uuid
from datetime import timedelta
from typing import Any

from .models import PendingLaunch, SessionRecord, utc_now
from .networking import candidate_endpoint_urls


class SessionRegistry:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sessions: dict[str, SessionRecord] = {}
        self._pending_launches: dict[str, PendingLaunch] = {}
        self._current_session_id: str | None = None
        self.stale_after = timedelta(seconds=30)

    def register_pending_launch(self, pending: PendingLaunch) -> None:
        with self._lock:
            self._pending_launches[pending.launch_token] = pending

    def get_pending_launch(self, launch_token: str) -> PendingLaunch | None:
        with self._lock:
            return self._pending_launches.get(launch_token)

    def pop_pending_launch(self, launch_token: str) -> PendingLaunch | None:
        with self._lock:
            return self._pending_launches.pop(launch_token, None)

    def _make_session_id(self, engine: str) -> str:
        return f"{engine}-{uuid.uuid4().hex[:8]}"

    def _link_pending_launch(self, session: SessionRecord) -> None:
        launch_token = str(session.metadata.get("launch_token") or "")
        if not launch_token:
            return
        pending = self._pending_launches.get(launch_token)
        if session.engine == "headless":
            session.source = "manager_created"
            session.closable = True
        if pending is None:
            return
        session.source = "manager_created"
        session.closable = pending.engine == "headless"
        if pending.pid is not None:
            session.owner_pid = pending.pid
        if pending.metadata:
            merged = dict(pending.metadata)
            merged.update(session.metadata)
            session.metadata = merged
        self._pending_launches.pop(launch_token, None)

    def register_session(self, payload: dict[str, Any]) -> SessionRecord:
        session_data = payload["session"]
        requested_id = payload.get("session_id")
        with self._lock:
            record = None
            if requested_id:
                record = self._sessions.get(requested_id)
            if record is None:
                for candidate in self._sessions.values():
                    if (
                        candidate.owner_pid == session_data.get("owner_pid")
                        and candidate.endpoint.get("url") == session_data.get("endpoint", {}).get("url")
                    ):
                        record = candidate
                        break
            if record is None:
                endpoint = dict(session_data.get("endpoint", {}))
                if endpoint.get("url"):
                    candidates = candidate_endpoint_urls(endpoint["url"])
                    endpoint["url"] = candidates[0]
                else:
                    candidates = []
                session_id = requested_id or self._make_session_id(session_data["engine"])
                metadata = dict(session_data.get("metadata", {}))
                if candidates:
                    metadata["endpoint_candidates"] = candidates
                record = SessionRecord(
                    session_id=session_id,
                    engine=session_data["engine"],
                    display_name=session_data.get("display_name", session_data["engine"]),
                    binary_path=session_data.get("binary_path", ""),
                    idb_path=session_data.get("idb_path", ""),
                    binary_hash=session_data.get("binary_hash", ""),
                    status=session_data.get("status", "ready"),
                    source="plugin_discovered",
                    capabilities=list(session_data.get("capabilities", [])),
                    endpoint=endpoint,
                    owner_pid=session_data.get("owner_pid"),
                    metadata=metadata,
                    closable=False,
                )
                self._sessions[record.session_id] = record
            else:
                endpoint = dict(session_data.get("endpoint", {}))
                if endpoint.get("url"):
                    candidates = candidate_endpoint_urls(endpoint["url"])
                    endpoint["url"] = candidates[0]
                else:
                    candidates = []
                metadata = dict(session_data.get("metadata", {}))
                if candidates:
                    metadata["endpoint_candidates"] = candidates
                record.engine = session_data["engine"]
                record.display_name = session_data.get("display_name", record.display_name)
                record.binary_path = session_data.get("binary_path", record.binary_path)
                record.idb_path = session_data.get("idb_path", record.idb_path)
                record.binary_hash = session_data.get("binary_hash", record.binary_hash)
                record.status = session_data.get("status", "ready")
                record.capabilities = list(session_data.get("capabilities", []))
                record.endpoint = endpoint
                record.owner_pid = session_data.get("owner_pid", record.owner_pid)
                record.metadata = metadata
            record.metadata.pop("unregister_reason", None)
            record.last_seen = utc_now()
            self._link_pending_launch(record)
            if self._current_session_id is None:
                self.select_session(record.session_id)
            return record

    def register_managed_session(
        self,
        *,
        engine: str,
        display_name: str,
        binary_path: str,
        idb_path: str,
        owner_pid: int | None,
        endpoint_url: str,
        metadata: dict[str, Any] | None = None,
    ) -> SessionRecord:
        with self._lock:
            candidates = candidate_endpoint_urls(endpoint_url)
            session_metadata = dict(metadata or {})
            session_metadata["endpoint_candidates"] = candidates
            record = SessionRecord(
                session_id=self._make_session_id(engine),
                engine=engine,
                display_name=display_name,
                binary_path=binary_path,
                idb_path=idb_path,
                binary_hash="",
                status="starting",
                source="manager_created",
                capabilities=[],
                endpoint={"transport": "streamable-http", "url": candidates[0]},
                owner_pid=owner_pid,
                metadata=session_metadata,
                closable=engine == "headless",
            )
            self._sessions[record.session_id] = record
            self.select_session(record.session_id)
            return record

    def update_managed_session(
        self,
        session_id: str,
        *,
        status: str | None = None,
        capabilities: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        owner_pid: int | None = None,
    ) -> SessionRecord | None:
        with self._lock:
            record = self._sessions.get(session_id)
            if record is None:
                return None
            if status is not None:
                record.status = status
            if capabilities is not None:
                record.capabilities = capabilities
            if metadata:
                record.metadata.update(metadata)
            if owner_pid is not None:
                record.owner_pid = owner_pid
            record.metadata.pop("unregister_reason", None)
            record.last_seen = utc_now()
            return record

    def heartbeat(self, session_id: str, payload: dict[str, Any]) -> SessionRecord | None:
        with self._lock:
            record = self._sessions.get(session_id)
            if record is None:
                return None
            record.last_seen = utc_now()
            record.status = payload.get("status", record.status)
            record.metadata.update(
                {
                    "current_address": payload.get("current_address", ""),
                    "current_function": payload.get("current_function", ""),
                    "busy": payload.get("busy", False),
                }
            )
            record.metadata.pop("unregister_reason", None)
            return record

    def unregister(self, session_id: str, reason: str) -> SessionRecord | None:
        with self._lock:
            record = self._sessions.get(session_id)
            if record is None:
                return None
            record.status = "dead"
            record.metadata["unregister_reason"] = reason
            record.last_seen = utc_now()
            if self._current_session_id == session_id:
                self._current_session_id = None
                record.current = False
            return record

    def _effective_status(self, record: SessionRecord) -> str:
        if record.status == "dead":
            return "dead"
        if record.source == "manager_created" and record.engine == "headless":
            return record.status
        if utc_now() - record.last_seen > self.stale_after:
            return "stale"
        return record.status

    def list_sessions(self, include_dead: bool = False) -> list[SessionRecord]:
        with self._lock:
            sessions = []
            for record in self._sessions.values():
                effective = self._effective_status(record)
                if not include_dead and effective == "dead":
                    continue
                record.status = effective
                record.current = record.session_id == self._current_session_id
                sessions.append(record)
            sessions.sort(key=lambda item: (not item.current, item.engine, item.display_name.lower()))
            return sessions

    def get_session(self, session_id: str | None) -> SessionRecord | None:
        with self._lock:
            if session_id is None:
                session_id = self._current_session_id
            if session_id is None:
                return None
            record = self._sessions.get(session_id)
            if record is None:
                return None
            record.status = self._effective_status(record)
            record.current = record.session_id == self._current_session_id
            return record

    def select_session(self, session_id: str) -> SessionRecord | None:
        with self._lock:
            record = self._sessions.get(session_id)
            if record is None:
                return None
            for item in self._sessions.values():
                item.current = False
            self._current_session_id = session_id
            record.current = True
            return record

    def find_candidates(self, *, engine: str | None = None, binary_name: str | None = None, binary_path: str | None = None) -> list[SessionRecord]:
        with self._lock:
            result = []
            for record in self._sessions.values():
                if self._effective_status(record) not in {"ready", "busy"}:
                    continue
                if engine and record.engine != engine:
                    continue
                if binary_path and record.binary_path.lower() != binary_path.lower():
                    continue
                if binary_name and record.display_name.lower() != binary_name.lower():
                    continue
                result.append(record)
            return result
