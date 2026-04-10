from __future__ import annotations

from contextlib import contextmanager
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
        self.stale_after = timedelta(seconds=30)

    def _attach_client_unlocked(
        self,
        record: SessionRecord,
        client_id: str | None,
        *,
        refresh_snapshot: bool = False,
    ) -> SessionRecord:
        if not client_id:
            return record
        entry = dict(record.attached_clients.get(client_id, {}))
        entry["attached_at"] = entry.get("attached_at") or utc_now()
        entry["last_seen"] = utc_now()
        if refresh_snapshot or "last_seen_txid" not in entry:
            entry["last_seen_txid"] = record.txid
        record.attached_clients[client_id] = entry
        return record

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

    def attach_client(
        self,
        session_id: str,
        client_id: str | None,
        *,
        refresh_snapshot: bool = False,
    ) -> SessionRecord | None:
        with self._lock:
            record = self._sessions.get(session_id)
            if record is None:
                return None
            if record.closing or record.status == "dead":
                return None
            record.last_seen = utc_now()
            return self._attach_client_unlocked(record, client_id, refresh_snapshot=refresh_snapshot)

    def touch_client(self, session_id: str, client_id: str | None) -> SessionRecord | None:
        with self._lock:
            record = self._sessions.get(session_id)
            if record is None:
                return None
            if client_id and client_id in record.attached_clients:
                record.attached_clients[client_id]["last_seen"] = utc_now()
                record.attached_clients[client_id]["last_seen_txid"] = record.txid
            record.last_seen = utc_now()
            return record

    def get_client_attachment(self, session_id: str, client_id: str | None) -> dict[str, Any] | None:
        if not client_id:
            return None
        with self._lock:
            record = self._sessions.get(session_id)
            if record is None:
                return None
            entry = record.attached_clients.get(client_id)
            return dict(entry) if isinstance(entry, dict) else None

    def get_attachment_count(self, session_id: str) -> int:
        with self._lock:
            record = self._sessions.get(session_id)
            if record is None:
                return 0
            return len(record.attached_clients)

    def get_txid(self, session_id: str) -> int | None:
        with self._lock:
            record = self._sessions.get(session_id)
            if record is None:
                return None
            return record.txid

    @contextmanager
    def track_operation(self, session_id: str):
        with self._lock:
            record = self._sessions.get(session_id)
            if record is None:
                raise ValueError(f"Unknown session: {session_id}")
            if record.closing or record.status == "dead":
                raise ValueError(f"Session {session_id} is closing")
            record.active_ops += 1
            record.last_seen = utc_now()
        try:
            yield record
        finally:
            with self._lock:
                current = self._sessions.get(session_id)
                if current is None:
                    return
                current.active_ops = max(0, int(current.active_ops) - 1)
                current.last_seen = utc_now()

    @contextmanager
    def acquire_write_lock(self, session_id: str):
        with self._lock:
            record = self._sessions.get(session_id)
            if record is None:
                raise ValueError(f"Unknown session: {session_id}")
            lock = record.write_lock
        lock.acquire()
        try:
            yield record
        finally:
            lock.release()

    def bump_txid(self, session_id: str, client_id: str | None, tool_name: str) -> SessionRecord | None:
        with self._lock:
            record = self._sessions.get(session_id)
            if record is None:
                return None
            record.txid += 1
            record.last_writer_client_id = client_id
            record.last_write_at = utc_now()
            record.metadata["last_write_tool"] = tool_name
            record.metadata["last_write_txid"] = record.txid
            if client_id:
                entry = record.attached_clients.get(client_id, {})
                entry["last_seen"] = utc_now()
                entry["last_seen_txid"] = record.txid
                record.attached_clients[client_id] = entry
            record.last_seen = utc_now()
            return record

    def detach_client(self, client_id: str | None) -> list[SessionRecord]:
        detached: list[SessionRecord] = []
        if not client_id:
            return detached
        with self._lock:
            for record in self._sessions.values():
                if client_id not in record.attached_clients:
                    continue
                record.attached_clients.pop(client_id, None)
                record.last_seen = utc_now()
                detached.append(record)
        return detached

    def begin_close(
        self,
        session_id: str,
        *,
        client_id: str | None = None,
        force: bool = False,
        require_client_attached: bool = False,
    ) -> tuple[SessionRecord | None, dict[str, Any] | None]:
        with self._lock:
            record = self._sessions.get(session_id)
            if record is None:
                return None, {"ok": False, "error": f"Unknown session: {session_id}"}
            if record.closing:
                return None, {"ok": False, "error": f"Session {session_id} is already closing"}
            if require_client_attached and client_id and client_id not in record.attached_clients:
                return None, {"ok": False, "error": f"Client {client_id} is not attached to session {session_id}"}
            other_clients = [attached for attached in record.attached_clients if attached != client_id]
            if other_clients and not force:
                return None, {
                    "ok": False,
                    "error": "Session is still attached by other clients",
                    "attached_client_count": len(record.attached_clients),
                    "other_clients": other_clients,
                }
            if record.active_ops > 0 and not force:
                return None, {
                    "ok": False,
                    "error": "Session still has active operations",
                    "active_ops": record.active_ops,
                }
            record.closing = True
            record.last_seen = utc_now()
            return record, None

    def cancel_close(self, session_id: str) -> SessionRecord | None:
        with self._lock:
            record = self._sessions.get(session_id)
            if record is None:
                return None
            if record.status != "dead":
                record.closing = False
                record.last_seen = utc_now()
            return record

    def unregister(self, session_id: str, reason: str) -> SessionRecord | None:
        with self._lock:
            record = self._sessions.get(session_id)
            if record is None:
                return None
            record.status = "dead"
            record.closing = False
            record.metadata["unregister_reason"] = reason
            record.last_seen = utc_now()
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
                sessions.append(record)
            sessions.sort(key=lambda item: (item.engine, item.display_name.lower()))
            return sessions

    def get_session(self, session_id: str | None) -> SessionRecord | None:
        with self._lock:
            if session_id is None:
                return None
            record = self._sessions.get(session_id)
            if record is None:
                return None
            record.status = self._effective_status(record)
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
