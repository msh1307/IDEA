from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .registry import SessionRegistry


class ManagerApiServer:
    def __init__(self, registry: SessionRegistry, host: str = "0.0.0.0", port: int = 18080) -> None:
        self.registry = registry
        self.host = host
        self.port = port
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        registry = self.registry

        class Handler(BaseHTTPRequestHandler):
            def _json(self, status: int, payload: dict[str, Any]) -> None:
                body = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:
                if self.path == "/healthz":
                    self._json(200, {"ok": True})
                    return
                self._json(404, {"ok": False, "error": "not_found"})

            def do_POST(self) -> None:
                content_length = int(self.headers.get("Content-Length", "0"))
                try:
                    payload = json.loads(self.rfile.read(content_length).decode("utf-8")) if content_length else {}
                except json.JSONDecodeError:
                    self._json(400, {"ok": False, "error": "invalid_json"})
                    return

                if self.path == "/api/sessions/register":
                    record = registry.register_session(payload)
                    self._json(200, {"ok": True, "session_id": record.session_id, "heartbeat_interval_sec": 10})
                    return
                if self.path == "/api/sessions/heartbeat":
                    record = registry.heartbeat(payload.get("session_id", ""), payload)
                    if record is None:
                        self._json(404, {"ok": False, "error": "unknown_session"})
                    else:
                        self._json(200, {"ok": True})
                    return
                if self.path == "/api/sessions/unregister":
                    record = registry.unregister(payload.get("session_id", ""), payload.get("reason", ""))
                    if record is None:
                        self._json(404, {"ok": False, "error": "unknown_session"})
                    else:
                        self._json(200, {"ok": True})
                    return
                self._json(404, {"ok": False, "error": "not_found"})

            def log_message(self, format: str, *args) -> None:
                return

        self._httpd = ThreadingHTTPServer((self.host, self.port), Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, name="ida-hybrid-manager-api", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
