from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .tools import TOOL_DEFINITIONS, call_tool


class NativeToolServer:
    def __init__(self) -> None:
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._running = False

    def start(self, host: str, port: int) -> None:
        server = self

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
                    self._json(200, {"ok": True, "service": "idea-ida", "version": "0.1.0"})
                    return
                if self.path == "/api/tools/list":
                    self._json(
                        200,
                        {
                            "ok": True,
                            "server": {"name": "idea-ida", "version": "0.1.0", "transport": "native-http"},
                            "tools": TOOL_DEFINITIONS,
                        },
                    )
                    return
                self._json(404, {"ok": False, "error": "not_found"})

            def do_POST(self) -> None:
                content_length = int(self.headers.get("Content-Length", "0"))
                try:
                    payload = json.loads(self.rfile.read(content_length).decode("utf-8")) if content_length else {}
                except json.JSONDecodeError:
                    self._json(400, {"ok": False, "error": "invalid_json"})
                    return

                if self.path != "/api/tools/call":
                    self._json(404, {"ok": False, "error": "not_found"})
                    return

                tool_name = str(payload.get("tool_name") or "")
                arguments = payload.get("arguments")
                try:
                    result = call_tool(tool_name, arguments)
                except Exception as exc:
                    self._json(500, {"ok": False, "error": str(exc)})
                    return
                self._json(200, {"ok": True, "result": result})

            def log_message(self, format: str, *args) -> None:
                return

        self._httpd = ThreadingHTTPServer((host, port), Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, name="idea-ida-http", daemon=True)
        self._thread.start()
        self._running = True

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        self._running = False
