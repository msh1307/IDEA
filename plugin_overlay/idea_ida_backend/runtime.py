from __future__ import annotations

import socket
import time

from .bridge import ManagerBridge
from .server import NativeToolServer


def pick_listen_port(host: str, preferred_port: int, max_tries: int = 32) -> int:
    for port in range(preferred_port, preferred_port + max_tries):
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind((host, port))
            return port
        except OSError:
            continue
        finally:
            probe.close()
    raise OSError(f"No free port available in range starting at {preferred_port}")


class IdeaIdaRuntime:
    def __init__(self) -> None:
        self.server = NativeToolServer()
        self.bridge: ManagerBridge | None = None
        self.host = "0.0.0.0"
        self.port = 0
        self.engine = "gui"

    @property
    def running(self) -> bool:
        return self.server._running

    def start(
        self,
        host: str,
        port: int,
        *,
        background: bool = True,
        engine: str = "gui",
        launch_token: str | None = None,
    ) -> int:
        self.host = host
        self.port = port
        self.engine = engine
        self.server.start(host, port)
        if self.bridge is None:
            self.bridge = ManagerBridge(host, port, engine=engine, launch_token=launch_token)
        else:
            self.bridge.update_endpoint(host, port, engine=engine, launch_token=launch_token)
        self.bridge.start()
        self.bridge.request_refresh("server_started")
        if not background:
            try:
                while self.running:
                    time.sleep(3600)
            finally:
                self.stop("headless_exit")
        return port

    def refresh_session(self, reason: str = "manual_refresh") -> None:
        if self.bridge is not None:
            self.bridge.request_refresh(reason)

    def unregister_session(self, reason: str = "manual_unregister") -> None:
        if self.bridge is not None:
            self.bridge._send_unregister(reason)

    def stop(self, reason: str = "shutdown") -> None:
        if self.bridge is not None:
            self.bridge.stop(reason)
        if self.running:
            self.server.stop()
