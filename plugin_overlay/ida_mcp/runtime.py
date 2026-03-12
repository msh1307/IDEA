import socket

from .api_core import init_caches
from .http import IdaMcpHttpRequestHandler
from .rpc import MCP_SERVER
from .session_bridge import SessionBridge


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


class IdaMcpRuntime:
    def __init__(self):
        self.server = MCP_SERVER
        self.bridge: SessionBridge | None = None
        self.host = "0.0.0.0"
        self.port = 0
        self.engine = "gui"

    @property
    def running(self) -> bool:
        return bool(getattr(self.server, "_running", False))

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

        try:
            init_caches()
        except Exception as exc:
            print(f"[MCP] Cache init failed: {exc}")

        if self.bridge is None:
            self.bridge = SessionBridge(host, port, engine=engine, launch_token=launch_token)
        else:
            self.bridge.update_endpoint(host, port, engine=engine, launch_token=launch_token)

        if background:
            self.server.serve(
                host,
                port,
                background=True,
                request_handler=IdaMcpHttpRequestHandler,
            )
            self.bridge.start()
            self.bridge.request_refresh("server_started")
        else:
            self.bridge._send_register()
            self.server.serve(
                host,
                port,
                background=False,
                request_handler=IdaMcpHttpRequestHandler,
            )
        return port

    def refresh_session(self, reason: str = "manual_refresh"):
        if self.bridge is not None:
            self.bridge.request_refresh(reason)

    def unregister_session(self, reason: str = "manual_unregister"):
        if self.bridge is not None:
            self.bridge._send_unregister(reason)

    def stop(self, reason: str = "shutdown"):
        if self.bridge is not None:
            self.bridge.stop(reason)
        if self.running:
            self.server.stop()
