"""IDA Pro MCP Plugin Loader

This file serves as the entry point for IDA Pro's plugin system.
It loads the actual implementation from the ida_mcp package.
"""

import sys
import idaapi
import ida_idaapi
import ida_netnode
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import ida_mcp


def unload_package(package_name: str):
    """Remove every module that belongs to the package from sys.modules."""
    to_remove = [
        mod_name
        for mod_name in sys.modules
        if mod_name == package_name or mod_name.startswith(package_name + ".")
    ]
    for mod_name in to_remove:
        del sys.modules[mod_name]


class MCP(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "MCP Plugin"
    help = "MCP"
    wanted_name = "MCP"
    wanted_hotkey = "Ctrl-Alt-M"

    # TODO: make these configurable
    HOST = "0.0.0.0"
    PORT = 13337

    def __init__(self):
        super().__init__()
        self.mcp: "ida_mcp.rpc.McpServer | None" = None
        self.runtime: "ida_mcp.IdaMcpRuntime | None" = None
        self.port = MCP.PORT

    @staticmethod
    def _config_json_get(key: str, default):
        node = ida_netnode.netnode(f"$ ida_mcp.{key}")
        blob = node.getblob(0, "C")
        if blob is None:
            return default
        try:
            import json

            return json.loads(blob)
        except Exception:
            return default

    @staticmethod
    def _config_bool(key: str, default: bool) -> bool:
        return bool(MCP._config_json_get(key, default))

    @staticmethod
    def _config_int(key: str, default: int) -> int:
        value = MCP._config_json_get(key, default)
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def _load_runtime(self):
        unload_package("ida_mcp")
        if TYPE_CHECKING:
            from .ida_mcp import IdaMcpRuntime, pick_listen_port
        else:
            from ida_mcp import IdaMcpRuntime, pick_listen_port

        self.runtime = IdaMcpRuntime()
        self._pick_listen_port = pick_listen_port

    def _ensure_started(self, reason: str):
        if self.runtime is None:
            self._load_runtime()
        assert self.runtime is not None
        if self.runtime.running:
            self.runtime.refresh_session(reason)
            self.mcp = self.runtime.server
            return

        base_port = self._config_int("port", MCP.PORT)
        self.port = self._pick_listen_port(self.HOST, base_port)
        self.runtime.start(self.HOST, self.port, background=True, engine="gui")
        print(f"[MCP] Server ready on http://{self.HOST}:{self.port}/mcp ({reason})")
        self.mcp = self.runtime.server

    def _notify_handler(self, code, old=0):
        if code == ida_idaapi.NW_OPENIDB:
            self._ensure_started("database_opened")
        elif code == ida_idaapi.NW_CLOSEIDB:
            if self.runtime is not None:
                self.runtime.unregister_session("database_closed")
        elif code == ida_idaapi.NW_TERMIDA:
            when = (
                ida_idaapi.NW_TERMIDA
                | ida_idaapi.NW_OPENIDB
                | ida_idaapi.NW_CLOSEIDB
                | ida_idaapi.NW_REMOVE
            )
            ida_idaapi.notify_when(when, self._notify_handler)

    def init(self):
        hotkey = MCP.wanted_hotkey.replace("-", "+")
        if __import__("sys").platform == "darwin":
            hotkey = hotkey.replace("Alt", "Option")

        print(
            f"[MCP] Plugin loaded, use Edit -> Plugins -> MCP ({hotkey}) to restart the server"
        )
        when = ida_idaapi.NW_TERMIDA | ida_idaapi.NW_OPENIDB | ida_idaapi.NW_CLOSEIDB
        ida_idaapi.notify_when(when, self._notify_handler)
        if self._config_bool("auto_start", True):
            self._ensure_started("auto_start")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        if self.runtime and self.runtime.running:
            self.runtime.stop("manual_restart")
            self.runtime = None
            self.mcp = None
        self._ensure_started("manual_restart")
        print(f"  Config: http://{self.HOST}:{self.port}/config.html")

    def term(self):
        if self.runtime is not None:
            self.runtime.stop("ida_exit")


def PLUGIN_ENTRY():
    return MCP()


# IDA plugin flags
PLUGIN_FLAGS = idaapi.PLUGIN_HIDE | idaapi.PLUGIN_FIX
