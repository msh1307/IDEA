import os
import sys

import ida_idaapi
import ida_netnode
import idaapi


def unload_package(package_name: str) -> None:
    to_remove = [name for name in sys.modules if name == package_name or name.startswith(package_name + ".")]
    for name in to_remove:
        del sys.modules[name]


class IDEA(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "IDEA raw API backend"
    help = "IDEA raw API backend"
    wanted_name = "IDEA Raw API"
    wanted_hotkey = "Ctrl-Alt-I"

    HOST = "0.0.0.0"
    PORT = 13337

    def __init__(self):
        super().__init__()
        self.runtime = None
        self.port = IDEA.PORT

    @staticmethod
    def _config_json_get(key: str, default):
        node = ida_netnode.netnode(f"$ idea_ida.{key}")
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
        env = os.getenv(f"IDEA_IDA_{key.upper()}")
        if env is not None:
            return env.strip().lower() not in {"0", "false", "no", "off"}
        return bool(IDEA._config_json_get(key, default))

    @staticmethod
    def _config_int(key: str, default: int) -> int:
        env = os.getenv(f"IDEA_IDA_{key.upper()}")
        if env:
            try:
                return int(env)
            except ValueError:
                return default
        value = IDEA._config_json_get(key, default)
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def _load_runtime(self) -> None:
        unload_package("idea_ida_backend")
        from idea_ida_backend import IdeaIdaRuntime, pick_listen_port

        self.runtime = IdeaIdaRuntime()
        self._pick_listen_port = pick_listen_port

    def _ensure_started(self, reason: str) -> None:
        if self.runtime is None:
            self._load_runtime()
        assert self.runtime is not None
        if self.runtime.running:
            self.runtime.refresh_session(reason)
            return
        base_port = self._config_int("port", IDEA.PORT)
        self.port = self._pick_listen_port(self.HOST, base_port)
        self.runtime.start(self.HOST, self.port, background=True, engine="gui")
        print(f"[IDEA] Server ready on http://{self.HOST}:{self.port} ({reason})")

    def _notify_handler(self, code, old=0):
        if code == ida_idaapi.NW_OPENIDB:
            self._ensure_started("database_opened")
        elif code == ida_idaapi.NW_CLOSEIDB:
            if self.runtime is not None:
                self.runtime.unregister_session("database_closed")
        elif code == ida_idaapi.NW_TERMIDA:
            when = ida_idaapi.NW_TERMIDA | ida_idaapi.NW_OPENIDB | ida_idaapi.NW_CLOSEIDB | ida_idaapi.NW_REMOVE
            ida_idaapi.notify_when(when, self._notify_handler)

    def init(self):
        hotkey = IDEA.wanted_hotkey.replace("-", "+")
        print(f"[IDEA] Plugin loaded, use Edit -> Plugins -> IDEA Raw API ({hotkey}) to restart the server")
        when = ida_idaapi.NW_TERMIDA | ida_idaapi.NW_OPENIDB | ida_idaapi.NW_CLOSEIDB
        ida_idaapi.notify_when(when, self._notify_handler)
        if self._config_bool("auto_start", True):
            self._ensure_started("auto_start")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        if self.runtime is not None and self.runtime.running:
            self.runtime.stop("manual_restart")
            self.runtime = None
        self._ensure_started("manual_restart")

    def term(self):
        if self.runtime is not None:
            self.runtime.stop("ida_exit")


def PLUGIN_ENTRY():
    return IDEA()


PLUGIN_FLAGS = idaapi.PLUGIN_HIDE | idaapi.PLUGIN_FIX
