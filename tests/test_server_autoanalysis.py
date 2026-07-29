import time
import unittest
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch

from ida_hybrid_manager import server
from ida_hybrid_manager.models import PendingLaunch, utc_now
from ida_hybrid_manager.registry import SessionRegistry


def _stale_status() -> dict:
    return {
        "autoanalysis_complete": False,
        "status": "analyzing",
        "progress_percent": 7.14,
        "message": "AU_CODE / LOAD / 0x0",
        "phase": {"name": "AU_CODE"},
        "current": {"address": "0x0", "segment": "LOAD"},
        "function_total": 0,
        "text_segments": [],
        "source": "heartbeat",
        "checked_at": utc_now().isoformat(),
        "checked_at_epoch": time.time(),
    }


def _complete_status() -> dict:
    return {
        "autoanalysis_complete": True,
        "status": "complete",
        "progress_percent": 100.0,
        "message": "done",
        "phase": {"name": "done"},
        "current": {"address": "0x2000", "segment": ".text"},
        "function_total": 1,
        "text_segments": [{"text_like": True}],
        "source": "bridge",
        "checked_at": utc_now().isoformat(),
        "checked_at_epoch": time.time(),
    }


class WaitQueuedAutoanalysisTests(unittest.TestCase):
    def test_queued_wait_uses_backend_status_over_heartbeat(self) -> None:
        sample_session = SimpleNamespace(
            session_id="sess-queued-test",
            status="busy",
            endpoint={"url": "http://127.0.0.1:9999"},
            last_seen=utc_now(),
            metadata={"autoanalysis": _stale_status()},
        )
        probe_statuses = iter([_stale_status(), _complete_status(), _complete_status()])

        async def _probe(*_args, **_kwargs):
            return next(probe_statuses)

        with patch.object(
            server,
            "call_backend_tool_any",
            side_effect=_probe,
        ) as run_mock, patch.object(
            server,
            "registry",
            SimpleNamespace(get_session=lambda sid: sample_session),
        ), patch.object(
            server,
            "_backend_candidates",
            return_value=[{"url": "http://127.0.0.1:9999", "transport": "native-http"}],
        ), patch.object(
            server, "_update_session_autoanalysis", side_effect=lambda *_args, **_kwargs: _complete_status()
        ):
            result = server._wait_for_queued_autoanalysis("sess-queued-test", operation="open_binary", operation_id="op")

        self.assertTrue(result.get("autoanalysis_complete"))
        self.assertEqual(run_mock.call_count, 2)
        self.assertTrue(all(call.args[1] == "wait_for_autoanalysis" for call in run_mock.call_args_list))
        self.assertTrue(all(call.args[2].get("max_work_sec") == 0.5 for call in run_mock.call_args_list))

    def test_wait_for_session_stops_when_headless_process_exits(self) -> None:
        pending = PendingLaunch(
            launch_token="launch-test",
            binary_path="sample",
            idb_path="sample.i64",
            engine="headless",
            port=12345,
            pid=42,
        )
        with patch.object(server, "registry", SimpleNamespace(list_sessions=lambda include_dead=False: [])), patch.object(
            server,
            "_get_launcher",
            return_value=SimpleNamespace(is_process_alive=lambda _pid: False),
        ):
            result = server._wait_for_session(pending, timeout_sec=30)

        self.assertIsNone(result)
        self.assertTrue(pending.metadata["process_exited_before_register"])
        self.assertIn("exited before registering", server._session_wait_error(pending))

    def test_sweep_removes_stale_gui_when_owner_exited(self) -> None:
        registry = SessionRegistry()
        record = registry.register_session(
            {
                "session": {
                    "engine": "gui",
                    "display_name": "sample",
                    "binary_path": "sample",
                    "idb_path": "sample.i64",
                    "status": "ready",
                    "endpoint": {"url": "http://127.0.0.1:12345"},
                    "owner_pid": 42,
                }
            }
        )
        record.last_seen = utc_now() - timedelta(minutes=1)

        with patch.object(server, "registry", registry), patch.object(server, "_owner_pid_alive", return_value=False):
            server._sweep_unreachable_sessions()

        self.assertEqual(registry.get_session(record.session_id).status, "dead")


if __name__ == "__main__":
    unittest.main()
