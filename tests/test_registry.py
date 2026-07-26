import unittest

from ida_hybrid_manager.registry import SessionRegistry


class RegistryOperationTests(unittest.TestCase):
    def test_removed_session_does_not_suppress_operation_error(self) -> None:
        registry = SessionRegistry()
        record = registry.register_managed_session(
            engine="headless",
            display_name="sample",
            binary_path="",
            idb_path="",
            owner_pid=None,
            endpoint_url="http://127.0.0.1:12345",
        )
        registry.update_managed_session(record.session_id, status="ready")

        with self.assertRaisesRegex(RuntimeError, "operation failed"):
            with registry.track_operation(record.session_id):
                with registry._lock:
                    registry._sessions.pop(record.session_id)
                raise RuntimeError("operation failed")


if __name__ == "__main__":
    unittest.main()
