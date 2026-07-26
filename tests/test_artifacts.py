import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ida_hybrid_manager import server


class ArtifactTests(unittest.TestCase):
    def test_large_daemon_result_is_replaced_by_artifact_handle(self) -> None:
        with tempfile.TemporaryDirectory() as root, patch.object(server, "MCP_ARTIFACT_DIR", Path(root)), patch.object(
            server, "MCP_INLINE_RESULT_BYTES", 512
        ), patch.object(server, "MCP_ARTIFACT_MAX_BYTES", 4096), patch.object(
            server, "_artifact_cleanup_last_at", 0.0
        ):
            payload = {"meta": {"session_id": "session-1"}, "code": "x" * 2048}
            bounded, artifact = server._externalize_result(payload)

            self.assertIsNotNone(artifact)
            self.assertEqual(bounded["artifact_id"], artifact["artifact_id"])
            self.assertEqual(bounded["session_id"], "session-1")
            stored = json.loads(Path(bounded["path"]).read_text(encoding="utf-8"))
            self.assertEqual(stored, payload)

            repeated, repeated_artifact = server._externalize_result(bounded)
            self.assertEqual(repeated, bounded)
            self.assertIsNone(repeated_artifact)

    def test_result_larger_than_total_artifact_budget_fails_compactly(self) -> None:
        with tempfile.TemporaryDirectory() as root, patch.object(server, "MCP_ARTIFACT_DIR", Path(root)), patch.object(
            server, "MCP_INLINE_RESULT_BYTES", 32
        ), patch.object(server, "MCP_ARTIFACT_MAX_BYTES", 64), patch.object(
            server, "_artifact_cleanup_last_at", 0.0
        ):
            bounded, artifact = server._externalize_result({"code": "x" * 256})

            self.assertIsNone(artifact)
            self.assertEqual(bounded["error"], "result_exceeds_artifact_limit")
            self.assertFalse(list(Path(root).glob("*.json")))


if __name__ == "__main__":
    unittest.main()
