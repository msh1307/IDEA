import os
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ida_hybrid_manager.launch import IdaLauncher, STAGE_METADATA_NAME, _default_stage_root


class StageRootTests(unittest.TestCase):
    def test_stage_root_defaults_under_temp(self) -> None:
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("IDA_MCP_STAGE_ROOT", None)
            self.assertEqual(_default_stage_root(Path("/tmp/manager")), Path("/tmp/manager/staged"))

    def test_stage_root_accepts_windows_drive(self) -> None:
        with patch.dict(os.environ, {"IDA_MCP_STAGE_ROOT": r"E:\ida-stage"}):
            self.assertEqual(_default_stage_root(Path("/tmp/manager")), Path("/mnt/e/ida-stage"))

    def test_recover_staged_metadata_is_root_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            launcher = IdaLauncher.__new__(IdaLauncher)
            launcher.wsl_temp = Path(root) / "temp"
            launcher.stage_root = Path(root) / "stage"
            staged = launcher.stage_root / "0123456789ab"
            staged.mkdir(parents=True)
            metadata = {"source_idb_wsl_path": "/source/input.i64"}
            (staged / STAGE_METADATA_NAME).write_text(json.dumps(metadata), encoding="utf-8")

            recovered = launcher.recover_staged_metadata(str(staged / "input.i64"))
            self.assertEqual(recovered["source_idb_wsl_path"], "/source/input.i64")
            self.assertEqual(recovered["staged_dir"], str(staged))
            self.assertEqual(recovered["staged_idb_path"], str(staged / "input.i64"))
            self.assertEqual(launcher.recover_staged_metadata(str(Path(root) / "outside" / "input.i64")), {})
            (staged / STAGE_METADATA_NAME).unlink()
            self.assertEqual(launcher.recover_staged_metadata(str(staged / "input.i64")), {})

    def test_cleanup_refuses_unmanaged_directory(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            launcher = IdaLauncher.__new__(IdaLauncher)
            launcher.wsl_temp = Path(root) / "temp"
            launcher.stage_root = Path(root) / "stage"
            outside = Path(root) / "0123456789ab"
            outside.mkdir()
            with self.assertRaises(ValueError):
                launcher.cleanup_staged_dir(str(outside))
            self.assertTrue(outside.exists())


if __name__ == "__main__":
    unittest.main()
