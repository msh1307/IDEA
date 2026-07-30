import os
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ida_hybrid_manager import launch
from ida_hybrid_manager.launch import IdaLauncher, STAGE_METADATA_NAME, _default_stage_root, _default_temp_root
from ida_hybrid_manager.pathing import to_windows_path


class StageRootTests(unittest.TestCase):
    def test_windows_temp_ignores_wsl_only_override(self) -> None:
        with patch.object(launch.HOST, "native_windows", True), patch.dict(
            os.environ, {"IDA_WSL_TEMP": "/tmp/wsl-only"}
        ):
            self.assertEqual(_default_temp_root(r"E:\Temp"), r"E:\Temp")

    def test_windows_path_accepts_wsl_drive_root(self) -> None:
        self.assertEqual(to_windows_path("/mnt/e"), "E:\\")

    def test_stage_root_defaults_under_temp(self) -> None:
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("IDA_MCP_STAGE_ROOT", None)
            self.assertEqual(_default_stage_root(Path("/tmp/manager")), Path("/tmp/manager/staged"))

    def test_stage_root_accepts_windows_drive(self) -> None:
        with patch.dict(os.environ, {"IDA_MCP_STAGE_ROOT": r"E:\ida-stage"}):
            self.assertEqual(_default_stage_root(Path("/tmp/manager")), Path("/mnt/e/ida-stage"))

    def test_stage_root_rejects_windows_drive_relative_path(self) -> None:
        with patch.dict(os.environ, {"IDA_MCP_STAGE_ROOT": r"E:ida-stage"}):
            with self.assertRaisesRegex(ValueError, "drive-relative"):
                _default_stage_root(Path("/tmp/manager"))

    def test_recover_staged_metadata_is_root_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            launcher = IdaLauncher.__new__(IdaLauncher)
            launcher.temp_root = Path(root) / "temp"
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
            launcher.temp_root = Path(root) / "temp"
            launcher.stage_root = Path(root) / "stage"
            outside = Path(root) / "0123456789ab"
            outside.mkdir()
            with self.assertRaises(ValueError):
                launcher.cleanup_staged_dir(str(outside))
            self.assertTrue(outside.exists())

    def test_architecture_script_sets_application_and_segment_bitness(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            launcher = IdaLauncher.__new__(IdaLauncher)
            launcher.temp_root = Path(root)
            architecture = {
                "processor": "ARM",
                "compiler": None,
                "bitness": 32,
                "thumb_mode": None,
                "thumb_address": None,
            }
            with patch("ida_hybrid_manager.launch.to_windows_path", side_effect=lambda path: path):
                script_path = launcher._write_architecture_script("token", architecture)
            source = Path(script_path).read_text(encoding="utf-8")
            compile(source, script_path, "exec")
            self.assertIn("ida_ida.inf_set_app_bitness(bitness)", source)
            self.assertIn("idc.set_segm_addressing", source)

    def test_start_process_returns_pid_without_waiting_for_wrapper_exit(self) -> None:
        launcher = IdaLauncher.__new__(IdaLauncher)

        class Wrapper:
            def __init__(self) -> None:
                self.stdout = io.StringIO("1234\n")
                self.returncode = None
                self.terminated = False

            def poll(self):
                return self.returncode

            def terminate(self) -> None:
                self.terminated = True
                self.returncode = -15

            def wait(self, timeout=None):
                return self.returncode

            def kill(self) -> None:
                self.returncode = -9

        wrapper = Wrapper()
        with patch("ida_hybrid_manager.host.subprocess.Popen", return_value=wrapper), patch(
            "ida_hybrid_manager.host.select.select",
            return_value=([wrapper.stdout], [], []),
        ):
            pid = launcher._start_process(r"C:\IDA\idat.exe", ["sample.i64"])

        self.assertEqual(pid, 1234)
        self.assertTrue(wrapper.terminated)


if __name__ == "__main__":
    unittest.main()
