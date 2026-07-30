import unittest
from pathlib import Path

from scripts.install_codex_config import (
    render_env_inline_table,
    render_windows_fallback_block,
    render_windows_server_block,
    render_wsl_server_block,
)
from scripts.install_manager_config import _windows_path, _wsl_path


class InstallConfigTests(unittest.TestCase):
    def test_installed_profiles_default_to_lite(self) -> None:
        repo = Path("/root/ida-hybrid-manager")
        wsl = render_wsl_server_block(repo, "127.0.0.1", r"C:\IDA", r"E:\stage")
        windows = render_windows_server_block(repo, "127.0.0.1", r"C:\IDA", r"E:\stage")
        self.assertIn('IDA_MCP_PROFILE = "lite"', wsl)
        self.assertIn('"IDA_MCP_PROFILE=lite"', windows)
        self.assertIn("IDA_MCP_STAGE_ROOT = '/mnt/e/stage'", wsl)
        self.assertIn('"IDA_MCP_STAGE_ROOT=/mnt/e/stage"', windows)

    def test_windows_fallback_uses_native_launcher_and_windows_stage_path(self) -> None:
        block = render_windows_fallback_block(
            "/mnt/e/ida-hybrid-manager-native",
            Path("/root/ida-hybrid-manager"),
            r"C:\IDA",
            "/mnt/e/stage",
        )
        self.assertIn('command = "powershell.exe"', block)
        self.assertIn(r'"E:\\ida-hybrid-manager-native\\run_manager_fallback.ps1"', block)
        self.assertIn(r'"E:\\stage"', block)

    def test_windows_fallback_can_use_single_install_config(self) -> None:
        block = render_windows_fallback_block(
            "/mnt/e/ida-hybrid-manager/native",
            Path("/root/ida-hybrid-manager"),
            r"C:\IDA",
            install_config=r"C:\Users\msh\AppData\Local\ida-hybrid-manager\config.json",
        )
        self.assertIn('"-Config"', block)
        self.assertIn(r'"C:\\Users\\msh\\AppData\\Local\\ida-hybrid-manager\\config.json"', block)
        self.assertNotIn('"-Distro"', block)

    def test_root_path_conversion_and_managed_data_env(self) -> None:
        self.assertEqual(_windows_path("/mnt/e/ida-hybrid-manager"), r"E:\ida-hybrid-manager")
        self.assertEqual(_wsl_path(r"E:\ida-hybrid-manager\native"), "/mnt/e/ida-hybrid-manager/native")
        env = render_env_inline_table(
            "127.0.0.1",
            r"C:\IDA",
            r"E:\ida-hybrid-manager\staging",
            windows_temp=r"E:\ida-hybrid-manager\temp",
            artifact_root=r"E:\ida-hybrid-manager\artifacts",
            replay_root=r"E:\ida-hybrid-manager\replay",
        )
        self.assertIn("IDA_WSL_TEMP = '/mnt/e/ida-hybrid-manager/temp'", env)
        self.assertIn("IDA_MCP_ARTIFACT_DIR = '/mnt/e/ida-hybrid-manager/artifacts'", env)


if __name__ == "__main__":
    unittest.main()
