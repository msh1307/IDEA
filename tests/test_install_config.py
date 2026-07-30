import unittest
from pathlib import Path

from scripts.install_codex_config import (
    render_windows_fallback_block,
    render_windows_server_block,
    render_wsl_server_block,
)


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
            r"E:\ida-hybrid-manager-native",
            Path("/root/ida-hybrid-manager"),
            r"C:\IDA",
            "/mnt/e/stage",
        )
        self.assertIn('command = "powershell.exe"', block)
        self.assertIn(r'"E:\\ida-hybrid-manager-native\\run_manager_fallback.ps1"', block)
        self.assertIn(r'"E:\\stage"', block)


if __name__ == "__main__":
    unittest.main()
