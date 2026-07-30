import tempfile
import unittest
from pathlib import Path

from scripts.install_claude_config import SERVER_NAME, upsert, windows_entry


class ClaudeInstallConfigTests(unittest.TestCase):
    def test_upsert_preserves_other_servers_and_replaces_legacy_ida(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / ".claude.json"
            path.write_text(
                '{"other":1,"mcpServers":{"keep":{"command":"keep"},"ida-pro-mcp":{"command":"old"}}}',
                encoding="utf-8",
            )
            entry = {"type": "stdio", "command": "new", "args": []}
            self.assertEqual(upsert(path, entry), "updated")
            payload = __import__("json").loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["other"], 1)
            self.assertIn("keep", payload["mcpServers"])
            self.assertNotIn("ida-pro-mcp", payload["mcpServers"])
            self.assertEqual(payload["mcpServers"][SERVER_NAME], entry)
            self.assertEqual(upsert(path, entry), "unchanged")

    def test_windows_entry_uses_shared_config_launcher(self) -> None:
        settings = {"fallback_root": r"E:\ida-hybrid-manager\native"}
        entry = windows_entry(
            settings,
            r"C:\Users\msh\AppData\Local\ida-hybrid-manager\config.json",
        )
        self.assertEqual(entry["command"], "powershell.exe")
        self.assertIn(r"E:\ida-hybrid-manager\native\run_manager_fallback.ps1", entry["args"])
        self.assertIn(r"C:\Users\msh\AppData\Local\ida-hybrid-manager\config.json", entry["args"])


if __name__ == "__main__":
    unittest.main()
