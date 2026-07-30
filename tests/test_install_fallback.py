import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
INSTALLER = REPO_ROOT / "scripts" / "install_windows_fallback.sh"


class WindowsFallbackInstallTests(unittest.TestCase):
    def _run(self, fallback: Path, powershell: str) -> subprocess.CompletedProcess[str]:
        stub = fallback.parent / "bin"
        stub.mkdir()
        (stub / "powershell.exe").write_text(f"#!/bin/sh\n{powershell}\n", encoding="utf-8")
        (stub / "wslpath").write_text("#!/bin/sh\nprintf 'Z:\\\\fallback\\n'\n", encoding="utf-8")
        for path in stub.iterdir():
            path.chmod(0o755)
        env = os.environ.copy()
        env["PATH"] = f"{stub}:{env['PATH']}"
        env["IDA_WINDOWS_FALLBACK_ROOT"] = str(fallback)
        return subprocess.run(
            ["bash", str(INSTALLER)],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_dependency_refresh_is_deferred_when_windows_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            result = self._run(Path(root) / "fallback", "exit 1")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("dependency refresh deferred", result.stderr)
            self.assertNotIn("No such file", result.stderr)
            self.assertTrue((Path(root) / "fallback" / "run_manager_fallback.ps1").is_file())

    def test_matching_dependency_marker_skips_windows_process(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            fallback = Path(root) / "fallback"
            (fallback / ".venv" / "Scripts").mkdir(parents=True)
            (fallback / ".venv" / "Scripts" / "python.exe").touch()
            (fallback / ".ida-hybrid-manager-native").touch()
            digest = hashlib.sha256((REPO_ROOT / "pyproject.toml").read_bytes()).hexdigest()
            (fallback / ".ida-hybrid-manager-deps.sha256").write_text(digest + "\n", encoding="ascii")
            result = self._run(fallback, "exit 99")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("dependency refresh deferred", result.stderr)


if __name__ == "__main__":
    unittest.main()
