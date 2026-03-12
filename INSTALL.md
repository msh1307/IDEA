# Install

## 1. WSL manager

```bash
git clone <repo-url>
cd ida-hybrid-manager
./scripts/install_wsl.sh
```

This creates `.venv` and installs the manager in editable mode.

## 2. Windows IDA plugin overlay

Open PowerShell on Windows:

```powershell
cd <repo>\ida-hybrid-manager
.\scripts\install_plugin.ps1
```

Default target:

- `C:\Users\<user>\AppData\Roaming\Hex-Rays\IDA Pro\plugins`

What it does:

- backs up the current `ida_mcp` plugin files
- overlays the patched files from `plugin_overlay/`
- leaves unrelated plugin files untouched

## 3. Run the manager

From WSL:

```bash
cd ida-hybrid-manager
./scripts/run_manager.sh
```

Manager endpoints:

- health API: `http://0.0.0.0:18080/healthz`
- MCP server: `http://0.0.0.0:18081/mcp`

## 4. Quick smoke test

From WSL:

```bash
./scripts/smoke_test_headless.sh
```

## Notes

- The manager package is meant to be installed from Git like a normal Python project.
- The plugin overlay is intentionally separate because it patches an existing `ida_mcp` install instead of replacing the whole plugin tree.
- If your Codex or local MCP config already pins the correct Windows host path, keep using that. The code still keeps fallback probes because WSL networking is inconsistent across systems.
